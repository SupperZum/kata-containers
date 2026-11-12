// SPDX-License-Identifier: Apache-2.0
//! Authenticate the immutable guest artifacts and signed attempt before
//! accepting the preparation role's private channel.
use crate::{
    exec_observer::Observer,
    final_task_runtime::FinalTaskRuntime,
    gcp_protected_export::GcpExportConfig,
    rootfs_custody::{ReceiverFactory, ReceiverLimits, ReceiverProgress},
};
use anyhow::{anyhow, ensure, Context, Result};
use execution_proof_contract::{gcp_policy_receipt::GcpAggregateExpectations, GrantExpectations};
use execution_proof_handoff::{
    admission::gcp::GcpGuestAdmissionConfig,
    fd_transport::{FdExpectation, SendOutcome},
    gcp_startup::{self as startup, LoadedRole, Publication, PublicationKind, KATA_SOCKET},
    startup::{Role, StartupBoundChannel},
};
use image_rs::preparation::{
    erofs_mount::{ErofsMountLimits, MountedViewLimits},
    launch_spec::{BoundEffectiveSpec, EffectiveSpecLimits, EffectiveSpecPolicy},
    received_view::ReceivedViewLimits,
    static_elf::StaticElfLimits,
};
use std::{
    ffi::OsString,
    fs::File,
    os::{fd::AsFd, unix::fs::MetadataExt},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const STARTUP_TIME: Duration = Duration::from_secs(60);
const RECEIVER_TIME: Duration = Duration::from_secs(300);
const ROLE_TIME: Duration = Duration::from_secs(600);
const POLL: Duration = Duration::from_millis(1);
const IMAGE_BYTES: usize = startup::MAX_IMAGE_BYTES as usize;
const IMAGE_INODES: usize = startup::MAX_IMAGE_INODES as usize;

pub(super) fn entrypoint() -> Result<()> {
    protect_process()?;
    validate_arguments(std::env::args_os())?;
    ensure!(
        unsafe { libc::getpid() } != 1,
        "Kata proof role requires its preparation owner"
    );
    // C/D fixed paths, readonly EROFS and all actual leaves are checked here.
    // The inherited capsule hint selects only an owned sealed-public FD.
    let loaded = startup::load(Role::Kata).context("authenticate immutable role closure")?;
    ensure!(
        loaded.artifacts().config().rpc_policy_sha384
            == hash(startup::rpc_policy_bytes(loaded.sandbox_gateway_enabled())),
        "compiled RPC policy mismatch"
    );
    // SAFETY: this dedicated entrypoint owns the inherited startup descriptors,
    // calls once before any other code can close/reassign them, and obtains all
    // expected role/config/executable pins from the independent fixed loader.
    let channel =
        unsafe { StartupBoundChannel::accept_inherited(loaded.expected_startup(), STARTUP_TIME) }
            .context("authenticate private role channel")?;
    capctl::prctl::set_subreaper(true).context("initialize private task reaper")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(loaded, channel))
}

pub(super) fn protect_process() -> Result<()> {
    // exec resets dumpability. Establish this before reading the capsule or
    // starting any worker.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
        "disable role dumping"
    );
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core) } == 0,
        "disable role core dumps"
    );
    // Before any worker or listener: prevent the bind's initial socket inode
    // from being publicly accessible before its explicit role-group ownership.
    unsafe {
        libc::umask(0o077);
    }
    Ok(())
}
fn validate_arguments(args: impl IntoIterator<Item = OsString>) -> Result<()> {
    ensure!(
        args.into_iter().count() == 1,
        "proof role accepts no configuration arguments"
    );
    Ok(())
}
pub(super) fn hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha384};
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn raw<const N: usize>(value: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == N * 2
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid role commitment"
    );
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    ensure!(result != [0; N], "empty role commitment");
    Ok(result)
}
fn receiver_limits() -> ReceiverLimits {
    ReceiverLimits {
        admission_bytes: 1 << 20,
        provenance_bytes: 1 << 20,
        view: ReceivedViewLimits {
            mount: ErofsMountLimits {
                view: MountedViewLimits {
                    inodes: IMAGE_INODES,
                    live_file_bytes: IMAGE_BYTES,
                    path_bytes: 256,
                    path_components: 32,
                    directory_entry_bytes: 4 << 20,
                },
                backing_bytes: IMAGE_BYTES,
                ramfs_data_bytes: IMAGE_BYTES,
                wall_time: RECEIVER_TIME,
            },
            inventory_path_bytes: 4 << 20,
        },
        elf: StaticElfLimits {
            file_bytes: IMAGE_BYTES,
            program_headers: 128,
            mapped_bytes: IMAGE_BYTES as u64,
            virtual_span_bytes: IMAGE_BYTES as u64,
        },
        wall_time: RECEIVER_TIME,
    }
}
fn spec_limits() -> EffectiveSpecLimits {
    EffectiveSpecLimits {
        spec_bytes: 256 << 10,
        args: 32,
        env: 64,
        string_bytes: 4096,
        total_string_bytes: 64 << 10,
        path_bytes: 256,
        path_components: 32,
        syscalls: 32,
        json_depth: 16,
    }
}

pub(super) fn parse_effective_spec(bytes: &[u8], sha384: &str) -> Result<BoundEffectiveSpec> {
    BoundEffectiveSpec::parse(
        bytes,
        sha384,
        &EffectiveSpecPolicy {
            uid: startup::WORKLOAD_UID,
            gid: startup::WORKLOAD_GID,
            seccomp_syscalls: startup::WORKLOAD_SYSCALLS
                .iter()
                .map(|name| (*name).into())
                .collect(),
        },
        spec_limits(),
    )
    .context("validate signed effective spec")
}
fn admission(loaded: &LoadedRole) -> GcpGuestAdmissionConfig {
    let config = loaded.artifacts().config();
    GcpGuestAdmissionConfig {
        grant: GrantExpectations {
            authority_public_key: config.roots.authority_public_key,
            audience: config.grant_audience.clone(),
            authority: config.authority.clone(),
            tenant: config.tenant.clone(),
            profile_sha384: loaded.grant().binding.profile_sha384.clone(),
            launch_policy_sha384: config.launch_policy_sha384.clone(),
            image_policy_sha384: config.image_policy_sha384.clone(),
        },
        expected_grant: loaded.grant().clone(),
        aggregate: GcpAggregateExpectations {
            kbs_proof_public_key: config.roots.kbs_proof_public_key,
            boot_binding: loaded.binding().clone(),
            expected: loaded.aggregate().clone(),
        },
        audience: config.admission_receipt_audience.clone(),
        issuer: config.authority.clone(),
        admission_policy_sha384: loaded.plan().admission_policy_sha384.clone(),
    }
}
async fn run(loaded: LoadedRole, channel: StartupBoundChannel) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(ROLE_TIME)
        .ok_or_else(|| anyhow!("role lifetime invalid"))?;
    let startup_binding = channel.binding_commitment();
    let cid = loaded.plan().container_id.clone();
    let spec = parse_effective_spec(
        &loaded.capsule().effective_spec,
        &loaded.plan().effective_spec_sha384,
    )?;
    let factory = ReceiverFactory::new(1)?;
    let mut receiver = factory.begin_gcp(channel, admission(&loaded), spec, receiver_limits())?;
    // This owner is retained across synchronous parsing/mount calls. Cancellation
    // is cooperative; the external preparation owner retains a physical timeout.
    let lease = loop {
        ensure!(Instant::now() < deadline, "role deadline");
        if receiver.advance(&|| Instant::now() >= deadline)? == ReceiverProgress::Finalized {
            break receiver.take_lease()?;
        }
        tokio::time::sleep(POLL).await;
    };
    let mut channel = receiver.take_completed_channel()?;
    drop(receiver);
    let (tasks, export_owner) = FinalTaskRuntime::with_gcp_protected_export(
        1,
        GcpExportConfig {
            audience: loaded.plan().execution_audience.clone(),
            boot_binding: loaded.binding().clone(),
            trust_snapshot_sha384: raw(&loaded.plan().trust_snapshot_sha384)?,
            expected_startup_binding_sha384: startup_binding,
        },
    )?;
    tasks.stage(&cid, lease)?;
    let mut observer = OwnedObserver::new()?;
    let result = serve(
        &loaded,
        &tasks,
        &observer.observer,
        &cid,
        &mut channel,
        deadline,
    )
    .await;
    // Stop new requests before task cleanup. Existing calls select only the
    // one runtime tombstone; no additional lease can enter through RPC.
    let cleanup = tasks.remove(&cid).await;
    observer.finish()?;
    drop(tasks);
    let export_cleanup = export_owner.shutdown();
    ensure!(factory.active() == 0, "receiver lease cleanup incomplete");
    result?;
    cleanup?;
    export_cleanup?;
    Ok(())
}
async fn serve(
    loaded: &LoadedRole,
    tasks: &FinalTaskRuntime,
    observer: &Observer,
    cid: &str,
    channel: &mut StartupBoundChannel,
    deadline: Instant,
) -> Result<()> {
    let socket_parent = private_socket_parent(KATA_SOCKET)?;
    let address = format!("unix://{KATA_SOCKET}");
    let mut server = crate::gcp_rpc::start_gcp_proof(&address, observer.clone(), tasks.clone())?;
    let mode = if loaded.sandbox_gateway_enabled() {
        0o600
    } else {
        0o660
    };
    let name = std::ffi::CStr::from_bytes_with_nul(b"kata-agent.sock\0")?;
    private_socket_permissions(&socket_parent, name, mode)?;
    server.start().await?;
    let result = publish_until_stop(loaded, tasks, cid, channel, deadline).await;
    server.stop_listen().await;
    // Resolve active WaitProcess/Start requests before disconnect waits for them.
    let remove = tasks.remove(cid).await;
    let shutdown = server.shutdown().await;
    result?;
    remove?;
    shutdown?;
    Ok(())
}
pub(super) fn private_socket_parent(path: &str) -> Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let root = File::open("/")?;
    let open = |parent: &File, name: &std::ffi::CStr| -> Result<File> {
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        ensure!(raw >= 0, "private listener parent unavailable");
        Ok(unsafe { File::from_raw_fd(raw) })
    };
    let run = open(&root, std::ffi::CStr::from_bytes_with_nul(b"run\0")?)?;
    let run_metadata = run.metadata()?;
    ensure!(
        run_metadata.uid() == 0 && run_metadata.mode() & 0o022 == 0,
        "runtime parent writable"
    );
    let parent = open(&run, std::ffi::CStr::from_bytes_with_nul(b"onb17\0")?)?;
    let metadata = parent.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.gid() == 1001 && metadata.mode() & 0o777 == 0o750,
        "private listener parent invalid"
    );
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatfs(parent.as_raw_fd(), &mut filesystem) } == 0
            && [0x8584_58f6u64, 0x0102_1994u64].contains(&(filesystem.f_type as u64)),
        "private runtime filesystem rejected"
    );
    ensure!(
        std::fs::symlink_metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "private listener already exists"
    );
    Ok(parent)
}

pub(super) fn private_socket_permissions(
    parent: &File,
    name: &std::ffi::CStr,
    mode: libc::mode_t,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = parent.as_raw_fd();
    ensure!(
        unsafe { libc::fchownat(fd, name.as_ptr(), 0, 1001, libc::AT_SYMLINK_NOFOLLOW) } == 0,
        "private listener ownership failed"
    );
    // Direct fchmodat2 has no libc path-following fallback. Unsupported kernels
    // fail closed; the selected kernel/closure must support this operation.
    ensure!(
        unsafe {
            libc::syscall(
                libc::SYS_fchmodat2,
                fd,
                name.as_ptr(),
                mode,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0,
        "private listener mode failed"
    );
    let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::fstatat(fd, name.as_ptr(), &mut metadata, libc::AT_SYMLINK_NOFOLLOW) } == 0
            && metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && metadata.st_uid == 0
            && metadata.st_gid == 1001
            && metadata.st_mode & 0o777 == mode,
        "private listener invalid"
    );
    Ok(())
}

async fn publish_until_stop(
    loaded: &LoadedRole,
    tasks: &FinalTaskRuntime,
    cid: &str,
    channel: &mut StartupBoundChannel,
    deadline: Instant,
) -> Result<()> {
    send(
        channel,
        &Publication::control(PublicationKind::Ready)?,
        None,
        deadline,
    )
    .await?;
    let mut requested = false;
    let mut published = false;
    loop {
        ensure!(Instant::now() < deadline, "role lifetime exceeded");
        if let Some(packet) = channel.try_receive_bound(FdExpectation::None)? {
            let (wire, fd) = packet.into_parts();
            ensure!(
                fd.is_none() && Publication::decode(&wire)?.kind == PublicationKind::Stop,
                "unexpected private control frame"
            );
            return Ok(());
        }
        if !requested && !published && tasks.record(cid)?.is_some() {
            let challenge =
                tasks.gcp_export_challenge(cid, raw(&loaded.plan().execution_nonce_hex)?)?;
            tasks.request_gcp_export(cid, &challenge)?;
            requested = true;
        }
        if !requested && !published && tasks.gcp_proof_unavailable(cid)? {
            // Missing proof is not a NoExec claim, even after a failed start.
            send(
                channel,
                &Publication::control(PublicationKind::Unproven)?,
                None,
                deadline,
            )
            .await?;
            published = true;
        }
        if requested && !published {
            use crate::protected_export::ExportStatus;
            match tasks.gcp_export_status(cid)? {
                ExportStatus::Ready => {
                    let output = tasks
                        .gcp_exported(cid)?
                        .ok_or_else(|| anyhow!("public export unavailable"))?;
                    let bytes = output.encode_public()?;
                    let (publication, file) = Publication::export(&bytes)?;
                    send(channel, &publication, Some(&file), deadline).await?;
                    published = true;
                }
                ExportStatus::Exhausted(_) | ExportStatus::Stopped => {
                    send(
                        channel,
                        &Publication::control(PublicationKind::Unproven)?,
                        None,
                        deadline,
                    )
                    .await?;
                    published = true;
                }
                ExportStatus::Pending { .. } => (),
            }
        }
        tokio::time::sleep(POLL).await;
    }
}
async fn send(
    channel: &mut StartupBoundChannel,
    publication: &Publication,
    file: Option<&File>,
    deadline: Instant,
) -> Result<()> {
    let wire = publication.encode()?;
    loop {
        ensure!(Instant::now() < deadline, "publication deadline");
        if channel.try_send(&wire, file.map(AsFd::as_fd))? == SendOutcome::Sent {
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
}
struct OwnedObserver {
    observer: Observer,
    owner: Option<JoinHandle<Result<()>>>,
    reaper: Option<JoinHandle<Result<()>>>,
    stop: Arc<AtomicBool>,
}
impl OwnedObserver {
    fn new() -> Result<Self> {
        let (observer, owner) = Observer::start(4)?;
        let stop = Arc::new(AtomicBool::new(false));
        let observed = observer.clone();
        let stopping = stop.clone();
        let reaper = thread::Builder::new()
            .name("gcp-proof-reaper".into())
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) || observed.active_tasks()? != 0 {
                    {
                        let _gate = observed.wait_guard()?;
                        while observed.poll_kernel_wait()?.is_some() {}
                    }
                    thread::sleep(POLL);
                }
                Ok(())
            });
        let reaper = match reaper {
            Ok(reaper) => reaper,
            Err(error) => {
                observer.shutdown();
                let _ = owner.join();
                return Err(error.into());
            }
        };
        Ok(Self {
            observer,
            owner: Some(owner),
            reaper: Some(reaper),
            stop,
        })
    }
    fn finish(&mut self) -> Result<()> {
        self.observer.shutdown();
        self.stop.store(true, Ordering::Release);
        let reaper = self
            .reaper
            .take()
            .map(|owner| owner.join().map_err(|_| anyhow!("reaper owner failed")));
        let observer = self
            .owner
            .take()
            .map(|owner| owner.join().map_err(|_| anyhow!("observer owner failed")));
        // Take and join both owners even when one panicked or returned failure.
        if let Some(result) = reaper {
            result??;
        }
        if let Some(result) = observer {
            result??;
        }
        ensure!(self.observer.active_tasks()? == 0, "observer tasks remain");
        Ok(())
    }
}
impl Drop for OwnedObserver {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_arguments_cannot_select_config_paths_or_runtime_mode() {
        assert!(validate_arguments([OsString::from("kata-agent")]).is_ok());
        assert!(validate_arguments([
            OsString::from("kata-agent"),
            OsString::from("--config"),
            OsString::from("/host/config")
        ])
        .is_err());
        assert!(validate_arguments(std::iter::empty()).is_err());
    }
    #[test]
    fn private_observer_owner_stops_and_joins_without_task_state() {
        let mut owner = OwnedObserver::new().unwrap();
        owner.finish().unwrap();
        assert!(owner.owner.is_none() && owner.reaper.is_none());
    }
}
