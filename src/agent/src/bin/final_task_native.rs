// SPDX-License-Identifier: Apache-2.0
//! Native role exercising the actual final-task runtime with a received lease.

#[path = "../../../../../guest-components-prepared-dev/tests/launch-credential-checks/src/custody_fixture_config.rs"]
pub mod custody_fixture_config;
#[path = "../exec_observer.rs"]
pub mod exec_observer;
#[path = "../final_task.rs"]
mod final_task;
#[path = "../final_task_runtime.rs"]
pub mod final_task_runtime;
#[cfg(feature = "protected-export-gcp-tdx")]
#[path = "../gcp_protected_export.rs"]
pub mod gcp_protected_export;
#[cfg(feature = "protected-export")]
#[path = "../protected_export.rs"]
pub mod protected_export;
#[path = "../rootfs_custody.rs"]
pub mod rootfs_custody;

#[cfg(all(
    feature = "protected-export-native",
    feature = "protected-export-gcp-native"
))]
compile_error!("select exactly one native protected-export profile");
use anyhow::{bail, ensure, Context, Result};
use custody_fixture_config::{FixtureMode, FixtureReceiverWire, TaskCase, FIXTURE_CONFIG_BYTES};
use exec_observer::Observer;
use execution_proof_handoff::{
    execution::ExecutionRecord,
    startup::{ExpectedStartup, Role, StartupBoundChannel},
};
use final_task_runtime::FinalTaskRuntime;
use image_rs::preparation::{
    erofs_mount::{ErofsMountLimits, MountedViewLimits},
    received_view::ReceivedViewLimits,
    static_elf::StaticElfLimits,
    SealedImageBytes,
};
use rootfs_custody::{ReceiverFactory, ReceiverLimits, ReceiverProgress};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{fd::AsFd, unix::fs::FileExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

const WORK_TIME: Duration = Duration::from_secs(60);
const IMAGE_BYTES: usize = 1 << 20;
const CONTAINER: &str = "native-final-application";

struct Arguments {
    config_fd: u32,
    config_sha384: [u8; 48],
    preparation_sha384: [u8; 48],
    kata_sha384: [u8; 48],
}

fn main() {
    let mut control = None;
    let initial_fds = descriptor_count().expect("initial descriptor inventory");
    // Startup transfers the role endpoint and its bootstrap ticket. Both are
    // consumed before final teardown, including the ticket read at admission.
    let final_baseline = initial_fds.checked_sub(2).expect("two startup descriptors");
    let initial_mounts = fs::read("/proc/self/mountinfo").expect("initial mount inventory");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("fixture runtime");
    let result = runtime.block_on(run(&mut control));
    drop(runtime);
    let result = result.and_then(|mut result| {
        let final_fds = descriptor_count()?;
        let mounts_unchanged = fs::read("/proc/self/mountinfo")? == initial_mounts;
        ensure!(
            final_fds == final_baseline,
            "descriptor cleanup: {initial_fds} startup -> {final_fds}, expected {final_baseline}"
        );
        ensure!(mounts_unchanged, "mount inventory changed");
        result["descriptor_cleanup"] = json!(true);
        result["descriptors_before"] = json!(initial_fds);
        result["startup_descriptors_consumed"] = json!(2);
        result["descriptors_after"] = json!(final_fds);
        result["mountinfo_unchanged"] = json!(true);
        Ok(result)
    });
    if let Some(directory) = control {
        let public = match &result {
            Ok(value) => value.clone(),
            Err(error) => json!({"status":"FAIL", "error":format!("{error:#}")}),
        };
        if let Err(error) = write_json(&directory, "result.json", &public) {
            eprintln!("final-task result: {error:#}");
            std::process::exit(1);
        }
    }
    if let Err(error) = result {
        eprintln!("native final-task fixture: {error:#}");
        std::process::exit(1);
    }
}

async fn run(control: &mut Option<PathBuf>) -> Result<serde_json::Value> {
    let deadline = Instant::now() + WORK_TIME;
    let arguments = arguments()?;
    let fixture = read_configuration(&arguments)?;
    *control = Some(fixture.control_directory.clone());
    ensure!(
        fixture.mode == FixtureMode::NativeFinalTask,
        "wrong native role"
    );
    let case = fixture.task_case.context("missing final-task case")?;
    let candidate = fixture.spec().map_err(anyhow::Error::msg)?;
    let actual_spec: oci_spec::runtime::Spec = serde_json::from_slice(&fixture.candidate_spec)?;
    let mut process = actual_spec
        .process()
        .as_ref()
        .context("missing process")?
        .clone();
    // SAFETY: this dedicated role entrypoint owns its inherited startup FDs.
    let channel = unsafe {
        StartupBoundChannel::accept_inherited(
            ExpectedStartup {
                role: Role::Kata,
                boot_config_sha384: arguments.config_sha384,
                own_executable_sha384: arguments.kata_sha384,
                peer_executable_sha384: arguments.preparation_sha384,
            },
            remaining(deadline)?,
        )
    }?;
    let factory = ReceiverFactory::new(1)?;
    let mut receiver = factory.begin(
        channel,
        fixture.admission(),
        candidate,
        limits(fixture.mode),
    )?;
    let lease = loop {
        remaining(deadline)?;
        if receiver.advance(&|| false)? == ReceiverProgress::Finalized {
            break receiver.take_lease()?;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    drop(receiver);
    ensure!(factory.active() == 1, "receiver lease capacity");

    let (observer, owner) = Observer::start(4)?;
    let stop = Arc::new(AtomicBool::new(false));
    let poll_stop = stop.clone();
    let poll_observer = observer.clone();
    let reaper = tokio::spawn(async move {
        while !poll_stop.load(Ordering::Acquire) || poll_observer.active_tasks()? != 0 {
            {
                let _gate = poll_observer.wait_guard()?;
                while poll_observer.poll_kernel_wait()?.is_some() {}
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Ok::<_, anyhow::Error>(())
    });
    #[cfg(not(any(
        feature = "protected-export-native",
        feature = "protected-export-gcp-native"
    )))]
    let tasks = FinalTaskRuntime::new(1)?;
    #[cfg(feature = "protected-export-native")]
    let (tasks, export_owner) = {
        for path in [
            "/dev/tdx_guest",
            "/sys/devices/virtual/misc/tdx_guest",
            "/sys/module/tdx_guest",
            "/sys/kernel/config/tsm/report",
        ] {
            ensure!(
                !Path::new(path).exists(),
                "native fail-closed fixture requires no TDX/TSM interface"
            );
        }
        FinalTaskRuntime::with_protected_export(
            1,
            protected_export::ExportConfig {
                audience: "onb17-native-fail-closed-verifier".into(),
                producer_profile_sha384: decode(&fixture.profile_sha384)?,
                trust_snapshot_sha384: decode(&fixture.admission_policy_sha384)?,
                expected_init_data: decode(&fixture.expected_aggregate.init_data_sha384)?,
            },
        )?
    };
    #[cfg(feature = "protected-export-gcp-native")]
    let (tasks, export_owner) = {
        for path in ["/dev/tdx_guest", "/sys/kernel/config/tsm/report"] {
            ensure!(
                !Path::new(path).exists(),
                "native fixture requires no TDX/TSM interface"
            );
        }
        FinalTaskRuntime::with_gcp_protected_export(
            1,
            gcp_protected_export::GcpExportConfig {
                audience: "onb17-native-fail-closed-verifier".into(),
                // Software-only profile fixture, never an enrolled hardware context.
                boot_binding: execution_proof_contract::gcp_boot_binding::GcpBootBindingV1::new(
                    [1; 48], [2; 48], [3; 48], [4; 48],
                )?,
                trust_snapshot_sha384: decode(&fixture.admission_policy_sha384)?,
                expected_startup_binding_sha384: decode(&lease.record().startup_binding_sha384)?,
            },
        )?
    };
    tasks.stage(CONTAINER, lease)?;
    let (reached_send, reached_receive) = mpsc::sync_channel(1);
    let (release_send, release_receive) = mpsc::sync_channel(1);
    if case == TaskCase::Positive {
        observer.capture_barrier(reached_send, release_receive)?;
    }
    let mut record = None;
    let mut marker_seen = false;
    let mut observed = false;
    let mut captured = false;
    let mut capture_before_resume = false;
    let mut failed_after_exec = false;
    let mut exit_code = None;
    if case == TaskCase::SpecMismatch {
        process.set_args(Some(vec!["/different-entry".into()]));
        // The separate Process frame is authoritative for what is executed.
        let error = tasks
            .create(CONTAINER, &actual_spec, &process, &observer)
            .expect_err("changed final Process accepted");
        ensure!(
            format!("{error:#}").contains("SpecRejected"),
            "unexpected rejection: {error:#}"
        );
        ensure!(tasks.record(CONTAINER)?.is_none(), "record without a task");
    } else {
        let identity = tasks.create(CONTAINER, &actual_spec, &process, &observer)?;
        ensure!(
            identity.pid > 0 && identity.generation > 0,
            "actual task identity"
        );
        ensure!(
            tasks
                .create(CONTAINER, &actual_spec, &process, &observer)
                .is_err(),
            "duplicate Create replaced the live task"
        );
        if case == TaskCase::CancelBeforeStart {
            tasks.remove(CONTAINER).await?;
            ensure!(
                tasks.record(CONTAINER)?.is_none(),
                "record for cancelled gated child"
            );
        } else if case == TaskCase::CaptureRejected {
            observer.fail_next_capture();
            ensure!(
                tasks.start(CONTAINER, &observer).await.is_err(),
                "rejected capture permitted start success"
            );
            let snapshot = tasks.snapshot(CONTAINER)?;
            observed = snapshot.observed;
            captured = snapshot.captured;
            ensure!(
                observed && !captured,
                "failed capture erased the committed exec observation"
            );
            ensure!(
                tasks.record(CONTAINER)?.is_none(),
                "R published after rejected capture"
            );
            let code = tasks.wait(CONTAINER).await?;
            exit_code = Some(code);
            ensure!(
                code == 128 + libc::SIGKILL,
                "capture failure did not kill the task"
            );
            ensure!(
                tasks.read_stdout(CONTAINER, 32768)?.is_empty(),
                "application progressed after rejected capture"
            );
            failed_after_exec = true;
            tasks.remove(CONTAINER).await?;
        } else {
            {
                let _gate = observer.wait_guard()?;
                ensure!(
                    observer
                        .route_wait(nix::sys::wait::WaitStatus::PtraceEvent(
                            nix::unistd::Pid::from_raw(identity.pid),
                            nix::sys::signal::Signal::SIGTRAP,
                            libc::PTRACE_EVENT_EXEC
                        ))
                        .is_err(),
                    "data-only wait status captured proof"
                );
                ensure!(
                    tasks.record(CONTAINER)?.is_none(),
                    "R before actual kernel exec"
                );
            }
            tasks.start(CONTAINER, &observer).await?;
            let snapshot = tasks.snapshot(CONTAINER)?;
            observed = snapshot.observed;
            captured = snapshot.captured;
            ensure!(observed && captured, "execution not captured");
            let bytes = tasks
                .record(CONTAINER)?
                .context("captured record missing")?;
            ensure!(
                tasks
                    .create(CONTAINER, &actual_spec, &process, &observer)
                    .is_err(),
                "duplicate Create replaced the captured task"
            );
            ensure!(
                tasks.record(CONTAINER)?.as_ref() == Some(&bytes),
                "duplicate Create changed protected R"
            );
            let decoded = ExecutionRecord::decode(&bytes)?;
            ensure!(
                decoded.task.pid == identity.pid as u32
                    && decoded.task.generation == identity.generation
                    && decoded.task.container_id == CONTAINER,
                "R/task mismatch"
            );
            record = Some(decoded);
            capture_before_resume = true;
            if case == TaskCase::Positive {
                reached_receive.recv_timeout(remaining(deadline)?)?;
                ensure!(
                    tasks.read_stdout(CONTAINER, 32768)?.is_empty(),
                    "application progressed before protected capture release"
                );
                ensure!(factory.active() == 1, "live task lost its view permit");
                write_marker(&fixture.control_directory, "r-captured")?;
                wait_marker(&fixture.control_directory, "producer-closed", deadline)?;
                ensure!(factory.active() == 1, "producer cleanup revoked task view");
                wait_marker(&fixture.control_directory, "allow-resume", deadline)?;
                release_send.send(())?;
            }
            let code = tasks.wait(CONTAINER).await?;
            exit_code = Some(code);
            let stdout = tasks.read_stdout(CONTAINER, 32768)?;
            marker_seen = stdout == b"ONB17_APP_RAN\n";
            if case == TaskCase::Positive {
                ensure!(code == 0 && marker_seen, "positive application outcome");
            } else {
                ensure!(
                    code == 128 + libc::SIGSEGV && !marker_seen,
                    "post-exec failure outcome"
                );
                failed_after_exec = true;
            }
            tasks.remove(CONTAINER).await?;
            let historical = tasks
                .record(CONTAINER)?
                .context("R lost during task removal")?;
            ensure!(historical == bytes, "task removal changed captured R bytes");
            ensure!(
                Some(ExecutionRecord::decode(&historical)?) == record,
                "task removal changed the protected R/event"
            );
        }
    }
    ensure!(
        factory.active() == 0,
        "view permit retained after actual terminal cleanup"
    );
    ensure!(
        observer.active_tasks()? == 0,
        "tracked task survived cleanup"
    );
    #[cfg(any(
        feature = "protected-export-native",
        feature = "protected-export-gcp-native"
    ))]
    let export_result = {
        let before = tasks.record(CONTAINER)?;
        let mut attempts = 0u8;
        if record.is_some() {
            #[cfg(feature = "protected-export-native")]
            let decoded = record.as_ref().context("native R unavailable")?;
            #[cfg(feature = "protected-export-native")]
            let challenge = execution_proof_handoff::execution_quote::QuoteChallenge::new(
                "onb17-native-fail-closed-verifier".into(),
                [0x77; 32],
                decoded,
                decode(&fixture.profile_sha384)?,
                decode(&fixture.admission_policy_sha384)?,
            )?;
            #[cfg(feature = "protected-export-native")]
            tasks.request_export(CONTAINER, &challenge)?;
            #[cfg(feature = "protected-export-gcp-native")]
            {
                let challenge = tasks.gcp_export_challenge(CONTAINER, [0x77; 32])?;
                tasks.request_gcp_export(CONTAINER, &challenge)?;
            }
            loop {
                remaining(deadline)?;
                #[cfg(feature = "protected-export-native")]
                let status = tasks.export_status(CONTAINER)?;
                #[cfg(feature = "protected-export-gcp-native")]
                let status = tasks.gcp_export_status(CONTAINER)?;
                match status {
                    protected_export::ExportStatus::Pending { .. } => (),
                    protected_export::ExportStatus::Exhausted(
                        protected_export::ExportError::QuoteFailed,
                    ) => {
                        #[cfg(feature = "protected-export-native")]
                        {
                            attempts = tasks.export_attempts(CONTAINER)?;
                        }
                        #[cfg(feature = "protected-export-gcp-native")]
                        {
                            attempts = tasks.gcp_export_attempts(CONTAINER)?;
                        }
                        ensure!(attempts == 3, "native quote attempt budget");
                        break;
                    }
                    other => bail!("unexpected native export outcome: {other:?}"),
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            #[cfg(feature = "protected-export-native")]
            ensure!(
                tasks.exported(CONTAINER)?.is_none(),
                "unavailable TDX produced export bytes"
            );
            #[cfg(feature = "protected-export-gcp-native")]
            ensure!(
                tasks.gcp_exported(CONTAINER)?.is_none(),
                "unavailable GCP TDX produced export bytes"
            );
            ensure!(
                tasks.record(CONTAINER)? == before,
                "quote failure changed protected R"
            );
        } else {
            ensure!(tasks.record(CONTAINER)?.is_none(), "negative task minted R");
        }
        export_owner.shutdown()?;
        #[cfg(feature = "protected-export-native")]
        let profile = "real-tdx-unavailable-fail-closed";
        #[cfg(feature = "protected-export-gcp-native")]
        let profile = "real-gcp-tdx-unavailable-fail-closed";
        json!({"export_attempts":attempts,"exported":false,"r_preserved_after_export_failure":record.is_some(),"export_profile":profile})
    };
    drop(tasks);
    stop.store(true, Ordering::Release);
    reaper.await??;
    observer.shutdown();
    owner
        .join()
        .map_err(|_| anyhow::anyhow!("observer owner panicked"))??;
    drop(observer);
    let result = json!({
        "status":"PASS", "case":case, "record":record,
        "observed":observed, "captured":captured, "marker_seen":marker_seen,
        "capture_before_resume":capture_before_resume, "failed_after_exec":failed_after_exec,
        "exit_code":exit_code, "active_after_task_exit":factory.active(),
    });
    #[cfg(any(
        feature = "protected-export-native",
        feature = "protected-export-gcp-native"
    ))]
    let result = {
        let mut result = result;
        result
            .as_object_mut()
            .context("fixture result object")?
            .extend(
                export_result
                    .as_object()
                    .context("export result object")?
                    .clone(),
            );
        result
    };
    Ok(result)
}

fn limits(mode: FixtureMode) -> ReceiverLimits {
    ReceiverLimits {
        admission_bytes: FIXTURE_CONFIG_BYTES,
        provenance_bytes: FIXTURE_CONFIG_BYTES,
        view: ReceivedViewLimits {
            mount: ErofsMountLimits {
                view: MountedViewLimits {
                    inodes: if mode == FixtureMode::RejectBeforeMount {
                        1
                    } else {
                        32
                    },
                    live_file_bytes: IMAGE_BYTES,
                    path_bytes: 256,
                    path_components: 16,
                    directory_entry_bytes: 16384,
                },
                backing_bytes: IMAGE_BYTES,
                ramfs_data_bytes: IMAGE_BYTES,
                wall_time: WORK_TIME,
            },
            inventory_path_bytes: 16384,
        },
        elf: StaticElfLimits {
            file_bytes: 4096,
            program_headers: 16,
            mapped_bytes: 65536,
            virtual_span_bytes: 65536,
        },
        wall_time: WORK_TIME,
    }
}

fn read_configuration(arguments: &Arguments) -> Result<FixtureReceiverWire> {
    unsafe extern "C" {
        fn getppid() -> std::ffi::c_int;
    }
    // SAFETY: getppid takes no pointers and returns the current parent process ID.
    let parent = unsafe { getppid() };
    ensure!(parent > 1, "fixture launcher missing");
    let file = File::open(format!("/proc/{parent}/fd/{}", arguments.config_fd))
        .context("fixture config descriptor")?;
    let sealed = SealedImageBytes::from_received_fd(
        file.into(),
        FIXTURE_CONFIG_BYTES as u64,
        arguments.config_sha384,
    )
    .context("sealed fixture config")?;
    let mut bytes = vec![0; sealed.byte_len() as usize];
    let alias = File::from(
        sealed
            .as_fd()
            .try_clone_to_owned()
            .context("fixture config alias")?,
    );
    alias
        .read_exact_at(&mut bytes, 0)
        .context("fixture config read")?;
    FixtureReceiverWire::decode(&bytes).map_err(anyhow::Error::msg)
}

fn arguments() -> Result<Arguments> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    ensure!(arguments.len() == 8, "expected four fixture argument pairs");
    let mut config_fd = None;
    let mut config_sha384 = None;
    let mut preparation_sha384 = None;
    let mut kata_sha384 = None;
    for pair in arguments.as_chunks::<2>().0 {
        match pair[0].as_str() {
            "--fixture-config-fd" if config_fd.is_none() => {
                config_fd = Some(pair[1].parse::<u32>().context("fixture config FD number")?);
            }
            "--fixture-config-sha384" if config_sha384.is_none() => {
                config_sha384 = Some(decode(&pair[1])?)
            }
            "--preparation-sha384" if preparation_sha384.is_none() => {
                preparation_sha384 = Some(decode(&pair[1])?)
            }
            "--kata-sha384" if kata_sha384.is_none() => kata_sha384 = Some(decode(&pair[1])?),
            _ => bail!("unknown or duplicate fixture argument"),
        }
    }
    Ok(Arguments {
        config_fd: config_fd.context("fixture config FD missing")?,
        config_sha384: config_sha384.context("fixture config hash missing")?,
        preparation_sha384: preparation_sha384.context("preparation hash missing")?,
        kata_sha384: kata_sha384.context("Kata hash missing")?,
    })
}

fn decode(value: &str) -> Result<[u8; 48]> {
    ensure!(
        value.len() == 96
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "fixture SHA384 must be canonical lowercase hexadecimal"
    );
    let mut digest = [0; 48];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        digest[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(digest)
}

fn descriptor_count() -> Result<usize> {
    // The directory iterator itself owns the fourth FD while it is counted.
    fs::read_dir("/proc/self/fd")
        .context("descriptor inventory")?
        .try_fold(0, |count, entry| entry.map(|_| count + 1))
        .context("descriptor inventory entry")
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    ensure!(!duration.is_zero(), "native custody fixture deadline");
    Ok(duration)
}

fn marker_exists(directory: &Path, name: &str) -> Result<bool> {
    directory
        .join(name)
        .try_exists()
        .context("barrier readiness")
}

fn wait_marker(directory: &Path, name: &str, deadline: Instant) -> Result<()> {
    loop {
        remaining(deadline)?;
        if marker_exists(directory, name)? {
            return Ok(());
        }
        poll_pause();
    }
}

fn poll_pause() {
    // Throttle readiness polling; barrier files, rather than elapsed time,
    // determine when either protocol participant may make the next transition.
    std::thread::sleep(Duration::from_millis(1));
}

fn write_marker(directory: &Path, name: &str) -> Result<()> {
    write_atomic(directory, name, b"ready\n")
}

fn write_json(directory: &Path, name: &str, value: &serde_json::Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).context("public result encoding")?;
    bytes.push(b'\n');
    write_atomic(directory, name, &bytes)
}

fn write_atomic(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = directory.join(format!(".{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .context("public marker creation")?;
    file.write_all(bytes).context("public marker write")?;
    file.sync_all().context("public marker sync")?;
    drop(file);
    fs::rename(temporary, directory.join(name)).context("public marker publication")
}
