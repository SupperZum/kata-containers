// SPDX-License-Identifier: Apache-2.0
//! Measured early sandbox role and its private preparation-owner protocol.
use crate::{gcp_sandbox_gateway, gcp_startup};
use anyhow::{ensure, Context, Result};
use execution_proof_contract::gcp_startup::MAX_SPEC_BYTES;
use execution_proof_handoff::{
    fd_transport::{FdExpectation, SendOutcome},
    gcp_startup::{self as startup, KATA_SOCKET},
    sandbox_gateway::{ChildEvent, ParentCommand, ARGUMENT, SOCKET},
    startup::{Role, StartupBoundChannel},
};
use std::{
    fs::File,
    os::fd::OwnedFd,
    time::{Duration, Instant},
};

pub(super) const PAUSE_ARGUMENT: &str = "--gcp-sandbox-pause";
const PHASE_TIMEOUT: Duration = Duration::from_secs(60);
const ROLE_TIMEOUT: Duration = Duration::from_secs(600);
const WORKER_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_millis(1);

pub(super) fn entrypoint() -> Result<()> {
    require_mode(ARGUMENT)?;
    gcp_startup::protect_process()?;
    let embedded = startup::load_embedded(Role::Kata)?;
    ensure!(
        embedded.sandbox_gateway_enabled(),
        "sandbox gateway requires the measured relay profile"
    );
    // The authenticated launcher reserves and owns the inherited descriptor
    // aliases. The measured closure independently supplies both executable pins.
    let mut channel = unsafe {
        StartupBoundChannel::accept_inherited(embedded.expected_startup(), PHASE_TIMEOUT)
    }?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(&mut channel))
}

async fn serve(channel: &mut StartupBoundChannel) -> Result<()> {
    let parent = gcp_startup::private_socket_parent(SOCKET)?;
    let address = format!("unix://{SOCKET}");
    let (mut server, mut gateway) = gcp_sandbox_gateway::bind_with_exit_barrier(&address)?;
    let name = std::ffi::CStr::from_bytes_with_nul(b"kata-sandbox.sock\0")?;
    gcp_startup::private_socket_permissions(&parent, name, 0o660)?;
    server.start().await?;
    let result = run(&mut gateway, channel).await;
    server.stop_listen().await;
    let tasks = gateway.shutdown().await;
    let transport = server.shutdown().await;
    result?;
    tasks?;
    transport?;
    Ok(())
}

async fn run(
    gateway: &mut gcp_sandbox_gateway::GatewayControl,
    channel: &mut StartupBoundChannel,
) -> Result<()> {
    let expiry = Instant::now() + ROLE_TIMEOUT;
    send(channel, ChildEvent::Ready, expiry).await?;
    let candidate = tokio::time::timeout(PHASE_TIMEOUT, gateway.candidate()).await??;
    send(
        channel,
        ChildEvent::Candidate {
            container_id: candidate.container_id,
            wire_sha384: candidate.wire_sha384,
        },
        expiry,
    )
    .await?;

    let (command, descriptor) = tokio::select! {
        result = receive(channel, phase_deadline(expiry)) => result?,
        _ = gateway.cancelled() => anyhow::bail!("sandbox closed before application binding"),
    };
    let ParentCommand::Bind {
        container_id,
        image_ref,
    } = command
    else {
        anyhow::bail!("expected sandbox Bind command");
    };
    let file = File::from(descriptor.context("missing effective spec descriptor")?);
    let bytes = startup::read_sealed_public(&file, MAX_SPEC_BYTES)?;
    // The preparation owner authenticated the signed plan and this exact hash
    // before sending the descriptor over the startup-bound private channel.
    let spec = gcp_startup::parse_effective_spec(&bytes, &gcp_startup::hash(&bytes))?;
    gateway.bind(&container_id, &image_ref, &spec)?;
    send(channel, ChildEvent::Bound, expiry).await?;

    let (command, descriptor) = tokio::select! {
        result = receive(channel, phase_deadline(expiry)) => result?,
        _ = gateway.cancelled() => anyhow::bail!("sandbox closed before protected attach"),
    };
    ensure!(
        matches!(command, ParentCommand::Attach) && descriptor.is_none(),
        "expected sandbox Attach command"
    );
    let app_address = format!("unix://{KATA_SOCKET}");
    tokio::time::timeout_at(phase_deadline(expiry).into(), gateway.attach(&app_address)).await??;
    send(channel, ChildEvent::Attached, expiry).await?;

    let (command, descriptor) = tokio::select! {
        result = receive(channel, expiry) => result?,
        _ = gateway.wait_for_worker_teardown() => anyhow::bail!("sandbox closed before app exit release"),
    };
    ensure!(
        descriptor.is_none(),
        "unexpected sandbox control descriptor"
    );
    match command {
        ParentCommand::ReleaseExit {} => {
            gateway.release_app_exit()?;
            // Keep the relay's agent endpoint available while the worker
            // handles the released terminal status and requests teardown.
            let deadline = (Instant::now() + WORKER_TEARDOWN_TIMEOUT).min(expiry);
            let _ =
                tokio::time::timeout_at(deadline.into(), gateway.wait_for_worker_teardown()).await;
            Ok(())
        }
        ParentCommand::Shutdown => Ok(()),
        _ => anyhow::bail!("expected sandbox ReleaseExit or Shutdown command"),
    }
}

fn phase_deadline(expiry: Instant) -> Instant {
    (Instant::now() + PHASE_TIMEOUT).min(expiry)
}

async fn send(channel: &mut StartupBoundChannel, event: ChildEvent, expiry: Instant) -> Result<()> {
    let wire = serde_json::to_vec(&event)?;
    let deadline = phase_deadline(expiry);
    loop {
        ensure!(Instant::now() < deadline, "sandbox event deadline");
        if channel.try_send(&wire, None)? == SendOutcome::Sent {
            return Ok(());
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn receive(
    channel: &mut StartupBoundChannel,
    deadline: Instant,
) -> Result<(ParentCommand, Option<OwnedFd>)> {
    loop {
        ensure!(Instant::now() < deadline, "sandbox control deadline");
        if let Some(packet) = channel.try_receive(FdExpectation::Optional)? {
            let (wire, descriptor) = packet.into_parts();
            return Ok((serde_json::from_slice(&wire)?, descriptor));
        }
        tokio::time::sleep(POLL).await;
    }
}

fn require_mode(argument: &str) -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    ensure!(
        args.next().as_deref() == Some(std::ffi::OsStr::new(argument)) && args.next().is_none(),
        "invalid sandbox role arguments"
    );
    ensure!(
        unsafe { libc::getuid() == 0 && libc::geteuid() == 0 && libc::getpid() != 1 },
        "sandbox role requires the trusted owner"
    );
    Ok(())
}

pub(super) fn pause_entrypoint() -> Result<()> {
    require_mode(PAUSE_ARGUMENT)?;
    gcp_startup::protect_process()?;
    let parent: libc::pid_t = std::env::var("ONB17_GCP_PAUSE_PARENT")?.parse()?;
    ensure!(
        parent > 1 && unsafe { libc::getppid() == parent },
        "pause owner unavailable"
    );
    const PAUSE_UID_GID: u32 = 65534;
    // The pause is the same pinned program in a separate exec. Drop identity
    // and inherited descriptors before publishing readiness; parent death
    // terminates it even if the sandbox owner cannot reap normally.
    ensure!(
        unsafe {
            libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) == 0
                && libc::setgroups(0, std::ptr::null()) == 0
                && libc::setresgid(PAUSE_UID_GID, PAUSE_UID_GID, PAUSE_UID_GID) == 0
                && libc::setresuid(PAUSE_UID_GID, PAUSE_UID_GID, PAUSE_UID_GID) == 0
                && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == 0
                && libc::getppid() == parent
                && libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == 0
        },
        "pause confinement failed"
    );
    let ready = b"P";
    ensure!(
        unsafe { libc::write(libc::STDOUT_FILENO, ready.as_ptr().cast(), ready.len()) == 1 },
        "pause readiness failed"
    );
    unsafe {
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
    loop {
        unsafe { libc::pause() };
    }
}
