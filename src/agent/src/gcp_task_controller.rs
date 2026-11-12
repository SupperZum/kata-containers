// SPDX-License-Identifier: Apache-2.0
//! Drive task RPCs for the candidate already authenticated by the guest.
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{gcp_startup::GcpAttemptPlanV1, Signed};
use image_rs::preparation::launch_spec::{
    BoundEffectiveSpec, EffectiveSpecLimits, EffectiveSpecPolicy,
};
use protobuf::MessageField;
use protocols::{
    agent as rpc, agent_ttrpc_async::AgentServiceClient, health_ttrpc_async::HealthClient,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::Duration,
};
use tokio::time::Instant;

const MAX_CONTROL: usize = 2 << 20;
const MAX_SPEC: usize = 256 << 10;
const STDIO_BYTES: u32 = 32768;
const PROFILE_VERSION: &str = "onb17.gcp-proof-startup.v1";
const PROFILE_MARKER: &str = "gcp-proof-startup";
const PURPOSE: &str = "qlad.execution-proof.gcp-manual-task-control.v1";
const HELP: &str = "GCP execution-proof task controller\n\nUsage: kata-gcp-task-controller --control PUBLIC.json --socket /absolute/caa-proxy.sock [--timeout-seconds 120]\n\nSubmit one signed candidate to an existing CAA Unix proxy socket. The guest authenticates its plan and custody lease. Output reports RPC transport results only.\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    version: u16,
    purpose: String,
    signed_plan: Signed<GcpAttemptPlanV1>,
    #[serde(deserialize_with = "spec_bytes")]
    effective_spec: Vec<u8>,
    sandbox_alias: String,
}
fn spec_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> serde::de::Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded nonempty public candidate bytes")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<u8>, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
                if bytes.len() == MAX_SPEC {
                    return Err(serde::de::Error::custom("candidate byte bound"));
                }
                bytes.push(byte);
            }
            if bytes.is_empty() {
                return Err(serde::de::Error::custom("empty candidate"));
            }
            Ok(bytes)
        }
    }
    d.deserialize_seq(Bytes)
}
struct Prepared {
    cid: String,
    sandbox_alias: String,
    spec: protocols::oci::Spec,
}

/// Standard OCI-to-protobuf encoding with no host namespace, mount, root path,
/// identity, seccomp, environment or capability transformations.
pub(crate) fn candidate_to_protocol(
    raw: &[u8],
    plan: &GcpAttemptPlanV1,
) -> Result<protocols::oci::Spec> {
    let candidate = checked_candidate(raw, plan)?;
    let spec: oci_spec::runtime::Spec = serde_json::from_slice(candidate.raw_bytes())?;
    Ok(spec.into())
}
fn checked_candidate(raw: &[u8], plan: &GcpAttemptPlanV1) -> Result<BoundEffectiveSpec> {
    plan.signing_bytes()?;
    Ok(BoundEffectiveSpec::parse(
        raw,
        &plan.effective_spec_sha384,
        &EffectiveSpecPolicy {
            uid: 1000,
            gid: 1000,
            seccomp_syscalls: vec!["execveat".into(), "exit_group".into(), "write".into()],
        },
        EffectiveSpecLimits {
            spec_bytes: MAX_SPEC,
            args: 32,
            env: 64,
            string_bytes: 4096,
            total_string_bytes: 32 << 10,
            path_bytes: 256,
            path_components: 32,
            syscalls: 3,
            json_depth: 16,
        },
    )?)
}
fn parse_control(wire: &[u8]) -> Result<Prepared> {
    ensure!(
        !wire.is_empty() && wire.len() <= MAX_CONTROL,
        "control bound"
    );
    let control: Control = serde_json::from_slice(wire)?;
    ensure!(
        control.version == 1 && control.purpose == PURPOSE,
        "control domain"
    );
    let plan = &control.signed_plan.statement;
    // No host-selected trust root is accepted. This checks statement structure
    // and signature encoding only; the signature is not authenticated here.
    plan.signing_bytes()?;
    ensure!(
        control.signed_plan.signature.len() == 128
            && control
                .signed_plan
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && control.signed_plan.signature != "00".repeat(64),
        "signature encoding"
    );
    ensure!(identifier(&plan.container_id, false), "guest task selector");
    ensure!(identifier(&control.sandbox_alias, true), "sandbox alias");
    Ok(Prepared {
        cid: plan.container_id.clone(),
        sandbox_alias: control.sandbox_alias,
        spec: candidate_to_protocol(&control.effective_spec, plan)?,
    })
}
fn identifier(value: &str, colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b) || (colon && b == b':'))
}

struct Options {
    control: PathBuf,
    socket: String,
    timeout: Duration,
}
enum Arguments {
    Help,
    Run(Options),
}
fn arguments(args: impl IntoIterator<Item = OsString>) -> Result<Arguments> {
    let mut args = args.into_iter();
    args.next();
    let args: Vec<_> = args.take(8).collect();
    if args == [OsString::from("--help")] {
        return Ok(Arguments::Help);
    }
    ensure!(args.len() == 4 || args.len() == 6, "arguments");
    let mut control = None;
    let mut socket = None;
    let mut timeout = None;
    for pair in args.as_chunks::<2>().0 {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("argument encoding"))?;
        match key {
            "--control" if control.is_none() => {
                ensure!(pair[1].len() <= 4096, "control path bound");
                control = Some(PathBuf::from(&pair[1]));
            }
            "--socket" if socket.is_none() => {
                let value = pair[1]
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("socket encoding"))?;
                let path = Path::new(value);
                ensure!(
                    !value.is_empty()
                        && value.len() <= 100
                        && path.is_absolute()
                        && !value.as_bytes().contains(&0)
                        && path
                            .components()
                            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                    "literal Unix socket path required"
                );
                socket = Some(value.to_owned());
            }
            "--timeout-seconds" if timeout.is_none() => {
                let value = pair[1]
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("timeout encoding"))?;
                let seconds: u64 = value.parse()?;
                ensure!(
                    (1..=120).contains(&seconds) && seconds.to_string() == value,
                    "timeout bound"
                );
                timeout = Some(Duration::from_secs(seconds));
            }
            _ => anyhow::bail!("unknown or duplicate argument"),
        }
    }
    Ok(Arguments::Run(Options {
        control: control.ok_or_else(|| anyhow::anyhow!("missing control"))?,
        socket: socket.ok_or_else(|| anyhow::anyhow!("missing socket"))?,
        timeout: timeout.unwrap_or(Duration::from_secs(120)),
    }))
}

#[derive(Serialize)]
struct TransportResult {
    version: u16,
    purpose: &'static str,
    rpc_outcome: &'static str,
    last_completed_rpc: Option<&'static str>,
    wait_status: Option<i32>,
    stdout_b64: String,
    stderr_b64: String,
    stdio_limit_bytes: u32,
    stdout_may_have_more: bool,
    stderr_may_have_more: bool,
    error_cleanup: &'static str,
}
impl TransportResult {
    fn new() -> Self {
        Self {
            version: 1,
            purpose: "qlad.execution-proof.gcp-manual-rpc-transport-result.v1",
            rpc_outcome: "rejected",
            last_completed_rpc: None,
            wait_status: None,
            stdout_b64: String::new(),
            stderr_b64: String::new(),
            stdio_limit_bytes: STDIO_BYTES,
            stdout_may_have_more: false,
            stderr_may_have_more: false,
            error_cleanup: "not_requested",
        }
    }
}
fn context(deadline: Instant) -> ttrpc::context::Context {
    let nanoseconds = deadline
        .saturating_duration_since(Instant::now())
        .as_nanos();
    ttrpc::context::with_timeout(nanoseconds.clamp(1, i64::MAX as u128) as i64)
}
fn is_profile(response: &rpc::GuestDetailsResponse) -> bool {
    let Some(details) = response.agent_details.as_ref() else {
        return false;
    };
    response
        .special_fields
        .unknown_fields()
        .iter()
        .next()
        .is_none()
        && details
            .special_fields
            .unknown_fields()
            .iter()
            .next()
            .is_none()
        && response.mem_block_size_bytes == 0
        && !response.support_mem_hotplug_probe
        && details.version == PROFILE_VERSION
        && details.extra_features == [PROFILE_MARKER]
        && !details.init_daemon
        && details.device_handlers.is_empty()
        && details.storage_handlers.is_empty()
        && details.supports_seccomp
}
async fn sequence(
    agent: &AgentServiceClient,
    health: &HealthClient,
    control: &Prepared,
    deadline: Instant,
    report: &mut TransportResult,
    create_attempted: &mut bool,
) -> Result<()> {
    let response = health
        .check(
            context(deadline),
            &protocols::health::CheckRequest {
                service: "grpc.AgentService".into(),
                ..Default::default()
            },
        )
        .await?;
    ensure!(
        response.status() == protocols::health::health_check_response::ServingStatus::SERVING,
        "health rejected"
    );
    report.last_completed_rpc = Some("Health.Check");
    agent
        .create_sandbox(
            context(deadline),
            &rpc::CreateSandboxRequest {
                sandbox_id: control.sandbox_alias.clone(),
                ..Default::default()
            },
        )
        .await?;
    report.last_completed_rpc = Some("CreateSandbox");
    let details = agent
        .get_guest_details(context(deadline), &rpc::GuestDetailsRequest::new())
        .await?;
    ensure!(is_profile(&details), "closed GCP profile required");
    report.last_completed_rpc = Some("GetGuestDetails");
    *create_attempted = true;
    agent
        .create_container(
            context(deadline),
            &rpc::CreateContainerRequest {
                container_id: control.cid.clone(),
                exec_id: control.cid.clone(),
                OCI: MessageField::some(control.spec.clone()),
                ..Default::default()
            },
        )
        .await?;
    report.last_completed_rpc = Some("CreateContainer");
    agent
        .start_container(
            context(deadline),
            &rpc::StartContainerRequest {
                container_id: control.cid.clone(),
                ..Default::default()
            },
        )
        .await?;
    report.last_completed_rpc = Some("StartContainer");
    // Keep all three futures owned by this sequence. A child can fill its pipe
    // before exiting; waiting for exit before reading would deadlock it.
    let terminal = AtomicBool::new(false);
    let progress = Mutex::new(report);
    let wait = async {
        let status = agent
            .wait_process(
                context(deadline),
                &rpc::WaitProcessRequest {
                    container_id: control.cid.clone(),
                    exec_id: control.cid.clone(),
                    ..Default::default()
                },
            )
            .await?
            .status;
        {
            let mut report = progress
                .lock()
                .map_err(|_| anyhow::anyhow!("transport progress unavailable"))?;
            report.wait_status = Some(status);
            report.last_completed_rpc = Some("WaitProcess");
        }
        terminal.store(true, Ordering::Relaxed);
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(
        wait,
        drain_stream(agent, &control.cid, deadline, true, &terminal, &progress),
        drain_stream(agent, &control.cid, deadline, false, &terminal, &progress)
    )?;
    Ok(())
}

async fn drain_stream(
    agent: &AgentServiceClient,
    cid: &str,
    deadline: Instant,
    stdout: bool,
    terminal: &AtomicBool,
    progress: &Mutex<&mut TransportResult>,
) -> Result<()> {
    drain_stream_with(cid, stdout, terminal, progress, |request| async move {
        if stdout {
            agent.read_stdout(context(deadline), &request).await
        } else {
            agent.read_stderr(context(deadline), &request).await
        }
    })
    .await
}

async fn drain_stream_with<F, Fut>(
    cid: &str,
    stdout: bool,
    terminal: &AtomicBool,
    progress: &Mutex<&mut TransportResult>,
    mut read: F,
) -> Result<()>
where
    F: FnMut(rpc::ReadStreamRequest) -> Fut,
    Fut: std::future::Future<Output = ttrpc::Result<rpc::ReadStreamResponse>>,
{
    let mut bytes = Vec::new();
    loop {
        let left = STDIO_BYTES as usize - bytes.len();
        if left == 0 {
            let mut report = progress
                .lock()
                .map_err(|_| anyhow::anyhow!("transport progress unavailable"))?;
            if stdout {
                report.stdout_may_have_more = true;
            } else {
                report.stderr_may_have_more = true;
            }
            return Ok(());
        }
        let request = rpc::ReadStreamRequest {
            container_id: cid.into(),
            exec_id: cid.into(),
            len: left.min(8192) as u32,
            ..Default::default()
        };
        let request_len = request.len;
        // An empty reply selected before child exit may arrive after Wait.
        // Only a read issued after Wait was already observed can establish EOF.
        let issued_after_wait = terminal.load(Ordering::Relaxed);
        let data = read(request).await?.data;
        ensure!(data.len() <= request_len as usize, "stream response bound");
        {
            let mut report = progress
                .lock()
                .map_err(|_| anyhow::anyhow!("transport progress unavailable"))?;
            report.last_completed_rpc = Some(if stdout { "ReadStdout" } else { "ReadStderr" });
            if !data.is_empty() {
                bytes.extend_from_slice(&data);
                if stdout {
                    report.stdout_b64 = STANDARD.encode(&bytes);
                } else {
                    report.stderr_b64 = STANDARD.encode(&bytes);
                }
            }
        }
        if data.is_empty() {
            // Empty reads before Wait returns mean EAGAIN, not EOF. Once the
            // wait response is received, the first empty read ends this drain.
            if issued_after_wait {
                return Ok(());
            }
            if !terminal.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn execute(socket: &str, control: Prepared, timeout: Duration) -> TransportResult {
    let mut report = TransportResult::new();
    if timeout.is_zero() || timeout > Duration::from_secs(120) {
        return report;
    }
    let end = Instant::now() + timeout;
    let cleanup_time = Duration::from_secs(5).min(timeout / 4);
    let deadline = end - cleanup_time;
    let client = match tokio::time::timeout_at(
        deadline,
        ttrpc::r#async::Client::connect(&format!("unix://{socket}")),
    )
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(_)) => {
            report.rpc_outcome = "connect_failed";
            return report;
        }
        Err(_) => {
            report.rpc_outcome = "timeout";
            return report;
        }
    };
    let agent = AgentServiceClient::new(client.clone());
    let health = HealthClient::new(client);
    let mut create_attempted = false;
    match tokio::time::timeout_at(
        deadline,
        sequence(
            &agent,
            &health,
            &control,
            deadline,
            &mut report,
            &mut create_attempted,
        ),
    )
    .await
    {
        Ok(Ok(())) => {
            report.rpc_outcome = "completed";
            return report;
        }
        Ok(Err(_)) => (),
        Err(_) => report.rpc_outcome = "timeout",
    }
    if create_attempted {
        report.error_cleanup = match tokio::time::timeout_at(
            end,
            agent.remove_container(
                context(end),
                &rpc::RemoveContainerRequest {
                    container_id: control.cid,
                    timeout: cleanup_time.as_secs().max(1) as u32,
                    ..Default::default()
                },
            ),
        )
        .await
        {
            Ok(Ok(_)) => "remove_acknowledged",
            _ => "remove_failed",
        };
    }
    report
}

pub(super) fn entrypoint() -> Result<bool> {
    let options = match arguments(std::env::args_os())? {
        Arguments::Help => {
            print!("{HELP}");
            return Ok(true);
        }
        Arguments::Run(options) => options,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(options.control)?;
    ensure!(
        file.metadata()?.is_file(),
        "regular public control file required"
    );
    let mut bytes = Vec::new();
    file.take(MAX_CONTROL as u64 + 1).read_to_end(&mut bytes)?;
    let control = parse_control(&bytes)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(execute(&options.socket, control, options.timeout));
    let success = report.rpc_outcome == "completed";
    println!("{}", serde_json::to_string(&report)?);
    Ok(success)
}

#[cfg(test)]
#[path = "gcp_task_spec.rs"]
mod guest_spec_gate;
#[cfg(test)]
#[path = "gcp_task_controller_tests.rs"]
mod tests;
