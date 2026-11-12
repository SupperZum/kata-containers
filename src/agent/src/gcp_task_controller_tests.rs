use super::*;
use async_trait::async_trait;
use execution_proof_contract::gcp_boot_binding::GcpBootBindingV1;
use protobuf::Message;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::sync::{atomic::AtomicUsize, Arc, Mutex};
use ttrpc::r#async::{Server, TtrpcContext};

fn candidate() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "ociVersion":"1.2.1","root":{"path":"rootfs","readonly":true},
        "process":{"terminal":false,"user":{"uid":1000,"gid":1000,"additionalGids":[]},
            "args":["/app"],"env":["HOME=/"],"cwd":"/","noNewPrivileges":true,
            "capabilities":{"bounding":[],"effective":[],"inheritable":[],"permitted":[],"ambient":[]}},
        "mounts":[],"linux":{"namespaces":[{"type":"mount"},{"type":"pid"},{"type":"ipc"},{"type":"uts"},{"type":"network"}],
            "seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64"],
                "syscalls":[{"names":["execveat","exit_group","write"],"action":"SCMP_ACT_ALLOW"}]}}
    })).unwrap()
}
fn plan(raw: &[u8]) -> GcpAttemptPlanV1 {
    GcpAttemptPlanV1 {
        version: 1,
        purpose: execution_proof_contract::gcp_startup::PLAN_PURPOSE.into(),
        authority: "test-only-authority".into(),
        boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        grant_sha384: "11".repeat(48),
        aggregate_sha384: "22".repeat(48),
        admission_policy_sha384: "33".repeat(48),
        container_id: "authorized-before-cri-id".into(),
        execution_audience: "test-only-rp".into(),
        execution_nonce_hex: "44".repeat(32),
        effective_spec_sha384: Sha384::digest(raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        trust_snapshot_sha384: "55".repeat(48),
    }
}
fn control() -> Value {
    let raw = candidate();
    json!({"version":1,"purpose":PURPOSE,
        "signed_plan":{"statement":plan(&raw),"signature":"66".repeat(64)},
        "effective_spec":raw,"sandbox_alias":"untrusted-cp-sandbox-alias"})
}
fn prepared() -> Prepared {
    parse_control(&serde_json::to_vec(&control()).unwrap()).unwrap()
}

#[test]
fn candidate_encoding_preserves_the_exact_protocol_profile_and_original_digest() {
    let raw = candidate();
    let attempt_plan = plan(&raw);
    let wire = candidate_to_protocol(&raw, &attempt_plan).unwrap();
    let decoded = protocols::oci::Spec::parse_from_bytes(&wire.write_to_bytes().unwrap()).unwrap();
    assert_eq!(decoded, wire);
    assert_eq!(decoded.Root.Path, "rootfs");
    assert!(decoded.Root.Readonly);
    assert!(decoded.Mounts.is_empty());
    assert_eq!(decoded.Process.User.UID, 1000);
    assert_eq!(decoded.Process.User.GID, 1000);
    assert_eq!(
        decoded.Linux.Seccomp.Syscalls[0].Names,
        ["execveat", "exit_group", "write"]
    );
    assert_eq!(prepared().spec, decoded);
    let checked = checked_candidate(&raw, &attempt_plan).unwrap();
    let retained = guest_spec_gate::verified_protocol_spec(&checked, &decoded).unwrap();
    assert_eq!(
        serde_json::to_value(retained).unwrap(),
        serde_json::from_slice::<Value>(&raw).unwrap()
    );
    // The shared protobuf->OCI conversion is lossy for absent/empty defaults
    // and defaultErrnoRet. The GCP guest gate must compare against its retained
    // candidate's exact protobuf, then use that original signed OCI for create.
    let lossy: oci_spec::runtime::Spec = decoded.into();
    assert_ne!(
        serde_json::to_value(lossy).unwrap(),
        serde_json::from_slice::<Value>(&raw).unwrap()
    );
    assert_eq!(checked.raw_bytes(), raw);
}

#[test]
fn public_control_is_strict_bounded_and_does_not_accept_trust_roots() {
    for case in [
        "unknown",
        "root",
        "signature",
        "digest",
        "mount",
        "alias",
        "cid",
    ] {
        let mut value = control();
        match case {
            "unknown" => value["unmodeled"] = json!(true),
            "root" => value["authority_public_key"] = json!("11".repeat(32)),
            "signature" => value["signed_plan"]["signature"] = json!("AA".repeat(64)),
            "digest" => {
                value["signed_plan"]["statement"]["effective_spec_sha384"] = json!("77".repeat(48))
            }
            "mount" => {
                let mut spec: Value = serde_json::from_slice(&candidate()).unwrap();
                spec["mounts"] = json!([{"destination":"/app","source":"/host/app","type":"bind"}]);
                let raw = serde_json::to_vec(&spec).unwrap();
                value["signed_plan"]["statement"] = serde_json::to_value(plan(&raw)).unwrap();
                value["effective_spec"] = serde_json::to_value(raw).unwrap();
            }
            "alias" => value["sandbox_alias"] = json!("../escape"),
            "cid" => value["signed_plan"]["statement"]["container_id"] = json!("guest:cid"),
            _ => unreachable!(),
        }
        assert!(
            parse_control(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{}",
            case
        );
    }
    let wire = serde_json::to_string(&control()).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(parse_control(wire.as_bytes()).is_err());
    assert!(parse_control(&vec![b' '; MAX_CONTROL + 1]).is_err());
}

#[test]
fn cli_allows_one_literal_unix_socket_and_at_most_120_seconds() {
    let args = |values: &[&str]| arguments(values.iter().map(OsString::from));
    assert!(matches!(args(&["ctl", "--help"]).unwrap(), Arguments::Help));
    assert!(matches!(
        args(&[
            "ctl",
            "--socket",
            "/run/caa.sock",
            "--control",
            "public.json"
        ])
        .unwrap(),
        Arguments::Run(_)
    ));
    for values in [
        vec![
            "ctl",
            "--socket",
            "tcp://127.0.0.1:15150",
            "--control",
            "public.json",
        ],
        vec![
            "ctl",
            "--socket",
            "/run/caa.sock",
            "--socket",
            "/tmp/another.sock",
        ],
        vec![
            "ctl",
            "--socket",
            "/run/caa.sock",
            "--control",
            "public.json",
            "--timeout-seconds",
            "121",
        ],
        vec![
            "ctl",
            "--socket",
            "/run/caa.sock",
            "--control",
            "public.json",
            "--timeout-seconds",
            "0",
        ],
    ] {
        assert!(args(&values).is_err());
    }
}

struct Fixture {
    calls: Mutex<Vec<&'static str>>,
    expected: Prepared,
    mode: &'static str,
    release_wait: tokio::sync::Notify,
    stdout_reads: AtomicUsize,
    stderr_reads: AtomicUsize,
}
impl Fixture {
    fn record(&self, name: &'static str) {
        self.calls.lock().unwrap().push(name);
    }
    fn stream(
        &self,
        name: &'static str,
        req: rpc::ReadStreamRequest,
    ) -> ttrpc::Result<rpc::ReadStreamResponse> {
        self.record(name);
        assert!((1..=8192).contains(&req.len));
        assert_eq!(
            req,
            rpc::ReadStreamRequest {
                container_id: self.expected.cid.clone(),
                exec_id: self.expected.cid.clone(),
                len: req.len,
                ..Default::default()
            }
        );
        let data = if name == "ReadStdout" {
            let count = self.stdout_reads.fetch_add(1, Ordering::Relaxed);
            if self.mode == "oversize" {
                vec![0; STDIO_BYTES as usize + 1]
            } else if self.mode == "output-cap" {
                self.release_wait.notify_one();
                vec![b'A'; req.len as usize]
            } else if count == 1 {
                // First empty read is EAGAIN. Wait cannot finish until the
                // controller reads again and receives this output.
                if self.mode == "success" {
                    self.release_wait.notify_one();
                }
                vec![0, 255, 1]
            } else {
                vec![]
            }
        } else if self.stderr_reads.fetch_add(1, Ordering::Relaxed) == 0 {
            b"test-stderr".to_vec()
        } else {
            vec![]
        };
        Ok(rpc::ReadStreamResponse {
            data,
            ..Default::default()
        })
    }
}
#[async_trait]
impl protocols::health_ttrpc_async::Health for Fixture {
    async fn check(
        &self,
        _: &TtrpcContext,
        req: protocols::health::CheckRequest,
    ) -> ttrpc::Result<protocols::health::HealthCheckResponse> {
        self.record("Health.Check");
        assert_eq!(req.service, "grpc.AgentService");
        let mut response = protocols::health::HealthCheckResponse::new();
        response.set_status(protocols::health::health_check_response::ServingStatus::SERVING);
        Ok(response)
    }
}
#[async_trait]
impl protocols::agent_ttrpc_async::AgentService for Fixture {
    async fn create_sandbox(
        &self,
        _: &TtrpcContext,
        req: rpc::CreateSandboxRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        self.record("CreateSandbox");
        assert_eq!(
            req,
            rpc::CreateSandboxRequest {
                sandbox_id: self.expected.sandbox_alias.clone(),
                ..Default::default()
            }
        );
        Ok(protocols::empty::Empty::new())
    }
    async fn get_guest_details(
        &self,
        _: &TtrpcContext,
        req: rpc::GuestDetailsRequest,
    ) -> ttrpc::Result<rpc::GuestDetailsResponse> {
        self.record("GetGuestDetails");
        assert_eq!(req, rpc::GuestDetailsRequest::new());
        Ok(rpc::GuestDetailsResponse {
            agent_details: MessageField::some(rpc::AgentDetails {
                version: if self.mode == "unsupported" {
                    "ordinary-agent"
                } else {
                    PROFILE_VERSION
                }
                .into(),
                extra_features: vec![PROFILE_MARKER.into()],
                supports_seccomp: true,
                ..Default::default()
            }),
            ..Default::default()
        })
    }
    async fn create_container(
        &self,
        _: &TtrpcContext,
        req: rpc::CreateContainerRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        self.record("CreateContainer");
        assert_eq!(
            req,
            rpc::CreateContainerRequest {
                container_id: self.expected.cid.clone(),
                exec_id: self.expected.cid.clone(),
                OCI: MessageField::some(self.expected.spec.clone()),
                ..Default::default()
            }
        );
        assert_ne!(req.container_id, self.expected.sandbox_alias);
        Ok(protocols::empty::Empty::new())
    }
    async fn start_container(
        &self,
        _: &TtrpcContext,
        req: rpc::StartContainerRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        self.record("StartContainer");
        assert_eq!(req.container_id, self.expected.cid);
        if matches!(self.mode, "start-reject" | "cleanup-reject") {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::FAILED_PRECONDITION,
                "test-only-start-reject",
            )));
        }
        Ok(protocols::empty::Empty::new())
    }
    async fn wait_process(
        &self,
        _: &TtrpcContext,
        req: rpc::WaitProcessRequest,
    ) -> ttrpc::Result<rpc::WaitProcessResponse> {
        self.record("WaitProcess");
        assert_eq!(
            req,
            rpc::WaitProcessRequest {
                container_id: self.expected.cid.clone(),
                exec_id: self.expected.cid.clone(),
                ..Default::default()
            }
        );
        if matches!(self.mode, "wait-timeout" | "success" | "output-cap") {
            self.release_wait.notified().await;
        }
        Ok(rpc::WaitProcessResponse {
            status: 42,
            ..Default::default()
        })
    }
    async fn read_stdout(
        &self,
        _: &TtrpcContext,
        req: rpc::ReadStreamRequest,
    ) -> ttrpc::Result<rpc::ReadStreamResponse> {
        self.stream("ReadStdout", req)
    }
    async fn read_stderr(
        &self,
        _: &TtrpcContext,
        req: rpc::ReadStreamRequest,
    ) -> ttrpc::Result<rpc::ReadStreamResponse> {
        self.stream("ReadStderr", req)
    }
    async fn remove_container(
        &self,
        _: &TtrpcContext,
        req: rpc::RemoveContainerRequest,
    ) -> ttrpc::Result<protocols::empty::Empty> {
        self.record("RemoveContainer");
        assert_eq!(req.container_id, self.expected.cid);
        assert!((1..=5).contains(&req.timeout));
        self.release_wait.notify_waiters();
        if self.mode == "cleanup-reject" {
            return Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                ttrpc::Code::UNAVAILABLE,
                "test-only-cleanup-reject",
            )));
        }
        Ok(protocols::empty::Empty::new())
    }
}
async fn with_fixture(
    mode: &'static str,
    timeout: Duration,
) -> (TransportResult, Vec<&'static str>) {
    let fixture = Arc::new(Fixture {
        calls: Mutex::new(Vec::new()),
        expected: prepared(),
        mode,
        release_wait: tokio::sync::Notify::new(),
        stdout_reads: AtomicUsize::new(0),
        stderr_reads: AtomicUsize::new(0),
    });
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("caa-proxy.sock");
    let mut server = Server::new()
        .bind(&format!("unix://{}", socket.display()))
        .unwrap()
        .register_service(protocols::agent_ttrpc_async::create_agent_service(
            fixture.clone(),
        ))
        .register_service(protocols::health_ttrpc_async::create_health(
            fixture.clone(),
        ));
    server.start().await.unwrap();
    let result = execute(socket.to_str().unwrap(), prepared(), timeout).await;
    server.shutdown().await.unwrap();
    let calls = fixture.calls.lock().unwrap().clone();
    (result, calls)
}

#[tokio::test]
async fn actual_unix_protocol_preserves_order_cid_oci_and_keeps_normal_task_for_export() {
    let (result, calls) = with_fixture("success", Duration::from_secs(2)).await;
    assert_eq!(
        &calls[..5],
        &[
            "Health.Check",
            "CreateSandbox",
            "GetGuestDetails",
            "CreateContainer",
            "StartContainer",
        ]
    );
    assert_eq!(
        calls.iter().filter(|name| **name == "WaitProcess").count(),
        1
    );
    assert!(calls.iter().filter(|name| **name == "ReadStdout").count() >= 3);
    assert!(calls.iter().filter(|name| **name == "ReadStderr").count() >= 2);
    assert!(!calls.contains(&"RemoveContainer"));
    assert_eq!(result.rpc_outcome, "completed");
    assert_eq!(result.wait_status, Some(42));
    assert_eq!(STANDARD.decode(result.stdout_b64).unwrap(), [0, 255, 1]);
    assert_eq!(STANDARD.decode(result.stderr_b64).unwrap(), b"test-stderr");
    assert_eq!(result.error_cleanup, "not_requested");
}
#[tokio::test]
async fn unsupported_guest_marker_stops_before_create_without_removing_other_tasks() {
    let (result, calls) = with_fixture("unsupported", Duration::from_secs(2)).await;
    assert_eq!(calls, ["Health.Check", "CreateSandbox", "GetGuestDetails"]);
    assert_eq!(result.rpc_outcome, "rejected");
    assert_eq!(result.error_cleanup, "not_requested");
}
#[tokio::test]
async fn failed_start_and_wait_deadline_make_one_bounded_cleanup_request() {
    for mode in ["start-reject", "wait-timeout", "oversize", "cleanup-reject"] {
        let (result, calls) = with_fixture(mode, Duration::from_millis(200)).await;
        assert_ne!(result.rpc_outcome, "completed");
        assert_eq!(
            calls
                .iter()
                .filter(|name| **name == "RemoveContainer")
                .count(),
            1
        );
        assert_eq!(calls.last(), Some(&"RemoveContainer"));
        assert_eq!(
            result.error_cleanup,
            if mode == "cleanup-reject" {
                "remove_failed"
            } else {
                "remove_acknowledged"
            }
        );
    }
}

#[tokio::test]
async fn output_cap_is_retained_and_reported_without_normal_remove() {
    let (result, calls) = with_fixture("output-cap", Duration::from_secs(2)).await;
    assert_eq!(result.rpc_outcome, "completed");
    assert_eq!(
        STANDARD.decode(result.stdout_b64).unwrap().len(),
        STDIO_BYTES as usize
    );
    assert!(result.stdout_may_have_more);
    assert!(!calls.contains(&"RemoveContainer"));
    assert_eq!(
        calls.iter().filter(|name| **name == "ReadStdout").count(),
        4
    );
}

#[tokio::test]
async fn empty_reply_issued_before_wait_requires_a_fresh_read_after_wait() {
    let terminal = AtomicBool::new(false);
    let mut report = TransportResult::new();
    let progress = Mutex::new(&mut report);
    let reads = AtomicUsize::new(0);
    drain_stream_with("guest-cid", true, &terminal, &progress, |_| async {
        let data = match reads.fetch_add(1, Ordering::Relaxed) {
            0 => {
                // The server selected EAGAIN before exit. Before delivering
                // that old empty response, Wait completes and final output is
                // available. The drain must not mistake this response for EOF.
                assert!(!terminal.load(Ordering::Relaxed));
                terminal.store(true, Ordering::Relaxed);
                vec![]
            }
            1 => b"final-output-after-old-eagain".to_vec(),
            2 => vec![],
            _ => panic!("unexpected extra drain request"),
        };
        Ok(rpc::ReadStreamResponse {
            data,
            ..Default::default()
        })
    })
    .await
    .unwrap();
    assert_eq!(reads.load(Ordering::Relaxed), 3);
    assert_eq!(
        STANDARD
            .decode(&progress.lock().unwrap().stdout_b64)
            .unwrap(),
        b"final-output-after-old-eagain"
    );
}
