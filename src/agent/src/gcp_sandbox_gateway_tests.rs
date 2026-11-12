// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::gcp_sandbox_projection::tests::{
    candidate, cri_candidate, cri_request, gke_candidate, gke_request, host_request, CID, CRI_CID,
    IMAGE, SANDBOX_ID,
};
use protobuf::Message;
use std::{
    collections::BTreeSet,
    sync::atomic::{AtomicUsize, Ordering},
};

const SANDBOX: &str = "sandbox-a";
const TEST_TIME: Duration = Duration::from_secs(5);

#[test]
fn gateway_matches_the_measured_rpc_policy() {
    let policy: serde_json::Value =
        serde_json::from_slice(execution_proof_handoff::gcp_startup::SANDBOX_RPC_POLICY_BYTES)
            .unwrap();
    for (key, names) in [
        ("agent_methods", AGENT_METHODS),
        ("health_methods", HEALTH_METHODS),
    ] {
        let declared: BTreeSet<&str> = policy[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap())
            .collect();
        assert_eq!(declared, names.iter().copied().collect());
    }
    assert_eq!(policy["service"], AGENT_SERVICE);
    assert_eq!(policy["inflight_requests"], MAX_INFLIGHT);
    assert_eq!(policy["max_rpc_payload_bytes"], MAX_WIRE_BYTES);
    assert_eq!(policy["copy_file_max_bytes"], MAX_COPY_BYTES);
    assert_eq!(policy["copy_file_max_pause"], MAX_PAUSE_COPIES);
    assert_eq!(policy["copy_file_max_app"], MAX_APP_COPIES);
    assert_eq!(policy["copy_file_max_wire_bytes"], MAX_COPY_WIRE);
    assert_eq!(policy["other_methods"], false);
}

struct Fixture {
    directory: tempfile::TempDir,
    server: Server,
    gateway: GatewayControl,
    host: AgentServiceClient,
    raw: Client,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_for(SANDBOX).await
    }

    async fn start_for(sandbox: &str) -> Self {
        Self::start_with_mode(sandbox, false).await
    }

    async fn start_with_mode(sandbox: &str, exit_barrier: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", directory.path().join("gateway.sock").display());
        let (mut server, gateway) = if exit_barrier {
            bind_with_exit_barrier(&address)
        } else {
            bind(&address)
        }
        .unwrap();
        server.start().await.unwrap();
        let client = Client::connect(&address).await.unwrap();
        let health = health_ttrpc_async::HealthClient::new(client.clone());
        assert_eq!(
            health
                .check(backend_context(TEST_TIME), &CheckRequest::new())
                .await
                .unwrap()
                .status(),
            health::health_check_response::ServingStatus::SERVING
        );
        let host = AgentServiceClient::new(client.clone());
        let request = CreateSandboxRequest {
            hostname: "onb17".into(),
            dns: vec!["nameserver 192.0.2.1".into(), "".into()],
            sandbox_id: sandbox.into(),
            storages: vec![Storage {
                driver: "ephemeral".into(),
                source: "shm".into(),
                fstype: "tmpfs".into(),
                mount_point: "/run/kata-containers/sandbox/shm".into(),
                options: ["noexec", "nosuid", "nodev", "mode=1777", "size=67108864"]
                    .map(str::to_owned)
                    .to_vec(),
                ..Default::default()
            }],
            ..Default::default()
        };
        host.create_sandbox(backend_context(TEST_TIME), &request)
            .await
            .unwrap();
        host.create_sandbox(backend_context(TEST_TIME), &request)
            .await
            .unwrap();
        let mut substituted = request.clone();
        substituted.sandbox_id = "sandbox-b".into();
        assert!(host
            .create_sandbox(backend_context(TEST_TIME), &substituted)
            .await
            .is_err());
        let copy = copy_request(sandbox, "resolv.conf");
        for bad_copy in [
            CopyFileRequest {
                path: "/run/unknown".into(),
                ..copy.clone()
            },
            CopyFileRequest {
                offset: 1,
                ..copy.clone()
            },
            CopyFileRequest {
                file_mode: libc::S_IFLNK | 0o644,
                ..copy.clone()
            },
            CopyFileRequest {
                file_size: (MAX_COPY_BYTES + 1) as i64,
                ..copy.clone()
            },
        ] {
            assert!(host
                .copy_file(backend_context(TEST_TIME), &bad_copy)
                .await
                .is_err());
        }
        host.copy_file(backend_context(TEST_TIME), &copy)
            .await
            .unwrap();
        assert!(host
            .copy_file(backend_context(TEST_TIME), &copy)
            .await
            .is_err());
        let mut pause_request = CreateContainerRequest {
            container_id: sandbox.into(),
            exec_id: sandbox.into(),
            storages: vec![Storage {
                driver: "image_guest_pull".into(),
                source: "pause".into(),
                fstype: "overlay".into(),
                mount_point: mount_point(sandbox),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut spec = protocols::oci::Spec::new();
        spec.Annotations
            .insert(CONTAINER_ROLE.into(), "sandbox".into());
        pause_request.OCI = Some(spec.clone()).into();
        assert!(host
            .create_container(backend_context(TEST_TIME), &pause_request)
            .await
            .is_err());
        spec.Mounts.push(protocols::oci::Mount {
            destination: "/etc/resolv.conf".into(),
            source: copy.path,
            type_: "bind".into(),
            options: ["rbind", "ro", "nosuid", "nodev", "noexec"]
                .map(str::to_owned)
                .to_vec(),
            ..Default::default()
        });
        pause_request.OCI = Some(spec).into();
        host.create_container(backend_context(TEST_TIME), &pause_request)
            .await
            .unwrap();
        assert!(host
            .create_container(backend_context(TEST_TIME), &pause_request)
            .await
            .is_err());
        // The test harness executable has no production pause entrypoint.
        // Exercise the same readiness pipe, pidfd, wait and reap with a fixed
        // unprivileged child process.
        gateway
            .state
            .pause
            .lock()
            .await
            .start_fixture()
            .await
            .unwrap();
        Self {
            directory,
            server,
            gateway,
            host,
            raw: client,
        }
    }

    async fn stop(mut self) {
        self.gateway.shutdown().await.unwrap();
        drop(self.host);
        drop(self.raw);
        self.server.shutdown().await.unwrap();
    }
}

#[derive(Default)]
struct Backend {
    sandbox_id: &'static str,
    container_id: &'static str,
    wait_status: Option<i32>,
    sandbox: AtomicUsize,
    creates: AtomicUsize,
    starts: AtomicUsize,
    removes: AtomicUsize,
    terminal_status: tokio::sync::Notify,
}

#[async_trait]
impl AgentService for Backend {
    async fn create_sandbox(
        &self,
        _: &TtrpcContext,
        request: CreateSandboxRequest,
    ) -> ttrpc::Result<Empty> {
        assert_eq!(request.sandbox_id, self.sandbox_id);
        assert!(request.dns.is_empty());
        assert!(request.storages.is_empty());
        self.sandbox.fetch_add(1, Ordering::Relaxed);
        Ok(Empty::new())
    }

    async fn create_container(
        &self,
        _: &TtrpcContext,
        request: CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        assert_eq!(request.container_id, self.container_id);
        assert_eq!(request.exec_id, self.container_id);
        assert!(request.storages.is_empty());
        assert_eq!(request.OCI.Root.Path, "rootfs");
        assert_eq!(request.OCI.Process.Args, ["/app"]);
        self.creates.fetch_add(1, Ordering::Relaxed);
        Ok(Empty::new())
    }

    async fn start_container(
        &self,
        _: &TtrpcContext,
        request: StartContainerRequest,
    ) -> ttrpc::Result<Empty> {
        assert_eq!(request.container_id, self.container_id);
        assert_eq!(self.creates.load(Ordering::Relaxed), 1);
        self.starts.fetch_add(1, Ordering::Relaxed);
        Ok(Empty::new())
    }

    async fn remove_container(
        &self,
        _: &TtrpcContext,
        request: RemoveContainerRequest,
    ) -> ttrpc::Result<Empty> {
        assert_eq!(request.container_id, self.container_id);
        self.removes.fetch_add(1, Ordering::Relaxed);
        Ok(Empty::new())
    }

    async fn wait_process(
        &self,
        _: &TtrpcContext,
        request: WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        assert_eq!(request.container_id, self.container_id);
        assert_eq!(self.starts.load(Ordering::Relaxed), 1);
        self.terminal_status.notify_one();
        Ok(WaitProcessResponse {
            status: self.wait_status.unwrap_or(17),
            ..Default::default()
        })
    }
}

fn start(cid: &str) -> StartContainerRequest {
    StartContainerRequest {
        container_id: cid.into(),
        ..Default::default()
    }
}

fn wait(cid: &str) -> WaitProcessRequest {
    WaitProcessRequest {
        container_id: cid.into(),
        exec_id: cid.into(),
        ..Default::default()
    }
}

fn copy_request(cid: &str, file: &str) -> CopyFileRequest {
    CopyFileRequest {
        path: format!("{COPY_PREFIX}{cid}-0123456789abcdef-{file}"),
        file_size: 1,
        file_mode: libc::S_IFREG | 0o644,
        dir_mode: 1 << 31 | 0o750,
        data: b"X".to_vec(),
        ..Default::default()
    }
}

#[test]
fn gke_termination_copy_requires_an_empty_regular_file() {
    use crate::gcp_sandbox_projection::tests::CRI_CID;

    let request = CopyFileRequest {
        path: format!("{COPY_PREFIX}{CRI_CID}-0123456789abcdef-termination-log"),
        file_mode: libc::S_IFREG | 0o666,
        dir_mode: 1 << 31 | 0o750,
        ..Default::default()
    };
    assert_eq!(
        validate_copy(&request).unwrap(),
        (CRI_CID, "termination-log")
    );
    assert!(validate_copy(&CopyFileRequest {
        file_mode: libc::S_IFREG | 0o644,
        ..request.clone()
    })
    .is_err());
    assert!(validate_copy(&CopyFileRequest {
        file_size: 1,
        data: vec![b'x'],
        ..request.clone()
    })
    .is_err());
    assert!(validate_copy(&CopyFileRequest {
        uid: 1000,
        ..request
    })
    .is_err());
}

#[tokio::test]
async fn gateway_keeps_app_create_pending_until_exact_bind_and_attach() {
    let mut fixture = Fixture::start().await;
    let backend_address = format!(
        "unix://{}",
        fixture.directory.path().join("app.sock").display()
    );
    let backend = Arc::new(Backend {
        sandbox_id: SANDBOX,
        container_id: CID,
        ..Default::default()
    });
    let mut backend_server = Server::new()
        .bind(&backend_address)
        .unwrap()
        .register_service(agent_ttrpc_async::create_agent_service(backend.clone()));
    backend_server.start().await.unwrap();

    let request = host_request();
    let wire = request.write_to_bytes().unwrap();
    let hash = Sha384::digest(&wire)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let client = fixture.raw.clone();
    let mut context = backend_context(TEST_TIME);
    context.add(CREATE_WIRE_HASH.into(), "host-supplied".into());
    let app_create = tokio::spawn(async move {
        client
            .request(Request {
                service: AGENT_SERVICE.into(),
                method: "CreateContainer".into(),
                payload: wire,
                timeout_nano: context.timeout_nano,
                metadata: ttrpc::context::to_pb(context.metadata),
                ..Default::default()
            })
            .await
    });
    let observed = tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.container_id, CID);
    assert_eq!(observed.wire_sha384, hash);
    assert!(!app_create.is_finished());
    assert!(fixture
        .host
        .start_container(backend_context(TEST_TIME), &start(CID))
        .await
        .is_err());
    fixture.gateway.bind(CID, IMAGE, &candidate()).unwrap();
    assert!(!app_create.is_finished());
    assert_eq!(backend.creates.load(Ordering::Relaxed), 0);
    fixture.gateway.attach(&backend_address).await.unwrap();
    app_create.await.unwrap().unwrap();
    assert_eq!(backend.sandbox.load(Ordering::Relaxed), 1);
    assert!(fixture
        .host
        .start_container(backend_context(TEST_TIME), &start("foreign-cid"))
        .await
        .is_err());
    fixture
        .host
        .start_container(backend_context(TEST_TIME), &start(CID))
        .await
        .unwrap();
    assert!(fixture
        .host
        .start_container(backend_context(TEST_TIME), &start(CID))
        .await
        .is_err());
    assert_eq!(backend.starts.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture
            .host
            .wait_process(backend_context(TEST_TIME), &wait(CID))
            .await
            .unwrap()
            .status,
        17
    );
    fixture
        .host
        .signal_process(
            backend_context(TEST_TIME),
            &SignalProcessRequest {
                container_id: SANDBOX.into(),
                signal: libc::SIGTERM as u32,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pause = fixture
        .host
        .wait_process(
            backend_context(TEST_TIME),
            &WaitProcessRequest {
                container_id: SANDBOX.into(),
                exec_id: SANDBOX.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(pause.status, 128 + libc::SIGTERM);
    fixture
        .host
        .destroy_sandbox(backend_context(TEST_TIME), &DestroySandboxRequest::new())
        .await
        .unwrap();
    assert!(!*fixture.gateway.state.aborted.borrow());
    fixture.stop().await;
    assert_eq!(backend.removes.load(Ordering::Relaxed), 1);
    backend_server.shutdown().await.unwrap();
}

async fn start_app_with_exit_barrier() -> (Fixture, Server, Arc<Backend>) {
    let mut fixture = Fixture::start_with_mode(SANDBOX, true).await;
    let address = format!(
        "unix://{}",
        fixture.directory.path().join("app.sock").display()
    );
    let backend = Arc::new(Backend {
        sandbox_id: SANDBOX,
        container_id: CID,
        ..Default::default()
    });
    let mut server = Server::new()
        .bind(&address)
        .unwrap()
        .register_service(agent_ttrpc_async::create_agent_service(backend.clone()));
    server.start().await.unwrap();
    let host = fixture.host.clone();
    let create = tokio::spawn(async move {
        host.create_container(backend_context(TEST_TIME), &host_request())
            .await
    });
    tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    fixture.gateway.bind(CID, IMAGE, &candidate()).unwrap();
    fixture.gateway.attach(&address).await.unwrap();
    create.await.unwrap().unwrap();
    fixture
        .host
        .start_container(backend_context(TEST_TIME), &start(CID))
        .await
        .unwrap();
    (fixture, server, backend)
}

#[tokio::test]
async fn app_wait_process_is_held_until_release_without_holding_pause_wait() {
    let (mut fixture, mut server, backend) = start_app_with_exit_barrier().await;
    let host = fixture.host.clone();
    let mut app_wait = tokio::spawn(async move {
        host.wait_process(backend_context(TEST_TIME), &wait(CID))
            .await
    });
    tokio::time::timeout(TEST_TIME, backend.terminal_status.notified())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut app_wait)
            .await
            .is_err(),
        "app terminal reply escaped before release"
    );
    fixture
        .host
        .signal_process(
            backend_context(TEST_TIME),
            &SignalProcessRequest {
                container_id: SANDBOX.into(),
                signal: libc::SIGTERM as u32,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pause = fixture
        .host
        .wait_process(backend_context(TEST_TIME), &wait(SANDBOX))
        .await
        .unwrap();
    assert_eq!(pause.status, 128 + libc::SIGTERM);
    fixture.gateway.release_app_exit().unwrap();
    assert_eq!(app_wait.await.unwrap().unwrap().status, 17);
    let host = fixture.host.clone();
    let destroy_request = DestroySandboxRequest::new();
    let destroy = host.destroy_sandbox(backend_context(TEST_TIME), &destroy_request);
    let drain = async {
        tokio::time::timeout(TEST_TIME, fixture.gateway.wait_for_worker_teardown())
            .await
            .unwrap();
        fixture.server.stop_listen().await;
        fixture.gateway.shutdown().await.unwrap();
        fixture.server.shutdown().await.unwrap();
    };
    let (destroy, ()) = tokio::join!(destroy, drain);
    destroy.unwrap();
    drop(fixture);
    server.shutdown().await.unwrap();
}

const QUALIFICATION_SANDBOX: &str = "qexp-fixture-sandbox";

struct FixturePauseStart {
    gateway: Arc<Gateway>,
    app_start: Box<dyn MethodHandler + Send + Sync>,
}

#[async_trait]
impl MethodHandler for FixturePauseStart {
    async fn handler(&self, context: TtrpcContext, request: Request) -> ttrpc::Result<Response> {
        let start = StartContainerRequest::parse_from_bytes(&request.payload)
            .map_err(|error| ttrpc::Error::Others(error.to_string()))?;
        if start.container_id != QUALIFICATION_SANDBOX {
            return self.app_start.handler(context, request).await;
        }
        known(&start.special_fields)?;
        assert_eq!(self.gateway.sandbox_id()?, QUALIFICATION_SANDBOX);
        let mut pause = self.gateway.pause.lock().await;
        self.gateway.ensure_open().map_err(rejected)?;
        // A libtest executable cannot enter the production pause mode.
        pause.start_fixture().await.map_err(rejected)?;
        let mut response = Response::new();
        response.set_status(ttrpc::get_status(Code::OK, ""));
        Ok(response)
    }
}

#[tokio::test]
#[ignore = "requires the exact Go client in ONB17_QUALIFICATION_KATA"]
async fn qualification_go_client_matches_gateway_wire_and_waits_for_ack() {
    use std::{env, process::Stdio};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        process::Command,
        time::timeout,
    };

    const APP: &str = "qexp-fixture-app";
    let binary = std::fs::canonicalize(env::var_os("ONB17_QUALIFICATION_KATA").unwrap()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("gateway.sock");
    let address = format!("unix://{}", socket.display());
    let (server, mut gateway) = bind_with_exit_barrier(&address).unwrap();
    let mut agent = agent_ttrpc_async::create_agent_service(gateway.state.clone());
    agent.retain(|name, _| name == AGENT_SERVICE);
    let methods = &mut agent.get_mut(AGENT_SERVICE).unwrap().methods;
    let app_start = methods.remove("StartContainer").unwrap();
    methods.insert(
        "StartContainer".into(),
        Box::new(FixturePauseStart {
            gateway: gateway.state.clone(),
            app_start,
        }),
    );
    restrict(
        &mut agent,
        AGENT_METHODS,
        &Arc::new(Semaphore::new(MAX_INFLIGHT)),
    )
    .unwrap();
    let mut server = server.register_service(agent);
    server.start().await.unwrap();

    let backend = Arc::new(Backend {
        sandbox_id: QUALIFICATION_SANDBOX,
        container_id: APP,
        wait_status: Some(0),
        ..Default::default()
    });
    let backend_address = format!("unix://{}", directory.path().join("app.sock").display());
    let mut backend_server = Server::new()
        .bind(&backend_address)
        .unwrap()
        .register_service(agent_ttrpc_async::create_agent_service(backend.clone()));
    backend_server.start().await.unwrap();

    let mut client = Command::new(binary)
        .arg("--socket")
        .arg(socket)
        .args([
            "--cid",
            APP,
            "--sandbox",
            QUALIFICATION_SANDBOX,
            "--image",
            IMAGE,
        ])
        .args(["--timeout-seconds", "20"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = client.stdin.take().unwrap();
    let mut output = BufReader::new(client.stdout.take().unwrap()).lines();

    let observed = timeout(TEST_TIME, gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    let line = timeout(TEST_TIME, output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(observed.container_id, APP);
    assert_eq!(
        receipt,
        serde_json::json!({
            "phase": "pending", "container_id": APP, "wire_sha384": observed.wire_sha384,
        })
    );
    assert!(
        timeout(Duration::from_millis(1100), output.next_line())
            .await
            .is_err(),
        "Go client exited while waiting for qualification Bind"
    );
    assert_eq!(backend.creates.load(Ordering::Relaxed), 0);
    gateway.bind(APP, IMAGE, &candidate()).unwrap();
    gateway.attach(&backend_address).await.unwrap();
    input.write_all(b"START\n").await.unwrap();
    drop(input);
    let line = timeout(TEST_TIME, output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap(),
        serde_json::json!({"phase": "started"})
    );
    timeout(TEST_TIME, backend.terminal_status.notified())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(1100), output.next_line())
            .await
            .is_err(),
        "Go client completed before app exit release"
    );
    assert_eq!(backend.removes.load(Ordering::Relaxed), 0);
    assert!(!*gateway.state.closed.borrow());

    gateway.release_app_exit().unwrap();
    let line = timeout(TEST_TIME, output.next_line())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&line).unwrap(),
        serde_json::json!({"phase": "finished", "wait_status": 0})
    );
    assert!(timeout(TEST_TIME, client.wait())
        .await
        .unwrap()
        .unwrap()
        .success());
    assert_eq!(backend.sandbox.load(Ordering::Relaxed), 1);
    assert_eq!(backend.creates.load(Ordering::Relaxed), 1);
    assert_eq!(backend.starts.load(Ordering::Relaxed), 1);
    assert_eq!(backend.removes.load(Ordering::Relaxed), 1);
    assert!(*gateway.state.closed.borrow());
    assert!(!*gateway.state.aborted.borrow());
    assert!(matches!(
        *gateway.state.pause.lock().await,
        pause::Pause::Removed(_)
    ));
    server.shutdown().await.unwrap();
    backend_server.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_teardown_cancels_held_app_wait_process() {
    for destroy_sandbox in [false, true] {
        let (fixture, mut server, backend) = start_app_with_exit_barrier().await;
        let host = fixture.host.clone();
        let app_wait = tokio::spawn(async move {
            host.wait_process(backend_context(TEST_TIME), &wait(CID))
                .await
        });
        tokio::time::timeout(TEST_TIME, backend.terminal_status.notified())
            .await
            .unwrap();
        if destroy_sandbox {
            fixture
                .host
                .destroy_sandbox(backend_context(TEST_TIME), &DestroySandboxRequest::new())
                .await
                .unwrap();
        } else {
            fixture
                .host
                .remove_container(backend_context(TEST_TIME), &remove_request(CID))
                .await
                .unwrap();
        }
        let result = app_wait.await.unwrap();
        assert!(matches!(
            result,
            Err(ttrpc::Error::RpcStatus(ref status)) if status.code() == Code::CANCELLED
        ));
        assert!(fixture.gateway.release_app_exit().is_err());
        assert_eq!(backend.removes.load(Ordering::Relaxed), 1);
        fixture.stop().await;
        server.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn gateway_terminates_on_wrong_bind_and_app_create_timeout() {
    for bad_bind in [true, false] {
        let mut fixture = Fixture::start().await;
        let client = fixture.host.clone();
        let pending = tokio::spawn(async move {
            client
                .create_container(backend_context(Duration::from_millis(200)), &host_request())
                .await
        });
        tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
            .await
            .unwrap()
            .unwrap();
        if bad_bind {
            assert!(fixture
                .gateway
                .bind("foreign-cid", IMAGE, &candidate())
                .is_err());
        }
        assert!(pending.await.unwrap().is_err());
        tokio::time::timeout(TEST_TIME, fixture.gateway.cancelled())
            .await
            .unwrap();
        assert!(fixture.gateway.bind(CID, IMAGE, &candidate()).is_err());
        assert!(fixture
            .host
            .start_container(backend_context(TEST_TIME), &start(CID))
            .await
            .is_err());
        fixture.stop().await;
    }
}

#[tokio::test]
async fn rejects_conflicting_copy_selectors_and_missing_projected_mounts() {
    let mut fixture = Fixture::start().await;
    let copy = copy_request(CID, "hosts");
    fixture
        .host
        .copy_file(backend_context(TEST_TIME), &copy)
        .await
        .unwrap();
    assert!(fixture
        .host
        .copy_file(
            backend_context(TEST_TIME),
            &copy_request("foreign-cid", "hosts")
        )
        .await
        .is_err());
    let mut foreign = host_request();
    foreign.container_id = "foreign-cid".into();
    foreign.exec_id = "foreign-cid".into();
    assert!(fixture
        .host
        .create_container(backend_context(TEST_TIME), &foreign)
        .await
        .is_err());
    let client = fixture.host.clone();
    let pending = tokio::spawn(async move {
        client
            .create_container(backend_context(TEST_TIME), &host_request())
            .await
    });
    tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    assert!(fixture.gateway.bind(CID, IMAGE, &candidate()).is_err());
    assert!(pending.await.unwrap().is_err());
    fixture.stop().await;
}

#[tokio::test]
async fn stock_cri_shape_waits_for_bind_and_attach_with_exact_copy_selectors() {
    let (request, copy_paths) = cri_request();
    assert_eq!(copy_paths.len(), 3);
    assert_cri_binds_with_copies(request, copy_paths, &cri_candidate()).await;
}

#[tokio::test]
async fn gke_cri_shape_binds_with_one_app_termination_copy() {
    let (request, copy_paths) = gke_request();
    assert_eq!(copy_paths.len(), MAX_APP_COPIES);
    assert_cri_binds_with_copies(request, copy_paths, &gke_candidate()).await;
}

async fn assert_cri_binds_with_copies(
    request: CreateContainerRequest,
    copy_paths: Vec<String>,
    approved: &BoundEffectiveSpec,
) {
    let mut fixture = Fixture::start_for(SANDBOX_ID).await;
    let backend_address = format!(
        "unix://{}",
        fixture.directory.path().join("cri-app.sock").display()
    );
    let backend = Arc::new(Backend {
        sandbox_id: SANDBOX_ID,
        container_id: CRI_CID,
        ..Default::default()
    });
    let mut backend_server = Server::new()
        .bind(&backend_address)
        .unwrap()
        .register_service(agent_ttrpc_async::create_agent_service(backend.clone()));
    backend_server.start().await.unwrap();

    for path in copy_paths {
        let termination = path.ends_with("-termination-log");
        let copy = if termination {
            let mut pause = copy_request(SANDBOX_ID, "termination-log");
            pause.file_mode = libc::S_IFREG | 0o666;
            pause.data.clear();
            pause.file_size = 0;
            assert!(matches!(
                fixture.host.copy_file(backend_context(TEST_TIME), &pause).await,
                Err(ttrpc::Error::RpcStatus(ref status)) if status.code() == Code::INVALID_ARGUMENT
            ));
            CopyFileRequest { path, ..pause }
        } else {
            CopyFileRequest {
                path,
                ..copy_request(CRI_CID, "hosts")
            }
        };
        fixture
            .host
            .copy_file(backend_context(TEST_TIME), &copy)
            .await
            .unwrap();
        if termination {
            assert!(matches!(
                fixture.host.copy_file(backend_context(TEST_TIME), &copy).await,
                Err(ttrpc::Error::RpcStatus(ref status)) if status.code() == Code::ALREADY_EXISTS
            ));
        }
    }
    let host = fixture.host.clone();
    let pending = tokio::spawn(async move {
        host.create_container(backend_context(TEST_TIME), &request)
            .await
    });
    let observed = tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(observed.container_id, CRI_CID);
    fixture.gateway.bind(CRI_CID, IMAGE, approved).unwrap();
    assert!(!pending.is_finished());
    assert_eq!(backend.creates.load(Ordering::Relaxed), 0);
    fixture.gateway.attach(&backend_address).await.unwrap();
    pending.await.unwrap().unwrap();
    fixture
        .host
        .start_container(backend_context(TEST_TIME), &start(CRI_CID))
        .await
        .unwrap();
    assert_eq!(backend.starts.load(Ordering::Relaxed), 1);
    fixture.stop().await;
    assert_eq!(backend.removes.load(Ordering::Relaxed), 1);
    backend_server.shutdown().await.unwrap();
}

#[tokio::test]
async fn disconnected_frontend_consumes_pending_app_attempt() {
    use std::{net::Shutdown, os::fd::IntoRawFd, os::unix::net::UnixStream};

    let mut fixture = Fixture::start().await;
    let socket = UnixStream::connect(fixture.directory.path().join("gateway.sock")).unwrap();
    socket.set_nonblocking(true).unwrap();
    let disconnect = socket.try_clone().unwrap();
    // The client takes ownership of a connected, nonblocking Unix socket.
    let client = unsafe { Client::from_raw_unix_socket_fd(socket.into_raw_fd()) };
    let pending = tokio::spawn(async move {
        AgentServiceClient::new(client)
            .create_container(ttrpc::context::Context::default(), &host_request())
            .await
    });
    tokio::time::timeout(TEST_TIME, fixture.gateway.candidate())
        .await
        .unwrap()
        .unwrap();
    disconnect.shutdown(Shutdown::Both).unwrap();
    assert!(pending.await.unwrap().is_err());
    tokio::time::timeout(TEST_TIME, fixture.gateway.cancelled())
        .await
        .unwrap();
    assert!(fixture.gateway.bind(CID, IMAGE, &candidate()).is_err());
    fixture.stop().await;
}
