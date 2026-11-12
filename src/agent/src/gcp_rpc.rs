// SPDX-License-Identifier: Apache-2.0
//! Static registration and non-mutating handshake for the opt-in GCP proof
//! service. Neither mutable agent policy nor host aliases establish authority.
use anyhow::{ensure, Result};
use async_trait::async_trait;
use protobuf::MessageField;
use protocols::{
    agent::{AgentDetails, CreateSandboxRequest, GuestDetailsRequest, GuestDetailsResponse},
    empty::Empty,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use ttrpc::{
    r#async::{MethodHandler, Service, TtrpcContext},
    Request, Response,
};

const SERVICE: &str = "grpc.AgentService";
const INFLIGHT_REQUESTS: usize = 32;
// Each task handler selects only the single runtime-owned custody attempt.
// No other management/quote/exec route, including future routes, is registered.
const TASK_METHODS: &[&str] = &[
    "CreateContainer",
    "StartContainer",
    "RemoveContainer",
    "SignalProcess",
    "WaitProcess",
    "WriteStdin",
    "ReadStdout",
    "ReadStderr",
    "CloseStdin",
];
const HANDSHAKE_METHODS: &[&str] = &["CreateSandbox", "GetGuestDetails"];

#[derive(Eq, PartialEq)]
struct SandboxAlias {
    id: String,
    hostname: String,
}
/// Created only after trusted custody is staged. Host values are bounded aliases
/// used for exact retry handling, never tenant/workload/Pod authority.
pub(super) struct GcpHandshake {
    alias: Mutex<Option<SandboxAlias>>,
}
impl GcpHandshake {
    pub(super) fn new() -> Self {
        Self {
            alias: Mutex::new(None),
        }
    }
    fn require_accepted(&self) -> ttrpc::Result<()> {
        let state = self
            .alias
            .lock()
            .map_err(|_| status(ttrpc::Code::UNAVAILABLE, "GCP handshake unavailable"))?;
        if state.is_none() {
            return Err(status(
                ttrpc::Code::FAILED_PRECONDITION,
                "GCP sandbox handshake required",
            ));
        }
        Ok(())
    }
    pub(super) fn create_sandbox(&self, request: &CreateSandboxRequest) -> ttrpc::Result<Empty> {
        // Never call normal sandbox setup: no hostname/DNS/rootfs/network/module
        // changes, hooks, shared PID namespace or filesystem writes are allowed.
        if request
            .special_fields
            .unknown_fields()
            .iter()
            .next()
            .is_some()
            || !request.dns.is_empty()
            || !request.storages.is_empty()
            || request.sandbox_pidns
            || !request.guest_hook_path.is_empty()
            || !request.kernel_modules.is_empty()
            || !alias(&request.sandbox_id, false)
            || !alias(&request.hostname, true)
        {
            return Err(status(
                ttrpc::Code::INVALID_ARGUMENT,
                "unsupported GCP sandbox handshake",
            ));
        }
        let alias = SandboxAlias {
            id: request.sandbox_id.clone(),
            hostname: request.hostname.clone(),
        };
        let mut state = self
            .alias
            .lock()
            .map_err(|_| status(ttrpc::Code::UNAVAILABLE, "GCP handshake unavailable"))?;
        match state.as_ref() {
            Some(prior) if prior != &alias => Err(status(
                ttrpc::Code::FAILED_PRECONDITION,
                "GCP sandbox alias already fixed",
            )),
            Some(_) => Ok(Empty::new()),
            None => {
                *state = Some(alias);
                Ok(Empty::new())
            }
        }
    }
    pub(super) fn guest_details(
        &self,
        request: &GuestDetailsRequest,
    ) -> ttrpc::Result<GuestDetailsResponse> {
        self.require_accepted()?;
        if request
            .special_fields
            .unknown_fields()
            .iter()
            .next()
            .is_some()
        {
            return Err(status(
                ttrpc::Code::INVALID_ARGUMENT,
                "unsupported GCP details request",
            ));
        }
        // Closed profile constants: no sysfs reads and no hotplug/storage/tty
        // support are advertised. This response is not an attestation statement.
        Ok(GuestDetailsResponse {
            mem_block_size_bytes: 0,
            support_mem_hotplug_probe: false,
            agent_details: MessageField::some(AgentDetails {
                version: "onb17.gcp-proof-startup.v1".into(),
                init_daemon: false,
                device_handlers: vec![],
                storage_handlers: vec![],
                supports_seccomp: true,
                extra_features: vec!["gcp-proof-startup".into()],
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}
fn alias(value: &str, empty: bool) -> bool {
    (empty || !value.is_empty())
        && value.len() <= execution_proof_contract::MAX_ID_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn status(code: ttrpc::Code, message: &str) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message))
}
struct PendingTaskHandler {
    handshake: Option<Arc<GcpHandshake>>,
    budget: Arc<tokio::sync::Semaphore>,
    handler: Box<dyn MethodHandler + Send + Sync>,
}
#[async_trait]
impl MethodHandler for PendingTaskHandler {
    async fn handler(&self, ctx: TtrpcContext, request: Request) -> ttrpc::Result<Response> {
        // No waiter queue: reserve before protobuf decoding or any awaited
        // handler effect, and retain through actual handler completion/drop.
        let _permit = match self.budget.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Ok(rejected_response(ttrpc::get_status(
                    ttrpc::Code::RESOURCE_EXHAUSTED,
                    "GCP RPC capacity exhausted",
                )))
            }
        };
        if let Some(handshake) = &self.handshake {
            if let Err(error) = handshake.require_accepted() {
                // MethodHandler errors are mapped to UNKNOWN by ttrpc itself.
                // Encode intended statuses like generated method handlers do.
                let error = match error {
                    ttrpc::Error::RpcStatus(error) => error,
                    _ => ttrpc::get_status(ttrpc::Code::UNAVAILABLE, "GCP handshake unavailable"),
                };
                return Ok(rejected_response(error));
            }
        }
        self.handler.handler(ctx, request).await
    }
}
fn rejected_response(status: ttrpc::Status) -> Response {
    let mut response = Response::new();
    response.set_status(status);
    response
}
fn bound_service(
    service: &mut Service,
    budget: Arc<tokio::sync::Semaphore>,
    handshake: Option<Arc<GcpHandshake>>,
) {
    let methods = std::mem::take(&mut service.methods);
    for (name, handler) in methods {
        let gate = if TASK_METHODS.contains(&name.as_str()) {
            handshake.clone()
        } else {
            None
        };
        service.methods.insert(
            name,
            Box::new(PendingTaskHandler {
                handshake: gate,
                budget: budget.clone(),
                handler,
            }),
        );
    }
}

pub(super) fn restrict_agent_services(
    mut services: HashMap<String, Service>,
    handshake: Arc<GcpHandshake>,
    budget: Arc<tokio::sync::Semaphore>,
) -> Result<HashMap<String, Service>> {
    services.retain(|name, _| name == SERVICE);
    let service = services
        .get_mut(SERVICE)
        .ok_or_else(|| anyhow::anyhow!("GCP agent service missing"))?;
    ensure!(
        TASK_METHODS
            .iter()
            .chain(HANDSHAKE_METHODS)
            .all(|method| service.methods.contains_key(*method)),
        "GCP agent methods missing"
    );
    service.methods.retain(|method, _| {
        TASK_METHODS.contains(&method.as_str()) || HANDSHAKE_METHODS.contains(&method.as_str())
    });
    bound_service(service, budget, Some(handshake));
    service.streams.clear();
    Ok(services)
}

// The dedicated service has no generic Sandbox, netlink task, mutable policy,
// management proxy, or ordinary launch fallback. Only the private runtime owner
// can stage the one actual custody lease required before construction.
struct GcpAgentService {
    runtime: crate::final_task_runtime::FinalTaskRuntime,
    observer: crate::exec_observer::Observer,
    handshake: Arc<GcpHandshake>,
}
fn known(fields: &protobuf::SpecialFields) -> ttrpc::Result<()> {
    if fields.unknown_fields().iter().next().is_some() {
        Err(status(
            ttrpc::Code::INVALID_ARGUMENT,
            "unknown GCP request fields",
        ))
    } else {
        Ok(())
    }
}
fn operation(_: anyhow::Error) -> ttrpc::Error {
    status(
        ttrpc::Code::FAILED_PRECONDITION,
        "GCP task operation rejected",
    )
}
fn init_id(cid: &str, exec_id: &str, allow_empty: bool) -> ttrpc::Result<()> {
    if exec_id == cid || (allow_empty && exec_id.is_empty()) {
        Ok(())
    } else {
        Err(status(
            ttrpc::Code::INVALID_ARGUMENT,
            "GCP init task ID mismatch",
        ))
    }
}
#[async_trait]
impl protocols::agent_ttrpc_async::AgentService for GcpAgentService {
    async fn create_sandbox(
        &self,
        _: &TtrpcContext,
        request: CreateSandboxRequest,
    ) -> ttrpc::Result<Empty> {
        self.handshake.create_sandbox(&request)
    }
    async fn get_guest_details(
        &self,
        _: &TtrpcContext,
        request: GuestDetailsRequest,
    ) -> ttrpc::Result<GuestDetailsResponse> {
        self.handshake.guest_details(&request)
    }
    async fn create_container(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, true)?;
        if !request.devices.is_empty()
            || !request.storages.is_empty()
            || !request.shared_mounts.is_empty()
            || request.sandbox_pidns
            || request.string_user.is_some()
            || request.stdin_port != 0
            || request.stdout_port != 0
            || request.stderr_port != 0
        {
            return Err(status(
                ttrpc::Code::INVALID_ARGUMENT,
                "unsupported GCP task transform",
            ));
        }
        let spec = request
            .OCI
            .into_option()
            .ok_or_else(|| status(ttrpc::Code::INVALID_ARGUMENT, "GCP task spec missing"))?;
        self.runtime
            .create_gcp_protocol(&request.container_id, &spec, &self.observer)
            .map_err(operation)?;
        Ok(Empty::new())
    }
    async fn start_container(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::StartContainerRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        self.runtime
            .start(&request.container_id, &self.observer)
            .await
            .map_err(operation)?;
        Ok(Empty::new())
    }
    async fn remove_container(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::RemoveContainerRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        let remove = self.runtime.remove(&request.container_id);
        if request.timeout == 0 {
            remove.await.map_err(operation)?;
        } else {
            tokio::time::timeout(
                std::time::Duration::from_secs(request.timeout.into()),
                remove,
            )
            .await
            .map_err(|_| status(ttrpc::Code::DEADLINE_EXCEEDED, "GCP task cleanup pending"))?
            .map_err(operation)?;
        }
        Ok(Empty::new())
    }
    async fn signal_process(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::SignalProcessRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, true)?;
        self.runtime
            .signal(&request.container_id, request.signal as i32)
            .map_err(operation)?;
        Ok(Empty::new())
    }
    async fn wait_process(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::WaitProcessRequest,
    ) -> ttrpc::Result<protocols::agent::WaitProcessResponse> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, false)?;
        let status = self
            .runtime
            .wait(&request.container_id)
            .await
            .map_err(operation)?;
        Ok(protocols::agent::WaitProcessResponse {
            status,
            ..Default::default()
        })
    }
    async fn write_stdin(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::WriteStreamRequest,
    ) -> ttrpc::Result<protocols::agent::WriteStreamResponse> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, false)?;
        let len = if request.data.is_empty() {
            self.runtime
                .close_stdin(&request.container_id)
                .map_err(operation)?;
            0
        } else {
            self.runtime
                .write_stdin(&request.container_id, &request.data)
                .map_err(operation)?
        };
        Ok(protocols::agent::WriteStreamResponse {
            len: len as u32,
            ..Default::default()
        })
    }
    async fn read_stdout(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::ReadStreamRequest,
    ) -> ttrpc::Result<protocols::agent::ReadStreamResponse> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, false)?;
        let data = self
            .runtime
            .read_stdout(&request.container_id, request.len as usize)
            .map_err(operation)?;
        Ok(protocols::agent::ReadStreamResponse {
            data,
            ..Default::default()
        })
    }
    async fn read_stderr(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::ReadStreamRequest,
    ) -> ttrpc::Result<protocols::agent::ReadStreamResponse> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, false)?;
        let data = self
            .runtime
            .read_stderr(&request.container_id, request.len as usize)
            .map_err(operation)?;
        Ok(protocols::agent::ReadStreamResponse {
            data,
            ..Default::default()
        })
    }
    async fn close_stdin(
        &self,
        _: &TtrpcContext,
        request: protocols::agent::CloseStdinRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        init_id(&request.container_id, &request.exec_id, false)?;
        self.runtime
            .close_stdin(&request.container_id)
            .map_err(operation)?;
        Ok(Empty::new())
    }
}

struct GcpHealthService;
#[async_trait]
impl protocols::health_ttrpc_async::Health for GcpHealthService {
    async fn check(
        &self,
        _: &TtrpcContext,
        request: protocols::health::CheckRequest,
    ) -> ttrpc::Result<protocols::health::HealthCheckResponse> {
        known(&request.special_fields)?;
        let mut response = protocols::health::HealthCheckResponse::new();
        response.set_status(protocols::health::health_check_response::ServingStatus::SERVING);
        Ok(response)
    }
    async fn version(
        &self,
        _: &TtrpcContext,
        request: protocols::health::CheckRequest,
    ) -> ttrpc::Result<protocols::health::VersionCheckResponse> {
        known(&request.special_fields)?;
        Ok(protocols::health::VersionCheckResponse {
            agent_version: "onb17.gcp-proof-startup.v1".into(),
            grpc_version: "0.0.1".into(),
            ..Default::default()
        })
    }
}

pub(crate) fn start_gcp_proof(
    address: &str,
    observer: crate::exec_observer::Observer,
    runtime: crate::final_task_runtime::FinalTaskRuntime,
) -> Result<ttrpc::r#async::Server> {
    runtime.validate_gcp_proof_service()?;
    let handshake = Arc::new(GcpHandshake::new());
    let service = protocols::agent_ttrpc_async::create_agent_service(Arc::new(GcpAgentService {
        runtime,
        observer,
        handshake: handshake.clone(),
    }));
    let budget = Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS));
    let service = restrict_agent_services(service, handshake, budget.clone())?;
    let mut health = protocols::health_ttrpc_async::create_health(Arc::new(GcpHealthService));
    for service in health.values_mut() {
        bound_service(service, budget.clone(), None);
    }
    Ok(ttrpc::r#async::Server::new()
        .bind(address)?
        .register_service(service)
        .register_service(health))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use ttrpc::{
        r#async::{Client, MethodHandler, Server, TtrpcContext},
        Request, Response,
    };

    struct EmptyAgent;
    #[async_trait]
    impl protocols::agent_ttrpc_async::AgentService for EmptyAgent {}
    struct Counting(Arc<AtomicUsize>);
    #[async_trait]
    impl MethodHandler for Counting {
        async fn handler(&self, _ctx: TtrpcContext, _req: Request) -> ttrpc::Result<Response> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new())
        }
    }

    #[tokio::test]
    async fn denied_wire_methods_never_decode_or_invoke_a_mutating_handler() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut services = protocols::agent_ttrpc_async::create_agent_service(Arc::new(EmptyAgent));
        let service = services.get_mut(SERVICE).unwrap();
        // Start with every actual generated method plus an invented future one.
        service.methods.insert(
            "FutureManagementMutation".into(),
            Box::new(Counting(calls.clone())),
        );
        let all: Vec<_> = service.methods.keys().cloned().collect();
        for handler in service.methods.values_mut() {
            *handler = Box::new(Counting(calls.clone()));
        }
        let original_count = service.methods.len();
        let handshake = Arc::new(GcpHandshake::new());
        let services = restrict_agent_services(
            services,
            handshake.clone(),
            Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS)),
        )
        .unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(
            services[SERVICE].methods.len(),
            (TASK_METHODS.len() + HANDSHAKE_METHODS.len())
        );
        assert!(services[SERVICE].streams.is_empty());
        assert!(original_count > (TASK_METHODS.len() + HANDSHAKE_METHODS.len()));
        let directory = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", directory.path().join("agent.sock").display());
        let mut server = Server::new()
            .bind(&address)
            .unwrap()
            .register_service(services);
        server.start().await.unwrap();
        let client = Client::connect(&address).await.unwrap();
        for method in all.iter().filter(|name| {
            !TASK_METHODS.contains(&name.as_str()) && !HANDSHAKE_METHODS.contains(&name.as_str())
        }) {
            let request = Request {
                service: SERVICE.into(),
                method: method.clone(),
                payload: vec![0xff; 17],
                timeout_nano: 2_000_000_000,
                ..Default::default()
            };
            let error = client.request(request).await.err().unwrap();
            let ttrpc::Error::RpcStatus(status) = error else {
                panic!("expected denied method status");
            };
            assert_eq!(status.code(), ttrpc::Code::UNIMPLEMENTED, "{method}");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // A task method cannot dispatch before the non-mutating handshake.
        let pending = Request {
            service: SERVICE.into(),
            method: "WaitProcess".into(),
            timeout_nano: 2_000_000_000,
            ..Default::default()
        };
        let ttrpc::Error::RpcStatus(status) = client.request(pending).await.err().unwrap() else {
            panic!("expected pending handshake");
        };
        assert_eq!(status.code(), ttrpc::Code::FAILED_PRECONDITION);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        handshake
            .create_sandbox(&CreateSandboxRequest {
                sandbox_id: "untrusted-host-alias".into(),
                ..Default::default()
            })
            .unwrap();
        // A retained method reaches its handler, proving an active transport.
        let request = Request {
            service: SERVICE.into(),
            method: "WaitProcess".into(),
            timeout_nano: 2_000_000_000,
            ..Default::default()
        };
        client.request(request).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(10), server.shutdown())
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn gcp_service_rejects_an_unconfigured_runtime() {
        assert!(crate::final_task_runtime::FinalTaskRuntime::new(1)
            .unwrap()
            .validate_gcp_proof_service()
            .is_err());
    }

    #[test]
    fn incomplete_service_registration_fails_closed() {
        assert!(restrict_agent_services(
            HashMap::new(),
            Arc::new(GcpHandshake::new()),
            Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS))
        )
        .is_err());
        let mut services = protocols::agent_ttrpc_async::create_agent_service(Arc::new(EmptyAgent));
        services
            .get_mut(SERVICE)
            .unwrap()
            .methods
            .remove("WaitProcess");
        assert!(restrict_agent_services(
            services,
            Arc::new(GcpHandshake::new()),
            Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS))
        )
        .is_err());
    }
    fn sandbox_request() -> CreateSandboxRequest {
        CreateSandboxRequest {
            sandbox_id: "cp-reported-pod-alias".into(),
            hostname: "cp-reported-hostname".into(),
            ..Default::default()
        }
    }
    #[test]
    fn handshake_is_one_bounded_alias_with_exact_retries_and_no_mutations() {
        let state = GcpHandshake::new();
        assert!(state.guest_details(&GuestDetailsRequest::new()).is_err());
        for changed in [
            "dns", "storage", "hooks", "module", "pidns", "unknown", "empty-id", "long-id",
            "hostname",
        ] {
            let mut request = sandbox_request();
            match changed {
                "dns" => request.dns.push("nameserver 127.0.0.1".into()),
                "storage" => request.storages.push(protocols::agent::Storage::new()),
                "hooks" => request.guest_hook_path = "/host/hooks".into(),
                "module" => request
                    .kernel_modules
                    .push(protocols::agent::KernelModule::new()),
                "pidns" => request.sandbox_pidns = true,
                "unknown" => request
                    .special_fields
                    .mut_unknown_fields()
                    .add_varint(99, 1),
                "empty-id" => request.sandbox_id.clear(),
                "long-id" => request.sandbox_id = "x".repeat(129),
                "hostname" => request.hostname = "bad/hostname".into(),
                _ => unreachable!(),
            }
            assert!(state.create_sandbox(&request).is_err(), "{}", changed);
            assert!(state.require_accepted().is_err(), "{}", changed);
        }
        let request = sandbox_request();
        state.create_sandbox(&request).unwrap();
        state.create_sandbox(&request).unwrap();
        let mut changed = request.clone();
        changed.sandbox_id = "second-pod-alias".into();
        assert!(state.create_sandbox(&changed).is_err());
        let mut changed = request.clone();
        changed.hostname = "second-host-alias".into();
        assert!(state.create_sandbox(&changed).is_err());
        let first = state.guest_details(&GuestDetailsRequest::new()).unwrap();
        let second = state
            .guest_details(&GuestDetailsRequest {
                mem_block_size: true,
                mem_hotplug_probe: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.mem_block_size_bytes, 0);
        assert!(!first.support_mem_hotplug_probe);
        let detail = first.agent_details.as_ref().unwrap();
        assert!(detail.supports_seccomp);
        assert!(detail.device_handlers.is_empty() && detail.storage_handlers.is_empty());
        let mut unknown = GuestDetailsRequest::new();
        unknown
            .special_fields
            .mut_unknown_fields()
            .add_varint(99, 1);
        assert!(state.guest_details(&unknown).is_err());
    }
    struct HandshakeAgent {
        handshake: Arc<GcpHandshake>,
    }
    #[async_trait]
    impl protocols::agent_ttrpc_async::AgentService for HandshakeAgent {
        async fn create_sandbox(
            &self,
            _: &TtrpcContext,
            request: CreateSandboxRequest,
        ) -> ttrpc::Result<Empty> {
            self.handshake.create_sandbox(&request)
        }
        async fn get_guest_details(
            &self,
            _: &TtrpcContext,
            request: GuestDetailsRequest,
        ) -> ttrpc::Result<GuestDetailsResponse> {
            self.handshake.guest_details(&request)
        }
    }
    #[tokio::test]
    async fn generated_handshake_transport_checks_fields_and_fixed_details() {
        use protobuf::Message;
        let handshake = Arc::new(GcpHandshake::new());
        let services =
            protocols::agent_ttrpc_async::create_agent_service(Arc::new(HandshakeAgent {
                handshake: handshake.clone(),
            }));
        let services = restrict_agent_services(
            services,
            handshake,
            Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS)),
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", directory.path().join("agent.sock").display());
        let mut server = Server::new()
            .bind(&address)
            .unwrap()
            .register_service(services);
        server.start().await.unwrap();
        let client = Client::connect(&address).await.unwrap();
        let mut sandbox = sandbox_request();
        sandbox.guest_hook_path = "/ignored-but-dangerous".into();
        let request = Request {
            service: SERVICE.into(),
            method: "CreateSandbox".into(),
            payload: sandbox.write_to_bytes().unwrap(),
            timeout_nano: 2_000_000_000,
            ..Default::default()
        };
        let ttrpc::Error::RpcStatus(status) = client.request(request).await.err().unwrap() else {
            panic!("expected rejection");
        };
        assert_eq!(status.code(), ttrpc::Code::INVALID_ARGUMENT);
        for _ in 0..2 {
            let request = Request {
                service: SERVICE.into(),
                method: "CreateSandbox".into(),
                payload: sandbox_request().write_to_bytes().unwrap(),
                timeout_nano: 2_000_000_000,
                ..Default::default()
            };
            client.request(request).await.unwrap();
        }
        let request = Request {
            service: SERVICE.into(),
            method: "GetGuestDetails".into(),
            payload: GuestDetailsRequest {
                mem_block_size: true,
                mem_hotplug_probe: true,
                ..Default::default()
            }
            .write_to_bytes()
            .unwrap(),
            timeout_nano: 2_000_000_000,
            ..Default::default()
        };
        let details =
            GuestDetailsResponse::parse_from_bytes(&client.request(request).await.unwrap().payload)
                .unwrap();
        assert!(!details.support_mem_hotplug_probe);
        assert_eq!(
            details.agent_details.as_ref().unwrap().version,
            "onb17.gcp-proof-startup.v1"
        );
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(10), server.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
    #[cfg(feature = "gcp-proof-startup")]
    #[test]
    fn registration_matches_the_immutable_declared_rpc_policy() {
        let policy: serde_json::Value =
            serde_json::from_slice(execution_proof_handoff::gcp_startup::RPC_POLICY_BYTES).unwrap();
        let names = |name: &str| -> std::collections::BTreeSet<String> {
            policy[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            names("task_methods"),
            TASK_METHODS.iter().map(|v| (*v).to_owned()).collect()
        );
        assert_eq!(
            names("handshake_methods"),
            HANDSHAKE_METHODS.iter().map(|v| (*v).to_owned()).collect()
        );
        assert_eq!(policy["task_requires_sandbox_ack"], true);
        assert_eq!(policy["inflight_requests"], INFLIGHT_REQUESTS);
        assert_eq!(
            policy["sandbox_alias_bytes"],
            execution_proof_contract::MAX_ID_BYTES
        );
        assert_eq!(policy["other_methods"], false);
    }
    struct BlockedHandler {
        entered: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl MethodHandler for BlockedHandler {
        async fn handler(&self, _: TtrpcContext, _: Request) -> ttrpc::Result<Response> {
            let release = self.release.notified();
            tokio::pin!(release);
            // Register before signaling entry, so notify_waiters cannot race a
            // still-unpolled future. No sleeps stand in for synchronization.
            release.as_mut().enable();
            self.entered.add_permits(1);
            release.await;
            Ok(Response::new())
        }
    }
    #[tokio::test]
    async fn rpc_capacity_is_shared_bounded_and_reusable_after_release() {
        let handshake = Arc::new(GcpHandshake::new());
        handshake.create_sandbox(&sandbox_request()).unwrap();
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let mut services = protocols::agent_ttrpc_async::create_agent_service(Arc::new(EmptyAgent));
        services.get_mut(SERVICE).unwrap().methods.insert(
            "WaitProcess".into(),
            Box::new(BlockedHandler {
                entered: entered.clone(),
                release: release.clone(),
            }),
        );
        let budget = Arc::new(tokio::sync::Semaphore::new(INFLIGHT_REQUESTS));
        let services = restrict_agent_services(services, handshake, budget.clone()).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let address = format!("unix://{}", directory.path().join("agent.sock").display());
        let mut server = Server::new()
            .bind(&address)
            .unwrap()
            .register_service(services);
        server.start().await.unwrap();
        let client = Arc::new(Client::connect(&address).await.unwrap());
        let request = || Request {
            service: SERVICE.into(),
            method: "WaitProcess".into(),
            timeout_nano: 10_000_000_000,
            ..Default::default()
        };
        let mut owners = Vec::new();
        for _ in 0..INFLIGHT_REQUESTS {
            let client = client.clone();
            let request = request();
            owners.push(tokio::spawn(async move { client.request(request).await }));
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            entered.acquire_many(INFLIGHT_REQUESTS as u32),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();
        assert_eq!(budget.available_permits(), 0);
        let ttrpc::Error::RpcStatus(status) = client.request(request()).await.err().unwrap() else {
            panic!("expected capacity rejection");
        };
        assert_eq!(status.code(), ttrpc::Code::RESOURCE_EXHAUSTED);
        release.notify_waiters();
        for owner in owners {
            owner.await.unwrap().unwrap();
        }
        assert_eq!(budget.available_permits(), INFLIGHT_REQUESTS);
        let final_client = client.clone();
        let final_request = request();
        let owner = tokio::spawn(async move { final_client.request(final_request).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        release.notify_waiters();
        owner.await.unwrap().unwrap();
        assert_eq!(budget.available_permits(), INFLIGHT_REQUESTS);
        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(10), server.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}
