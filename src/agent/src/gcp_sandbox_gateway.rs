// SPDX-License-Identifier: Apache-2.0
//! One bounded sandbox and a separately admitted protected app task. The
//! sandbox alias is only a transport selector and has no proof authority.

#[path = "gcp_sandbox_gateway_pause.rs"]
mod pause;

use anyhow::{anyhow, ensure, Result};
use async_trait::async_trait;
use image_rs::preparation::launch_spec::BoundEffectiveSpec;
use protocols::{
    agent::*,
    agent_ttrpc_async::{self, AgentService, AgentServiceClient},
    empty::Empty,
    health::{self, CheckRequest, HealthCheckResponse, VersionCheckResponse},
    health_ttrpc_async,
};
use sha2::{Digest, Sha384};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Semaphore};
use ttrpc::{
    r#async::{Client, MethodHandler, Server, Service, TtrpcContext},
    Code, Request, Response,
};

const AGENT_SERVICE: &str = "grpc.AgentService";
const CONTAINER_ROLE: &str = "io.kubernetes.cri.container-type";
const CREATE_WIRE_HASH: &str = "onb17-gateway-wire-sha384";
const MAX_WIRE_BYTES: usize = 272 << 10;
const COPY_PREFIX: &str = "/run/kata-containers/shared/containers/";
const MAX_COPY_BYTES: usize = 4096;
const MAX_COPY_WIRE: usize = MAX_COPY_BYTES + 512;
const MAX_PAUSE_COPIES: usize = 3;
const MAX_APP_COPIES: usize = 4;
const TERMINATION_LOG: &str = "termination-log";
const MAX_INFLIGHT: usize = 32;
const CREATE_TIME: Duration = Duration::from_secs(60);
const BACKEND_TIME: Duration = Duration::from_secs(5);
const WAIT_TIME: Duration = Duration::from_secs(600);
const AGENT_METHODS: &[&str] = &[
    "CreateSandbox",
    "DestroySandbox",
    "GetGuestDetails",
    "CopyFile",
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
const HEALTH_METHODS: &[&str] = &["Check", "Version"];

#[derive(Debug)]
pub(super) struct GatewayCandidate {
    pub(super) container_id: String,
    pub(super) wire_sha384: String,
}

pub(super) struct GatewayControl {
    state: Arc<Gateway>,
    candidates: mpsc::Receiver<GatewayCandidate>,
}

#[derive(Default)]
enum App {
    #[default]
    Empty,
    Pending(Pending),
    Attached(Attached),
    Consumed,
}

struct Pending {
    request: Box<CreateContainerRequest>,
    activate: oneshot::Sender<Activation>,
    validated: bool,
}

struct Attached {
    cid: String,
    backend: AgentServiceClient,
    created: bool,
    started: bool,
    removed: bool,
}

struct Activation {
    request: Box<CreateContainerRequest>,
    backend: AgentServiceClient,
}

#[derive(Default)]
struct State {
    sandbox: Option<CreateSandboxRequest>,
    pause_copies: Vec<String>,
    app_copies: Option<AppCopies>,
    app: App,
}

struct AppCopies {
    cid: String,
    paths: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppExit {
    Held,
    Released,
    Cancelled,
}

struct Gateway {
    state: Mutex<State>,
    closed: watch::Sender<bool>,
    aborted: watch::Sender<bool>,
    app_exit: Option<watch::Sender<AppExit>>,
    candidates: mpsc::Sender<GatewayCandidate>,
    pause: AsyncMutex<pause::Pause>,
    mutations: AsyncMutex<()>,
}

#[cfg(any(test, feature = "protected-export-gcp-native"))]
pub(super) fn bind(address: &str) -> Result<(Server, GatewayControl)> {
    bind_inner(address, None)
}

pub(super) fn bind_with_exit_barrier(address: &str) -> Result<(Server, GatewayControl)> {
    bind_inner(address, Some(watch::channel(AppExit::Held).0))
}

fn bind_inner(
    address: &str,
    app_exit: Option<watch::Sender<AppExit>>,
) -> Result<(Server, GatewayControl)> {
    let (candidate_tx, candidates) = mpsc::channel(1);
    let (closed, _) = watch::channel(false);
    let (aborted, _) = watch::channel(false);
    let gateway = Arc::new(Gateway {
        state: Mutex::new(State::default()),
        closed,
        aborted,
        app_exit,
        candidates: candidate_tx,
        pause: AsyncMutex::default(),
        mutations: AsyncMutex::default(),
    });
    let mut agent = agent_ttrpc_async::create_agent_service(gateway.clone());
    agent.retain(|name, _| name == AGENT_SERVICE);
    let mut health = health_ttrpc_async::create_health(gateway.clone());
    let budget = Arc::new(Semaphore::new(MAX_INFLIGHT));
    restrict(&mut agent, AGENT_METHODS, &budget)?;
    restrict(&mut health, HEALTH_METHODS, &budget)?;
    let server = Server::new()
        .bind(address)?
        .register_service(agent)
        .register_service(health);
    Ok((
        server,
        GatewayControl {
            state: gateway,
            candidates,
        },
    ))
}

impl GatewayControl {
    pub(super) async fn candidate(&mut self) -> Result<GatewayCandidate> {
        let mut closed = self.state.closed.subscribe();
        tokio::select! {
            biased;
            _ = closed.wait_for(|closed| *closed) => Err(anyhow!("sandbox gateway closed")),
            candidate = self.candidates.recv() => candidate.ok_or_else(|| anyhow!("no app candidate")),
        }
    }

    pub(super) fn bind(
        &self,
        container_id: &str,
        image_ref: &str,
        spec: &BoundEffectiveSpec,
    ) -> Result<()> {
        let result = (|| {
            let mut state = self.state.lock()?;
            self.state.ensure_open()?;
            let State {
                sandbox,
                app_copies,
                app,
                ..
            } = &mut *state;
            let App::Pending(pending) = app else {
                return Err(anyhow!("no pending app candidate"));
            };
            ensure!(!pending.validated, "app candidate already validated");
            let sandbox = sandbox.as_ref().ok_or_else(|| anyhow!("sandbox missing"))?;
            let paths = app_copies
                .as_ref()
                .map_or(&[][..], |copies| copies.paths.as_slice());
            let projected = crate::gcp_sandbox_projection::project_app_create(
                &pending.request,
                container_id,
                image_ref,
                spec,
                &sandbox.sandbox_id,
                paths,
            )?;
            pending.request = Box::new(projected);
            pending.validated = true;
            Ok(())
        })();
        if result.is_err() {
            self.state.abort();
        }
        result
    }

    pub(super) async fn attach(&self, address: &str) -> Result<()> {
        let result = self.attach_inner(address).await;
        if result.is_err() {
            self.state.abort();
        }
        result
    }

    async fn attach_inner(&self, address: &str) -> Result<()> {
        let sandbox = {
            let state = self.state.lock()?;
            self.state.ensure_open()?;
            ensure!(
                matches!(&state.app, App::Pending(pending) if pending.validated),
                "no validated app candidate"
            );
            let sandbox = state
                .sandbox
                .as_ref()
                .ok_or_else(|| anyhow!("no sandbox"))?;
            CreateSandboxRequest {
                hostname: sandbox.hostname.clone(),
                sandbox_id: sandbox.sandbox_id.clone(),
                ..Default::default()
            }
        };
        let client = tokio::time::timeout(BACKEND_TIME, Client::connect(address)).await??;
        let backend = AgentServiceClient::new(client);
        // Send only the bounded alias to the unchanged proof agent. The
        // protected lease and independent verifier own app and Pod identity.
        backend
            .create_sandbox(backend_context(BACKEND_TIME), &sandbox)
            .await?;

        let mut state = self.state.lock()?;
        self.state.ensure_open()?;
        let App::Pending(pending) = std::mem::replace(&mut state.app, App::Consumed) else {
            return Err(anyhow!("app candidate no longer pending"));
        };
        ensure!(pending.validated, "app candidate no longer validated");
        state.app = App::Attached(Attached {
            cid: pending.request.container_id.clone(),
            backend: backend.clone(),
            created: false,
            started: false,
            removed: false,
        });
        pending
            .activate
            .send(Activation {
                request: pending.request,
                backend,
            })
            .map_err(|_| anyhow!("app Create caller no longer waiting"))
    }

    pub(super) async fn cancelled(&self) {
        let _ = self
            .state
            .aborted
            .subscribe()
            .wait_for(|aborted| *aborted)
            .await;
    }

    pub(super) fn release_app_exit(&self) -> Result<()> {
        let _state = self.state.lock()?;
        self.state.ensure_open()?;
        let exit = self
            .state
            .app_exit
            .as_ref()
            .ok_or_else(|| anyhow!("app exit barrier is disabled"))?;
        ensure!(
            *exit.borrow() != AppExit::Cancelled,
            "app wait was cancelled"
        );
        exit.send_replace(AppExit::Released);
        Ok(())
    }

    pub(super) async fn wait_for_worker_teardown(&self) {
        let _ = self
            .state
            .closed
            .subscribe()
            .wait_for(|closed| *closed)
            .await;
    }

    pub(super) async fn shutdown(&self) -> Result<()> {
        self.state.shutdown().await
    }
}

impl Gateway {
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| anyhow!("gateway state unavailable"))
    }

    fn ensure_open(&self) -> Result<()> {
        ensure!(!*self.closed.borrow(), "sandbox gateway closed");
        Ok(())
    }

    fn close(&self) {
        let state = self.state.lock();
        self.signal_closed();
        if let Ok(mut state) = state {
            if matches!(state.app, App::Pending(_)) {
                // Dropping this sender wakes the app Create holder immediately.
                state.app = App::Consumed;
            }
        }
    }

    fn signal_closed(&self) {
        self.closed.send_replace(true);
        self.cancel_app_exit();
    }

    fn cancel_app_exit(&self) {
        if let Some(exit) = &self.app_exit {
            exit.send_replace(AppExit::Cancelled);
        }
    }

    fn abort(&self) {
        self.close();
        self.aborted.send_replace(true);
    }

    async fn shutdown(&self) -> Result<()> {
        self.close();
        let (pause, app) = tokio::join!(async { self.pause.lock().await.remove().await }, async {
            let _mutation = self.mutations.lock().await;
            let app = match &self.lock()?.app {
                App::Attached(app) if !app.removed => Some((app.cid.clone(), app.backend.clone())),
                _ => None,
            };
            if let Some((cid, backend)) = app {
                backend
                    .remove_container(backend_context(BACKEND_TIME), &remove_request(&cid))
                    .await?;
                self.mark_removed(&cid)?;
            }
            Ok::<(), anyhow::Error>(())
        });
        pause?;
        app
    }

    fn mark_removed(&self, cid: &str) -> Result<()> {
        let mut state = self.lock()?;
        if let App::Attached(app) = &mut state.app {
            if app.cid == cid {
                app.removed = true;
                self.cancel_app_exit();
            }
        }
        Ok(())
    }

    fn sandbox_id(&self) -> ttrpc::Result<String> {
        self.lock()
            .map_err(rejected)?
            .sandbox
            .as_ref()
            .map(|sandbox| sandbox.sandbox_id.clone())
            .ok_or_else(|| status(Code::FAILED_PRECONDITION, "gateway sandbox missing"))
    }

    fn app_backend(&self, cid: &str) -> ttrpc::Result<AgentServiceClient> {
        let state = self.lock().map_err(rejected)?;
        self.ensure_open().map_err(rejected)?;
        match &state.app {
            App::Attached(app) if app.cid == cid && app.created && !app.removed => {
                Ok(app.backend.clone())
            }
            _ => Err(status(Code::FAILED_PRECONDITION, "app admission required")),
        }
    }

    fn start_app(&self, cid: &str) -> ttrpc::Result<AgentServiceClient> {
        let mut state = self.lock().map_err(rejected)?;
        self.ensure_open().map_err(rejected)?;
        match &mut state.app {
            App::Attached(app) if app.cid == cid && app.created && !app.started && !app.removed => {
                app.started = true;
                Ok(app.backend.clone())
            }
            _ => Err(status(
                Code::FAILED_PRECONDITION,
                "fresh app Start required",
            )),
        }
    }

    fn pending_app(
        &self,
        request: CreateContainerRequest,
        wire_sha384: String,
    ) -> ttrpc::Result<oneshot::Receiver<Activation>> {
        let mut state = self.lock().map_err(rejected)?;
        self.ensure_open().map_err(rejected)?;
        if !matches!(state.app, App::Empty) {
            return Err(status(
                Code::ALREADY_EXISTS,
                "app candidate slot already used",
            ));
        }
        if state
            .app_copies
            .as_ref()
            .is_some_and(|copies| copies.cid != request.container_id)
        {
            return Err(invalid(
                "app CopyFile selector differs from CreateContainer",
            ));
        }
        let (activate, wait) = oneshot::channel();
        let candidate = GatewayCandidate {
            container_id: request.container_id.clone(),
            wire_sha384,
        };
        state.app = App::Pending(Pending {
            request: Box::new(request),
            activate,
            validated: false,
        });
        if self.candidates.try_send(candidate).is_err() {
            state.app = App::Consumed;
            self.signal_closed();
            self.aborted.send_replace(true);
            return Err(status(Code::UNAVAILABLE, "app candidate owner unavailable"));
        }
        Ok(wait)
    }

    fn mark_created(&self, cid: &str) -> Result<()> {
        let mut state = self.lock()?;
        self.ensure_open()?;
        let App::Attached(app) = &mut state.app else {
            return Err(anyhow!("app backend unavailable"));
        };
        ensure!(
            app.cid == cid && !app.created,
            "app creation state mismatch"
        );
        app.created = true;
        Ok(())
    }
}

struct CreateFlight<'a> {
    gateway: &'a Gateway,
    armed: bool,
}

impl Drop for CreateFlight<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.gateway.abort();
        }
    }
}

fn status(code: Code, text: &str) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, text))
}

fn rejected(_: anyhow::Error) -> ttrpc::Error {
    status(
        Code::FAILED_PRECONDITION,
        "sandbox gateway operation rejected",
    )
}

fn invalid(text: &str) -> ttrpc::Error {
    status(Code::INVALID_ARGUMENT, text)
}

fn backend_context(timeout: Duration) -> ttrpc::context::Context {
    ttrpc::context::with_timeout(timeout.as_nanos() as i64)
}

fn known(fields: &protobuf::SpecialFields) -> ttrpc::Result<()> {
    if fields.unknown_fields().iter().next().is_some() {
        return Err(invalid("unknown gateway RPC fields"));
    }
    Ok(())
}

fn alias(value: &str, empty: bool) -> bool {
    (empty || !value.is_empty())
        && !matches!(value, "." | "..")
        && value.len() <= execution_proof_contract::MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}

fn mount_point(cid: &str) -> String {
    format!("/run/kata-containers/{cid}/rootfs")
}

fn copy_selector(path: &str) -> Option<(&str, &str)> {
    let flat = path.strip_prefix(COPY_PREFIX)?;
    let (stem, file) = if let Some(stem) = flat.strip_suffix("-termination-log") {
        (stem, TERMINATION_LOG)
    } else {
        flat.rsplit_once('-')?
    };
    let (cid, nonce) = stem.rsplit_once('-')?;
    if alias(cid, false)
        && nonce.len() == 16
        && nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && matches!(file, "hostname" | "hosts" | "resolv.conf" | TERMINATION_LOG)
    {
        Some((cid, file))
    } else {
        None
    }
}

fn validate_copy(request: &CopyFileRequest) -> ttrpc::Result<(&str, &str)> {
    known(&request.special_fields)?;
    let selector =
        copy_selector(&request.path).ok_or_else(|| invalid("unsupported CopyFile path"))?;
    let regular = request.file_mode & libc::S_IFMT == libc::S_IFREG;
    let permissions = request.file_mode & !libc::S_IFMT;
    let valid_file = if selector.1 == TERMINATION_LOG {
        permissions == 0o666 && request.data.is_empty()
    } else {
        matches!(permissions, 0o600 | 0o644)
    };
    // Kata Go sends os.FileMode(0750)|os.ModeDir, not a Linux stat mode.
    if !regular
        || !valid_file
        || request.dir_mode != (1 << 31 | 0o750)
        || request.uid != 0
        || request.gid != 0
        || request.offset != 0
        || request.data.len() > MAX_COPY_BYTES
        || request.file_size != request.data.len() as i64
    {
        return Err(invalid("unsupported CopyFile metadata or size"));
    }
    Ok(selector)
}

fn record_copy(
    paths: &mut Vec<String>,
    path: String,
    file: &str,
    max_copies: usize,
) -> ttrpc::Result<()> {
    if paths.len() == max_copies
        || paths
            .iter()
            .any(|prior| copy_selector(prior).is_some_and(|(_, old_file)| old_file == file))
    {
        return Err(status(Code::ALREADY_EXISTS, "CopyFile slot already used"));
    }
    paths.push(path);
    Ok(())
}

fn valid_sandbox(request: &CreateSandboxRequest) -> ttrpc::Result<()> {
    known(&request.special_fields)?;
    if !alias(&request.sandbox_id, false)
        || !alias(&request.hostname, true)
        || request.sandbox_pidns
        || !request.guest_hook_path.is_empty()
        || !request.kernel_modules.is_empty()
        || request.dns.len() > 16
        || request.dns.iter().any(|line| {
            line.len() > 256
                || !line
                    .bytes()
                    .all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
        })
        || request.storages.len() > 1
    {
        return Err(invalid("unsupported gateway sandbox shape"));
    }
    if let Some(storage) = request.storages.first() {
        known(&storage.special_fields)?;
        let valid_options = match storage.options.as_slice() {
            [noexec, nosuid, nodev, mode, size] => {
                [
                    noexec.as_str(),
                    nosuid.as_str(),
                    nodev.as_str(),
                    mode.as_str(),
                ] == ["noexec", "nosuid", "nodev", "mode=1777"]
                    && size
                        .strip_prefix("size=")
                        .and_then(|value| value.parse::<u64>().ok())
                        .is_some_and(|bytes| (1..=64 << 20).contains(&bytes))
            }
            _ => false,
        };
        if storage.driver != "ephemeral"
            || storage.source != "shm"
            || storage.fstype != "tmpfs"
            || storage.mount_point != "/run/kata-containers/sandbox/shm"
            || !valid_options
            || !storage.driver_options.is_empty()
            || storage.fs_group.is_some()
            || storage.shared
        {
            return Err(invalid("unsupported gateway sandbox storage"));
        }
    }
    // DNS and shm belong to the bounded stock shape. This gateway neither
    // configures the guest network nor mounts an unused sandbox shm.
    Ok(())
}

fn validate_create_shape(request: &CreateContainerRequest) -> ttrpc::Result<&str> {
    known(&request.special_fields)?;
    if !alias(&request.container_id, false)
        || request.exec_id != request.container_id
        || request.sandbox_pidns
        || request.string_user.is_some()
        || !request.devices.is_empty()
        || !request.shared_mounts.is_empty()
        || request.stdin_port != 0
        || request.stdout_port != 0
        || request.stderr_port != 0
    {
        return Err(invalid("unsupported gateway CreateContainer shape"));
    }
    let spec = request
        .OCI
        .as_ref()
        .ok_or_else(|| invalid("missing gateway OCI"))?;
    known(&spec.special_fields)?;
    spec.Annotations
        .get(CONTAINER_ROLE)
        .map(String::as_str)
        .ok_or_else(|| invalid("gateway CRI role missing"))
}

fn validate_pause(request: &CreateContainerRequest, paths: &[String]) -> ttrpc::Result<()> {
    let [storage] = request.storages.as_slice() else {
        return Err(invalid("unsupported pause storage count"));
    };
    known(&storage.special_fields)?;
    if storage.driver != "image_guest_pull"
        || storage.source != "pause"
        || storage.fstype != "overlay"
        || storage.mount_point != mount_point(&request.container_id)
        || storage.fs_group.is_some()
        || storage.shared
        || !storage.options.is_empty()
        || storage.driver_options.len() > 1
        || storage
            .driver_options
            .iter()
            .any(|option| option.len() > 16 << 10 || !option.starts_with("image_guest_pull="))
    {
        return Err(invalid("unsupported gateway pause storage"));
    }
    let spec = request
        .OCI
        .as_ref()
        .ok_or_else(|| invalid("missing pause OCI"))?;
    let mut observed = Vec::new();
    for mount in spec.Mounts.iter().filter(|mount| {
        mount.source.starts_with(COPY_PREFIX)
            || matches!(
                mount.destination.as_str(),
                "/etc/hostname" | "/etc/hosts" | "/etc/resolv.conf"
            )
    }) {
        known(&mount.special_fields)?;
        let (_, file) = copy_selector(&mount.source)
            .ok_or_else(|| invalid("unsupported pause CopyFile mount source"))?;
        if !paths.contains(&mount.source)
            || mount.destination != format!("/etc/{file}")
            || mount.type_ != "bind"
            || mount.options != ["rbind", "ro", "nosuid", "nodev", "noexec"]
            || observed.contains(&mount.source)
        {
            return Err(invalid("unsupported pause CopyFile mount"));
        }
        observed.push(mount.source.clone());
    }
    if observed.len() != paths.len() {
        return Err(invalid("unused pause CopyFile selector"));
    }
    // The measured pause executable ignores all supplied OCI process, path,
    // mount and metadata fields. Host bytes are never passed to the process.
    Ok(())
}

fn init_task(cid: &str, exec_id: &str, allow_empty: bool) -> ttrpc::Result<()> {
    if exec_id == cid || (allow_empty && exec_id.is_empty()) {
        Ok(())
    } else {
        Err(invalid("gateway init task ID mismatch"))
    }
}

fn remove_request(cid: &str) -> RemoveContainerRequest {
    RemoveContainerRequest {
        container_id: cid.into(),
        timeout: BACKEND_TIME.as_secs() as u32,
        ..Default::default()
    }
}

fn restrict(
    services: &mut HashMap<String, Service>,
    methods: &[&str],
    budget: &Arc<Semaphore>,
) -> Result<()> {
    ensure!(services.len() == 1, "invalid gateway service registration");
    for service in services.values_mut() {
        ensure!(
            methods
                .iter()
                .all(|name| service.methods.contains_key(*name)),
            "incomplete gateway service registration"
        );
        service
            .methods
            .retain(|name, _| methods.contains(&name.as_str()));
        for (name, method) in std::mem::take(&mut service.methods) {
            let handler = Budgeted {
                create: name == "CreateContainer",
                max_payload: if name == "CopyFile" {
                    MAX_COPY_WIRE
                } else {
                    MAX_WIRE_BYTES
                },
                budget: budget.clone(),
                method,
            };
            service.methods.insert(name, Box::new(handler));
        }
        service.streams.clear();
    }
    Ok(())
}

struct Budgeted {
    create: bool,
    max_payload: usize,
    budget: Arc<Semaphore>,
    method: Box<dyn MethodHandler + Send + Sync>,
}

#[async_trait]
impl MethodHandler for Budgeted {
    async fn handler(&self, mut ctx: TtrpcContext, request: Request) -> ttrpc::Result<Response> {
        let reject = |code, message| {
            let mut response = Response::new();
            response.set_status(ttrpc::get_status(code, message));
            Ok(response)
        };
        if request.payload.len() > self.max_payload {
            return reject(Code::RESOURCE_EXHAUSTED, "gateway RPC size exceeds limit");
        }
        let Ok(_permit) = self.budget.clone().try_acquire_owned() else {
            return reject(Code::RESOURCE_EXHAUSTED, "gateway RPC capacity exhausted");
        };
        if self.create {
            let hash = Sha384::digest(&request.payload)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            // Always replace any host-supplied metadata under this key with
            // the commitment to these exact, original RPC payload bytes.
            ctx.metadata.insert(CREATE_WIRE_HASH.into(), vec![hash]);
        }
        self.method.handler(ctx, request).await
    }
}

#[async_trait]
impl health_ttrpc_async::Health for Gateway {
    async fn check(
        &self,
        _: &TtrpcContext,
        request: CheckRequest,
    ) -> ttrpc::Result<HealthCheckResponse> {
        known(&request.special_fields)?;
        self.ensure_open().map_err(rejected)?;
        let mut response = HealthCheckResponse::new();
        response.set_status(health::health_check_response::ServingStatus::SERVING);
        Ok(response)
    }

    async fn version(
        &self,
        _: &TtrpcContext,
        request: CheckRequest,
    ) -> ttrpc::Result<VersionCheckResponse> {
        known(&request.special_fields)?;
        self.ensure_open().map_err(rejected)?;
        Ok(VersionCheckResponse {
            agent_version: "onb17.gcp-sandbox-gateway.v1".into(),
            grpc_version: "0.0.1".into(),
            ..Default::default()
        })
    }
}

#[async_trait]
impl AgentService for Gateway {
    async fn create_sandbox(
        &self,
        _: &TtrpcContext,
        request: CreateSandboxRequest,
    ) -> ttrpc::Result<Empty> {
        valid_sandbox(&request)?;
        let mut state = self.lock().map_err(rejected)?;
        self.ensure_open().map_err(rejected)?;
        match &state.sandbox {
            Some(prior) if prior != &request => {
                return Err(status(Code::ALREADY_EXISTS, "sandbox alias already fixed"));
            }
            Some(_) => {}
            None => state.sandbox = Some(request),
        }
        Ok(Empty::new())
    }

    async fn get_guest_details(
        &self,
        _: &TtrpcContext,
        request: GuestDetailsRequest,
    ) -> ttrpc::Result<GuestDetailsResponse> {
        known(&request.special_fields)?;
        self.ensure_open().map_err(rejected)?;
        let id = self.sandbox_id()?;
        let handshake = crate::gcp_rpc::GcpHandshake::new();
        handshake.create_sandbox(&CreateSandboxRequest {
            sandbox_id: id,
            ..Default::default()
        })?;
        handshake.guest_details(&request)
    }

    async fn destroy_sandbox(
        &self,
        _: &TtrpcContext,
        request: DestroySandboxRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        self.shutdown().await.map_err(rejected)?;
        Ok(Empty::new())
    }

    async fn copy_file(&self, _: &TtrpcContext, request: CopyFileRequest) -> ttrpc::Result<Empty> {
        let (cid, file) = validate_copy(&request)?;
        let mut pause = self.pause.lock().await;
        let mut state = self.lock().map_err(rejected)?;
        self.ensure_open().map_err(rejected)?;
        let sandbox = state
            .sandbox
            .as_ref()
            .ok_or_else(|| status(Code::FAILED_PRECONDITION, "gateway sandbox missing"))?;
        let (paths, max_copies) = if sandbox.sandbox_id == cid {
            if file == TERMINATION_LOG {
                return Err(invalid("termination CopyFile is application-only"));
            }
            if !matches!(*pause, pause::Pause::Empty) {
                return Err(status(
                    Code::FAILED_PRECONDITION,
                    "pause CopyFile phase closed",
                ));
            }
            (&mut state.pause_copies, MAX_PAUSE_COPIES)
        } else {
            if !matches!(state.app, App::Empty) || !pause.running().map_err(rejected)? {
                return Err(status(
                    Code::FAILED_PRECONDITION,
                    "app CopyFile phase closed",
                ));
            }
            let copies = state.app_copies.get_or_insert_with(|| AppCopies {
                cid: cid.into(),
                paths: Vec::new(),
            });
            if copies.cid != cid {
                return Err(invalid("app CopyFile selector changed"));
            }
            (&mut copies.paths, MAX_APP_COPIES)
        };
        // Remember only the selectors for exact mount matching. All host
        // payload bytes and metadata are discarded without a filesystem write.
        record_copy(paths, request.path.clone(), file, max_copies)?;
        Ok(Empty::new())
    }

    async fn create_container(
        &self,
        ctx: &TtrpcContext,
        request: CreateContainerRequest,
    ) -> ttrpc::Result<Empty> {
        let role = validate_create_shape(&request)?;
        let sandbox_id = self.sandbox_id()?;
        if request.container_id == sandbox_id {
            if role != "sandbox" {
                return Err(invalid("pause request role mismatch"));
            }
            let mut pause = self.pause.lock().await;
            self.ensure_open().map_err(rejected)?;
            validate_pause(&request, &self.lock().map_err(rejected)?.pause_copies)?;
            pause.create().map_err(rejected)?;
            return Ok(Empty::new());
        }
        if role != "container" || !self.pause.lock().await.running().map_err(rejected)? {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "running sandbox pause required",
            ));
        }
        let hash = ctx
            .metadata
            .get(CREATE_WIRE_HASH)
            .and_then(|hashes| hashes.first())
            .ok_or_else(|| status(Code::UNAVAILABLE, "gateway request commitment missing"))?
            .clone();
        let wait = self.pending_app(request, hash)?;
        let mut flight = CreateFlight {
            gateway: self,
            armed: true,
        };
        tokio::time::timeout(CREATE_TIME, async {
            let activation = wait
                .await
                .map_err(|_| status(Code::FAILED_PRECONDITION, "app admission cancelled"))?;
            let _mutation = self.mutations.lock().await;
            self.ensure_open().map_err(rejected)?;
            activation
                .backend
                .create_container(backend_context(BACKEND_TIME), &activation.request)
                .await?;
            self.mark_created(&activation.request.container_id)
                .map_err(rejected)?;
            Ok::<(), ttrpc::Error>(())
        })
        .await
        .map_err(|_| status(Code::DEADLINE_EXCEEDED, "app admission deadline"))??;
        flight.armed = false;
        Ok(Empty::new())
    }

    async fn start_container(
        &self,
        _: &TtrpcContext,
        request: StartContainerRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        if request.container_id == self.sandbox_id()? {
            let mut pause = self.pause.lock().await;
            self.ensure_open().map_err(rejected)?;
            pause.start().await.map_err(rejected)?;
            return Ok(Empty::new());
        }
        let _mutation = self.mutations.lock().await;
        if !self.pause.lock().await.running().map_err(rejected)? {
            return Err(status(
                Code::FAILED_PRECONDITION,
                "running sandbox pause required",
            ));
        }
        self.start_app(&request.container_id)?
            .start_container(backend_context(BACKEND_TIME), &request)
            .await
    }

    async fn remove_container(
        &self,
        _: &TtrpcContext,
        request: RemoveContainerRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        if request.container_id == self.sandbox_id()? {
            self.shutdown().await.map_err(rejected)?;
            return Ok(Empty::new());
        }
        let _mutation = self.mutations.lock().await;
        let backend = {
            let state = self.lock().map_err(rejected)?;
            match &state.app {
                App::Pending(pending) if pending.request.container_id == request.container_id => {
                    None
                }
                App::Attached(app) if app.cid == request.container_id => {
                    if app.removed {
                        return Ok(Empty::new());
                    }
                    Some(app.backend.clone())
                }
                _ => return Err(status(Code::NOT_FOUND, "unknown app task")),
            }
        };
        let Some(backend) = backend else {
            self.abort();
            return Ok(Empty::new());
        };
        // Bound cleanup independently of a caller-supplied RPC timeout.
        let result = backend
            .remove_container(
                backend_context(BACKEND_TIME),
                &remove_request(&request.container_id),
            )
            .await?;
        self.mark_removed(&request.container_id).map_err(rejected)?;
        Ok(result)
    }

    async fn signal_process(
        &self,
        _: &TtrpcContext,
        request: SignalProcessRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, true)?;
        if request.container_id == self.sandbox_id()? {
            self.pause
                .lock()
                .await
                .signal(request.signal as i32)
                .map_err(rejected)?;
            return Ok(Empty::new());
        }
        self.app_backend(&request.container_id)?
            .signal_process(backend_context(BACKEND_TIME), &request)
            .await
    }

    async fn wait_process(
        &self,
        _: &TtrpcContext,
        request: WaitProcessRequest,
    ) -> ttrpc::Result<WaitProcessResponse> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, false)?;
        if request.container_id == self.sandbox_id()? {
            let status = pause::Pause::wait(&self.pause).await.map_err(rejected)?;
            return Ok(WaitProcessResponse {
                status,
                ..Default::default()
            });
        }
        let backend = self.app_backend(&request.container_id)?;
        let wait = backend.wait_process(backend_context(WAIT_TIME), &request);
        let Some(exit) = &self.app_exit else {
            return wait.await;
        };
        let mut exit = exit.subscribe();
        let cancelled = || status(Code::CANCELLED, "app wait cancelled");
        let response = tokio::select! {
            biased;
            _ = exit.wait_for(|state| *state == AppExit::Cancelled) => return Err(cancelled()),
            result = wait => result?,
        };
        // Kubelet can tear down the PodVM as soon as it sees this terminal
        // status. The preparation owner releases it after serial acknowledgement.
        let state = exit
            .wait_for(|state| *state != AppExit::Held)
            .await
            .map_err(|_| cancelled())?;
        if *state != AppExit::Released {
            return Err(cancelled());
        }
        Ok(response)
    }

    async fn write_stdin(
        &self,
        _: &TtrpcContext,
        request: WriteStreamRequest,
    ) -> ttrpc::Result<WriteStreamResponse> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, false)?;
        if request.container_id == self.sandbox_id()? && request.data.is_empty() {
            return Ok(WriteStreamResponse::new());
        }
        self.app_backend(&request.container_id)?
            .write_stdin(backend_context(BACKEND_TIME), &request)
            .await
    }

    async fn read_stdout(
        &self,
        _: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, false)?;
        if request.container_id == self.sandbox_id()? {
            return Ok(ReadStreamResponse::new());
        }
        self.app_backend(&request.container_id)?
            .read_stdout(backend_context(BACKEND_TIME), &request)
            .await
    }

    async fn read_stderr(
        &self,
        _: &TtrpcContext,
        request: ReadStreamRequest,
    ) -> ttrpc::Result<ReadStreamResponse> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, false)?;
        if request.container_id == self.sandbox_id()? {
            return Ok(ReadStreamResponse::new());
        }
        self.app_backend(&request.container_id)?
            .read_stderr(backend_context(BACKEND_TIME), &request)
            .await
    }

    async fn close_stdin(
        &self,
        _: &TtrpcContext,
        request: CloseStdinRequest,
    ) -> ttrpc::Result<Empty> {
        known(&request.special_fields)?;
        init_task(&request.container_id, &request.exec_id, false)?;
        if request.container_id == self.sandbox_id()? {
            return Ok(Empty::new());
        }
        self.app_backend(&request.container_id)?
            .close_stdin(backend_context(BACKEND_TIME), &request)
            .await
    }
}

#[cfg(test)]
#[path = "gcp_sandbox_gateway_tests.rs"]
mod tests;
