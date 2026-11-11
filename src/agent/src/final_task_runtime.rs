// SPDX-License-Identifier: Apache-2.0

//! Bounded trusted lease staging and the proof-only task lifecycle.
//! Host IDs select a staged lease but cannot create or restore one.

use crate::{
    exec_observer::{Attempt, CapturedRecord, Observer, Snapshot, TaskIdentity},
    final_task::{process_start_ticks, FinalLaunchPlan},
    rootfs_custody::PreparedRootfsLease,
};
use anyhow::{anyhow, bail, ensure, Result};
use oci_spec::runtime as oci;
use rustjail::final_task::{ExecInputs, PreparedExec, ReleaseGate};
use std::{
    collections::HashMap,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
    time::Duration,
};

const IO_BYTES: usize = 32768;
const START_TIME: Duration = Duration::from_secs(5);

#[cfg(feature = "gcp-proof-startup")]
#[path = "gcp_task_spec.rs"]
mod gcp_task_spec;
#[cfg(feature = "gcp-proof-startup")]
pub(crate) use gcp_task_spec::verified_protocol_spec;

struct TaskIo {
    stdin: Option<OwnedFd>,
    stdout: OwnedFd,
    stderr: OwnedFd,
}
struct Running {
    attempt: Arc<Attempt>,
    release: Option<ReleaseGate>,
    io: TaskIo,
    starting: bool,
}
enum State {
    Staged(Box<PreparedRootfsLease>),
    Active(Running),
    Consumed { record: Option<Arc<CapturedRecord>> },
}
struct Registry {
    tasks: HashMap<String, State>,
    generation: u64,
}
struct Inner {
    state: Mutex<Registry>,
    capacity: usize,
    #[cfg(feature = "protected-export")]
    exporter: Option<crate::protected_export::ProtectedExporter>,
    #[cfg(feature = "protected-export-gcp-tdx")]
    gcp_exporter: Option<crate::gcp_protected_export::GcpProtectedExporter>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in state.tasks.values() {
            if let State::Active(active) = task {
                active.attempt.kill();
            }
        }
    }
}

#[derive(Clone)]
pub struct FinalTaskRuntime {
    inner: Arc<Inner>,
}
impl std::fmt::Debug for FinalTaskRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalTaskRuntime").finish_non_exhaustive()
    }
}

impl FinalTaskRuntime {
    pub fn new(capacity: usize) -> Result<Self> {
        ensure!(
            (1..=4).contains(&capacity),
            "final task capacity must be 1..4"
        );
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(Registry {
                    tasks: HashMap::new(),
                    generation: 0,
                }),
                capacity,
                #[cfg(feature = "protected-export")]
                exporter: None,
                #[cfg(feature = "protected-export-gcp-tdx")]
                gcp_exporter: None,
            }),
        })
    }
    #[cfg(feature = "protected-export")]
    pub fn with_protected_export(
        capacity: usize,
        config: crate::protected_export::ExportConfig,
    ) -> Result<(Self, crate::protected_export::ExportOwner)> {
        let mut runtime = Self::new(capacity)?;
        let (exporter, owner) = crate::protected_export::ProtectedExporter::new(config)?;
        Arc::get_mut(&mut runtime.inner)
            .ok_or_else(|| anyhow!("new final task runtime unexpectedly shared"))?
            .exporter = Some(exporter);
        Ok((runtime, owner))
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn with_gcp_protected_export(
        capacity: usize,
        config: crate::gcp_protected_export::GcpExportConfig,
    ) -> Result<(Self, crate::gcp_protected_export::GcpExportOwner)> {
        let mut runtime = Self::new(capacity)?;
        let (exporter, owner) = crate::gcp_protected_export::GcpProtectedExporter::new(config)?;
        Arc::get_mut(&mut runtime.inner)
            .ok_or_else(|| anyhow!("new runtime unexpectedly shared"))?
            .gcp_exporter = Some(exporter);
        Ok((runtime, owner))
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    /// Local constructor check only; it does not authenticate the boot profile
    /// or qualify producer isolation.
    pub fn validate_gcp_proof_service(&self) -> Result<()> {
        ensure!(
            self.inner.gcp_exporter.is_some() && self.inner.exporter.is_none(),
            "GCP proof service requires its dedicated exporter"
        );
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        ensure!(
            registry.tasks.len() == 1
                && registry
                    .tasks
                    .values()
                    .all(|state| matches!(state, State::Staged(_))),
            "GCP proof service requires one finalized staged custody lease"
        );
        Ok(())
    }
    /// Only a trusted custody owner can supply the non-restorable lease.
    /// Slots/tombstones are retained for this runtime's lifetime.
    pub fn stage(&self, cid: &str, lease: PreparedRootfsLease) -> Result<()> {
        ensure!(
            !cid.is_empty()
                && cid.len() <= 128
                && cid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
            "invalid final task ID"
        );
        let mut registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        ensure!(
            registry.tasks.len() < self.inner.capacity && !registry.tasks.contains_key(cid),
            "final task capacity or replay history exhausted"
        );
        registry
            .tasks
            .insert(cid.to_owned(), State::Staged(Box::new(lease)));
        Ok(())
    }
    pub fn contains(&self, cid: &str) -> bool {
        self.inner
            .state
            .lock()
            .is_ok_and(|state| state.tasks.contains_key(cid))
    }

    /// The GCP wire is an exact public representation of the already staged
    /// signed candidate. Never convert untrusted protocol enums/defaults into
    /// executable OCI state: omitted protocol fields come from the signed spec.
    #[cfg(feature = "gcp-proof-startup")]
    pub(crate) fn create_gcp_protocol(
        &self,
        cid: &str,
        submitted: &protocols::oci::Spec,
        observer: &Observer,
    ) -> Result<TaskIdentity> {
        let spec = {
            let registry = self
                .inner
                .state
                .lock()
                .map_err(|_| anyhow!("final task registry poisoned"))?;
            let Some(State::Staged(lease)) = registry.tasks.get(cid) else {
                bail!("no unconsumed trusted lease staged for GCP task");
            };
            verified_protocol_spec(lease.candidate_spec(), submitted)?
        };
        let process = spec
            .process()
            .as_ref()
            .ok_or_else(|| anyhow!("trusted GCP process missing"))?;
        // No await or restored/replaced lease exists here. A concurrent create
        // or remove can only consume this CID; create then rejects its tombstone.
        self.create(cid, &spec, process, observer)
    }

    /// No await after clone: registration and the owned lease are installed
    /// while the sole reaper's gate is still held. Errors after clone retain an
    /// entry until the actual kernel terminal status triggers cleanup.
    pub fn create(
        &self,
        cid: &str,
        spec: &oci::Spec,
        process: &oci::Process,
        observer: &Observer,
    ) -> Result<TaskIdentity> {
        let mut registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        let entry = registry
            .tasks
            .get_mut(cid)
            .ok_or_else(|| anyhow!("no trusted lease staged for final task"))?;
        ensure!(
            matches!(entry, State::Staged(_)),
            "final task lease already consumed"
        );
        let State::Staged(lease) = std::mem::replace(entry, State::Consumed { record: None })
        else {
            unreachable!("staged state checked under registry lock");
        };
        let plan = FinalLaunchPlan::new(*lease, spec, process)?;
        #[cfg(feature = "protected-export-gcp-tdx")]
        if let Some(exporter) = &self.inner.gcp_exporter {
            plan.prepare_gcp_export(exporter, cid)?;
        }

        #[cfg(feature = "protected-export")]
        let plan = {
            let mut plan = plan;
            if let Some(exporter) = &self.inner.exporter {
                plan.prepare_export(exporter)?;
            }
            plan
        };
        registry.generation = registry
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("task generation exhausted"))?;
        let generation = registry.generation;
        let (input, input_writer) = pipe()?;
        let (output_reader, output) = pipe()?;
        let (error_reader, error) = pipe()?;
        let prepared = PreparedExec::new(ExecInputs {
            root: plan.root_fd(),
            cwd: plan.cwd_fd(),
            executable: plan.executable_fd(),
            args: plan.spec().args(),
            env: plan.spec().env(),
            uid: plan.spec().uid(),
            gid: plan.spec().gid(),
            syscalls: plan.seccomp_syscalls(),
            stdio: [input.as_fd(), output.as_fd(), error.as_fd()],
        })?;
        let gate = observer.wait_guard()?;
        observer.check_final_slot(cid, generation)?;
        let child = prepared.spawn()?;
        let (pid, pidfd, release) = child.into_parts();
        let identity = TaskIdentity {
            container_id: cid.to_owned(),
            generation,
            pid,
        };
        let ticks = process_start_ticks(pid).unwrap_or(0);
        let attempt = Arc::new(observer.arm_final(identity.clone(), plan, ticks, pidfd));
        let failed = attempt.snapshot().failure.is_some();
        registry.tasks.insert(
            cid.to_owned(),
            State::Active(Running {
                attempt,
                release: Some(release),
                io: TaskIo {
                    stdin: Some(input_writer),
                    stdout: output_reader,
                    stderr: error_reader,
                },
                starting: false,
            }),
        );
        drop(gate);
        ensure!(!failed, "final task registration failed closed");
        Ok(identity)
    }

    pub async fn start(&self, cid: &str, _observer: &Observer) -> Result<()> {
        let (attempt, mut release) = {
            let mut registry = self
                .inner
                .state
                .lock()
                .map_err(|_| anyhow!("final task registry poisoned"))?;
            let Some(State::Active(task)) = registry.tasks.get_mut(cid) else {
                bail!("final task is not created");
            };
            ensure!(!task.starting, "final task start is one-use");
            task.starting = true;
            (
                task.attempt.clone(),
                task.release
                    .take()
                    .ok_or_else(|| anyhow!("final task already released"))?,
            )
        };
        let cancel = scopeguard::guard(attempt.clone(), |attempt| attempt.cancel());
        attempt.wait_armed(START_TIME).await?;
        release.release()?;
        attempt.wait_captured(START_TIME).await?;
        scopeguard::ScopeGuard::into_inner(cancel);
        Ok(())
    }
    fn attempt(&self, cid: &str) -> Result<Arc<Attempt>> {
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        let Some(State::Active(task)) = registry.tasks.get(cid) else {
            bail!("final task not active");
        };
        Ok(task.attempt.clone())
    }
    pub async fn wait(&self, cid: &str) -> Result<i32> {
        self.attempt(cid)?.wait_cleaned().await
    }
    pub async fn remove(&self, cid: &str) -> Result<()> {
        let attempt = {
            let mut registry = self
                .inner
                .state
                .lock()
                .map_err(|_| anyhow!("final task registry poisoned"))?;
            let state = registry
                .tasks
                .get_mut(cid)
                .ok_or_else(|| anyhow!("unknown final task"))?;
            match state {
                State::Staged(_) => {
                    let staged = std::mem::replace(state, State::Consumed { record: None });
                    drop(registry);
                    drop(staged);
                    return Ok(());
                }
                State::Consumed { .. } => return Ok(()),
                State::Active(task) => task.attempt.clone(),
            }
        };
        attempt.kill();
        attempt.wait_cleaned().await?;
        let record = attempt.captured_record()?;
        let mut registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        registry
            .tasks
            .insert(cid.to_owned(), State::Consumed { record });
        Ok(())
    }
    pub fn signal(&self, cid: &str, signal: i32) -> Result<()> {
        ensure!(signal == libc::SIGKILL, "proof task supports SIGKILL only");
        self.attempt(cid)?.kill();
        Ok(())
    }
    pub fn snapshot(&self, cid: &str) -> Result<Snapshot> {
        Ok(self.attempt(cid)?.snapshot())
    }
    pub fn record(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .captured_record(cid)?
            .map(|record| record.canonical_bytes().to_vec()))
    }
    fn captured_record(&self, cid: &str) -> Result<Option<Arc<CapturedRecord>>> {
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        match registry
            .tasks
            .get(cid)
            .ok_or_else(|| anyhow!("unknown final task"))?
        {
            State::Active(task) => task.attempt.captured_record(),
            State::Consumed { record } => Ok(record.clone()),
            State::Staged(_) => Ok(None),
        }
    }
    #[cfg(feature = "protected-export")]
    pub fn request_export(
        &self,
        cid: &str,
        challenge: &execution_proof_handoff::execution_quote::QuoteChallenge,
    ) -> Result<crate::protected_export::ExportStatus> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        let exporter = self
            .inner
            .exporter
            .as_ref()
            .ok_or_else(|| anyhow!("protected export unavailable"))?;
        Ok(exporter.request(record, challenge)?)
    }
    #[cfg(feature = "protected-export")]
    pub fn export_status(&self, cid: &str) -> Result<crate::protected_export::ExportStatus> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        let exporter = self
            .inner
            .exporter
            .as_ref()
            .ok_or_else(|| anyhow!("protected export unavailable"))?;
        Ok(exporter.status(&record)?)
    }
    #[cfg(feature = "protected-export")]
    pub fn export_attempts(&self, cid: &str) -> Result<u8> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        let exporter = self
            .inner
            .exporter
            .as_ref()
            .ok_or_else(|| anyhow!("protected export unavailable"))?;
        Ok(exporter.attempts(&record)?)
    }
    #[cfg(feature = "protected-export")]
    pub fn exported(
        &self,
        cid: &str,
    ) -> Result<Option<Arc<crate::protected_export::ExportedRecord>>> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        let exporter = self
            .inner
            .exporter
            .as_ref()
            .ok_or_else(|| anyhow!("protected export unavailable"))?;
        Ok(exporter.output(&record)?)
    }

    #[cfg(feature = "gcp-proof-startup")]
    pub(crate) fn gcp_proof_unavailable(&self, cid: &str) -> Result<bool> {
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        match registry
            .tasks
            .get(cid)
            .ok_or_else(|| anyhow!("unknown final task"))?
        {
            State::Consumed { record } => Ok(record.is_none()),
            State::Active(task) => {
                let state = task.attempt.snapshot();
                Ok(!state.captured && (state.terminal || state.failure.is_some()))
            }
            State::Staged(_) => Ok(false),
        }
    }

    #[cfg(feature = "protected-export-gcp-tdx")]
    fn gcp_exporter(&self) -> Result<&crate::gcp_protected_export::GcpProtectedExporter> {
        self.inner
            .gcp_exporter
            .as_ref()
            .ok_or_else(|| anyhow!("GCP protected export unavailable"))
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn gcp_export_challenge(
        &self,
        cid: &str,
        nonce: [u8; 32],
    ) -> Result<execution_proof_contract::gcp_execution_quote::GcpQuoteChallenge> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        Ok(self.gcp_exporter()?.challenge(&record, nonce)?)
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn request_gcp_export(
        &self,
        cid: &str,
        challenge: &execution_proof_contract::gcp_execution_quote::GcpQuoteChallenge,
    ) -> Result<crate::protected_export::ExportStatus> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        Ok(self.gcp_exporter()?.request(record, challenge)?)
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn gcp_export_status(&self, cid: &str) -> Result<crate::protected_export::ExportStatus> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        Ok(self.gcp_exporter()?.status(&record)?)
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn gcp_export_attempts(&self, cid: &str) -> Result<u8> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        Ok(self.gcp_exporter()?.attempts(&record)?)
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn gcp_exported(
        &self,
        cid: &str,
    ) -> Result<Option<Arc<crate::gcp_protected_export::GcpExportedRecord>>> {
        let record = self
            .captured_record(cid)?
            .ok_or_else(|| anyhow!("execution record not captured"))?;
        Ok(self.gcp_exporter()?.output(&record)?)
    }
    pub fn read_stdout(&self, cid: &str, maximum: usize) -> Result<Vec<u8>> {
        self.read_output(cid, maximum, false)
    }
    pub fn read_stderr(&self, cid: &str, maximum: usize) -> Result<Vec<u8>> {
        self.read_output(cid, maximum, true)
    }
    fn read_output(&self, cid: &str, maximum: usize, error: bool) -> Result<Vec<u8>> {
        ensure!(maximum > 0 && maximum <= IO_BYTES, "final task read budget");
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        let Some(State::Active(task)) = registry.tasks.get(cid) else {
            bail!("final task not active");
        };
        let fd = if error {
            &task.io.stderr
        } else {
            &task.io.stdout
        };
        let mut bytes = vec![0; maximum];
        let count = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)) {
                return Ok(Vec::new());
            }
            return Err(error.into());
        }
        bytes.truncate(count as usize);
        Ok(bytes)
    }
    pub fn write_stdin(&self, cid: &str, data: &[u8]) -> Result<usize> {
        ensure!(data.len() <= IO_BYTES, "final task input budget");
        let registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        let Some(State::Active(task)) = registry.tasks.get(cid) else {
            bail!("final task not active");
        };
        let fd = task
            .io
            .stdin
            .as_ref()
            .ok_or_else(|| anyhow!("final task stdin closed"))?;
        let count = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(count as usize)
    }
    pub fn close_stdin(&self, cid: &str) -> Result<()> {
        let mut registry = self
            .inner
            .state
            .lock()
            .map_err(|_| anyhow!("final task registry poisoned"))?;
        let Some(State::Active(task)) = registry.tasks.get_mut(cid) else {
            bail!("final task not active");
        };
        task.io.stdin.take();
        Ok(())
    }
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    ensure!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == 0,
        "create proof stdio pipe: {}",
        std::io::Error::last_os_error()
    );
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    ensure!(
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, IO_BYTES) } > 0,
        "bound proof stdio pipe size"
    );
    Ok((read, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absent_trusted_lease_and_invalid_capacity_never_spawn() {
        assert!(FinalTaskRuntime::new(0).is_err());
        assert!(FinalTaskRuntime::new(5).is_err());
        let runtime = FinalTaskRuntime::new(4).unwrap();
        assert!(!runtime.contains("missing"));
        assert!(runtime.record("missing").is_err());
        assert!(runtime.read_stdout("missing", 1).is_err());
        assert!(runtime.signal("missing", libc::SIGKILL).is_err());
    }
}
