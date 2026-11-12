// SPDX-License-Identifier: Apache-2.0

//! Bind a receiver lease to one task, its OCI spec and process, and its held
//! filesystem view. The candidate digest commits to the original signed bytes.

use crate::{
    exec_observer::{KernelExecStop, TaskIdentity},
    rootfs_custody::{PreparedExecutionLease, PreparedRootfsLease},
};
use execution_proof_handoff::{
    execution::{
        ExecutionRecord, ExecutionTask, EXECUTION_APPLICATION_ROLE, EXECUTION_RECORD_CLAIM,
        EXECUTION_RECORD_PROFILE, EXECUTION_RECORD_PURPOSE, EXECUTION_RECORD_VERSION,
    },
    rootfs_custody::PreparationRecord,
};
use image_rs::preparation::launch_spec::BoundEffectiveSpec;
use nix::libc;
use oci_spec::runtime::{Process, Spec};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::{
    collections::BTreeSet,
    fmt,
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

#[cfg(feature = "protected-export")]
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalTaskError {
    SpecRejected,
    ViewRejected,
    TaskRejected,
    Operation,
    AlreadyCaptured,
    RecordRejected,
}
impl fmt::Display for FinalTaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "final task binding rejected: {self:?}")
    }
}
impl std::error::Error for FinalTaskError {}

/// Created before spawning: a failed or cancelled creation still retains this
/// owner until every child that received one of its FDs is killed and reaped.
pub(crate) struct FinalLaunchPlan {
    lease: Box<PreparedExecutionLease>,
    final_spec_sha384: String,
    seccomp_syscalls: Vec<String>,
    executable_identity: FileIdentity,
    #[cfg(feature = "protected-export")]
    export: Option<Arc<crate::protected_export::CapturedExport>>,
}
impl FinalLaunchPlan {
    pub(crate) fn new(
        lease: PreparedRootfsLease,
        actual_spec: &Spec,
        actual_process: &Process,
    ) -> Result<Self, FinalTaskError> {
        // Allocate before a child exists. Returning a failed bind then retains
        // ownership in a small error without allocating during spawn cleanup.
        let lease = Box::new(lease.into_execution());
        require_application_role(&lease.admission().binding().container_role)?;
        let (final_spec_sha384, seccomp_syscalls) =
            project_spec(lease.spec(), actual_spec, actual_process, lease.record())?;
        let root = file_identity(lease.view().root_fd())?;
        let cwd = file_identity(lease.view().cwd_fd())?;
        let executable_identity = file_identity(lease.view().executable_fd())?;
        if root.mount_id != lease.record().mount_id
            || cwd.mount_id != root.mount_id
            || executable_identity.mount_id != root.mount_id
            || root.mode & libc::S_IFMT != libc::S_IFDIR
            || cwd.mode & libc::S_IFMT != libc::S_IFDIR
            || executable_identity.mode & libc::S_IFMT != libc::S_IFREG
            || executable_identity.bytes == 0
        {
            return Err(FinalTaskError::ViewRejected);
        }
        Ok(Self {
            lease,
            final_spec_sha384,
            seccomp_syscalls,
            executable_identity,
            #[cfg(feature = "protected-export")]
            export: None,
        })
    }
    #[cfg(feature = "protected-export")]
    pub(crate) fn prepare_export(
        &mut self,
        exporter: &crate::protected_export::ProtectedExporter,
    ) -> Result<(), FinalTaskError> {
        self.export = Some(
            exporter
                .reserve_snapshot(&self.lease)
                .map_err(|_| FinalTaskError::Operation)?,
        );
        Ok(())
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub(crate) fn prepare_gcp_export(
        &self,
        exporter: &crate::gcp_protected_export::GcpProtectedExporter,
        cid: &str,
    ) -> Result<(), FinalTaskError> {
        exporter
            .reserve_snapshot(cid, &self.lease)
            .map_err(|_| FinalTaskError::Operation)
    }
    pub(crate) fn spec(&self) -> &BoundEffectiveSpec {
        self.lease.spec()
    }
    pub(crate) fn root_fd(&self) -> BorrowedFd<'_> {
        self.lease.view().root_fd()
    }
    pub(crate) fn cwd_fd(&self) -> BorrowedFd<'_> {
        self.lease.view().cwd_fd()
    }
    pub(crate) fn executable_fd(&self) -> BorrowedFd<'_> {
        self.lease.view().executable_fd()
    }
    pub(crate) fn seccomp_syscalls(&self) -> &[String] {
        &self.seccomp_syscalls
    }
    /// Only the trusted spawn/registration path calls this, while it owns the
    /// actual child and pidfd under the reaper gate. Failure returns ownership:
    /// the caller must kill/reap the child before dropping the returned plan.
    pub(crate) fn bind(
        self,
        identity: TaskIdentity,
        process_start_time_ticks: u64,
    ) -> Result<BoundFinalTask, BindFailure> {
        if !valid_task(&identity, process_start_time_ticks)
            || process_start_ticks(identity.pid) != Ok(process_start_time_ticks)
        {
            return Err(BindFailure { plan: self });
        }
        Ok(BoundFinalTask {
            plan: self,
            task: ExecutionTask {
                container_id: identity.container_id,
                generation: identity.generation,
                pid: identity.pid as u32,
                process_start_time_ticks,
            },
            captured: None,
        })
    }
}

pub(crate) struct BindFailure {
    plan: FinalLaunchPlan,
}
impl BindFailure {
    pub(crate) fn into_plan(self) -> FinalLaunchPlan {
        self.plan
    }
}
impl fmt::Debug for BindFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindFailure")
            .field("error", &FinalTaskError::TaskRejected)
            .finish_non_exhaustive()
    }
}

/// Retained by the actual task/observer owner until terminal reaping. The public
/// identity and record data cannot reconstruct this non-Clone capability.
pub(crate) struct BoundFinalTask {
    plan: FinalLaunchPlan,
    task: ExecutionTask,
    captured: Option<ExecutionRecord>,
}
impl BoundFinalTask {
    #[cfg(feature = "protected-export")]
    pub(crate) fn take_export(&mut self) -> Option<Arc<crate::protected_export::CapturedExport>> {
        self.plan.export.take()
    }
    /// The observer calls this only at its owned kernel EXEC stop, before any
    /// detach/resume. Failure must kill the child; callers cannot supply an
    /// executable path, digest, or replacement lease to repair a failed capture.
    pub(crate) fn execution_record(
        &mut self,
        witness: KernelExecStop,
        event_id: [u8; 32],
    ) -> Result<&ExecutionRecord, FinalTaskError> {
        if self.captured.is_some() {
            return Err(FinalTaskError::AlreadyCaptured);
        }
        if !witness.matches(&TaskIdentity {
            container_id: self.task.container_id.clone(),
            generation: self.task.generation,
            pid: self.task.pid as i32,
        }) {
            return Err(FinalTaskError::TaskRejected);
        }
        if process_start_ticks(self.task.pid as i32)? != self.task.process_start_time_ticks {
            return Err(FinalTaskError::TaskRejected);
        }
        // /proc's kernel-owned executable link is inspected at the stopped
        // task. It is intentionally not an application-supplied pathname.
        let actual = File::open(format!("/proc/{}/exe", self.task.pid))
            .map_err(|_| FinalTaskError::Operation)?;
        if file_identity(actual.as_fd())? != self.plan.executable_identity {
            return Err(FinalTaskError::ViewRejected);
        }
        let p = self.plan.lease.record();
        let record = ExecutionRecord {
            version: EXECUTION_RECORD_VERSION,
            purpose: EXECUTION_RECORD_PURPOSE.into(),
            profile: EXECUTION_RECORD_PROFILE.into(),
            claim: EXECUTION_RECORD_CLAIM.into(),
            event_id: hex(&event_id),
            grant_sha384: self.plan.lease.admission().grant_digest().into(),
            admission_context_sha384: self.plan.lease.admission().context_digest().into(),
            preparation_record_sha384: hex(&p
                .sha384()
                .map_err(|_| FinalTaskError::RecordRejected)?),
            startup_binding_sha384: p.startup_binding_sha384.clone(),
            candidate_spec_sha384: p.candidate_spec_sha384.clone(),
            final_spec_sha384: self.plan.final_spec_sha384.clone(),
            image_sha384: p.image_sha384.clone(),
            executable_sha384: p.executable_sha384.clone(),
            mount_id: p.mount_id,
            task: self.task.clone(),
        };
        record
            .validate()
            .map_err(|_| FinalTaskError::RecordRejected)?;
        self.captured = Some(record);
        self.captured.as_ref().ok_or(FinalTaskError::RecordRejected)
    }
}

fn valid_task(identity: &TaskIdentity, start: u64) -> bool {
    !identity.container_id.is_empty()
        && identity.container_id.len() <= 128
        && identity
            .container_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        && identity.pid > 0
        && identity.generation > 0
        && start > 0
}

fn require_application_role(role: &str) -> Result<(), FinalTaskError> {
    if role == EXECUTION_APPLICATION_ROLE {
        Ok(())
    } else {
        Err(FinalTaskError::TaskRejected)
    }
}

pub(crate) fn process_start_ticks(pid: i32) -> Result<u64, FinalTaskError> {
    if pid <= 0 {
        return Err(FinalTaskError::TaskRejected);
    }
    let file = File::open(format!("/proc/{pid}/stat")).map_err(|_| FinalTaskError::Operation)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| FinalTaskError::Operation)?;
    if bytes.len() > 4096 {
        return Err(FinalTaskError::TaskRejected);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| FinalTaskError::TaskRejected)?;
    parse_start_ticks(text, pid)
}

fn parse_start_ticks(text: &str, pid: i32) -> Result<u64, FinalTaskError> {
    let (prefix, _) = text.split_once('(').ok_or(FinalTaskError::TaskRejected)?;
    if prefix.trim().parse::<i32>() != Ok(pid) {
        return Err(FinalTaskError::TaskRejected);
    }
    let (_, fields) = text.rsplit_once(')').ok_or(FinalTaskError::TaskRejected)?;
    fields
        .split_whitespace()
        .nth(19)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(FinalTaskError::TaskRejected)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    mount_id: u64,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    mode: u32,
    bytes: u64,
}
fn file_identity(fd: BorrowedFd<'_>) -> Result<FileIdentity, FinalTaskError> {
    const EMPTY_PATH: &std::ffi::CStr = match std::ffi::CStr::from_bytes_with_nul(b"\0") {
        Ok(path) => path,
        Err(_) => panic!("invalid empty C string"),
    };
    let mut stat = unsafe { std::mem::zeroed::<libc::statx>() };
    let mask = libc::STATX_MNT_ID
        | libc::STATX_INO
        | libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_SIZE;
    // SAFETY: an empty NUL-terminated path with AT_EMPTY_PATH inspects only the
    // borrowed live FD; stat is a fully-sized initialized writable output.
    if unsafe {
        libc::statx(
            fd.as_raw_fd(),
            EMPTY_PATH.as_ptr(),
            libc::AT_EMPTY_PATH,
            mask,
            &mut stat,
        )
    } != 0
        || stat.stx_mask & mask != mask
    {
        return Err(FinalTaskError::Operation);
    }
    Ok(FileIdentity {
        mount_id: stat.stx_mnt_id,
        inode: stat.stx_ino,
        device_major: stat.stx_dev_major,
        device_minor: stat.stx_dev_minor,
        mode: u32::from(stat.stx_mode),
        bytes: stat.stx_size,
    })
}

fn project_spec(
    candidate: &BoundEffectiveSpec,
    actual_spec: &Spec,
    actual_process: &Process,
    preparation: &PreparationRecord,
) -> Result<(String, Vec<String>), FinalTaskError> {
    let maximum = candidate
        .raw_bytes()
        .len()
        .checked_mul(2)
        .filter(|n| *n <= isize::MAX as usize)
        .ok_or(FinalTaskError::SpecRejected)?;
    let expected: Value =
        serde_json::from_slice(candidate.raw_bytes()).map_err(|_| FinalTaskError::SpecRejected)?;
    let mut actual = bounded_value(actual_spec, maximum)?;
    let process = bounded_value(actual_process, maximum)?;
    if actual.get("process") != Some(&process) {
        return Err(FinalTaskError::SpecRejected);
    }
    let mut expected = expected;
    normalize(&mut expected)?;
    let syscalls = normalize(&mut actual)?;
    if actual != expected || preparation.candidate_spec_sha384 != candidate.sha384() {
        return Err(FinalTaskError::SpecRejected);
    }
    let mut projection = json!({
        "version":1,
        "purpose":"qlad.execution-proof.final-spec.v1",
        "profile":"static-elf-owned-view.v1",
        "candidate_spec_sha384":candidate.sha384(),
        "image_sha384":preparation.image_sha384,
        "executable_sha384":preparation.executable_sha384,
        "mount_id":preparation.mount_id,
        "spec":actual,
    });
    sort_objects(&mut projection);
    let encoded = serde_json::to_vec(&projection).map_err(|_| FinalTaskError::SpecRejected)?;
    Ok((hex(&Sha384::digest(&encoded)), syscalls))
}

fn normalize(spec: &mut Value) -> Result<Vec<String>, FinalTaskError> {
    let namespaces = spec
        .pointer_mut("/linux/namespaces")
        .and_then(Value::as_array_mut)
        .ok_or(FinalTaskError::SpecRejected)?;
    namespaces.sort_by(|a, b| {
        a.get("type")
            .and_then(Value::as_str)
            .cmp(&b.get("type").and_then(Value::as_str))
    });
    let rules = spec
        .pointer_mut("/linux/seccomp/syscalls")
        .and_then(Value::as_array_mut)
        .ok_or(FinalTaskError::SpecRejected)?;
    let mut names = BTreeSet::new();
    for rule in rules.iter() {
        let object = rule.as_object().ok_or(FinalTaskError::SpecRejected)?;
        if object.len() != 2
            || object.get("action").and_then(Value::as_str) != Some("SCMP_ACT_ALLOW")
        {
            return Err(FinalTaskError::SpecRejected);
        }
        let list = object
            .get("names")
            .and_then(Value::as_array)
            .filter(|list| !list.is_empty())
            .ok_or(FinalTaskError::SpecRejected)?;
        for name in list {
            let name = name.as_str().ok_or(FinalTaskError::SpecRejected)?;
            if !names.insert(name.to_owned()) {
                return Err(FinalTaskError::SpecRejected);
            }
        }
    }
    let syscalls: Vec<String> = names.into_iter().collect();
    *rules = syscalls
        .iter()
        .map(|name| json!({"names":[name],"action":"SCMP_ACT_ALLOW"}))
        .collect();
    sort_objects(spec);
    Ok(syscalls)
}

fn sort_objects(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for child in object.values_mut() {
                sort_objects(child);
            }
            object.sort_keys();
        }
        Value::Array(array) => {
            for child in array {
                sort_objects(child);
            }
        }
        _ => (),
    }
}

struct BoundedBytes {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let size = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("final spec bound exceeded"))?;
        self.bytes
            .try_reserve(size - self.bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_value(value: &impl Serialize, maximum: usize) -> Result<Value, FinalTaskError> {
    let mut writer = BoundedBytes {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| FinalTaskError::SpecRejected)?;
    serde_json::from_slice(&writer.bytes).map_err(|_| FinalTaskError::SpecRejected)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "final_task_tests.rs"]
mod tests;
