// SPDX-License-Identifier: Apache-2.0
//! Private CapturedRecord-bound GCP collection. Public R/challenge/config bytes
//! cannot mint a capture or establish boot/producer qualification.
use crate::{
    exec_observer::CapturedRecord,
    protected_export::{ExportError, ExportStatus},
    rootfs_custody::PreparedExecutionLease,
};
use base64::{engine::general_purpose::STANDARD, write::EncoderWriter};
use execution_proof_contract::{
    execution::ExecutionRecord,
    gcp_boot_binding::GcpBootBindingV1,
    gcp_execution_envelope::GcpExecutionEnvelope,
    gcp_execution_quote::{report_data, GcpQuoteChallenge},
};
use execution_proof_handoff::rootfs_custody::MAX_PROVENANCE_BYTES;
use std::{
    collections::HashMap,
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
const RECORDS: usize = 4;
const SLOT_BYTES: usize = 8 << 20;
const QUEUE_BYTES: usize = 64 << 20;
const MAX_EXPORT_BYTES: usize = 12 << 20;
const QUOTE_TIME: Duration = Duration::from_secs(30);
const PENDING_TIME: Duration = Duration::from_secs(300);
const BACKOFF: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(5)];
/// Trusted factory inputs, not an attested boot capability. The factory must
/// authenticate B and the startup binding before enabling this runtime.
#[derive(Clone)]
pub struct GcpExportConfig {
    pub audience: String,
    pub boot_binding: GcpBootBindingV1,
    pub trust_snapshot_sha384: [u8; 48],
    pub expected_startup_binding_sha384: [u8; 48],
}
struct PublicSnapshot {
    admission: Vec<u8>,
    preparation: Vec<u8>,
    provenance: Vec<u8>,
    announcement: Vec<u8>,
    validated_receipt: Vec<u8>,
}
impl PublicSnapshot {
    fn retained_capacity(&self) -> usize {
        self.admission.capacity()
            + self.preparation.capacity()
            + self.provenance.capacity()
            + self.announcement.capacity()
            + self.validated_receipt.capacity()
    }
    fn validate(&self) -> Result<(), ExportError> {
        if self.admission.len() > MAX_PROVENANCE_BYTES
            || self.preparation.len() > 16 << 10
            || self.provenance.len() > MAX_PROVENANCE_BYTES
            || self.announcement.len() > 1024
            || self.validated_receipt.len() > 1024
            || self.retained_capacity() + 4096 > SLOT_BYTES
        {
            return Err(ExportError::TooLarge);
        }
        Ok(())
    }
}
pub struct GcpExportedRecord {
    record: Arc<CapturedRecord>,
    snapshot: Arc<PublicSnapshot>,
    envelope: Vec<u8>,
}
impl GcpExportedRecord {
    pub fn record(&self) -> &[u8] {
        self.record.canonical_bytes()
    }
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    /// Bounded secret-free transport over the owner's actual pre-exec custody
    /// snapshot and observer-created R. The returned Vec belongs to the caller;
    /// it is not another retained per-slot copy or an authorization capability.
    pub fn encode_public(&self) -> Result<Vec<u8>, ExportError> {
        let mut output = BoundedWriter(Vec::new());
        let result = (|| -> io::Result<()> {
            output.write_all(
                br#"{"version":2,"purpose":"qlad.execution-proof.protected-export.v2""#,
            )?;
            for (name, bytes) in [
                ("record_b64", self.record()),
                ("admission_b64", self.snapshot.admission.as_slice()),
                ("preparation_b64", self.snapshot.preparation.as_slice()),
                ("provenance_b64", self.snapshot.provenance.as_slice()),
                ("announcement_b64", self.snapshot.announcement.as_slice()),
                (
                    "validated_receipt_b64",
                    self.snapshot.validated_receipt.as_slice(),
                ),
                ("quote_b64", self.envelope()),
            ] {
                output.write_all(b",\"")?;
                output.write_all(name.as_bytes())?;
                output.write_all(b"\":\"")?;
                {
                    let mut encoder = EncoderWriter::new(&mut output, &STANDARD);
                    encoder.write_all(bytes)?;
                    encoder.finish()?;
                }
                output.write_all(b"\"")?;
            }
            output.write_all(b"}")
        })();
        result.map_err(|_| ExportError::TooLarge)?;
        output.0.shrink_to_fit();
        Ok(output.0)
    }
}
struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_EXPORT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GCP export byte limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[derive(Default)]
struct State {
    record: Option<Arc<CapturedRecord>>,
    challenge: Option<GcpQuoteChallenge>,
    queued: bool,
    in_flight: Option<Instant>,
    attempts: u8,
    error: Option<ExportError>,
    exhausted: bool,
    output: Option<Arc<GcpExportedRecord>>,
}
struct Slot {
    snapshot: Arc<PublicSnapshot>,
    state: Mutex<State>,
    changed: Condvar,
}
struct Control {
    stopped: AtomicBool,
    failed: AtomicBool,
    wait: Mutex<()>,
    wake: Condvar,
}
struct Inner {
    config: GcpExportConfig,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    requests: SyncSender<Arc<Slot>>,
    control: Arc<Control>,
}
#[derive(Clone)]
pub(crate) struct GcpProtectedExporter {
    inner: Arc<Inner>,
}
/// Owns and joins the sole blocking worker. A kernel operation cannot be
/// preempted by this watchdog; shutdown may wait for it, never detach it.
pub struct GcpExportOwner {
    worker: Option<JoinHandle<()>>,
    control: Arc<Control>,
    requests: Option<SyncSender<Arc<Slot>>>,
}
impl GcpExportOwner {
    pub fn shutdown(mut self) -> Result<(), ExportError> {
        self.stop_and_join()
    }
    fn stop_and_join(&mut self) -> Result<(), ExportError> {
        {
            let _publish = self
                .control
                .wait
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.control.stopped.store(true, Ordering::Release);
            self.control.wake.notify_all();
        }
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ExportError::WorkerFailed)?;
        }
        if self.control.failed.load(Ordering::Acquire) {
            return Err(ExportError::WorkerFailed);
        }
        Ok(())
    }
}
impl Drop for GcpExportOwner {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}
trait Backend: Send {
    fn collect(
        &mut self,
        report: [u8; 64],
    ) -> Result<attester::gcp_execution_quote::GcpRawExecutionEvidence, ExportError>;
}
struct FixedBackend;
impl Backend for FixedBackend {
    fn collect(
        &mut self,
        report: [u8; 64],
    ) -> Result<attester::gcp_execution_quote::GcpRawExecutionEvidence, ExportError> {
        use attester::gcp_execution_quote::{
            collect_gcp_tdx_execution_evidence, GcpExecutionQuoteError as E,
        };
        collect_gcp_tdx_execution_evidence(report).map_err(|e| match e {
            E::Unavailable => ExportError::QuoteFailed,
            E::Bounds => ExportError::TooLarge,
            E::InvalidBinding => ExportError::InvalidChallenge,
            E::InvalidEvidence => ExportError::InvalidConfiguration,
        })
    }
}
impl GcpProtectedExporter {
    pub(crate) fn new(config: GcpExportConfig) -> Result<(Self, GcpExportOwner), ExportError> {
        Self::start(config, Box::new(FixedBackend), BACKOFF)
    }
    fn start(
        config: GcpExportConfig,
        backend: Box<dyn Backend>,
        backoff: [Duration; 2],
    ) -> Result<(Self, GcpExportOwner), ExportError> {
        config
            .boot_binding
            .validate()
            .map_err(|_| ExportError::InvalidConfiguration)?;
        if config.audience.is_empty()
            || config.audience.len() > 128
            || !config
                .audience
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || config.trust_snapshot_sha384 == [0; 48]
            || config.expected_startup_binding_sha384 == [0; 48]
        {
            return Err(ExportError::InvalidConfiguration);
        }
        let control = Arc::new(Control {
            stopped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wait: Mutex::new(()),
            wake: Condvar::new(),
        });
        let (send, recv) = mpsc::sync_channel(RECORDS);
        let inner = Arc::new(Inner {
            config,
            slots: Mutex::new(HashMap::new()),
            requests: send.clone(),
            control: control.clone(),
        });
        let worker_inner = inner.clone();
        let worker = thread::Builder::new()
            .name("gcp-protected-r-export".into())
            .spawn(move || worker_loop(recv, worker_inner, backend, backoff))
            .map_err(|_| ExportError::Unavailable)?;
        Ok((
            Self { inner },
            GcpExportOwner {
                worker: Some(worker),
                control,
                requests: Some(send),
            },
        ))
    }
    /// Reserve before exec; tombstones/outputs are retained until runtime ends.
    pub(crate) fn reserve_snapshot(
        &self,
        cid: &str,
        lease: &PreparedExecutionLease,
    ) -> Result<(), ExportError> {
        let evidence = lease.public_evidence();
        self.reserve_owned(
            cid,
            PublicSnapshot {
                admission: evidence.admission.clone(),
                preparation: lease
                    .record()
                    .encode(MAX_PROVENANCE_BYTES)
                    .map_err(|_| ExportError::TooLarge)?,
                provenance: lease
                    .provenance()
                    .encode(MAX_PROVENANCE_BYTES)
                    .map_err(|_| ExportError::TooLarge)?,
                announcement: evidence.announcement.clone(),
                validated_receipt: evidence.validated_receipt.clone(),
            },
        )
    }
    #[cfg(test)]
    fn reserve(&self, cid: &str) -> Result<(), ExportError> {
        self.reserve_owned(
            cid,
            PublicSnapshot {
                admission: vec![],
                preparation: vec![],
                provenance: vec![],
                announcement: vec![],
                validated_receipt: vec![],
            },
        )
    }
    fn reserve_owned(&self, cid: &str, snapshot: PublicSnapshot) -> Result<(), ExportError> {
        if cid.is_empty()
            || cid.len() > execution_proof_contract::MAX_ID_BYTES
            || !cid
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(ExportError::InvalidConfiguration);
        }
        snapshot.validate()?;
        if self.inner.control.stopped.load(Ordering::Acquire) {
            return Err(ExportError::Stopped);
        }
        let mut slots = self.inner.slots.lock().map_err(|_| ExportError::Poisoned)?;
        if slots.contains_key(cid) {
            return Err(ExportError::Conflict);
        }
        if slots.len() >= RECORDS || (slots.len() + 1) * SLOT_BYTES > QUEUE_BYTES {
            return Err(ExportError::QueueFull);
        }
        slots.insert(
            cid.to_owned(),
            Arc::new(Slot {
                snapshot: Arc::new(snapshot),
                state: Mutex::new(State::default()),
                changed: Condvar::new(),
            }),
        );
        Ok(())
    }
    fn checked(
        &self,
        record: &CapturedRecord,
    ) -> Result<(ExecutionRecord, Arc<Slot>), ExportError> {
        if record.canonical_bytes().len() > 16 << 10 || record.retained_capacity() > 16 << 10 {
            return Err(ExportError::TooLarge);
        }
        let r = ExecutionRecord::decode(record.canonical_bytes())
            .map_err(|_| ExportError::MissingCapture)?;
        if r.startup_binding_sha384 != hex(&self.inner.config.expected_startup_binding_sha384) {
            return Err(ExportError::InvalidConfiguration);
        }
        let slot = self
            .inner
            .slots
            .lock()
            .map_err(|_| ExportError::Poisoned)?
            .get(&r.task.container_id)
            .cloned()
            .ok_or(ExportError::MissingCapture)?;
        Ok((r, slot))
    }
    pub(crate) fn challenge(
        &self,
        record: &CapturedRecord,
        nonce: [u8; 32],
    ) -> Result<GcpQuoteChallenge, ExportError> {
        let (r, _) = self.checked(record)?;
        GcpQuoteChallenge::new(
            self.inner.config.audience.clone(),
            nonce,
            &r,
            self.inner.config.boot_binding.clone(),
            self.inner.config.trust_snapshot_sha384,
        )
        .map_err(|_| ExportError::InvalidChallenge)
    }
    pub(crate) fn request(
        &self,
        record: Arc<CapturedRecord>,
        challenge: &GcpQuoteChallenge,
    ) -> Result<ExportStatus, ExportError> {
        let (r, slot) = self.checked(&record)?;
        report_data(&r, challenge).map_err(|_| ExportError::InvalidChallenge)?;
        let c = &self.inner.config;
        if challenge.audience != c.audience
            || challenge.boot_binding != c.boot_binding
            || challenge.trust_snapshot_sha384 != hex(&c.trust_snapshot_sha384)
        {
            return Err(ExportError::InvalidChallenge);
        }
        let mut s = slot.state.lock().map_err(|_| ExportError::Poisoned)?;
        if s.record.as_ref().is_some_and(|r| !Arc::ptr_eq(r, &record))
            || s.challenge.as_ref().is_some_and(|c| c != challenge)
        {
            return Err(ExportError::Conflict);
        }
        s.record = Some(record.clone());
        s.challenge = Some(challenge.clone());
        if !s.queued
            && !s.exhausted
            && s.output.is_none()
            && !self.inner.control.stopped.load(Ordering::Acquire)
        {
            if record.gcp_captured_at().elapsed() >= PENDING_TIME {
                s.exhausted = true;
                s.error = Some(ExportError::Deadline);
            } else {
                s.queued = true;
                if let Err(e) = self.inner.requests.try_send(slot.clone()) {
                    s.queued = false;
                    return Err(match e {
                        mpsc::TrySendError::Full(_) => ExportError::QueueFull,
                        mpsc::TrySendError::Disconnected(_) => ExportError::WorkerFailed,
                    });
                }
            }
        }
        Ok(status(&s, &self.inner.control))
    }
    pub(crate) fn status(&self, record: &Arc<CapturedRecord>) -> Result<ExportStatus, ExportError> {
        let (_, slot) = self.checked(record)?;
        let s = slot.state.lock().map_err(|_| ExportError::Poisoned)?;
        if s.record.as_ref().is_some_and(|r| !Arc::ptr_eq(r, record)) {
            return Err(ExportError::Conflict);
        }
        Ok(status(&s, &self.inner.control))
    }
    pub(crate) fn attempts(&self, record: &Arc<CapturedRecord>) -> Result<u8, ExportError> {
        let (_, slot) = self.checked(record)?;
        let s = slot.state.lock().map_err(|_| ExportError::Poisoned)?;
        if s.record.as_ref().is_some_and(|r| !Arc::ptr_eq(r, record)) {
            return Err(ExportError::Conflict);
        }
        Ok(s.attempts)
    }
    pub(crate) fn output(
        &self,
        record: &Arc<CapturedRecord>,
    ) -> Result<Option<Arc<GcpExportedRecord>>, ExportError> {
        let (_, slot) = self.checked(record)?;
        let s = slot.state.lock().map_err(|_| ExportError::Poisoned)?;
        if s.record.as_ref().is_some_and(|r| !Arc::ptr_eq(r, record)) {
            return Err(ExportError::Conflict);
        }
        Ok(s.output.clone())
    }
}
fn status(s: &State, c: &Control) -> ExportStatus {
    if s.output.is_some() {
        return ExportStatus::Ready;
    }
    if c.failed.load(Ordering::Acquire) {
        return ExportStatus::Exhausted(ExportError::WorkerFailed);
    }
    if c.stopped.load(Ordering::Acquire) {
        return ExportStatus::Stopped;
    }
    if s.in_flight.is_none()
        && s.record
            .as_ref()
            .is_some_and(|r| r.gcp_captured_at().elapsed() >= PENDING_TIME)
    {
        return ExportStatus::Exhausted(ExportError::Deadline);
    }
    if s.exhausted {
        return ExportStatus::Exhausted(s.error.unwrap_or(ExportError::AttemptsExhausted));
    }
    ExportStatus::Pending {
        attempts: s.attempts,
        in_flight: s.in_flight.is_some(),
        last_error: if s.in_flight.is_some_and(|t| t.elapsed() >= QUOTE_TIME) {
            Some(ExportError::Deadline)
        } else {
            s.error
        },
    }
}
fn worker_loop(
    recv: Receiver<Arc<Slot>>,
    inner: Arc<Inner>,
    mut backend: Box<dyn Backend>,
    backoff: [Duration; 2],
) {
    struct Life(Arc<Control>);
    impl Drop for Life {
        fn drop(&mut self) {
            if thread::panicking() {
                self.0.failed.store(true, Ordering::Release);
                self.0.stopped.store(true, Ordering::Release);
                self.0.wake.notify_all();
            }
        }
    }
    let _life = Life(inner.control.clone());
    // recv_timeout ensures stop wakes even though runtime retains a sender.
    while !inner.control.stopped.load(Ordering::Acquire) {
        match recv.recv_timeout(Duration::from_millis(100)) {
            Ok(slot) => process(&slot, &inner, backend.as_mut(), backoff),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}
fn process(slot: &Slot, inner: &Inner, backend: &mut dyn Backend, backoff: [Duration; 2]) {
    for (ordinal, pause) in backoff
        .iter()
        .copied()
        .chain(std::iter::once(Duration::ZERO))
        .enumerate()
    {
        let (record, challenge) = {
            let mut s = slot
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if inner.control.stopped.load(Ordering::Acquire) {
                return;
            }
            let (Some(record), Some(challenge)) = (s.record.clone(), s.challenge.clone()) else {
                return;
            };
            if record.gcp_captured_at().elapsed() >= PENDING_TIME {
                s.exhausted = true;
                s.error = Some(ExportError::Deadline);
                slot.changed.notify_all();
                return;
            }
            s.attempts += 1;
            s.in_flight = Some(Instant::now());
            slot.changed.notify_all();
            (record, challenge)
        };
        let start = Instant::now();
        let result = ExecutionRecord::decode(record.canonical_bytes())
            .map_err(|_| ExportError::MissingCapture)
            .and_then(|r| report_data(&r, &challenge).map_err(|_| ExportError::InvalidChallenge))
            .and_then(|report| backend.collect(report))
            .and_then(|raw| {
                GcpExecutionEnvelope::new(challenge, raw.tdx_quote, raw.ccel_table, raw.ccel_log)
                    .and_then(|e| e.encode())
                    .map_err(|_| ExportError::TooLarge)
            });
        // Publication and stop share this short gate. No blocking collection
        // holds it; shutdown cannot race a late output into Ready.
        let publish = inner
            .control
            .wait
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = if inner.control.stopped.load(Ordering::Acquire) {
            Err(ExportError::Stopped)
        } else if start.elapsed() >= QUOTE_TIME
            || record.gcp_captured_at().elapsed() >= PENDING_TIME
        {
            Err(ExportError::Deadline)
        } else {
            result
        };
        let mut s = slot
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.in_flight = None;
        match result {
            Ok(mut envelope) => {
                envelope.shrink_to_fit();
                if envelope.capacity()
                    + record.retained_capacity()
                    + slot.snapshot.retained_capacity()
                    + 4096
                    > SLOT_BYTES
                {
                    s.exhausted = true;
                    s.error = Some(ExportError::TooLarge);
                } else {
                    s.output = Some(Arc::new(GcpExportedRecord {
                        record,
                        snapshot: slot.snapshot.clone(),
                        envelope,
                    }));
                }
                slot.changed.notify_all();
                return;
            }
            Err(error) => {
                s.error = Some(error);
                s.exhausted = ordinal == 2
                    || !matches!(error, ExportError::QuoteFailed | ExportError::Deadline);
                slot.changed.notify_all();
                if s.exhausted {
                    return;
                }
            }
        }
        drop(s);
        drop(publish);
        let wait = inner
            .control
            .wait
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(inner.control.wake.wait_timeout_while(wait, pause, |_| {
            !inner.control.stopped.load(Ordering::Acquire)
        }));
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(test)]
#[path = "gcp_protected_export_tests.rs"]
mod tests;
