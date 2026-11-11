// SPDX-License-Identifier: Apache-2.0

//! Owned, bounded quote work over observer-created execution records.
//! Public export bytes carry no capability to create a record or request a quote.

use crate::{exec_observer::CapturedRecord, rootfs_custody::PreparedExecutionLease};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_handoff::{
    execution::ExecutionRecord,
    execution_quote::{report_data, ExecutionQuoteEnvelope, QuoteChallenge},
    rootfs_custody::MAX_PROVENANCE_BYTES,
};
use serde::Serialize;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Condvar, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const QUEUE_RECORDS: usize = 32;
const QUEUE_BYTES: usize = 64 << 20;
const RESERVED_BYTES: usize = 16 << 20;
const MAX_EXPORT_BYTES: usize = 12 << 20;
const MAX_RECORD_BYTES: usize = 16 << 10;
const MAX_ATTEMPTS: u8 = 3;
const QUOTE_TIME: Duration = Duration::from_secs(30);
const PENDING_TIME: Duration = Duration::from_secs(300);
const BACKOFF: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(5)];

/// Trusted constructor input. This is never deserialized from a host request.
#[derive(Clone)]
pub struct ExportConfig {
    pub audience: String,
    pub producer_profile_sha384: [u8; 48],
    pub trust_snapshot_sha384: [u8; 48],
    pub expected_init_data: [u8; 48],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportError {
    Unavailable,
    InvalidConfiguration,
    InvalidChallenge,
    MissingCapture,
    Conflict,
    QueueFull,
    TooLarge,
    Stopped,
    QuoteFailed,
    Deadline,
    AttemptsExhausted,
    Poisoned,
    WorkerFailed,
}
impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "protected export rejected: {self:?}")
    }
}
impl std::error::Error for ExportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportStatus {
    Pending {
        attempts: u8,
        in_flight: bool,
        last_error: Option<ExportError>,
    },
    Ready,
    Exhausted(ExportError),
    Stopped,
}

struct PublicSnapshot {
    admission: Vec<u8>,
    preparation: Vec<u8>,
    provenance: Vec<u8>,
    announcement: Vec<u8>,
    validated_receipt: Vec<u8>,
}
impl PublicSnapshot {
    fn bytes(&self) -> usize {
        self.admission.capacity()
            + self.preparation.capacity()
            + self.provenance.capacity()
            + self.announcement.capacity()
            + self.validated_receipt.capacity()
    }
}

/// Secret-free public data. Deserializing these bytes cannot recreate its owner.
pub struct ExportedRecord {
    _reservation: Arc<Reservation>,
    snapshot: Arc<PublicSnapshot>,
    record: Vec<u8>,
    quote: Vec<u8>,
    encoded: Vec<u8>,
}
impl ExportedRecord {
    pub fn record(&self) -> &[u8] {
        &self.record
    }
    pub fn admission(&self) -> &[u8] {
        &self.snapshot.admission
    }
    pub fn preparation(&self) -> &[u8] {
        &self.snapshot.preparation
    }
    pub fn provenance(&self) -> &[u8] {
        &self.snapshot.provenance
    }
    pub fn announcement(&self) -> &[u8] {
        &self.snapshot.announcement
    }
    pub fn validated_receipt(&self) -> &[u8] {
        &self.snapshot.validated_receipt
    }
    pub fn quote(&self) -> &[u8] {
        &self.quote
    }
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }
}

#[derive(Default)]
struct Usage {
    records: usize,
    bytes: usize,
}
struct Control {
    stopped: AtomicBool,
    failed: AtomicBool,
    wake: Condvar,
    wait: Mutex<()>,
}
struct Inner {
    config: ExportConfig,
    usage: Mutex<Usage>,
    requests: SyncSender<Message>,
    control: Arc<Control>,
    clock: Clock,
}
struct Reservation(Arc<Inner>);
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut usage = self
            .0
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        usage.records -= 1;
        usage.bytes -= RESERVED_BYTES;
    }
}

#[derive(Default)]
struct RecordState {
    challenge: Option<QuoteChallenge>,
    queued: bool,
    in_flight: Option<Instant>,
    attempts: u8,
    last_error: Option<ExportError>,
    exhausted: bool,
    output: Option<Arc<ExportedRecord>>,
}

/// Prepared before clone and attached only by the kernel capture transition.
/// This owner contains public metadata and a queue reservation, never view FDs.
pub(crate) struct CapturedExport {
    _reservation: Arc<Reservation>,
    snapshot: Arc<PublicSnapshot>,
    captured_at: OnceLock<Instant>,
    state: Mutex<RecordState>,
    changed: Condvar,
}
impl CapturedExport {
    pub(crate) fn captured(&self, instant: Instant) {
        // Only the observer's single successful capture transition calls this.
        let _ = self.captured_at.set(instant);
    }
}

#[derive(Clone)]
pub(crate) struct ProtectedExporter {
    inner: Arc<Inner>,
}

/// Must be retained by the trusted runtime owner. Shutdown/Drop joins the one
/// worker, including an in-progress blocking quote; it never detaches that work.
pub struct ExportOwner {
    worker: Option<JoinHandle<()>>,
    control: Arc<Control>,
    requests: SyncSender<Message>,
}
impl ExportOwner {
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
        let _ = self.requests.try_send(Message::Stop);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ExportError::WorkerFailed)?;
        }
        if self.control.failed.load(Ordering::Acquire) {
            return Err(ExportError::WorkerFailed);
        }
        Ok(())
    }
}
impl Drop for ExportOwner {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

enum Message {
    Quote(Arc<CapturedRecord>),
    Stop,
}

#[derive(Clone)]
enum Clock {
    System,
    #[cfg(test)]
    Controlled(Arc<Mutex<Instant>>),
}
impl Clock {
    fn now(&self) -> Instant {
        match self {
            Self::System => Instant::now(),
            #[cfg(test)]
            Self::Controlled(clock) => *clock.lock().unwrap(),
        }
    }
}

struct Budgets {
    quote: Duration,
    pending: Duration,
    backoff: [Duration; 2],
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            quote: QUOTE_TIME,
            pending: PENDING_TIME,
            backoff: BACKOFF,
        }
    }
}

trait QuoteBackend: Send {
    fn collect(&mut self, init: [u8; 48], report: [u8; 64]) -> Result<Vec<u8>, ExportError>;
}
#[cfg(feature = "protected-export-tdx")]
struct TdxBackend {
    runtime: tokio::runtime::Runtime,
}
#[cfg(feature = "protected-export-tdx")]
impl QuoteBackend for TdxBackend {
    fn collect(&mut self, init: [u8; 48], report: [u8; 64]) -> Result<Vec<u8>, ExportError> {
        self.runtime
            .block_on(attester::execution_quote::collect_tdx_execution_quote(
                init, report,
            ))
            .map_err(|error| match error {
                attester::execution_quote::ExecutionQuoteError::Unavailable => {
                    ExportError::QuoteFailed
                }
                attester::execution_quote::ExecutionQuoteError::InvalidBinding => {
                    ExportError::InvalidChallenge
                }
                attester::execution_quote::ExecutionQuoteError::InitDataMismatch => {
                    ExportError::InvalidConfiguration
                }
                attester::execution_quote::ExecutionQuoteError::Bounds
                | attester::execution_quote::ExecutionQuoteError::Encoding => ExportError::TooLarge,
            })
    }
}

impl ProtectedExporter {
    pub(crate) fn new(config: ExportConfig) -> Result<(Self, ExportOwner), ExportError> {
        validate_config(&config)?;
        Self::start(
            config,
            production_backend()?,
            Clock::System,
            Budgets::default(),
        )
    }

    fn start(
        config: ExportConfig,
        backend: Box<dyn QuoteBackend>,
        clock: Clock,
        budgets: Budgets,
    ) -> Result<(Self, ExportOwner), ExportError> {
        validate_config(&config)?;
        let control = Arc::new(Control {
            stopped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake: Condvar::new(),
            wait: Mutex::new(()),
        });
        let (requests, receiver) = mpsc::sync_channel(QUEUE_RECORDS);
        let inner = Arc::new(Inner {
            config,
            usage: Mutex::new(Usage::default()),
            requests: requests.clone(),
            control: control.clone(),
            clock,
        });
        let worker_control = control.clone();
        let worker = thread::Builder::new()
            .name("protected-r-export".into())
            .spawn(move || worker_loop(receiver, worker_control, backend, budgets))
            .map_err(|_| ExportError::Unavailable)?;
        Ok((
            Self { inner },
            ExportOwner {
                worker: Some(worker),
                control,
                requests,
            },
        ))
    }

    pub(crate) fn reserve_snapshot(
        &self,
        lease: &PreparedExecutionLease,
    ) -> Result<Arc<CapturedExport>, ExportError> {
        let evidence = lease.public_evidence();
        let snapshot = PublicSnapshot {
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
        };
        self.reserve(snapshot)
    }

    fn reserve(&self, snapshot: PublicSnapshot) -> Result<Arc<CapturedExport>, ExportError> {
        if self.inner.control.stopped.load(Ordering::Acquire) {
            return Err(ExportError::Stopped);
        }
        if snapshot.admission.len() > MAX_PROVENANCE_BYTES
            || snapshot.provenance.len() > MAX_PROVENANCE_BYTES
            || snapshot.preparation.len() > MAX_RECORD_BYTES
            || snapshot.announcement.len() > 1024
            || snapshot.validated_receipt.len() > 1024
        {
            return Err(ExportError::TooLarge);
        }
        let mut usage = self.inner.usage.lock().map_err(|_| ExportError::Poisoned)?;
        if usage.records >= QUEUE_RECORDS || usage.bytes > QUEUE_BYTES - RESERVED_BYTES {
            return Err(ExportError::QueueFull);
        }
        usage.records += 1;
        usage.bytes += RESERVED_BYTES;
        drop(usage);
        Ok(Arc::new(CapturedExport {
            _reservation: Arc::new(Reservation(self.inner.clone())),
            snapshot: Arc::new(snapshot),
            captured_at: OnceLock::new(),
            state: Mutex::new(RecordState::default()),
            changed: Condvar::new(),
        }))
    }

    pub(crate) fn request(
        &self,
        record: Arc<CapturedRecord>,
        challenge: &QuoteChallenge,
    ) -> Result<ExportStatus, ExportError> {
        let export = self.checked_export(&record)?;
        let decoded = ExecutionRecord::decode(record.canonical_bytes())
            .map_err(|_| ExportError::MissingCapture)?;
        report_data(&decoded, challenge).map_err(|_| ExportError::InvalidChallenge)?;
        if challenge.audience != self.inner.config.audience
            || challenge.producer_profile_sha384 != hex(&self.inner.config.producer_profile_sha384)
            || challenge.trust_snapshot_sha384 != hex(&self.inner.config.trust_snapshot_sha384)
        {
            return Err(ExportError::InvalidChallenge);
        }
        let mut state = export.state.lock().map_err(|_| ExportError::Poisoned)?;
        if let Some(previous) = &state.challenge {
            if previous != challenge {
                return Err(ExportError::Conflict);
            }
        } else {
            state.challenge = Some(challenge.clone());
        }
        if state.output.is_some() {
            return Ok(ExportStatus::Ready);
        }
        if self.inner.control.stopped.load(Ordering::Acquire) {
            if self.inner.control.failed.load(Ordering::Acquire) {
                return Err(ExportError::WorkerFailed);
            }
            return Ok(ExportStatus::Stopped);
        }
        if export
            .captured_at
            .get()
            .is_some_and(|at| self.inner.clock.now().saturating_duration_since(*at) >= PENDING_TIME)
        {
            state.exhausted = true;
            state.last_error = Some(ExportError::Deadline);
        }
        if state.output.is_none() && !state.queued && !state.exhausted {
            state.queued = true;
            match self.inner.requests.try_send(Message::Quote(record.clone())) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    state.queued = false;
                    return Err(ExportError::QueueFull);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    state.queued = false;
                    return Err(ExportError::WorkerFailed);
                }
            }
        }
        Ok(status(&state, export, &self.inner))
    }

    pub(crate) fn status(&self, record: &CapturedRecord) -> Result<ExportStatus, ExportError> {
        let export = self.checked_export(record)?;
        let state = export.state.lock().map_err(|_| ExportError::Poisoned)?;
        Ok(status(&state, export, &self.inner))
    }

    pub(crate) fn output(
        &self,
        record: &CapturedRecord,
    ) -> Result<Option<Arc<ExportedRecord>>, ExportError> {
        let export = self.checked_export(record)?;
        let state = export.state.lock().map_err(|_| ExportError::Poisoned)?;
        Ok(state.output.clone())
    }

    pub(crate) fn attempts(&self, record: &CapturedRecord) -> Result<u8, ExportError> {
        let export = self.checked_export(record)?;
        let state = export.state.lock().map_err(|_| ExportError::Poisoned)?;
        Ok(state.attempts)
    }

    fn checked_export<'a>(
        &self,
        record: &'a CapturedRecord,
    ) -> Result<&'a CapturedExport, ExportError> {
        let export = record.export().ok_or(ExportError::Unavailable)?;
        if !Arc::ptr_eq(&export._reservation.0, &self.inner) {
            return Err(ExportError::Conflict);
        }
        if export.captured_at.get().is_none() {
            return Err(ExportError::MissingCapture);
        }
        Ok(export)
    }
}

fn production_backend() -> Result<Box<dyn QuoteBackend>, ExportError> {
    #[cfg(feature = "protected-export-tdx")]
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| ExportError::Unavailable)?;
        Ok(Box::new(TdxBackend { runtime }))
    }
    #[cfg(not(feature = "protected-export-tdx"))]
    Err(ExportError::Unavailable)
}

fn status(state: &RecordState, export: &CapturedExport, inner: &Inner) -> ExportStatus {
    if state.output.is_some() {
        return ExportStatus::Ready;
    }
    if inner.control.failed.load(Ordering::Acquire) {
        return ExportStatus::Exhausted(ExportError::WorkerFailed);
    }
    if inner.control.stopped.load(Ordering::Acquire) {
        return ExportStatus::Stopped;
    }
    if state.exhausted {
        return ExportStatus::Exhausted(state.last_error.unwrap_or(ExportError::AttemptsExhausted));
    }
    let now = inner.clock.now();
    let elapsed = export
        .captured_at
        .get()
        .is_some_and(|at| now.saturating_duration_since(*at) >= PENDING_TIME);
    let quote_overdue = state
        .in_flight
        .is_some_and(|at| now.saturating_duration_since(at) >= QUOTE_TIME);
    if elapsed && state.in_flight.is_none() {
        return ExportStatus::Exhausted(ExportError::Deadline);
    }
    ExportStatus::Pending {
        attempts: state.attempts,
        in_flight: state.in_flight.is_some(),
        last_error: if elapsed || quote_overdue {
            Some(ExportError::Deadline)
        } else {
            state.last_error
        },
    }
}

fn validate_config(config: &ExportConfig) -> Result<(), ExportError> {
    if config.audience.is_empty()
        || config.audience.len() > 128
        || !config
            .audience
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
        || config.producer_profile_sha384 == [0; 48]
        || config.trust_snapshot_sha384 == [0; 48]
        || config.expected_init_data == [0; 48]
    {
        return Err(ExportError::InvalidConfiguration);
    }
    Ok(())
}

fn worker_loop(
    receiver: Receiver<Message>,
    control: Arc<Control>,
    mut backend: Box<dyn QuoteBackend>,
    budgets: Budgets,
) {
    struct WorkerLife(Arc<Control>);
    impl Drop for WorkerLife {
        fn drop(&mut self) {
            if thread::panicking() {
                self.0.failed.store(true, Ordering::Release);
                self.0.stopped.store(true, Ordering::Release);
                self.0.wake.notify_all();
            }
        }
    }
    let _life = WorkerLife(control.clone());
    while !control.stopped.load(Ordering::Acquire) {
        match receiver.recv() {
            Ok(Message::Quote(record)) => process_record(record, backend.as_mut(), &budgets),
            Ok(Message::Stop) | Err(_) => break,
        }
    }
}

fn process_record(record: Arc<CapturedRecord>, backend: &mut dyn QuoteBackend, budgets: &Budgets) {
    let Some(export) = record.export() else {
        return;
    };
    let inner = &export._reservation.0;
    let Some(captured_at) = export.captured_at.get() else {
        return;
    };
    for ordinal in 0..MAX_ATTEMPTS {
        if inner.control.stopped.load(Ordering::Acquire) {
            return;
        }
        let now = inner.clock.now();
        if now.saturating_duration_since(*captured_at) >= budgets.pending {
            finish_error(export, ExportError::Deadline, true);
            return;
        }
        let challenge = {
            let mut state = export
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(challenge) = state.challenge.clone() else {
                return;
            };
            state.attempts += 1;
            state.in_flight = Some(now);
            export.changed.notify_all();
            challenge
        };
        let result = ExecutionRecord::decode(record.canonical_bytes())
            .map_err(|_| ExportError::MissingCapture)
            .and_then(|decoded| {
                report_data(&decoded, &challenge).map_err(|_| ExportError::InvalidChallenge)
            })
            .and_then(|report| backend.collect(inner.config.expected_init_data, report));
        let ended = inner.clock.now();
        let result = if ended.saturating_duration_since(now) >= budgets.quote
            || ended.saturating_duration_since(*captured_at) >= budgets.pending
        {
            Err(ExportError::Deadline)
        } else {
            result
        };
        if inner.control.stopped.load(Ordering::Acquire) {
            finish_error(export, ExportError::Stopped, true);
            return;
        }
        match result.and_then(|evidence| make_output(&record, export, challenge, evidence)) {
            Ok(output) => {
                // Serialize publication with shutdown after encoding the output.
                let _publish = inner
                    .control
                    .wait
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if inner.control.stopped.load(Ordering::Acquire) {
                    finish_error(export, ExportError::Stopped, true);
                    return;
                }
                let mut state = export
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.in_flight = None;
                state.output = Some(Arc::new(output));
                export.changed.notify_all();
                return;
            }
            Err(error) => {
                let transient = matches!(error, ExportError::QuoteFailed | ExportError::Deadline);
                let last = ordinal + 1 == MAX_ATTEMPTS || !transient;
                finish_error(export, error, last);
                if last {
                    return;
                }
            }
        }
        let wait = inner
            .control
            .wait
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(inner.control.wake.wait_timeout_while(
            wait,
            budgets.backoff[ordinal as usize],
            |_| !inner.control.stopped.load(Ordering::Acquire),
        ));
    }
}

fn finish_error(export: &CapturedExport, error: ExportError, exhausted: bool) {
    let mut state = export
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.in_flight = None;
    state.last_error = Some(error);
    state.exhausted = exhausted;
    export.changed.notify_all();
}

fn make_output(
    record: &CapturedRecord,
    export: &CapturedExport,
    challenge: QuoteChallenge,
    evidence: Vec<u8>,
) -> Result<ExportedRecord, ExportError> {
    let mut quote = ExecutionQuoteEnvelope::new(challenge, evidence)
        .and_then(|envelope| envelope.encode())
        .map_err(|_| ExportError::TooLarge)?;
    #[derive(Serialize)]
    struct Wire {
        version: u16,
        purpose: &'static str,
        record_b64: String,
        admission_b64: String,
        preparation_b64: String,
        provenance_b64: String,
        announcement_b64: String,
        validated_receipt_b64: String,
        quote_b64: String,
    }
    let wire = Wire {
        version: 1,
        purpose: "qlad.execution-proof.protected-export.v1",
        record_b64: STANDARD.encode(record.canonical_bytes()),
        admission_b64: STANDARD.encode(&export.snapshot.admission),
        preparation_b64: STANDARD.encode(&export.snapshot.preparation),
        provenance_b64: STANDARD.encode(&export.snapshot.provenance),
        announcement_b64: STANDARD.encode(&export.snapshot.announcement),
        validated_receipt_b64: STANDARD.encode(&export.snapshot.validated_receipt),
        quote_b64: STANDARD.encode(&quote),
    };
    let mut output = BoundedWriter(Vec::new());
    serde_json::to_writer(&mut output, &wire).map_err(|_| ExportError::TooLarge)?;
    quote.shrink_to_fit();
    output.0.shrink_to_fit();
    let record_bytes = record.canonical_bytes().to_vec();
    let retained = export
        .snapshot
        .bytes()
        .checked_add(record.retained_capacity())
        .and_then(|n| n.checked_add(record_bytes.capacity()))
        .and_then(|n| n.checked_add(quote.capacity()))
        .and_then(|n| n.checked_add(output.0.capacity()))
        // Includes bounded challenge strings, Arc owners and bookkeeping.
        .and_then(|n| n.checked_add(4096))
        .ok_or(ExportError::TooLarge)?;
    if retained > RESERVED_BYTES {
        return Err(ExportError::TooLarge);
    }
    Ok(ExportedRecord {
        _reservation: export._reservation.clone(),
        snapshot: export.snapshot.clone(),
        record: record_bytes,
        quote,
        encoded: output.0,
    })
}

struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_EXPORT_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "protected export byte limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(test)]
#[path = "protected_export_tests.rs"]
mod tests;
