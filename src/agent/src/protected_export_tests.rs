use super::*;
use execution_proof_handoff::execution::{
    ExecutionTask, EXECUTION_RECORD_CLAIM, EXECUTION_RECORD_PROFILE, EXECUTION_RECORD_PURPOSE,
    EXECUTION_RECORD_VERSION,
};

struct ControlledBackend {
    started: mpsc::Sender<([u8; 48], [u8; 64])>,
    results: Receiver<Result<Vec<u8>, ExportError>>,
}
impl QuoteBackend for ControlledBackend {
    fn collect(&mut self, init: [u8; 48], report: [u8; 64]) -> Result<Vec<u8>, ExportError> {
        self.started
            .send((init, report))
            .map_err(|_| ExportError::Stopped)?;
        self.results
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| ExportError::Stopped)?
    }
}
struct Harness {
    exporter: ProtectedExporter,
    owner: Option<ExportOwner>,
    started: Receiver<([u8; 48], [u8; 64])>,
    results: mpsc::Sender<Result<Vec<u8>, ExportError>>,
    clock: Arc<Mutex<Instant>>,
}
impl Harness {
    fn new() -> Self {
        let (started_send, started) = mpsc::channel();
        let (results, results_receive) = mpsc::channel();
        let clock = Arc::new(Mutex::new(Instant::now()));
        let backend = Box::new(ControlledBackend {
            started: started_send,
            results: results_receive,
        });
        let (exporter, owner) = ProtectedExporter::start(
            config(),
            backend,
            Clock::Controlled(clock.clone()),
            Budgets {
                backoff: [Duration::ZERO; 2],
                ..Budgets::default()
            },
        )
        .unwrap();
        Self {
            exporter,
            owner: Some(owner),
            started,
            results,
            clock,
        }
    }
    fn record(&self, age: Duration) -> Arc<CapturedRecord> {
        let slot = self.exporter.reserve(snapshot()).unwrap();
        slot.captured(*self.clock.lock().unwrap() - age);
        CapturedRecord::export_fixture(record().encode().unwrap(), slot)
    }
    fn started(&self) -> ([u8; 48], [u8; 64]) {
        self.started.recv_timeout(Duration::from_secs(5)).unwrap()
    }
    fn result(&self, result: Result<Vec<u8>, ExportError>) {
        self.results.send(result).unwrap();
    }
    fn wait(&self, record: &CapturedRecord, ready: impl Fn(&RecordState) -> bool) {
        let export = record.export().unwrap();
        let state = export.state.lock().unwrap();
        let (state, timeout) = export
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| !ready(state))
            .unwrap();
        assert!(
            !timeout.timed_out() || ready(&state),
            "worker transition deadline"
        );
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.exporter
            .inner
            .control
            .stopped
            .store(true, Ordering::Release);
        self.exporter.inner.control.wake.notify_all();
        let _ = self.results.send(Err(ExportError::Stopped));
        if let Some(owner) = self.owner.take() {
            owner.shutdown().unwrap();
        }
    }
}
fn config() -> ExportConfig {
    ExportConfig {
        audience: "independent-verifier".into(),
        producer_profile_sha384: [3; 48],
        trust_snapshot_sha384: [4; 48],
        expected_init_data: [5; 48],
    }
}
fn snapshot() -> PublicSnapshot {
    PublicSnapshot {
        admission: b"public signed admission fixture".to_vec(),
        preparation: b"public P fixture".to_vec(),
        provenance: b"public provenance fixture".to_vec(),
        announcement: b"public custody announcement fixture".to_vec(),
        validated_receipt: b"public validated receipt fixture".to_vec(),
    }
}
fn record() -> ExecutionRecord {
    ExecutionRecord {
        version: EXECUTION_RECORD_VERSION,
        purpose: EXECUTION_RECORD_PURPOSE.into(),
        profile: EXECUTION_RECORD_PROFILE.into(),
        claim: EXECUTION_RECORD_CLAIM.into(),
        event_id: "01".repeat(32),
        grant_sha384: "02".repeat(48),
        admission_context_sha384: "03".repeat(48),
        preparation_record_sha384: "04".repeat(48),
        startup_binding_sha384: "05".repeat(48),
        candidate_spec_sha384: "06".repeat(48),
        final_spec_sha384: "07".repeat(48),
        image_sha384: "08".repeat(48),
        executable_sha384: "09".repeat(48),
        mount_id: 42,
        task: ExecutionTask {
            container_id: "app".into(),
            generation: 1,
            pid: 123,
            process_start_time_ticks: 500,
        },
    }
}
fn challenge(nonce: u8) -> QuoteChallenge {
    let config = config();
    QuoteChallenge::new(
        config.audience,
        [nonce; 32],
        &record(),
        config.producer_profile_sha384,
        config.trust_snapshot_sha384,
    )
    .unwrap()
}
fn evidence() -> Vec<u8> {
    br#"{"quote":"private-software-fixture","cc_eventlog":null}"#.to_vec()
}

#[test]
fn config_and_feature_absence_fail_closed() {
    let mut invalid = config();
    invalid.expected_init_data = [0; 48];
    assert_eq!(
        ProtectedExporter::new(invalid).err(),
        Some(ExportError::InvalidConfiguration)
    );
    #[cfg(not(feature = "protected-export-tdx"))]
    assert_eq!(
        ProtectedExporter::new(config()).err(),
        Some(ExportError::Unavailable)
    );
    assert_eq!(Budgets::default().quote, Duration::from_secs(30));
    assert_eq!(Budgets::default().pending, Duration::from_secs(300));
    assert_eq!(
        Budgets::default().backoff,
        [Duration::from_secs(1), Duration::from_secs(5)]
    );
}

#[test]
fn reservation_precedes_capture_and_enforces_memory_quota() {
    let harness = Harness::new();
    let mut slots = Vec::new();
    for _ in 0..4 {
        slots.push(harness.exporter.reserve(snapshot()).unwrap());
    }
    assert_eq!(
        harness.exporter.reserve(snapshot()).err(),
        Some(ExportError::QueueFull)
    );
    let uncaptured =
        CapturedRecord::export_fixture(record().encode().unwrap(), slots.pop().unwrap());
    assert_eq!(
        harness.exporter.request(uncaptured.clone(), &challenge(1)),
        Err(ExportError::MissingCapture)
    );
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(uncaptured);
    assert!(harness.exporter.reserve(snapshot()).is_ok());
    let mut excessive = snapshot();
    excessive.admission = vec![0; MAX_PROVENANCE_BYTES + 1];
    assert_eq!(
        harness.exporter.reserve(excessive).err(),
        Some(ExportError::TooLarge)
    );
}

#[test]
fn exact_retry_reuses_quote_and_public_snapshot_after_capture_owner_clone() {
    let harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    let decoded = ExecutionRecord::decode(record.canonical_bytes()).unwrap();
    let nonce = challenge(1);
    assert!(matches!(
        harness.exporter.request(record.clone(), &nonce),
        Ok(ExportStatus::Pending { .. })
    ));
    assert_eq!(
        harness.started(),
        ([5; 48], report_data(&decoded, &nonce).unwrap())
    );
    harness.result(Ok(evidence()));
    harness.wait(&record, |state| state.output.is_some());
    let output = harness.exporter.output(&record).unwrap().unwrap();
    assert_eq!(output.record(), record.canonical_bytes());
    assert_eq!(output.admission(), snapshot().admission);
    assert_eq!(output.preparation(), snapshot().preparation);
    assert_eq!(output.provenance(), snapshot().provenance);
    assert_eq!(output.announcement(), snapshot().announcement);
    assert_eq!(output.validated_receipt(), snapshot().validated_receipt);
    assert!(output.encoded().len() <= MAX_EXPORT_BYTES);
    let envelope = ExecutionQuoteEnvelope::decode(output.quote()).unwrap();
    assert_eq!(envelope.challenge, nonce);
    assert_eq!(envelope.tdx_evidence, evidence());
    assert_eq!(
        harness.exporter.request(record.clone(), &nonce),
        Ok(ExportStatus::Ready)
    );
    assert!(Arc::ptr_eq(
        &output,
        &harness.exporter.output(&record).unwrap().unwrap()
    ));
    assert_eq!(
        harness.exporter.request(record.clone(), &challenge(2)),
        Err(ExportError::Conflict)
    );
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    harness
        .exporter
        .inner
        .control
        .stopped
        .store(true, Ordering::Release);
    assert_eq!(
        harness.exporter.request(record.clone(), &nonce),
        Ok(ExportStatus::Ready)
    );
}

#[test]
fn foreign_queue_and_wrong_trust_configuration_do_not_quote() {
    let first = Harness::new();
    let second = Harness::new();
    let record = first.record(Duration::ZERO);
    assert_eq!(
        second.exporter.request(record.clone(), &challenge(1)),
        Err(ExportError::Conflict)
    );
    let mut wrong = challenge(1);
    wrong.trust_snapshot_sha384 = "ff".repeat(48);
    assert_eq!(
        first.exporter.request(record, &wrong),
        Err(ExportError::InvalidChallenge)
    );
    assert!(matches!(
        first.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn transient_failures_have_three_total_attempts_and_keep_record() {
    let harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    for _ in 0..MAX_ATTEMPTS {
        harness.started();
        harness.result(Err(ExportError::QuoteFailed));
    }
    harness.wait(&record, |state| state.exhausted);
    assert_eq!(record.export().unwrap().state.lock().unwrap().attempts, 3);
    assert_eq!(
        harness.exporter.status(&record),
        Ok(ExportStatus::Exhausted(ExportError::QuoteFailed))
    );
    assert!(harness.exporter.output(&record).unwrap().is_none());
    assert_eq!(
        ExecutionRecord::decode(record.canonical_bytes()).unwrap(),
        self::record()
    );
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn overdue_blocking_quote_keeps_worker_occupied_until_true_completion() {
    let harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    harness.started();
    *harness.clock.lock().unwrap() += Duration::from_secs(31);
    assert_eq!(
        harness.exporter.status(&record),
        Ok(ExportStatus::Pending {
            attempts: 1,
            in_flight: true,
            last_error: Some(ExportError::Deadline)
        })
    );
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    harness.result(Ok(evidence()));
    harness.started();
    harness.result(Ok(evidence()));
    harness.wait(&record, |state| state.output.is_some());
    assert_eq!(record.export().unwrap().state.lock().unwrap().attempts, 2);
}

#[test]
fn expired_pending_budget_never_starts_quote_or_erases_record() {
    let harness = Harness::new();
    let record = harness.record(Duration::from_secs(301));
    assert_eq!(
        harness.exporter.request(record.clone(), &challenge(1)),
        Ok(ExportStatus::Exhausted(ExportError::Deadline))
    );
    assert!(harness.exporter.output(&record).unwrap().is_none());
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn permanent_invalid_configuration_is_not_retried() {
    let harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    harness.started();
    harness.result(Err(ExportError::InvalidConfiguration));
    harness.wait(&record, |state| state.exhausted);
    assert_eq!(record.export().unwrap().state.lock().unwrap().attempts, 1);
    assert_eq!(
        harness.exporter.status(&record),
        Ok(ExportStatus::Exhausted(ExportError::InvalidConfiguration))
    );
}

#[test]
fn shutdown_joins_in_flight_worker_and_discards_late_quote() {
    let mut harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    harness.started();
    let owner = harness.owner.take().unwrap();
    let (joined_send, joined) = mpsc::channel();
    let join = thread::spawn(move || joined_send.send(owner.shutdown()).unwrap());
    let control = &harness.exporter.inner.control;
    let guard = control.wait.lock().unwrap();
    let (guard, timeout) = control
        .wake
        .wait_timeout_while(guard, Duration::from_secs(5), |_| {
            !control.stopped.load(Ordering::Acquire)
        })
        .unwrap();
    assert!(!timeout.timed_out());
    assert!(matches!(joined.try_recv(), Err(mpsc::TryRecvError::Empty)));
    drop(guard);
    harness.result(Ok(evidence()));
    assert_eq!(joined.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    join.join().unwrap();
    assert_eq!(harness.exporter.status(&record), Ok(ExportStatus::Stopped));
    assert!(harness.exporter.output(&record).unwrap().is_none());
    assert_eq!(
        ExecutionRecord::decode(record.canonical_bytes()).unwrap(),
        self::record()
    );
}

#[test]
fn different_records_share_one_worker_without_parallel_quote_calls() {
    let harness = Harness::new();
    let first = harness.record(Duration::ZERO);
    let second = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(first.clone(), &challenge(1))
        .unwrap();
    harness.started();
    harness
        .exporter
        .request(second.clone(), &challenge(2))
        .unwrap();
    assert!(matches!(
        harness.started.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    harness.result(Ok(evidence()));
    harness.started();
    harness.wait(&first, |state| state.output.is_some());
    harness.result(Ok(evidence()));
    harness.wait(&second, |state| state.output.is_some());
}

#[test]
fn public_output_retains_byte_reservation_after_record_owner_is_dropped() {
    let mut harness = Harness::new();
    let record = harness.record(Duration::ZERO);
    harness
        .exporter
        .request(record.clone(), &challenge(1))
        .unwrap();
    harness.started();
    harness.result(Ok(evidence()));
    harness.wait(&record, |state| state.output.is_some());
    let output = harness.exporter.output(&record).unwrap().unwrap();
    drop(record);
    harness.owner.take().unwrap().shutdown().unwrap();
    let usage = harness.exporter.inner.usage.lock().unwrap();
    assert_eq!(usage.records, 1);
    assert_eq!(usage.bytes, RESERVED_BYTES);
    drop(usage);
    assert!(!output.encoded().is_empty());
    drop(output);
    let usage = harness.exporter.inner.usage.lock().unwrap();
    assert_eq!(usage.records, 0);
    assert_eq!(usage.bytes, 0);
}
