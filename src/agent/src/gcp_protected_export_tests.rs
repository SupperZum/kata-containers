use super::*;
use attester::gcp_execution_quote::GcpRawExecutionEvidence;
use execution_proof_contract::execution::{
    ExecutionTask, EXECUTION_RECORD_CLAIM, EXECUTION_RECORD_PROFILE, EXECUTION_RECORD_PURPOSE,
    EXECUTION_RECORD_VERSION,
};
use std::{collections::VecDeque, sync::atomic::AtomicUsize};
fn config() -> GcpExportConfig {
    GcpExportConfig {
        audience: "independent-verifier".into(),
        boot_binding: GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap(),
        trust_snapshot_sha384: [6; 48],
        expected_startup_binding_sha384: [5; 48],
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
fn captured(age: Duration) -> Arc<CapturedRecord> {
    CapturedRecord::gcp_export_fixture(record().encode().unwrap(), Instant::now() - age)
}
fn raw() -> GcpRawExecutionEvidence {
    GcpRawExecutionEvidence {
        tdx_quote: vec![1],
        ccel_table: vec![2],
        ccel_log: vec![3],
    }
}
struct Script {
    calls: Arc<AtomicUsize>,
    reports: Arc<Mutex<Vec<[u8; 64]>>>,
    results: VecDeque<Result<GcpRawExecutionEvidence, ExportError>>,
}
impl Backend for Script {
    fn collect(&mut self, report: [u8; 64]) -> Result<GcpRawExecutionEvidence, ExportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reports.lock().unwrap().push(report);
        self.results
            .pop_front()
            .unwrap_or(Err(ExportError::QuoteFailed))
    }
}
fn harness(
    results: Vec<Result<GcpRawExecutionEvidence, ExportError>>,
) -> (
    GcpProtectedExporter,
    GcpExportOwner,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<[u8; 64]>>>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let reports = Arc::new(Mutex::new(Vec::new()));
    let (exporter, owner) = GcpProtectedExporter::start(
        config(),
        Box::new(Script {
            calls: calls.clone(),
            reports: reports.clone(),
            results: results.into(),
        }),
        [Duration::ZERO; 2],
    )
    .unwrap();
    (exporter, owner, calls, reports)
}
fn wait(exporter: &GcpProtectedExporter) {
    let slot = exporter
        .inner
        .slots
        .lock()
        .unwrap()
        .get("app")
        .unwrap()
        .clone();
    let s = slot.state.lock().unwrap();
    let (s, t) = slot
        .changed
        .wait_timeout_while(s, Duration::from_secs(5), |s| {
            !s.exhausted && s.output.is_none()
        })
        .unwrap();
    assert!(!t.timed_out() || s.exhausted || s.output.is_some());
}
#[test]
fn capture_bound_report_and_original_r_are_sticky_and_output_is_typed() {
    let (e, o, calls, reports) = harness(vec![Ok(raw())]);
    e.reserve("app").unwrap();
    let r = captured(Duration::ZERO);
    let bytes = r.canonical_bytes().to_vec();
    let ch = e.challenge(&r, [7; 32]).unwrap();
    e.request(r.clone(), &ch).unwrap();
    wait(&e);
    assert_eq!(e.status(&r).unwrap(), ExportStatus::Ready);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        reports.lock().unwrap()[0],
        report_data(&record(), &ch).unwrap()
    );
    let out = e.output(&r).unwrap().unwrap();
    assert_eq!(out.record(), bytes);
    let wire = GcpExecutionEnvelope::decode(out.envelope()).unwrap();
    assert_eq!(wire.challenge, ch);
    assert_eq!(wire.tdx_quote, [1]);
    assert_eq!(e.request(r.clone(), &ch).unwrap(), ExportStatus::Ready);
    let other = e.challenge(&r, [8; 32]).unwrap();
    assert_eq!(e.request(r, &other), Err(ExportError::Conflict));
    // Test-only synthetic raw bytes establish transport ownership only, not QVL.
    o.shutdown().unwrap();
}
#[test]
fn real_fixed_collector_unavailable_retries_three_same_records_without_output() {
    if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
        return;
    }
    let (e, o) =
        GcpProtectedExporter::start(config(), Box::new(FixedBackend), [Duration::ZERO; 2]).unwrap();
    e.reserve("app").unwrap();
    let r = captured(Duration::ZERO);
    let bytes = r.canonical_bytes().to_vec();
    let ch = e.challenge(&r, [7; 32]).unwrap();
    e.request(r.clone(), &ch).unwrap();
    wait(&e);
    assert_eq!(
        e.status(&r).unwrap(),
        ExportStatus::Exhausted(ExportError::QuoteFailed)
    );
    assert_eq!(
        e.inner.slots.lock().unwrap()["app"]
            .state
            .lock()
            .unwrap()
            .attempts,
        3
    );
    assert!(e.output(&r).unwrap().is_none());
    assert_eq!(r.canonical_bytes(), bytes);
    o.shutdown().unwrap();
}
#[test]
fn capture_deadline_capacity_and_missing_reservation_stop_before_collection() {
    let (e, o, calls, _) = harness(vec![]);
    let r = captured(PENDING_TIME);
    assert!(e.challenge(&r, [7; 32]).is_err());
    e.reserve("app").unwrap();
    let ch = e.challenge(&r, [7; 32]).unwrap();
    assert_eq!(
        e.request(r, &ch).unwrap(),
        ExportStatus::Exhausted(ExportError::Deadline)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(e.reserve("app"), Err(ExportError::Conflict));
    for id in ["two", "three", "four"] {
        e.reserve(id).unwrap();
    }
    assert_eq!(e.reserve("five"), Err(ExportError::QueueFull));
    o.shutdown().unwrap();
}
#[test]
fn wrong_boot_audience_trust_startup_and_copied_capture_reject() {
    let (e, o, calls, _) = harness(vec![Err(ExportError::InvalidChallenge)]);
    e.reserve("app").unwrap();
    let r = captured(Duration::ZERO);
    let ch = e.challenge(&r, [7; 32]).unwrap();
    for field in 0..3 {
        let mut wrong = ch.clone();
        match field {
            0 => wrong.boot_binding.config_sha384 = "12".repeat(48),
            1 => wrong.audience = "other".into(),
            _ => wrong.trust_snapshot_sha384 = "13".repeat(48),
        };
        assert_eq!(
            e.request(r.clone(), &wrong),
            Err(ExportError::InvalidChallenge)
        );
    }
    let mut wrong = record();
    wrong.startup_binding_sha384 = "14".repeat(48);
    let wrong = CapturedRecord::gcp_export_fixture(wrong.encode().unwrap(), Instant::now());
    assert!(e.challenge(&wrong, [7; 32]).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    e.request(r, &ch).unwrap();
    wait(&e);
    assert_eq!(
        e.request(captured(Duration::ZERO), &ch),
        Err(ExportError::Conflict)
    );
    assert!(e.output(&captured(Duration::ZERO)).is_err());
    o.shutdown().unwrap();
}
#[test]
fn malformed_and_oversized_raw_evidence_never_produce_output() {
    for evidence in [
        GcpRawExecutionEvidence {
            tdx_quote: vec![],
            ccel_table: vec![1],
            ccel_log: vec![1],
        },
        GcpRawExecutionEvidence {
            tdx_quote: vec![1],
            ccel_table: vec![1],
            ccel_log: vec![1; 1 << 20],
        },
    ] {
        let (e, o, calls, _) = harness(vec![Ok(evidence)]);
        e.reserve("app").unwrap();
        let r = captured(Duration::ZERO);
        let ch = e.challenge(&r, [7; 32]).unwrap();
        e.request(r.clone(), &ch).unwrap();
        wait(&e);
        assert_eq!(
            e.status(&r).unwrap(),
            ExportStatus::Exhausted(ExportError::TooLarge)
        );
        assert!(e.output(&r).unwrap().is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        o.shutdown().unwrap();
    }
}
#[test]
fn owner_shutdown_joins_inflight_and_late_result_cannot_publish() {
    struct Blocking {
        started: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Backend for Blocking {
        fn collect(&mut self, _: [u8; 64]) -> Result<GcpRawExecutionEvidence, ExportError> {
            self.started.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(raw())
        }
    }
    let (started_s, started) = mpsc::channel();
    let (release_s, release) = mpsc::channel();
    let (e, o) = GcpProtectedExporter::start(
        config(),
        Box::new(Blocking {
            started: started_s,
            release,
        }),
        [Duration::ZERO; 2],
    )
    .unwrap();
    e.reserve("app").unwrap();
    let r = captured(Duration::ZERO);
    let ch = e.challenge(&r, [7; 32]).unwrap();
    e.request(r.clone(), &ch).unwrap();
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let (done_s, done) = mpsc::channel();
    let join = thread::spawn(move || done_s.send(o.shutdown()).unwrap());
    while !e.inner.control.stopped.load(Ordering::Acquire) {
        thread::yield_now();
    }
    assert!(done.try_recv().is_err());
    release_s.send(()).unwrap();
    assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()));
    join.join().unwrap();
    assert!(e.output(&r).unwrap().is_none());
    assert_eq!(e.status(&r).unwrap(), ExportStatus::Stopped);
}

#[test]
fn unsupported_or_invalid_evidence_configuration_is_terminal_without_retry() {
    let (e, o, calls, _) = harness(vec![Err(ExportError::InvalidConfiguration), Ok(raw())]);
    e.reserve("app").unwrap();
    let r = captured(Duration::ZERO);
    let ch = e.challenge(&r, [7; 32]).unwrap();
    e.request(r.clone(), &ch).unwrap();
    wait(&e);
    assert_eq!(
        e.status(&r).unwrap(),
        ExportStatus::Exhausted(ExportError::InvalidConfiguration)
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(e.output(&r).unwrap().is_none());
    o.shutdown().unwrap();
}

#[test]
fn public_v2_transport_preserves_exact_owner_snapshot_and_bounded_base64() {
    use base64::Engine;
    let record = captured(Duration::ZERO);
    let snapshot = Arc::new(PublicSnapshot {
        admission: b"actual owner admission bytes".to_vec(),
        preparation: b"actual owner preparation bytes".to_vec(),
        provenance: b"actual owner provenance bytes".to_vec(),
        announcement: b"actual owner announcement".to_vec(),
        validated_receipt: b"actual owner receipt".to_vec(),
    });
    let output = GcpExportedRecord {
        record: record.clone(),
        snapshot: snapshot.clone(),
        envelope: b"fixture GCP envelope bytes".to_vec(),
    };
    let bytes = output.encode_public().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed["version"], 2);
    assert_eq!(
        parsed["purpose"],
        "qlad.execution-proof.protected-export.v2"
    );
    for (name, expected) in [
        ("record_b64", record.canonical_bytes()),
        ("admission_b64", snapshot.admission.as_slice()),
        ("preparation_b64", snapshot.preparation.as_slice()),
        ("provenance_b64", snapshot.provenance.as_slice()),
        ("announcement_b64", snapshot.announcement.as_slice()),
        (
            "validated_receipt_b64",
            snapshot.validated_receipt.as_slice(),
        ),
        ("quote_b64", output.envelope()),
    ] {
        let encoded = parsed[name].as_str().unwrap();
        let raw = STANDARD.decode(encoded).unwrap();
        assert_eq!(raw, expected);
        assert_eq!(STANDARD.encode(raw), encoded);
    }
    assert_eq!(parsed.as_object().unwrap().len(), 9);
    let mut writer = BoundedWriter(Vec::new());
    writer.write_all(&vec![0; MAX_EXPORT_BYTES]).unwrap();
    assert!(writer.write_all(&[1]).is_err());
}

#[test]
fn gcp_snapshot_limits_reject_before_reserving_slot() {
    let (e, owner, _, _) = harness(vec![]);
    let snapshot = PublicSnapshot {
        admission: vec![1; MAX_PROVENANCE_BYTES + 1],
        preparation: vec![],
        provenance: vec![],
        announcement: vec![],
        validated_receipt: vec![],
    };
    assert_eq!(e.reserve_owned("app", snapshot), Err(ExportError::TooLarge));
    assert_eq!(
        e.reserve(&"x".repeat(execution_proof_contract::MAX_ID_BYTES + 1)),
        Err(ExportError::InvalidConfiguration)
    );
    e.reserve("app").unwrap();
    owner.shutdown().unwrap();
}
