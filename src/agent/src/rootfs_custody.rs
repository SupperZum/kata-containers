// SPDX-License-Identifier: Apache-2.0

//! Receiver-owned custody of one authenticated preparation attempt.
//!
//! Run `advance` on an owned blocking worker: received-image parsing, hashing
//! and mount syscalls are synchronous and bounded, with cooperative cancellation.
//! A usable lease is published only after independent admission, actual view
//! validation, an exact producer P commit and the first final ACK being queued.
//! No task binding or start is opened.

use execution_proof_handoff::{
    admission::{
        GuestAdmissionConfig, GuestAdmissionError, ReceiverAdmissionVerifier, ReceiverChallenge,
        ReceiverEnrollmentError, VerifiedReceiverAdmission,
    },
    fd_transport::{FdExpectation, SendOutcome, TransportError},
    rootfs_custody::{
        AdmissionBundle, AdmissionDescriptor, CustodyAnnouncement, CustodyError, FinalizedAck,
        PCommit, PreparationProvenance, PreparationRecord, ProvenanceDescriptor, ValidatedReceipt,
        MAX_PROVENANCE_BYTES,
    },
    startup::{Role, StartupBoundChannel},
};
use image_rs::preparation::{
    launch_spec::BoundEffectiveSpec,
    received_view::{
        ReceivedMountedView, ReceivedOriginExpectation, ReceivedRootfsSummary, ReceivedViewError,
        ReceivedViewLimits,
    },
    static_elf::StaticElfLimits,
    SealedImageBytes,
};
use std::{
    fmt,
    fs::File,
    os::{
        fd::{AsFd, OwnedFd},
        unix::fs::FileExt,
    },
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

type Packet = (Vec<u8>, Option<OwnedFd>);

#[derive(Clone, Copy)]
pub struct ReceiverLimits {
    pub admission_bytes: usize,
    pub provenance_bytes: usize,
    pub view: ReceivedViewLimits,
    pub elf: StaticElfLimits,
    pub wall_time: Duration,
}
impl ReceiverLimits {
    pub fn validate(self) -> Result<(), ReceiverError> {
        if self.admission_bytes == 0
            || self.admission_bytes > MAX_PROVENANCE_BYTES
            || self.provenance_bytes == 0
            || self.provenance_bytes > MAX_PROVENANCE_BYTES
            || self.wall_time.is_zero()
            || Instant::now().checked_add(self.wall_time).is_none()
        {
            return Err(ReceiverError::InvalidConfiguration);
        }
        self.view
            .validate()
            .map_err(|_| ReceiverError::InvalidConfiguration)?;
        self.elf
            .validate()
            .map_err(|_| ReceiverError::InvalidConfiguration)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverError {
    InvalidConfiguration,
    WrongRole,
    Busy,
    Unavailable,
    NotReady,
    AlreadyTaken,
    Cancelled,
    Deadline,
    Descriptor,
    BindingMismatch,
    Operation,
    Enrollment(ReceiverEnrollmentError),
    Admission(GuestAdmissionError),
    Protocol(CustodyError),
    Transport(TransportError),
    View(ReceivedViewError),
}
impl fmt::Display for ReceiverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "receiver rootfs custody rejected: {self:?}")
    }
}
impl std::error::Error for ReceiverError {}

struct Capacity {
    active: AtomicUsize,
    maximum: usize,
}
struct ReceiverPermit(Arc<Capacity>);
impl Drop for ReceiverPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The same factory must outlive and account for all receiver views in its role.
#[derive(Clone)]
pub struct ReceiverFactory {
    capacity: Arc<Capacity>,
}
impl ReceiverFactory {
    pub fn new(active: usize) -> Result<Self, ReceiverError> {
        if !(1..=4).contains(&active) {
            return Err(ReceiverError::InvalidConfiguration);
        }
        Ok(Self {
            capacity: Arc::new(Capacity {
                active: AtomicUsize::new(0),
                maximum: active,
            }),
        })
    }
    pub fn active(&self) -> usize {
        self.capacity.active.load(Ordering::Acquire)
    }
    fn reserve(&self) -> Result<ReceiverPermit, ReceiverError> {
        let mut active = self.capacity.active.load(Ordering::Acquire);
        loop {
            if active >= self.capacity.maximum {
                return Err(ReceiverError::Busy);
            }
            match self.capacity.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(ReceiverPermit(self.capacity.clone())),
                Err(observed) => active = observed,
            }
        }
    }
    /// All expectations and spec bytes come from independently trusted guest
    /// configuration. The owned channel must be the Kata startup role endpoint.
    pub fn begin(
        &self,
        channel: StartupBoundChannel,
        configuration: GuestAdmissionConfig,
        spec: BoundEffectiveSpec,
        limits: ReceiverLimits,
    ) -> Result<ReceiverOwner, ReceiverError> {
        limits.validate()?;
        if channel.role() != Role::Kata {
            return Err(ReceiverError::WrongRole);
        }
        let expected_spec =
            decode::<48>(&configuration.expected_grant.binding.effective_launch_sha384)?;
        if spec.sha384() != configuration.expected_grant.binding.effective_launch_sha384 {
            return Err(ReceiverError::BindingMismatch);
        }
        let expected_manifest = decode::<32>(
            &configuration
                .expected_grant
                .binding
                .selected_manifest_sha256,
        )?;
        let expected_policy =
            decode::<48>(&configuration.expected_grant.binding.image_policy_sha384)?;
        let grant = configuration
            .expected_grant
            .digest_sha384()
            .map_err(|_| ReceiverError::InvalidConfiguration)?;
        let challenge = ReceiverChallenge::new(&channel, decode::<48>(&grant)?)
            .map_err(ReceiverError::Enrollment)?;
        let deadline = Instant::now()
            .checked_add(limits.wall_time)
            .ok_or(ReceiverError::InvalidConfiguration)?;
        Ok(ReceiverOwner {
            channel: Some(channel),
            phase: Phase::SendChallenge,
            challenge: Some(challenge),
            configuration: Some(AdmissionConfiguration::Legacy(configuration)),
            verifier: None,
            admission: None,
            #[cfg(feature = "protected-export")]
            admission_bundle: None,
            admission_descriptor: None,
            announcement: None,
            origin: None,
            provenance: None,
            pending_view: None,
            validated: None,
            commit: None,
            ack: None,
            lease: None,
            spec: Some(spec),
            permit: Some(self.reserve()?),
            limits,
            deadline,
            expected_context: None,
            expected_spec,
            expected_manifest,
            expected_policy,
            published: false,
            ack_sent: false,
            duplicate_finalized: false,
        })
    }
    #[cfg(feature = "protected-export-gcp-tdx")]
    pub fn begin_gcp(
        &self,
        channel: StartupBoundChannel,
        configuration: execution_proof_handoff::admission::gcp::GcpGuestAdmissionConfig,
        spec: BoundEffectiveSpec,
        limits: ReceiverLimits,
    ) -> Result<ReceiverOwner, ReceiverError> {
        limits.validate()?;
        if channel.role() != Role::Kata {
            return Err(ReceiverError::WrongRole);
        }
        let expected_spec =
            decode::<48>(&configuration.expected_grant.binding.effective_launch_sha384)?;
        if spec.sha384() != configuration.expected_grant.binding.effective_launch_sha384 {
            return Err(ReceiverError::BindingMismatch);
        }
        let expected_manifest = decode::<32>(
            &configuration
                .expected_grant
                .binding
                .selected_manifest_sha256,
        )?;
        let expected_policy =
            decode::<48>(&configuration.expected_grant.binding.image_policy_sha384)?;
        let grant = configuration
            .expected_grant
            .digest_sha384()
            .map_err(|_| ReceiverError::InvalidConfiguration)?;
        let challenge = ReceiverChallenge::new(&channel, decode::<48>(&grant)?)
            .map_err(ReceiverError::Enrollment)?;
        let deadline = Instant::now()
            .checked_add(limits.wall_time)
            .ok_or(ReceiverError::InvalidConfiguration)?;
        Ok(ReceiverOwner {
            channel: Some(channel),
            phase: Phase::SendChallenge,
            challenge: Some(challenge),
            configuration: Some(AdmissionConfiguration::Gcp(configuration)),
            verifier: None,
            admission: None,
            #[cfg(feature = "protected-export")]
            admission_bundle: None,
            admission_descriptor: None,
            announcement: None,
            origin: None,
            provenance: None,
            pending_view: None,
            validated: None,
            commit: None,
            ack: None,
            lease: None,
            spec: Some(spec),
            permit: Some(self.reserve()?),
            limits,
            deadline,
            expected_context: None,
            expected_spec,
            expected_manifest,
            expected_policy,
            published: false,
            ack_sent: false,
            duplicate_finalized: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverStatus {
    Enrolling,
    Receiving,
    AwaitingCommit,
    Finalizing,
    Finalized,
    Terminal,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiverProgress {
    Pending,
    Advanced,
    Finalized,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    SendChallenge,
    Enrollment,
    Admission,
    Announcement,
    Provenance,
    SendValidated,
    Commit,
    SendAck,
    Finalized,
    DuplicateAnnouncement,
    DuplicateProvenance,
    Terminal,
}

// Internal dispatch preserves the exact legacy verifier path. New GCP input
// can enter only through its separate trusted constructor and strong verifier.
enum AdmissionConfiguration {
    Legacy(GuestAdmissionConfig),
    #[cfg(feature = "protected-export-gcp-tdx")]
    Gcp(execution_proof_handoff::admission::gcp::GcpGuestAdmissionConfig),
}
impl AdmissionConfiguration {
    fn into_verifier(
        self,
        enrollment: execution_proof_handoff::admission::PendingReceiverEnrollment,
    ) -> Result<AdmissionVerifier, ReceiverEnrollmentError> {
        match self {
            Self::Legacy(config) => Ok(AdmissionVerifier::Legacy(ReceiverAdmissionVerifier::new(
                config, enrollment,
            )?)),
            #[cfg(feature = "protected-export-gcp-tdx")]
            Self::Gcp(config) => Ok(AdmissionVerifier::Gcp(
                execution_proof_handoff::admission::GcpReceiverAdmissionVerifier::new(
                    config, enrollment,
                )?,
            )),
        }
    }
}
enum AdmissionVerifier {
    Legacy(ReceiverAdmissionVerifier),
    #[cfg(feature = "protected-export-gcp-tdx")]
    Gcp(execution_proof_handoff::admission::GcpReceiverAdmissionVerifier),
}
impl AdmissionVerifier {
    fn verify_bundle(
        &self,
        grant: &[u8],
        aggregate: &[u8],
        receipt: &[u8],
    ) -> Result<execution_proof_handoff::admission::AdmissionCheck, GuestAdmissionError> {
        match self {
            Self::Legacy(value) => value.verify_bundle(grant, aggregate, receipt),
            #[cfg(feature = "protected-export-gcp-tdx")]
            Self::Gcp(value) => value.verify_bundle(grant, aggregate, receipt),
        }
    }
    fn take_verified(&self) -> Result<VerifiedReceiverAdmission, GuestAdmissionError> {
        match self {
            Self::Legacy(value) => value.take_verified(),
            #[cfg(feature = "protected-export-gcp-tdx")]
            Self::Gcp(value) => value.take_verified(),
        }
    }
}

/// One non-Clone, non-restorable receiver transaction. Only metadata tombstones
/// remain after the lease is taken; retries never create another view or lease.
pub struct ReceiverOwner {
    channel: Option<StartupBoundChannel>,
    phase: Phase,
    challenge: Option<ReceiverChallenge>,
    configuration: Option<AdmissionConfiguration>,
    verifier: Option<AdmissionVerifier>,
    admission: Option<VerifiedReceiverAdmission>,
    #[cfg(feature = "protected-export")]
    admission_bundle: Option<Vec<u8>>,
    admission_descriptor: Option<AdmissionDescriptor>,
    announcement: Option<CustodyAnnouncement>,
    origin: Option<OwnedFd>,
    provenance: Option<PreparationProvenance>,
    pending_view: Option<ReceivedMountedView>,
    validated: Option<ValidatedReceipt>,
    commit: Option<PCommit>,
    ack: Option<FinalizedAck>,
    lease: Option<PreparedRootfsLease>,
    spec: Option<BoundEffectiveSpec>,
    // Last owned resource: do not return capacity before closing pending views.
    permit: Option<ReceiverPermit>,
    limits: ReceiverLimits,
    deadline: Instant,
    expected_context: Option<[u8; 48]>,
    expected_spec: [u8; 48],
    expected_manifest: [u8; 32],
    expected_policy: [u8; 48],
    published: bool,
    ack_sent: bool,
    duplicate_finalized: bool,
}
impl ReceiverOwner {
    pub fn status(&self) -> ReceiverStatus {
        match self.phase {
            Phase::SendChallenge | Phase::Enrollment => ReceiverStatus::Enrolling,
            Phase::SendValidated | Phase::Commit => ReceiverStatus::AwaitingCommit,
            Phase::SendAck => ReceiverStatus::Finalizing,
            Phase::Finalized => ReceiverStatus::Finalized,
            Phase::Terminal => ReceiverStatus::Terminal,
            _ if self.published => ReceiverStatus::Finalizing,
            _ => ReceiverStatus::Receiving,
        }
    }
    pub fn advance(
        &mut self,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ReceiverProgress, ReceiverError> {
        let result = self.advance_inner(cancelled);
        if result.is_err() {
            self.cancel();
        }
        result
    }
    fn advance_inner(
        &mut self,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ReceiverProgress, ReceiverError> {
        if self.phase == Phase::Terminal {
            return Err(ReceiverError::Unavailable);
        }
        self.check_cancel(cancelled)?;
        match self.phase {
            Phase::SendChallenge => {
                let wire = self
                    .challenge
                    .as_ref()
                    .ok_or(ReceiverError::Unavailable)?
                    .encode();
                if self.send(&wire)? {
                    self.phase = Phase::Enrollment;
                    Ok(ReceiverProgress::Advanced)
                } else {
                    Ok(ReceiverProgress::Pending)
                }
            }
            Phase::Enrollment => {
                let Some(packet) = self
                    .channel
                    .as_mut()
                    .ok_or(ReceiverError::Unavailable)?
                    .try_receive_bound(FdExpectation::None)
                    .map_err(ReceiverError::Transport)?
                else {
                    return Ok(ReceiverProgress::Pending);
                };
                let enrollment = self
                    .challenge
                    .take()
                    .ok_or(ReceiverError::Unavailable)?
                    .accept(
                        packet,
                        self.channel.as_ref().ok_or(ReceiverError::Unavailable)?,
                    )
                    .map_err(ReceiverError::Enrollment)?;
                self.verifier = Some(
                    self.configuration
                        .take()
                        .ok_or(ReceiverError::Unavailable)?
                        .into_verifier(enrollment)
                        .map_err(ReceiverError::Enrollment)?,
                );
                self.phase = Phase::Admission;
                Ok(ReceiverProgress::Advanced)
            }
            Phase::Admission => self.receive_admission(),
            Phase::Announcement => self.receive_announcement(false),
            Phase::Provenance => self.receive_provenance(cancelled, false),
            Phase::SendValidated => {
                let wire = self
                    .validated
                    .as_ref()
                    .ok_or(ReceiverError::Unavailable)?
                    .encode()
                    .map_err(ReceiverError::Protocol)?;
                if self.send(&wire)? {
                    self.phase = Phase::Commit;
                    Ok(ReceiverProgress::Advanced)
                } else {
                    Ok(ReceiverProgress::Pending)
                }
            }
            Phase::Commit | Phase::Finalized => self.receive_commit_or_retry(cancelled),
            Phase::SendAck => {
                let wire = self
                    .ack
                    .as_ref()
                    .ok_or(ReceiverError::Unavailable)?
                    .encode()
                    .map_err(ReceiverError::Protocol)?;
                if self.send(&wire)? {
                    self.ack_sent = true;
                    self.phase = Phase::Finalized;
                    Ok(ReceiverProgress::Finalized)
                } else {
                    Ok(ReceiverProgress::Pending)
                }
            }
            Phase::DuplicateAnnouncement => self.receive_announcement(true),
            Phase::DuplicateProvenance => self.receive_provenance(cancelled, true),
            Phase::Terminal => Err(ReceiverError::Unavailable),
        }
    }
    fn receive_admission(&mut self) -> Result<ReceiverProgress, ReceiverError> {
        let Some((wire, descriptor)) = self.receive(FdExpectation::One)? else {
            return Ok(ReceiverProgress::Pending);
        };
        let description = AdmissionDescriptor::decode(&wire).map_err(ReceiverError::Protocol)?;
        let bytes = read_sealed(
            descriptor.ok_or(ReceiverError::Descriptor)?,
            description.sha384,
            description.byte_len,
            self.limits.admission_bytes,
        )?;
        let bundle = AdmissionBundle::decode(&bytes, self.limits.admission_bytes)
            .map_err(ReceiverError::Protocol)?;
        let verifier = self.verifier.take().ok_or(ReceiverError::Unavailable)?;
        verifier
            .verify_bundle(&bundle.grant, &bundle.aggregate, &bundle.receipt)
            .map_err(ReceiverError::Admission)?;
        let admission = verifier.take_verified().map_err(ReceiverError::Admission)?;
        if decode::<48>(&admission.binding().effective_launch_sha384)? != self.expected_spec
            || decode::<32>(&admission.binding().selected_manifest_sha256)?
                != self.expected_manifest
            || decode::<48>(&admission.binding().image_policy_sha384)? != self.expected_policy
            || admission.startup_binding_sha384()
                != &self
                    .channel
                    .as_ref()
                    .ok_or(ReceiverError::Unavailable)?
                    .binding_commitment()
        {
            return Err(ReceiverError::BindingMismatch);
        }
        self.expected_context = Some(decode::<48>(admission.context_digest())?);
        self.admission = Some(admission);
        #[cfg(feature = "protected-export")]
        {
            self.admission_bundle = Some(bytes);
        }
        self.admission_descriptor = Some(description);
        self.phase = Phase::Announcement;
        Ok(ReceiverProgress::Advanced)
    }
    fn receive_announcement(&mut self, duplicate: bool) -> Result<ReceiverProgress, ReceiverError> {
        let Some((wire, descriptor)) = self.receive(FdExpectation::One)? else {
            return Ok(ReceiverProgress::Pending);
        };
        let announcement = CustodyAnnouncement::decode(
            &wire,
            self.limits.view.mount.backing_bytes as u64,
            self.limits.provenance_bytes,
        )
        .map_err(ReceiverError::Protocol)?;
        if announcement.offer.context_sha384()
            != self
                .expected_context
                .as_ref()
                .ok_or(ReceiverError::Unavailable)?
            || announcement.offer.candidate_spec_sha384() != &self.expected_spec
        {
            return Err(ReceiverError::BindingMismatch);
        }
        let descriptor = descriptor.ok_or(ReceiverError::Descriptor)?;
        if duplicate {
            if self.announcement.as_ref() != Some(&announcement) {
                return Err(ReceiverError::BindingMismatch);
            }
            let source = SealedImageBytes::from_received_fd(
                descriptor,
                self.limits.view.mount.backing_bytes as u64,
                announcement.offer.backing().sha384,
            )
            .map_err(|_| ReceiverError::Descriptor)?;
            if source.byte_len() != announcement.offer.backing().byte_len {
                return Err(ReceiverError::BindingMismatch);
            }
            drop(source);
            self.phase = Phase::DuplicateProvenance;
        } else {
            self.origin = Some(descriptor);
            self.announcement = Some(announcement);
            self.phase = Phase::Provenance;
        }
        Ok(ReceiverProgress::Advanced)
    }
    fn receive_provenance(
        &mut self,
        cancelled: &impl Fn() -> bool,
        duplicate: bool,
    ) -> Result<ReceiverProgress, ReceiverError> {
        let Some((wire, descriptor)) = self.receive(FdExpectation::One)? else {
            return Ok(ReceiverProgress::Pending);
        };
        let announcement = self
            .announcement
            .as_ref()
            .ok_or(ReceiverError::Unavailable)?;
        let description = ProvenanceDescriptor::decode(&wire).map_err(ReceiverError::Protocol)?;
        description
            .validate_for(announcement)
            .map_err(ReceiverError::Protocol)?;
        let bytes = read_sealed(
            descriptor.ok_or(ReceiverError::Descriptor)?,
            description.provenance_sha384,
            description.provenance_bytes,
            self.limits.provenance_bytes,
        )?;
        let provenance = PreparationProvenance::decode(&bytes, self.limits.provenance_bytes)
            .map_err(ReceiverError::Protocol)?;
        provenance
            .validate_for(announcement)
            .map_err(ReceiverError::Protocol)?;
        if decode::<32>(&provenance.manifest_sha256)? != self.expected_manifest
            || decode::<48>(&provenance.signature.policy_sha384)? != self.expected_policy
        {
            return Err(ReceiverError::BindingMismatch);
        }
        if duplicate {
            self.phase = if self.duplicate_finalized {
                Phase::SendAck
            } else {
                Phase::SendValidated
            };
            return Ok(ReceiverProgress::Advanced);
        }
        if self
            .admission
            .as_ref()
            .ok_or(ReceiverError::Unavailable)?
            .startup_binding_sha384()
            != &self
                .channel
                .as_ref()
                .ok_or(ReceiverError::Unavailable)?
                .binding_commitment()
        {
            return Err(ReceiverError::BindingMismatch);
        }
        let deadline = self.deadline;
        let stopped = || cancelled() || Instant::now() >= deadline;
        let view = ReceivedMountedView::from_sealed_origin(
            self.origin.take().ok_or(ReceiverError::Unavailable)?,
            ReceivedOriginExpectation {
                image_sha384: announcement.offer.backing().sha384,
                byte_len: announcement.offer.backing().byte_len,
            },
            self.spec.as_ref().ok_or(ReceiverError::Unavailable)?,
            self.limits.elf,
            self.limits.view,
            &stopped,
        )
        .map_err(ReceiverError::View)?;
        if stopped() {
            return Err(ReceiverError::Cancelled);
        }
        let actual = view.summary();
        if provenance.builder.inodes != actual.executable().inodes() as u64
            || actual.image_sha384() != &announcement.offer.backing().sha384
            || actual.byte_len() != announcement.offer.backing().byte_len
            || decode::<48>(actual.executable().spec_sha384())? != self.expected_spec
        {
            return Err(ReceiverError::BindingMismatch);
        }
        self.validated = Some(ValidatedReceipt {
            announcement_sha384: announcement.commitment().map_err(ReceiverError::Protocol)?,
            startup_binding_sha384: self
                .channel
                .as_ref()
                .ok_or(ReceiverError::Unavailable)?
                .binding_commitment(),
            provenance_sha384: announcement.provenance_sha384,
            image_sha384: *actual.image_sha384(),
            candidate_spec_sha384: self.expected_spec,
            executable_sha384: decode::<48>(actual.executable().executable_sha384())?,
            receiver_nonce: fresh_nonce()?,
            mount_id: actual.mount_id(),
            inodes: actual.executable().inodes() as u64,
        });
        self.pending_view = Some(view);
        self.provenance = Some(provenance);
        self.phase = Phase::SendValidated;
        Ok(ReceiverProgress::Advanced)
    }
    fn receive_commit_or_retry(
        &mut self,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ReceiverProgress, ReceiverError> {
        let Some((wire, descriptor)) = self.receive(FdExpectation::Optional)? else {
            return Ok(ReceiverProgress::Pending);
        };
        if let Ok(description) = AdmissionDescriptor::decode(&wire) {
            if self.admission_descriptor.as_ref() != Some(&description) {
                return Err(ReceiverError::BindingMismatch);
            }
            let bytes = read_sealed(
                descriptor.ok_or(ReceiverError::Descriptor)?,
                description.sha384,
                description.byte_len,
                self.limits.admission_bytes,
            )?;
            AdmissionBundle::decode(&bytes, self.limits.admission_bytes)
                .map_err(ReceiverError::Protocol)?;
            self.duplicate_finalized = self.published;
            self.phase = Phase::DuplicateAnnouncement;
            return Ok(ReceiverProgress::Advanced);
        }
        if descriptor.is_some() {
            return Err(ReceiverError::Descriptor);
        }
        let commit = PCommit::decode(&wire).map_err(ReceiverError::Protocol)?;
        let announcement = self
            .announcement
            .as_ref()
            .ok_or(ReceiverError::Unavailable)?;
        let validated = self.validated.as_ref().ok_or(ReceiverError::Unavailable)?;
        commit
            .validate_for(announcement, validated)
            .map_err(ReceiverError::Protocol)?;
        if self.published {
            if self.commit.as_ref() != Some(&commit) {
                return Err(ReceiverError::BindingMismatch);
            }
            self.phase = Phase::SendAck;
            return Ok(ReceiverProgress::Advanced);
        }
        self.check_cancel(cancelled)?;
        self.ack =
            Some(FinalizedAck::for_commit(announcement, &commit).map_err(ReceiverError::Protocol)?);
        // All checks and all fallible operations finish before this publication.
        // This one owned value associates the P, admission, actual view and its
        // capacity permit. No detached lookup or reconstructed lease is needed.
        #[cfg(feature = "protected-export")]
        let public_evidence = ReceiverEvidence {
            admission: self
                .admission_bundle
                .take()
                .ok_or(ReceiverError::Unavailable)?,
            announcement: announcement.encode().map_err(ReceiverError::Protocol)?,
            validated_receipt: validated.encode().map_err(ReceiverError::Protocol)?,
        };
        self.lease = Some(PreparedRootfsLease {
            view: self.pending_view.take().ok_or(ReceiverError::Unavailable)?,
            admission: self.admission.take().ok_or(ReceiverError::Unavailable)?,
            spec: self.spec.take().ok_or(ReceiverError::Unavailable)?,
            provenance: self.provenance.take().ok_or(ReceiverError::Unavailable)?,
            record: commit.record.clone(),
            #[cfg(feature = "protected-export")]
            public_evidence,
            _permit: self.permit.take().ok_or(ReceiverError::Unavailable)?,
        });
        self.commit = Some(commit);
        self.published = true;
        self.phase = Phase::SendAck;
        Ok(ReceiverProgress::Advanced)
    }
    fn check_cancel(&self, cancelled: &impl Fn() -> bool) -> Result<(), ReceiverError> {
        if cancelled() {
            return Err(ReceiverError::Cancelled);
        }
        // This is an operation budget, not a new authority expiry check. A
        // completed lease is not renewed or revoked by a local clock reading.
        if !self.ack_sent && Instant::now() >= self.deadline {
            return Err(ReceiverError::Deadline);
        }
        Ok(())
    }
    fn send(&mut self, wire: &[u8]) -> Result<bool, ReceiverError> {
        match self
            .channel
            .as_mut()
            .ok_or(ReceiverError::Unavailable)?
            .try_send(wire, None)
            .map_err(ReceiverError::Transport)?
        {
            SendOutcome::Sent => Ok(true),
            SendOutcome::WouldBlock => Ok(false),
        }
    }
    fn receive(&mut self, expectation: FdExpectation) -> Result<Option<Packet>, ReceiverError> {
        self.channel
            .as_mut()
            .ok_or(ReceiverError::Unavailable)?
            .try_receive(expectation)
            .map(|packet| packet.map(|packet| packet.into_parts()))
            .map_err(ReceiverError::Transport)
    }
    /// Transfer once, after the first final ACK is queued. Historical retries
    /// keep that completion marker and never publish another lease.
    pub fn take_lease(&mut self) -> Result<PreparedRootfsLease, ReceiverError> {
        if self.phase == Phase::Terminal {
            return Err(ReceiverError::Unavailable);
        }
        if !self.published || !self.ack_sent {
            return Err(ReceiverError::NotReady);
        }
        self.lease.take().ok_or(ReceiverError::AlreadyTaken)
    }
    /// Transfer the authenticated role channel only after the first final ACK
    /// was queued and the sole usable lease was transferred. The production
    /// owner may then send bounded public result frames on this same channel.
    #[cfg(feature = "gcp-proof-startup")]
    pub(crate) fn take_completed_channel(&mut self) -> Result<StartupBoundChannel, ReceiverError> {
        if self.phase != Phase::Finalized
            || !self.published
            || !self.ack_sent
            || self.lease.is_some()
        {
            return Err(ReceiverError::NotReady);
        }
        self.channel.take().ok_or(ReceiverError::AlreadyTaken)
    }

    /// Local cancellation closes only owned references. It cannot revoke a
    /// lease already transferred to another trusted task-lifetime owner.
    pub fn cancel(&mut self) {
        self.phase = Phase::Terminal;
        drop(self.channel.take());
        drop(self.origin.take());
        drop(self.pending_view.take());
        drop(self.lease.take());
        drop(self.permit.take());
        self.challenge = None;
        self.configuration = None;
        self.verifier = None;
        self.admission = None;
        #[cfg(feature = "protected-export")]
        {
            self.admission_bundle = None;
        }
        self.spec = None;
        self.provenance = None;
    }
}
impl Drop for ReceiverOwner {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Verified public frames retained for protected execution export.
#[cfg(feature = "protected-export")]
pub(crate) struct ReceiverEvidence {
    pub(crate) admission: Vec<u8>,
    pub(crate) announcement: Vec<u8>,
    pub(crate) validated_receipt: Vec<u8>,
}

/// A receiver-local, one-use lease for the verified filesystem view. Public
/// preparation data cannot recreate the lease after cancellation or transfer.
pub struct PreparedRootfsLease {
    // Dependency order: actual view and admission close before capacity returns.
    view: ReceivedMountedView,
    admission: VerifiedReceiverAdmission,
    spec: BoundEffectiveSpec,
    provenance: PreparationProvenance,
    record: PreparationRecord,
    #[cfg(feature = "protected-export")]
    public_evidence: ReceiverEvidence,
    _permit: ReceiverPermit,
}
impl PreparedRootfsLease {
    pub fn record(&self) -> &PreparationRecord {
        &self.record
    }
    pub fn provenance(&self) -> &PreparationProvenance {
        &self.provenance
    }
    pub fn view_summary(&self) -> &ReceivedRootfsSummary {
        self.view.summary()
    }
    pub fn admission_context_digest(&self) -> &str {
        self.admission.context_digest()
    }
    pub fn candidate_spec(&self) -> &BoundEffectiveSpec {
        &self.spec
    }

    #[cfg(feature = "final-task")]
    pub(crate) fn into_execution(self) -> PreparedExecutionLease {
        PreparedExecutionLease {
            view: self.view.into_execution(),
            admission: self.admission,
            spec: self.spec,
            _provenance: self.provenance,
            record: self.record,
            #[cfg(feature = "protected-export")]
            public_evidence: self.public_evidence,
            _permit: self._permit,
        }
    }
}

/// Private one-way transition from receiver publication to task creation.
/// Keep this owner until every child that inherited an execution FD is reaped.
#[cfg(feature = "final-task")]
pub(crate) struct PreparedExecutionLease {
    view: image_rs::preparation::received_view::ExecutionView,
    admission: VerifiedReceiverAdmission,
    spec: BoundEffectiveSpec,
    _provenance: PreparationProvenance,
    record: PreparationRecord,
    #[cfg(feature = "protected-export")]
    public_evidence: ReceiverEvidence,
    _permit: ReceiverPermit,
}

#[cfg(feature = "final-task")]
impl PreparedExecutionLease {
    pub(crate) fn view(&self) -> &image_rs::preparation::received_view::ExecutionView {
        &self.view
    }
    pub(crate) fn admission(&self) -> &VerifiedReceiverAdmission {
        &self.admission
    }
    pub(crate) fn spec(&self) -> &BoundEffectiveSpec {
        &self.spec
    }
    pub(crate) fn record(&self) -> &PreparationRecord {
        &self.record
    }
    #[cfg(feature = "protected-export")]
    pub(crate) fn public_evidence(&self) -> &ReceiverEvidence {
        &self.public_evidence
    }
    #[cfg(feature = "protected-export")]
    pub(crate) fn provenance(&self) -> &PreparationProvenance {
        &self._provenance
    }
}

fn read_sealed(
    descriptor: OwnedFd,
    expected: [u8; 48],
    byte_len: u64,
    maximum: usize,
) -> Result<Vec<u8>, ReceiverError> {
    if byte_len == 0 || byte_len > maximum as u64 {
        return Err(ReceiverError::Descriptor);
    }
    let sealed = SealedImageBytes::from_received_fd(descriptor, maximum as u64, expected)
        .map_err(|_| ReceiverError::Descriptor)?;
    if sealed.byte_len() != byte_len {
        return Err(ReceiverError::BindingMismatch);
    }
    let file = File::from(
        sealed
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| ReceiverError::Operation)?,
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(byte_len as usize)
        .map_err(|_| ReceiverError::Operation)?;
    bytes.resize(byte_len as usize, 0);
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_| ReceiverError::Operation)?;
    Ok(bytes)
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], ReceiverError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ReceiverError::BindingMismatch);
    }
    let mut result = [0; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let nibble = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        result[index] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    Ok(result)
}
fn fresh_nonce() -> Result<[u8; 32], ReceiverError> {
    use std::io::Read;
    let mut bytes = [0; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| ReceiverError::Operation)?;
    if bytes == [0; 32] {
        return Err(ReceiverError::Operation);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "rootfs_custody_tests.rs"]
mod tests;
