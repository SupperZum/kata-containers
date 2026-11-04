// SPDX-License-Identifier: Apache-2.0

//! Trusted-runtime injection for the verification-only guest admission RPCs.
//! Ordinary startup installs no gate. No RPC field selects trust or a clock,
//! and a verified bundle never opens preparation or workload launch.

use execution_proof_handoff::admission::{GuestAdmissionError, GuestAdmissionGate};
use protocols::empty::Empty;
use std::{fmt, sync::Arc};

#[derive(Clone, Default)]
pub(crate) struct AdmissionRuntime {
    gate: Option<Arc<GuestAdmissionGate>>,
}

impl fmt::Debug for AdmissionRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdmissionRuntime").finish_non_exhaustive()
    }
}

impl AdmissionRuntime {
    pub(crate) fn with_gate(gate: Arc<GuestAdmissionGate>) -> Self {
        Self { gate: Some(gate) }
    }

    pub(crate) fn challenge(&self) -> ttrpc::Result<String> {
        let gate = self.gate.as_ref().ok_or_else(unavailable)?;
        Ok(gate.challenge_nonce().to_owned())
    }

    pub(crate) fn validate(
        &self,
        grant: &[u8],
        aggregate: &[u8],
        receipt: &[u8],
    ) -> ttrpc::Result<Empty> {
        let gate = self.gate.as_ref().ok_or_else(unavailable)?;
        match gate.validate_for_preparation(grant, aggregate, receipt) {
            Ok(never) => match never {},
            Err(error) => {
                let code = match error {
                    GuestAdmissionError::Unsupported(_) => ttrpc::Code::UNIMPLEMENTED,
                    GuestAdmissionError::TooLarge => ttrpc::Code::RESOURCE_EXHAUSTED,
                    GuestAdmissionError::Conflict => ttrpc::Code::FAILED_PRECONDITION,
                    GuestAdmissionError::ClockUnavailable
                    | GuestAdmissionError::ClockOutOfRange
                    | GuestAdmissionError::ClockRegression
                    | GuestAdmissionError::Poisoned
                    | GuestAdmissionError::EntropyUnavailable
                    | GuestAdmissionError::InvalidConfiguration => ttrpc::Code::UNAVAILABLE,
                    GuestAdmissionError::Contract(_) | GuestAdmissionError::BindingMismatch => {
                        ttrpc::Code::PERMISSION_DENIED
                    }
                };
                Err(ttrpc::Error::RpcStatus(ttrpc::get_status(
                    code,
                    error.to_string(),
                )))
            }
        }
    }
}

fn unavailable() -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(
        ttrpc::Code::UNIMPLEMENTED,
        "preparation admission: trusted guest gate unavailable",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_admission_default_runtime_never_accepts_host_bytes() {
        let runtime = AdmissionRuntime::default();
        for error in [
            runtime.challenge().err().unwrap(),
            runtime
                .validate(b"host-root", b"host-claims", b"true")
                .err()
                .unwrap(),
        ] {
            let ttrpc::Error::RpcStatus(status) = error else {
                panic!("expected RPC status");
            };
            assert_eq!(status.code(), ttrpc::Code::UNIMPLEMENTED);
            assert!(!status.message().contains("host-claims"));
        }
    }
}
