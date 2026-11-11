// SPDX-License-Identifier: Apache-2.0

//! Exact GCP protocol projection of an already authenticated signed candidate.
//! The protocol cannot represent every OCI field (notably defaultErrnoRet).
//! Such fields remain owned by the strict signed profile and original OCI spec.

use anyhow::{ensure, Context, Result};
use image_rs::preparation::launch_spec::BoundEffectiveSpec;
use oci_spec::runtime::Spec;

pub(crate) fn verified_protocol_spec(
    candidate: &BoundEffectiveSpec,
    submitted: &protocols::oci::Spec,
) -> Result<Spec> {
    // candidate was bounded and checked by the receiver's authenticated lease.
    // This conversion uses only trusted enum strings, never untrusted protobuf.
    let trusted: Spec =
        serde_json::from_slice(candidate.raw_bytes()).context("trusted GCP candidate rejected")?;
    let expected: protocols::oci::Spec = trusted.clone().into();
    // Generated message equality includes all nested fields, presence and
    // SpecialFields. Unknown fields and unsupported enum strings cannot vanish
    // through a lossy protocol-to-OCI conversion before this comparison.
    ensure!(submitted == &expected, "GCP protocol candidate mismatch");
    Ok(trusted)
}
