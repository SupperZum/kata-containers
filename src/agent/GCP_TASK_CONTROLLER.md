# GCP execution-proof task controller

`kata-gcp-task-controller` drives one task through an existing CAA Unix proxy
socket. Provision the PodVM and proxy separately and use an absolute Unix
socket path. Provision the guest with the `kata-agent-gcp-proof`
entrypoint. Include `libseccomp.so.2` in the measured guest image. The guest
loads it at runtime to resolve the approved syscall names, so an inventory
based on ELF link dependencies alone will omit it.

```sh
cargo build --locked --no-default-features --features gcp-task-controller --bin kata-gcp-task-controller
kata-gcp-task-controller --control public-control.json --socket /absolute/caa-proxy.sock --timeout-seconds 120
```

The public control JSON contains exactly the following fields.

| Field | Value |
| --- | --- |
| `version` | `1` |
| `purpose` | `qlad.execution-proof.gcp-manual-task-control.v1` |
| `signed_plan` | The public `Signed<GcpAttemptPlanV1>` object |
| `effective_spec` | The original candidate JSON as a byte array, up to 256 KiB |
| `sandbox_alias` | An untrusted control-plane identifier, up to 128 bytes |

The control file is limited to 2 MiB. The controller checks the plan's
structure, signature encoding, candidate SHA384 and supported OCI profile.
The guest independently authenticates the plan and admission, and selects the
task using the plan's `container_id` and its one-use custody lease. The OCI
profile permits up to 32 arguments and 64 environment entries, with a 4096-byte
limit per string and a 32 KiB aggregate limit. Paths may contain at most 256
bytes and 32 components. The profile uses three syscalls and a JSON depth
limit of 16.

The controller checks guest health, registers the sandbox alias, checks the
guest profile, and submits `CreateContainer` and `StartContainer`. It encodes
the signed OCI candidate directly as protobuf. The guest compares that
protobuf to its retained candidate and uses the original OCI spec to create the
task. This preserves fields omitted by the protobuf representation. The
ordinary CRI shim is outside this profile.

The controller waits for exit while draining stdout and stderr concurrently.
Before exit, an empty read can indicate temporary lack of data. The first empty
read issued after the wait response ends that stream. Each stream is capped at
32 KiB and sets its `may_have_more` flag when the cap is reached. A task that
blocks while writing additional output can reach the RPC deadline.

The timeout is 1 to 120 seconds, with up to five seconds reserved for one
best-effort `RemoveContainer` after a failed task RPC. An unsupported guest
profile stops before task creation. On successful transport, the guest keeps
the task record for the protected export and cleanup path.

The JSON result contains the RPC outcome, task exit status, and bounded base64
stdout and stderr. A nonzero task exit can accompany a successful transport
result. Use the protected export and independent verifier for execution-proof
evidence.
