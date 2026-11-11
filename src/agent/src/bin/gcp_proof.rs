// SPDX-License-Identifier: Apache-2.0
//! Dedicated guest entrypoint for the GCP execution-proof profile.
#[path = "../exec_observer.rs"]
pub mod exec_observer;
#[path = "../final_task.rs"]
mod final_task;
#[path = "../final_task_runtime.rs"]
pub mod final_task_runtime;
#[path = "../gcp_protected_export.rs"]
pub mod gcp_protected_export;
#[path = "../gcp_rpc.rs"]
mod gcp_rpc;
#[path = "../gcp_startup.rs"]
mod gcp_startup;
#[path = "../protected_export.rs"]
pub mod protected_export;
#[path = "../rootfs_custody.rs"]
pub mod rootfs_custody;

fn main() -> std::process::ExitCode {
    if gcp_startup::entrypoint().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("GCP proof role startup or lifecycle rejected");
        std::process::ExitCode::FAILURE
    }
}
