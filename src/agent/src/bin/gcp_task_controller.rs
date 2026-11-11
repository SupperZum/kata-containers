// SPDX-License-Identifier: Apache-2.0
//! Host-side task controller for the GCP execution-proof profile.
#[path = "../gcp_task_controller.rs"]
mod controller;

fn main() -> std::process::ExitCode {
    match controller::entrypoint() {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(_) => std::process::ExitCode::FAILURE,
        Err(_) => {
            eprintln!("manual GCP task controller input or runtime rejected");
            std::process::ExitCode::FAILURE
        }
    }
}
