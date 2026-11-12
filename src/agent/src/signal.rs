// Copyright (c) 2019-2020 Ant Financial
// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::sandbox::Sandbox;
use anyhow::{anyhow, Result};
use capctl::prctl::set_subreaper;
use nix::sys::wait::WaitStatus;
#[cfg(any(not(feature = "exec-observer"), test))]
use nix::sys::wait::{self, WaitPidFlag};
#[cfg(any(not(feature = "exec-observer"), test))]
use nix::unistd::Pid;
use slog::{error, info, o, Logger};
use std::sync::Arc;
use tokio::select;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch::Receiver;
use tokio::sync::Mutex;

// Offset added to a signal number to derive the exit code of a process that
// was terminated by that signal, following the conventional shell semantics
// described in https://tldp.org/LDP/abs/html/exitcodes.html.
const SIGNAL_EXIT_CODE_BASE: i32 = 128;

/// Derive a process exit code from its `WaitStatus`.
///
/// A process that exits normally reports its own exit code, while a process
/// terminated by a signal reports `128 + signal_number` (e.g. SIGKILL(9) ->
/// 137, SIGTERM(15) -> 143). Returns `None` for statuses that do not represent
/// process termination (e.g. stopped/continued), which the caller should skip.
fn exit_code_from_wait_status(wait_status: WaitStatus) -> Option<i32> {
    match wait_status {
        WaitStatus::Exited(_, code) => Some(code),
        WaitStatus::Signaled(_, sig, _) => Some(SIGNAL_EXIT_CODE_BASE + (sig as i32)),
        _ => None,
    }
}

#[cfg(not(feature = "exec-observer"))]
async fn handle_sigchild(logger: Logger, sandbox: Arc<Mutex<Sandbox>>) -> Result<()> {
    info!(logger, "handling signal"; "signal" => "SIGCHLD");

    loop {
        // Avoid reaping the undesirable child's signal, e.g., execute_hook's
        // The lock should be released immediately.
        let _locker = rustjail::container::WAIT_PID_LOCKER.lock().await;
        let result = wait::waitpid(
            Some(Pid::from_raw(-1)),
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::__WALL),
        );

        let wait_status = match result {
            Ok(s) => {
                if s == WaitStatus::StillAlive {
                    return Ok(());
                }
                s
            }
            Err(e) => return Err(anyhow!(e).context("waitpid reaper failed")),
        };

        info!(logger, "wait_status"; "wait_status result" => format!("{:?}", wait_status));

        if let Some(pid) = wait_status.pid() {
            let raw_pid = pid.as_raw();
            let child_pid = format!("{raw_pid}");

            let logger = logger.new(o!("child-pid" => child_pid));

            let sandbox_ref = sandbox.clone();
            let mut sandbox = sandbox_ref.lock().await;

            let process = sandbox.find_process(raw_pid);
            if process.is_none() {
                info!(logger, "child exited unexpectedly");
                continue;
            }

            let p = process.unwrap();

            let ret: i32 = match exit_code_from_wait_status(wait_status) {
                Some(code) => code,
                None => {
                    info!(logger, "got wrong status for process";
                                  "child-status" => format!("{:?}", wait_status));
                    continue;
                }
            };

            // In passfd io mode, we need to wait for the copy task end.
            if let Some(proc_io) = &mut p.proc_io {
                proc_io.wg_output.wait().await;
            }

            p.exit_code = ret;
            let _ = p.exit_tx.take();

            info!(logger, "notify term to close");
            // close the socket file to notify readStdio to close terminal specifically
            // in case this process's terminal has been inherited by its children.
            p.notify_term_close();
        }
    }
}

#[cfg(not(feature = "exec-observer"))]
pub async fn setup_signal_handler(
    logger: Logger,
    sandbox: Arc<Mutex<Sandbox>>,
    mut shutdown: Receiver<bool>,
) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "signals"));

    set_subreaper(true)
        .map_err(|err| anyhow!(err).context("failed to setup agent as a child subreaper"))?;

    let mut sigchild_stream = signal(SignalKind::child())?;

    loop {
        select! {
            _ = shutdown.changed() => {
                info!(logger, "got shutdown request");
                break;
            }

            _ = sigchild_stream.recv() => {
                let result = handle_sigchild(logger.clone(), sandbox.clone()).await;

                match result {
                    Ok(()) => (),
                    Err(e) => {
                        // Log errors, but don't abort - just wait for more signals!
                        error!(logger, "failed to handle signal"; "error" => format!("{:?}", e));
                    }
                }
            }
        }
    }

    Ok(())
}

/// Coordinate waitpid, observer routing and terminal task bookkeeping under one gate.
#[cfg(feature = "exec-observer")]
async fn reap_observed_status(
    observer: &crate::exec_observer::Observer,
    tasks: &crate::rpc::SharedExecTasks,
) -> Result<Option<(WaitStatus, Option<crate::exec_observer::TaskIdentity>)>> {
    let _wait = rustjail::container::WAIT_PID_LOCKER.lock().await;
    let _gate = observer.wait_guard()?;
    let Some(status) = observer.poll_kernel_wait()? else {
        return Ok(None);
    };
    let identity = if exit_code_from_wait_status(status).is_some() {
        let pid = status
            .pid()
            .ok_or_else(|| anyhow!("terminal status without PID"))?;
        tasks
            .lock()
            .map_err(|_| anyhow!("task registry poisoned"))?
            .terminal(pid.as_raw())
    } else {
        None
    };
    Ok(Some((status, identity)))
}

/// Route kernel stops before any sandbox/output await. Only registered init exits create jobs.
#[cfg(feature = "exec-observer")]
async fn drain_observed_children(
    logger: &Logger,
    sandbox: &Arc<Mutex<Sandbox>>,
    observer: &crate::exec_observer::Observer,
    tasks: &crate::rpc::SharedExecTasks,
    exits: &mut tokio::task::JoinSet<Result<()>>,
) -> Result<()> {
    loop {
        let Some((status, identity)) = reap_observed_status(observer, tasks).await? else {
            break;
        };
        if let Some(identity) = identity {
            while let Some(result) = exits.try_join_next() {
                observe_exit_job(logger, observer, tasks, result);
            }
            // A task registry slot is held until notification completion, bounding live jobs.
            if exits.len() >= 64 {
                if let Some(result) = exits.join_next().await {
                    observe_exit_job(logger, observer, tasks, result);
                }
            }
            exits.spawn(notify_observed_exit(
                sandbox.clone(),
                tasks.clone(),
                identity,
                status,
            ));
        } else if exit_code_from_wait_status(status).is_some() {
            info!(logger, "unregistered child exited");
        }
    }
    Ok(())
}

#[cfg(feature = "exec-observer")]
fn observe_exit_job(
    logger: &Logger,
    observer: &crate::exec_observer::Observer,
    tasks: &crate::rpc::SharedExecTasks,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) {
    let error = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error,
        Err(error) => anyhow!(error),
    };
    observer.shutdown();
    if let Ok(mut tasks) = tasks.lock() {
        tasks.stop_admission();
    }
    error!(logger, "exit notification failed"; "error" => error.to_string());
}

#[cfg(feature = "exec-observer")]
async fn notify_observed_exit(
    sandbox: Arc<Mutex<Sandbox>>,
    tasks: crate::rpc::SharedExecTasks,
    identity: crate::exec_observer::TaskIdentity,
    status: WaitStatus,
) -> Result<()> {
    let result = async {
        let notification = {
            let mut sandbox = sandbox.lock().await;
            let Some(container) = sandbox.containers.get(&identity.container_id) else {
                return Ok(());
            };
            if container.init_process_pid != identity.pid {
                return Err(anyhow!("exit task generation mismatch"));
            }
            let Some(process) = sandbox.find_process(identity.pid) else {
                return Ok(());
            };
            process.exit_code = exit_code_from_wait_status(status)
                .ok_or_else(|| anyhow!("nonterminal exit job"))?;
            let output = process
                .proc_io
                .as_mut()
                .map(|io| std::mem::take(&mut io.wg_output));
            (
                output,
                process.exit_tx.take(),
                process.term_exit_notifier.clone(),
            )
        };
        // Own this task's original notification objects; no lock or PID lookup after this wait.
        if let Some(mut output) = notification.0 {
            output.wait().await;
        }
        drop(notification.1);
        notification.2.notify_waiters();
        Ok(())
    }
    .await;
    tasks
        .lock()
        .map_err(|_| anyhow!("task registry poisoned"))?
        .finish(&identity);
    result
}

#[cfg(feature = "exec-observer")]
pub async fn setup_signal_handler(
    logger: Logger,
    sandbox: Arc<Mutex<Sandbox>>,
    mut shutdown: Receiver<bool>,
    observer: crate::exec_observer::Observer,
    tasks: crate::rpc::SharedExecTasks,
) -> Result<()> {
    let logger = logger.new(o!("subsystem" => "signals"));
    let _stop_owner = scopeguard::guard((observer.clone(), tasks.clone()), |(observer, tasks)| {
        observer.shutdown();
        if let Ok(mut tasks) = tasks.lock() {
            tasks.stop_admission();
        }
    });
    set_subreaper(true).map_err(|e| anyhow!(e).context("failed to setup subreaper"))?;
    let mut signals = signal(SignalKind::child())?;
    let mut exits = tokio::task::JoinSet::new();
    loop {
        select! {
            _ = shutdown.changed() => break,
            _ = signals.recv() => {
                if let Err(error) = drain_observed_children(&logger, &sandbox, &observer, &tasks, &mut exits).await {
                    observer.shutdown();
                    if let Ok(mut tasks) = tasks.lock() { tasks.stop_admission(); }
                    error!(logger, "observer reaper failed"; "error" => error.to_string());
                }
            },
            Some(result) = exits.join_next(), if !exits.is_empty() => {
                observe_exit_job(&logger, &observer, &tasks, result);
            },
        }
    }
    // Main shuts down and joins the ptrace owner while this wait consumer is still running.
    // A stuck output stream must not keep agent shutdown unbounded.
    let drain = async {
        while let Some(result) = exits.join_next().await {
            observe_exit_job(&logger, &observer, &tasks, result);
        }
    };
    if let Err(error) = tokio::time::timeout(std::time::Duration::from_secs(5), drain).await {
        exits.abort_all();
        while exits.join_next().await.is_some() {}
        return Err(anyhow!(error).context("exit output notification drain timed out"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::Signal;
    use tokio::pin;
    use tokio::sync::watch::channel;
    use tokio::time::Duration;

    #[test]
    fn test_exit_code_from_wait_status() {
        let pid = Pid::from_raw(1);

        // Normal exits report their own code unchanged.
        assert_eq!(
            exit_code_from_wait_status(WaitStatus::Exited(pid, 0)),
            Some(0)
        );
        assert_eq!(
            exit_code_from_wait_status(WaitStatus::Exited(pid, 42)),
            Some(42)
        );

        // Signal-terminated processes report 128 + signal number.
        // SIGKILL(9) -> 137, SIGTERM(15) -> 143, SIGINT(2) -> 130,
        // SIGSEGV(11) -> 139.
        for (sig, expected) in [
            (Signal::SIGKILL, 137),
            (Signal::SIGTERM, 143),
            (Signal::SIGINT, 130),
            (Signal::SIGSEGV, 139),
        ] {
            assert_eq!(
                exit_code_from_wait_status(WaitStatus::Signaled(pid, sig, false)),
                Some(expected),
                "unexpected exit code for {sig:?}"
            );
        }

        // Non-terminating statuses are skipped.
        assert_eq!(
            exit_code_from_wait_status(WaitStatus::Stopped(pid, Signal::SIGSTOP)),
            None
        );
        assert_eq!(exit_code_from_wait_status(WaitStatus::StillAlive), None);
    }

    #[tokio::test]
    async fn test_setup_signal_handler() {
        let logger = slog::Logger::root(slog::Discard, o!());
        let s = Sandbox::new(&logger).unwrap();

        let sandbox = Arc::new(Mutex::new(s));

        let (tx, rx) = channel(true);

        #[cfg(feature = "exec-observer")]
        let (observer, owner) = crate::exec_observer::Observer::start(4).unwrap();
        let handle = tokio::spawn(setup_signal_handler(
            logger,
            sandbox,
            rx,
            #[cfg(feature = "exec-observer")]
            observer.clone(),
            #[cfg(feature = "exec-observer")]
            Arc::new(std::sync::Mutex::new(crate::rpc::ExecTasks::default())),
        ));

        let timeout = tokio::time::sleep(Duration::from_secs(1));
        pin!(timeout);

        tx.send(true).expect("failed to request shutdown");

        select! {
            _ = handle => {
                println!("INFO: task completed");
            },
            _ = &mut timeout => {
                panic!("signal thread failed to stop");
            }
        }
        #[cfg(feature = "exec-observer")]
        {
            observer.shutdown();
            owner.join().unwrap().unwrap();
        }
    }
    /// Check kernel exec and terminal events through the kata-agent wait dispatcher.
    #[cfg(feature = "exec-observer")]
    #[tokio::test(flavor = "current_thread")]
    async fn test_observer_wait_routing_real_exec_and_terminal() {
        let mut gate = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // Use only async-signal-safe syscalls in the child before exec.
            unsafe {
                libc::close(gate[1]);
                libc::alarm(5);
                let mut go = 0u8;
                loop {
                    let n = libc::read(gate[0], (&mut go as *mut u8).cast(), 1);
                    if n == 1 {
                        break;
                    }
                    if n < 0 && *libc::__errno_location() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(125);
                }
                let path = b"/usr/bin/true\0";
                let args = [path.as_ptr().cast::<libc::c_char>(), std::ptr::null()];
                let env = [std::ptr::null::<libc::c_char>()];
                libc::execve(args[0], args.as_ptr(), env.as_ptr());
                libc::_exit(126);
            }
        }
        unsafe {
            libc::close(gate[0]);
        }
        let (observer, owner) = crate::exec_observer::Observer::start(4).unwrap();
        let _stop = scopeguard::guard(observer.clone(), |o| o.shutdown());
        let tasks = Arc::new(std::sync::Mutex::new(crate::rpc::ExecTasks::default()));
        let attempt = {
            let _guard = observer.wait_guard().unwrap();
            let task = tasks
                .lock()
                .unwrap()
                .register("local-reaper-fixture", pid)
                .unwrap();
            observer.arm(task).unwrap()
        };
        attempt.wait_armed(Duration::from_secs(2)).await.unwrap();
        assert_eq!(unsafe { libc::write(gate[1], b"G".as_ptr().cast(), 1) }, 1);
        unsafe {
            libc::close(gate[1]);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while !attempt.snapshot().terminal {
                reap_observed_status(&observer, &tasks).await.unwrap();
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(attempt.snapshot().observed);
        assert!(tasks
            .lock()
            .unwrap()
            .tasks
            .get("local-reaper-fixture")
            .is_none_or(|task| !task.live));
        tasks.lock().unwrap().finish(attempt.task());
        assert!(tasks.lock().unwrap().tasks.is_empty());
        assert_eq!(observer.active_tasks().unwrap(), 0);
        observer.shutdown();
        owner.join().unwrap().unwrap();
        assert_eq!(
            wait::waitpid(Some(Pid::from_raw(pid)), Some(WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
    }
}
