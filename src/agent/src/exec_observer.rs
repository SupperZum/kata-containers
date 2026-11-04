// SPDX-License-Identifier: Apache-2.0
//! Observe init-task exec events with the opt-in exec-observer feature.
//! Task identities bind local lifecycles and carry no attestation evidence.
//! The existing reaper supplies kernel wait statuses; the owner thread issues ptrace calls.

use anyhow::{anyhow, bail, ensure, Context, Result};
use nix::sys::{signal::Signal, wait::WaitStatus};
use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::watch;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskIdentity {
    pub container_id: String,
    pub generation: u64,
    pub pid: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Cancelled,
    ArmDenied(i32),
    QueueFull,
    ExitedBeforeExec,
    UnsupportedStop,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub armed: bool,
    pub observed: bool,
    pub terminal: bool,
    pub failure: Option<Failure>,
}

struct Entry {
    task: TaskIdentity,
    pidfd: OwnedFd,
    state: watch::Sender<Snapshot>,
}

impl Entry {
    fn observe_if_healthy(&self) {
        self.state.send_modify(|s| {
            if s.armed && s.failure.is_none() && !s.terminal {
                s.observed = true;
            }
        });
    }

    fn kill(&self) {
        // A pidfd targets this task even after its numeric PID has been reused.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }

    fn fail_and_kill(&self, failure: Failure) {
        self.state.send_modify(|s| {
            if !s.observed && !s.terminal && s.failure.is_none() {
                s.failure = Some(failure);
            }
        });
        self.kill();
    }

    fn cancel_unobserved(&self) {
        // Serialize cancellation with observation: dropping a successful RPC never kills it.
        let mut cancel = false;
        self.state.send_modify(|s| {
            if !s.observed && !s.terminal {
                s.failure.get_or_insert(Failure::Cancelled);
                cancel = true;
            }
        });
        if cancel {
            self.kill();
        }
    }
}

enum Command {
    Arm(Arc<Entry>),
    Wait(Arc<Entry>, WaitStatus),
    Wake,
}

#[derive(Default)]
struct Registry {
    active: HashMap<i32, Arc<Entry>>,
    // Bounded replay history: at most `capacity` distinct container IDs per observer lifetime.
    generations: HashMap<String, u64>,
}

struct Shared {
    registry: Mutex<Registry>,
    // Taken around SEIZE and around the sole reaper's nonblocking wait + routing.
    wait_gate: Mutex<()>,
    commands: SyncSender<Command>,
    stopping: AtomicBool,
    capacity: usize,
}

#[derive(Clone)]
pub struct Observer {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Observer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Observer").finish_non_exhaustive()
    }
}

pub struct Attempt {
    entry: Arc<Entry>,
}

impl Observer {
    pub fn start(capacity: usize) -> Result<(Self, JoinHandle<Result<()>>)> {
        ensure!((1..=1024).contains(&capacity), "invalid observer capacity");
        let (commands, receiver) = mpsc::sync_channel(capacity * 2);
        let shared = Arc::new(Shared {
            registry: Mutex::new(Registry::default()),
            wait_gate: Mutex::new(()),
            commands,
            stopping: AtomicBool::new(false),
            capacity,
        });
        let owner_shared = shared.clone();
        let owner = thread::Builder::new()
            .name("exec-observer".into())
            .spawn(move || owner_loop(owner_shared, receiver))?;
        Ok((Self { shared }, owner))
    }

    /// No await/blocking queue send. Caller holds `wait_guard()` while rechecking its live
    /// generation map and registering the gated task. The reaper invalidates that map under
    /// the same gate, before delayed exit bookkeeping, so a stale PID cannot name another task.
    pub fn arm(&self, task: TaskIdentity) -> Result<Attempt> {
        ensure!(
            !task.container_id.is_empty()
                && task.container_id.len() <= 256
                && task.generation != 0
                && task.pid > 0,
            "invalid local task identity"
        );
        ensure!(
            !self.shared.stopping.load(Ordering::Acquire),
            "observer stopping"
        );
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, task.pid, 0) };
        ensure!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let (state, _) = watch::channel(Snapshot::default());
        let entry = Arc::new(Entry { task, pidfd, state });
        let mut registry = self
            .shared
            .registry
            .lock()
            .map_err(|_| anyhow!("registry poisoned"))?;
        ensure!(
            !self.shared.stopping.load(Ordering::Acquire),
            "observer stopping"
        );
        ensure!(
            registry.active.len() < self.shared.capacity,
            "observer active capacity exhausted"
        );
        ensure!(
            !registry.active.contains_key(&entry.task.pid),
            "task PID already registered"
        );
        ensure!(
            !registry
                .active
                .values()
                .any(|e| e.task.container_id == entry.task.container_id),
            "container attempt already registered"
        );
        match registry.generations.get(&entry.task.container_id) {
            Some(previous) => ensure!(entry.task.generation > *previous, "stale task generation"),
            None => ensure!(
                registry.generations.len() < self.shared.capacity,
                "observer replay history full"
            ),
        }
        registry.active.insert(entry.task.pid, entry.clone());
        if self
            .shared
            .commands
            .try_send(Command::Arm(entry.clone()))
            .is_err()
        {
            registry.active.remove(&entry.task.pid);
            bail!("observer command capacity exhausted or owner unavailable");
        }
        registry
            .generations
            .insert(entry.task.container_id.clone(), entry.task.generation);
        Ok(Attempt { entry })
    }

    /// Hold only for waitpid(WNOHANG) + route_wait, and drop before sandbox/output/channel awaits.
    pub fn wait_guard(&self) -> Result<MutexGuard<'_, ()>> {
        self.shared
            .wait_gate
            .lock()
            .map_err(|_| anyhow!("observer wait gate poisoned"))
    }

    /// Called only by the existing kernel wait consumer, while holding `wait_guard()`.
    /// A tracked terminal status still needs the caller's ordinary exit bookkeeping.
    pub fn route_wait(&self, status: WaitStatus) -> Result<bool> {
        let Some(pid) = status.pid() else {
            return Ok(false);
        };
        let mut registry = self
            .shared
            .registry
            .lock()
            .map_err(|_| anyhow!("registry poisoned"))?;
        let Some(entry) = registry.active.get(&pid.as_raw()).cloned() else {
            return Ok(false);
        };
        // Preserve the kernel observation before queueing continuation: SIGKILL can produce
        // terminal status while the owner has not yet handled this EXEC stop.
        if matches!(status, WaitStatus::PtraceEvent(_, Signal::SIGTRAP, event)
            if event == libc::PTRACE_EVENT_EXEC)
        {
            entry.observe_if_healthy();
        }
        if matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..)) {
            entry.state.send_modify(|s| {
                s.terminal = true;
                if !s.observed && s.failure.is_none() {
                    s.failure = Some(Failure::ExitedBeforeExec);
                }
            });
            registry.active.remove(&pid.as_raw());
        } else if self
            .shared
            .commands
            .try_send(Command::Wait(entry.clone(), status))
            .is_err()
        {
            // Terminal routing never uses this queue. SIGKILL releases a stuck ptrace stop.
            entry.fail_and_kill(Failure::QueueFull);
        }
        Ok(true)
    }

    pub fn shutdown(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        let _ = self.shared.commands.try_send(Command::Wake);
    }

    pub fn active_tasks(&self) -> Result<usize> {
        Ok(self
            .shared
            .registry
            .lock()
            .map_err(|_| anyhow!("registry poisoned"))?
            .active
            .len())
    }
}

impl Attempt {
    pub fn task(&self) -> &TaskIdentity {
        &self.entry.task
    }
    pub fn snapshot(&self) -> Snapshot {
        *self.entry.state.borrow()
    }
    pub fn cancel(&self) {
        self.entry.cancel_unobserved();
    }

    async fn wait_for(&self, duration: Duration, observation: bool) -> Result<()> {
        let mut state = self.entry.state.subscribe();
        let wait = async {
            loop {
                let snapshot = *state.borrow_and_update();
                if snapshot.observed
                    || (!observation && snapshot.armed && snapshot.failure.is_none())
                {
                    return Ok(());
                }
                if let Some(failure) = snapshot.failure {
                    bail!("exec observer: {:?}", failure);
                }
                ensure!(!snapshot.terminal, "task terminated without observation");
                state.changed().await.context("observer state closed")?;
            }
        };
        match tokio::time::timeout(duration, wait).await {
            Ok(result) => result,
            Err(_) => {
                self.cancel();
                bail!("exec observer outcome timed out");
            }
        }
    }

    pub async fn wait_armed(&self, duration: Duration) -> Result<()> {
        self.wait_for(duration, false).await
    }
    pub async fn wait_observed(&self, duration: Duration) -> Result<TaskIdentity> {
        self.wait_for(duration, true).await?;
        Ok(self.entry.task.clone())
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        self.entry.cancel_unobserved();
    }
}

fn ptrace(request: libc::c_uint, pid: i32, data: usize) -> std::io::Result<()> {
    let result = unsafe { libc::ptrace(request, pid, std::ptr::null_mut::<libc::c_void>(), data) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn current(shared: &Shared, entry: &Arc<Entry>) -> Result<bool> {
    Ok(shared
        .registry
        .lock()
        .map_err(|_| anyhow!("registry poisoned"))?
        .active
        .get(&entry.task.pid)
        .is_some_and(|registered| Arc::ptr_eq(registered, entry)))
}

fn arm_on_owner(shared: &Shared, entry: &Arc<Entry>) -> Result<()> {
    let _gate = shared
        .wait_gate
        .lock()
        .map_err(|_| anyhow!("observer wait gate poisoned"))?;
    if !current(shared, entry)? || entry.state.borrow().failure.is_some() {
        return Ok(());
    }
    let result = ptrace(
        libc::PTRACE_SEIZE,
        entry.task.pid,
        (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
    );
    match result {
        Ok(()) => entry.state.send_modify(|s| {
            s.armed = true;
        }),
        Err(error) => entry.fail_and_kill(Failure::ArmDenied(
            error.raw_os_error().unwrap_or(libc::EIO),
        )),
    }
    Ok(())
}

fn wait_on_owner(shared: &Shared, entry: &Arc<Entry>, status: WaitStatus) -> Result<()> {
    if !current(shared, entry)? || entry.state.borrow().terminal {
        return Ok(());
    }
    if entry.state.borrow().failure.is_some() {
        entry.kill();
        return Ok(());
    }
    let resume = match status {
        WaitStatus::PtraceEvent(_, Signal::SIGTRAP, event) if event == libc::PTRACE_EVENT_EXEC => {
            entry.observe_if_healthy();
            ptrace(libc::PTRACE_CONT, entry.task.pid, 0)
        }
        WaitStatus::PtraceEvent(_, signal, event) if event == libc::PTRACE_EVENT_STOP => {
            if matches!(
                signal,
                Signal::SIGSTOP | Signal::SIGTSTP | Signal::SIGTTIN | Signal::SIGTTOU
            ) {
                ptrace(libc::PTRACE_LISTEN, entry.task.pid, 0)
            } else {
                ptrace(libc::PTRACE_CONT, entry.task.pid, 0)
            }
        }
        WaitStatus::Stopped(_, signal) => {
            ptrace(libc::PTRACE_CONT, entry.task.pid, signal as usize)
        }
        _ => {
            entry.fail_and_kill(Failure::UnsupportedStop);
            return Ok(());
        }
    };
    if resume.is_err() {
        entry.fail_and_kill(Failure::UnsupportedStop);
    }
    Ok(())
}

fn owner_loop(shared: Arc<Shared>, receiver: Receiver<Command>) -> Result<()> {
    let mut shutdown_started = None;
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            let started = *shutdown_started.get_or_insert_with(Instant::now);
            let active: Vec<_> = shared
                .registry
                .lock()
                .map_err(|_| anyhow!("registry poisoned"))?
                .active
                .values()
                .cloned()
                .collect();
            if active.is_empty() {
                return Ok(());
            }
            for entry in active {
                entry.fail_and_kill(Failure::Shutdown);
            }
            ensure!(
                started.elapsed() < SHUTDOWN_GRACE,
                "observer shutdown terminal drain timed out"
            );
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(Command::Arm(entry)) => arm_on_owner(&shared, &entry)?,
            Ok(Command::Wait(entry, status)) => wait_on_owner(&shared, &entry, status)?,
            Ok(Command::Wake) | Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                bail!("observer command channel disconnected")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::Pid;

    fn registered() -> (Observer, Arc<Entry>, Receiver<Command>) {
        let (commands, receiver) = mpsc::sync_channel(1);
        let (state, _) = watch::channel(Snapshot {
            armed: true,
            ..Snapshot::default()
        });
        let entry = Arc::new(Entry {
            task: TaskIdentity {
                container_id: "fixture".into(),
                generation: 1,
                pid: 123,
            },
            // Deliberately not a pidfd: these state/routing tests must never signal a task.
            pidfd: std::fs::File::open("/dev/null").unwrap().into(),
            state,
        });
        let shared = Arc::new(Shared {
            registry: Mutex::new(Registry {
                active: HashMap::from([(123, entry.clone())]),
                generations: HashMap::from([("fixture".into(), 1)]),
            }),
            wait_gate: Mutex::new(()),
            commands,
            stopping: AtomicBool::new(false),
            capacity: 1,
        });
        (Observer { shared }, entry, receiver)
    }

    #[tokio::test]
    async fn exit127_after_exec_preserves_observation_and_drop() {
        let (observer, entry, _receiver) = registered();
        entry.state.send_modify(|s| s.observed = true);
        let attempt = Attempt {
            entry: entry.clone(),
        };
        let _gate = observer.wait_guard().unwrap();
        assert!(observer
            .route_wait(WaitStatus::Exited(Pid::from_raw(123), 127))
            .unwrap());
        drop(_gate);
        assert_eq!(
            attempt.wait_observed(Duration::from_secs(1)).await.unwrap(),
            entry.task
        );
        drop(attempt);
        assert_eq!(
            *entry.state.borrow(),
            Snapshot {
                armed: true,
                observed: true,
                terminal: true,
                failure: None,
            }
        );
        assert_eq!(observer.active_tasks().unwrap(), 0);
    }

    #[tokio::test]
    async fn terminal_before_owner_processes_exec_keeps_kernel_observation() {
        let (observer, entry, _receiver) = registered();
        let attempt = Attempt {
            entry: entry.clone(),
        };
        let gate = observer.wait_guard().unwrap();
        observer
            .route_wait(WaitStatus::PtraceEvent(
                Pid::from_raw(123),
                Signal::SIGTRAP,
                libc::PTRACE_EVENT_EXEC,
            ))
            .unwrap();
        // No owner thread drains the queued EXEC before this terminal status.
        observer
            .route_wait(WaitStatus::Signaled(
                Pid::from_raw(123),
                Signal::SIGKILL,
                false,
            ))
            .unwrap();
        drop(gate);
        assert_eq!(
            attempt.wait_observed(Duration::from_secs(1)).await.unwrap(),
            entry.task
        );
        assert!(attempt.snapshot().terminal);
        assert_eq!(attempt.snapshot().failure, None);
        assert_eq!(observer.active_tasks().unwrap(), 0);
    }

    #[test]
    fn queued_exec_from_old_generation_cannot_observe_replacement() {
        let (observer, old, _receiver) = registered();
        let (state, _) = watch::channel(Snapshot {
            armed: true,
            ..Snapshot::default()
        });
        let replacement = Arc::new(Entry {
            task: TaskIdentity {
                generation: 2,
                ..old.task.clone()
            },
            pidfd: std::fs::File::open("/dev/null").unwrap().into(),
            state,
        });
        observer
            .shared
            .registry
            .lock()
            .unwrap()
            .active
            .insert(123, replacement.clone());
        wait_on_owner(
            &observer.shared,
            &old,
            WaitStatus::PtraceEvent(Pid::from_raw(123), Signal::SIGTRAP, libc::PTRACE_EVENT_EXEC),
        )
        .unwrap();
        assert!(!old.state.borrow().observed);
        assert!(!replacement.state.borrow().observed);
    }

    #[test]
    fn cancellation_before_queued_exec_prevents_observation() {
        let (observer, entry, _receiver) = registered();
        entry.cancel_unobserved();
        wait_on_owner(
            &observer.shared,
            &entry,
            WaitStatus::PtraceEvent(Pid::from_raw(123), Signal::SIGTRAP, libc::PTRACE_EVENT_EXEC),
        )
        .unwrap();
        assert_eq!(entry.state.borrow().failure, Some(Failure::Cancelled));
        assert!(!entry.state.borrow().observed);
    }

    #[test]
    fn full_stop_queue_still_allows_terminal_drain() {
        let (observer, entry, _receiver) = registered();
        assert!(observer.shared.commands.try_send(Command::Wake).is_ok());
        let _gate = observer.wait_guard().unwrap();
        assert!(observer
            .route_wait(WaitStatus::Stopped(Pid::from_raw(123), Signal::SIGTERM))
            .unwrap());
        assert_eq!(entry.state.borrow().failure, Some(Failure::QueueFull));
        assert!(observer
            .route_wait(WaitStatus::Signaled(
                Pid::from_raw(123),
                Signal::SIGKILL,
                false
            ))
            .unwrap());
        assert!(entry.state.borrow().terminal);
        assert!(!entry.state.borrow().observed);
        assert_eq!(observer.active_tasks().unwrap(), 0);
    }
}
