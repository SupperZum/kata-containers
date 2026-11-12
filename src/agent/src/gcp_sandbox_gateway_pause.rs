// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, ensure, Result};
use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::ExitStatusExt,
    },
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStdout},
    sync::Mutex,
};

const READY_TIME: Duration = Duration::from_secs(2);
const REAP_TIME: Duration = Duration::from_secs(3);

#[derive(Default)]
pub(super) enum Pause {
    #[default]
    Empty,
    Created,
    Starting(Process),
    Running(Process),
    Exited(i32),
    Removed(Option<i32>),
}

pub(super) struct Process {
    child: Child,
    pidfd: OwnedFd,
}

impl Process {
    async fn spawn(mut command: tokio::process::Command) -> Result<(Self, ChildStdout)> {
        command
            .env_clear()
            .env("ONB17_GCP_PAUSE_PARENT", std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let pid = child.id().ok_or_else(|| anyhow!("pause child missing"))?;
        // The child is owned by this handle and has not been reaped. Use its
        // pidfd for subsequent signals so PID reuse cannot retarget a request.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            child.kill().await?;
            return Err(error.into());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let ready = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("pause readiness pipe missing"))?;
        Ok((Self { child, pidfd }, ready))
    }

    async fn wait_ready(mut ready: ChildStdout) -> Result<()> {
        let read = async {
            let mut marker = [0; 1];
            ready.read_exact(&mut marker).await?;
            ensure!(marker == *b"P", "pause readiness marker mismatch");
            ensure!(
                ready.read(&mut marker).await? == 0,
                "pause readiness framing"
            );
            Ok(())
        };
        tokio::time::timeout(READY_TIME, read)
            .await
            .unwrap_or_else(|_| Err(anyhow!("pause readiness deadline")))
    }

    fn signal(&self, signal: i32) -> Result<()> {
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(())
    }
}

fn exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

impl Pause {
    pub(super) fn create(&mut self) -> Result<()> {
        ensure!(matches!(self, Self::Empty), "pause slot already used");
        *self = Self::Created;
        Ok(())
    }

    pub(super) async fn start(&mut self) -> Result<()> {
        let mut command = tokio::process::Command::new("/proc/self/exe");
        command.arg("--gcp-sandbox-pause");
        self.launch(command).await
    }

    #[cfg(test)]
    pub(super) async fn start_fixture(&mut self) -> Result<()> {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "printf P; exec 1>&-; exec /bin/sleep 300"]);
        self.launch(command).await
    }

    async fn launch(&mut self, command: tokio::process::Command) -> Result<()> {
        ensure!(matches!(self, Self::Created), "pause start out of order");
        // Reserve the one launch before spawning. The gateway continues to
        // own the actual child if the caller drops Start during readiness.
        *self = Self::Removed(None);
        let (process, ready) = Process::spawn(command).await?;
        *self = Self::Starting(process);
        if let Err(error) = Process::wait_ready(ready).await {
            self.remove().await?;
            return Err(error);
        }
        let Self::Starting(process) = std::mem::replace(self, Self::Removed(None)) else {
            return Err(anyhow!("pause process ownership lost"));
        };
        *self = Self::Running(process);
        Ok(())
    }

    pub(super) fn signal(&mut self, signal: i32) -> Result<()> {
        ensure!(
            matches!(signal, libc::SIGTERM | libc::SIGKILL),
            "unsupported pause signal"
        );
        match self {
            Self::Running(process) => process.signal(signal),
            Self::Exited(_) | Self::Removed(Some(_)) => Ok(()),
            _ => Err(anyhow!("pause process unavailable")),
        }
    }

    pub(super) fn running(&mut self) -> Result<bool> {
        if let Self::Running(process) = self {
            if let Some(status) = process.child.try_wait()? {
                *self = Self::Exited(exit_code(status));
            }
        }
        Ok(matches!(self, Self::Running(_)))
    }

    pub(super) async fn wait(pause: &Mutex<Self>) -> Result<i32> {
        loop {
            {
                let mut pause = pause.lock().await;
                pause.running()?;
                match &*pause {
                    Self::Running(_) => {}
                    Self::Exited(code) | Self::Removed(Some(code)) => return Ok(*code),
                    _ => return Err(anyhow!("pause process unavailable")),
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub(super) async fn remove(&mut self) -> Result<()> {
        self.running()?;
        let code = match self {
            Self::Starting(process) | Self::Running(process) => {
                process.signal(libc::SIGKILL)?;
                let status = tokio::time::timeout(REAP_TIME, process.child.wait()).await??;
                Some(exit_code(status))
            }
            Self::Exited(code) => Some(*code),
            Self::Removed(_) => return Ok(()),
            _ => None,
        };
        *self = Self::Removed(code);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_start_retains_pause_child_for_explicit_reap() {
        let mut pause = Pause::Created;
        let mut command = tokio::process::Command::new("/bin/sleep");
        command.arg("300");
        let mut start = Box::pin(pause.launch(command));
        // This child never produces the readiness marker. Poll until the
        // handle is in the shared Starting state, then drop the caller.
        assert!(futures::poll!(&mut start).is_pending());
        drop(start);
        assert!(matches!(pause, Pause::Starting(_)));
        pause.remove().await.unwrap();
        assert!(matches!(pause, Pause::Removed(Some(code)) if code == 128 + libc::SIGKILL));
    }
}
