// SPDX-License-Identifier: Apache-2.0

//! Launch a gated init task with its pidfd and private namespaces.
//! The child uses preallocated inputs and executes the held entry descriptor.

use anyhow::{anyhow, ensure, Result};
use std::{
    ffi::CString,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    ptr,
};

const AUDIT_X86_64: u32 = 0xc000003e;

pub struct ExecInputs<'a> {
    pub root: BorrowedFd<'a>,
    pub cwd: BorrowedFd<'a>,
    pub executable: BorrowedFd<'a>,
    pub args: &'a [String],
    pub env: &'a [String],
    pub uid: u32,
    pub gid: u32,
    pub syscalls: &'a [String],
    pub stdio: [BorrowedFd<'a>; 3],
}

pub struct PreparedExec {
    root: OwnedFd,
    cwd: OwnedFd,
    executable: OwnedFd,
    _args: Vec<CString>,
    _env: Vec<CString>,
    stdio: [OwnedFd; 3],
    argv: Vec<*const libc::c_char>,
    envp: Vec<*const libc::c_char>,
    uid: u32,
    gid: u32,
    filter: Vec<libc::sock_filter>,
}

impl PreparedExec {
    pub fn new(inputs: ExecInputs<'_>) -> Result<Self> {
        let ExecInputs {
            root,
            cwd,
            executable,
            args,
            env,
            uid,
            gid,
            syscalls,
            stdio,
        } = inputs;
        ensure!(
            cfg!(target_arch = "x86_64")
                && uid != 0
                && gid != 0
                && uid != u32::MAX
                && gid != u32::MAX,
            "unsupported final task identity or architecture"
        );
        ensure!(
            !args.is_empty() && args.len() <= 256 && env.len() <= 256,
            "final task string count"
        );
        let convert = |items: &[String]| -> Result<Vec<CString>> {
            let mut total = 0usize;
            items
                .iter()
                .map(|s| {
                    total = total
                        .checked_add(s.len() + 1)
                        .ok_or_else(|| anyhow!("final task string budget"))?;
                    ensure!(
                        s.len() <= 16384 && total <= 1 << 20,
                        "final task string budget"
                    );
                    Ok(CString::new(s.as_bytes())?)
                })
                .collect()
        };
        let args = convert(args)?;
        let env = convert(env)?;
        let mut argv: Vec<_> = args.iter().map(|s| s.as_ptr()).collect();
        argv.push(ptr::null());
        let mut envp: Vec<_> = env.iter().map(|s| s.as_ptr()).collect();
        envp.push(ptr::null());
        Ok(Self {
            root: reserve_alias(root)?,
            cwd: reserve_alias(cwd)?,
            executable: reserve_alias(executable)?,
            _args: args,
            _env: env,
            stdio: [
                reserve_alias(stdio[0])?,
                reserve_alias(stdio[1])?,
                reserve_alias(stdio[2])?,
            ],
            argv,
            envp,
            uid,
            gid,
            filter: compile_filter(syscalls)?,
        })
    }

    /// The caller holds the sole reaper's wait gate until PID registration.
    /// After success only the designated reaper may wait for the child.
    pub fn spawn(self) -> Result<GatedChild> {
        let mut ends = [-1; 2];
        ensure!(
            unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
            "create final task gate: {}",
            std::io::Error::last_os_error()
        );
        let read = unsafe { OwnedFd::from_raw_fd(ends[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(ends[1]) };
        let parent_fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        ensure!(parent_fd >= 0, "open creator pidfd");
        let original_parent = unsafe { OwnedFd::from_raw_fd(parent_fd as i32) };
        let parent_fd = reserve_alias(std::os::fd::AsFd::as_fd(&original_parent))?;
        drop(original_parent);
        let mut pidfd = -1i32;
        let clone = CloneArgs {
            flags: (libc::CLONE_PIDFD
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWNET) as u64,
            pidfd: (&mut pidfd as *mut i32) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        // SAFETY: clone3 has fork semantics (no shared VM). In the child only
        // libc syscalls over preallocated immutable inputs run before execveat.
        let pid =
            unsafe { libc::syscall(libc::SYS_clone3, &clone, std::mem::size_of::<CloneArgs>()) };
        if pid == 0 {
            unsafe { self.child(read.as_raw_fd(), write.as_raw_fd(), parent_fd.as_raw_fd()) }
        }
        ensure!(
            pid > 0 && pidfd >= 0,
            "clone3 final task: {}",
            std::io::Error::last_os_error()
        );
        drop(read);
        Ok(GatedChild {
            pid: pid as i32,
            pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
            gate: Some(write),
        })
    }

    unsafe fn child(&self, read: i32, write: i32, parent: i32) -> ! {
        let fail = || unsafe { libc::_exit(126) };
        libc::close(write);
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            fail();
        }
        let mut parent_poll = libc::pollfd {
            fd: parent,
            events: libc::POLLIN,
            revents: 0,
        };
        if libc::poll(&mut parent_poll, 1, 0) != 0 {
            fail();
        }
        let mut byte = [0u8];
        loop {
            let n = libc::read(read, byte.as_mut_ptr().cast(), 1);
            if n == 1 {
                break;
            }
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            fail();
        }
        libc::close(read);
        for (target, source) in self.stdio.iter().enumerate() {
            if libc::dup2(source.as_raw_fd(), target as i32) < 0 {
                fail();
            }
        }
        libc::umask(0o022);
        if libc::prctl(libc::PR_SET_SECUREBITS, 0, 0, 0, 0) != 0 {
            fail();
        }
        for capability in 0..64 {
            let exists = libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0);
            if exists < 0 {
                if *libc::__errno_location() == libc::EINVAL {
                    break;
                }
                fail();
            }
            if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
                fail();
            }
        }
        for fd in 0..3 {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) != 0 {
                fail();
            }
        }
        if byte[0] != 1
            || libc::mount(
                ptr::null(),
                b"/\0".as_ptr().cast::<libc::c_char>(),
                ptr::null(),
                (libc::MS_REC | libc::MS_PRIVATE) as _,
                ptr::null(),
            ) != 0
            || libc::fchdir(self.root.as_raw_fd()) != 0
            || libc::chroot(b".\0".as_ptr().cast::<libc::c_char>()) != 0
            || libc::fchdir(self.cwd.as_raw_fd()) != 0
            || libc::setgroups(0, ptr::null()) != 0
            || libc::setresgid(self.gid, self.gid, self.gid) != 0
            || libc::setresuid(self.uid, self.uid, self.uid) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            fail();
        }
        // setresuid from root clears permitted/effective/ambient capabilities;
        // clear inheritable explicitly so no future file can recover authority.
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let header = Header {
            version: 0x20080522,
            pid: 0,
        };
        let data = [
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            Data {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &header, data.as_ptr()) != 0 {
            fail();
        }
        // Credential changes clear PDEATHSIG. Reinstall it and close the race
        // with the retained creator pidfd before releasing that descriptor.
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
            fail();
        }
        if libc::poll(&mut parent_poll, 1, 0) != 0 {
            fail();
        }
        libc::close(parent);

        // Every inherited descriptor closes on successful exec. The entry FD
        // remains usable by execveat itself; no interpreter is supported.
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
            fail();
        }
        let program = libc::sock_fprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr() as *mut _,
        };
        if libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0 {
            fail();
        }
        libc::syscall(
            libc::SYS_execveat,
            self.executable.as_raw_fd(),
            b"\0".as_ptr().cast::<libc::c_char>(),
            self.argv.as_ptr(),
            self.envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127)
    }
}

#[derive(Default)]
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub struct GatedChild {
    pid: i32,
    pidfd: OwnedFd,
    gate: Option<OwnedFd>,
}
impl GatedChild {
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn into_parts(mut self) -> (i32, OwnedFd, ReleaseGate) {
        let gate = self.gate.take().expect("unreleased gate");
        let pidfd = unsafe { std::ptr::read(&self.pidfd) };
        let pid = self.pid;
        std::mem::forget(self);
        (pid, pidfd, ReleaseGate(Some(gate)))
    }
    pub fn kill(&self) {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }
}
impl Drop for GatedChild {
    fn drop(&mut self) {
        if self.gate.is_some() {
            self.kill();
        }
    }
}

pub struct ReleaseGate(Option<OwnedFd>);
impl ReleaseGate {
    pub fn release(&mut self) -> Result<()> {
        let gate = self
            .0
            .take()
            .ok_or_else(|| anyhow!("final task already released"))?;
        let byte = [1u8];
        let n = unsafe { libc::write(gate.as_raw_fd(), byte.as_ptr().cast(), 1) };
        ensure!(
            n == 1,
            "final task gate release: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}

fn reserve_alias(fd: BorrowedFd<'_>) -> Result<OwnedFd> {
    let alias = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 128) };
    ensure!(
        alias >= 128,
        "reserve final task descriptor alias: {}",
        std::io::Error::last_os_error()
    );
    Ok(unsafe { OwnedFd::from_raw_fd(alias) })
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}
fn compile_filter(names: &[String]) -> Result<Vec<libc::sock_filter>> {
    ensure!(
        !names
            .iter()
            .any(|name| matches!(name.as_str(), "fork" | "vfork" | "clone" | "clone3")),
        "final task profile supports one init process only"
    );

    ensure!(
        !names.is_empty() && names.len() <= 32,
        "seccomp syscall count"
    );
    // Resolve names in the trusted parent. Child execution needs no dynamic
    // loader, allocation or seccomp library after clone3.
    let handle = unsafe {
        libc::dlopen(
            b"libseccomp.so.2\0".as_ptr().cast::<libc::c_char>(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        )
    };
    ensure!(
        !handle.is_null(),
        "installed seccomp syscall resolver unavailable"
    );
    struct Library(*mut libc::c_void);
    impl Drop for Library {
        fn drop(&mut self) {
            unsafe {
                libc::dlclose(self.0);
            }
        }
    }
    let _library = Library(handle);
    let symbol = unsafe {
        libc::dlsym(
            handle,
            b"seccomp_syscall_resolve_name_arch\0"
                .as_ptr()
                .cast::<libc::c_char>(),
        )
    };
    ensure!(
        !symbol.is_null(),
        "seccomp syscall resolver symbol unavailable"
    );
    let resolve: unsafe extern "C" fn(u32, *const libc::c_char) -> i32 =
        unsafe { std::mem::transmute(symbol) };
    let mut numbers = std::collections::BTreeSet::new();
    for name in names {
        let name = CString::new(name.as_bytes())?;
        let number = unsafe { resolve(AUDIT_X86_64, name.as_ptr()) };
        ensure!(number >= 0, "unsupported native syscall name");
        numbers.insert(number as u32);
    }
    ensure!(
        numbers.contains(&(libc::SYS_execveat as u32))
            && numbers.contains(&(libc::SYS_exit_group as u32)),
        "seccomp profile must allow final exec and failure exit"
    );
    let mut code = vec![
        instruction(0x20, 0, 0, 4),
        instruction(0x15, 1, 0, AUDIT_X86_64),
        instruction(0x06, 0, 0, 0x80000000),
        instruction(0x20, 0, 0, 0),
        instruction(0x45, 0, 1, 0x40000000),
        instruction(0x06, 0, 0, 0x80000000),
    ];
    for number in numbers {
        code.push(instruction(0x15, 0, 1, number));
        code.push(instruction(0x06, 0, 0, 0x7fff0000));
    }
    code.push(instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32));
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn evaluate(filter: &[libc::sock_filter], nr: u32, arch: u32) -> u32 {
        let (mut pc, mut value) = (0usize, 0u32);
        loop {
            let instruction = &filter[pc];
            match instruction.code {
                0x20 => value = if instruction.k == 4 { arch } else { nr },
                0x15 => {
                    pc += if value == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize
                }
                0x45 => {
                    pc += if value & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize
                }
                0x06 => return instruction.k,
                _ => panic!("unexpected BPF instruction"),
            }
            pc += 1;
        }
    }

    #[test]
    fn exact_native_filter_rejects_other_arch_x32_and_unlisted_calls() {
        let filter =
            compile_filter(&["execveat".into(), "exit_group".into(), "write".into()]).unwrap();
        assert_eq!(
            evaluate(&filter, libc::SYS_write as u32, AUDIT_X86_64),
            0x7fff0000
        );
        assert_eq!(
            evaluate(&filter, libc::SYS_getppid as u32, AUDIT_X86_64),
            0x00050000 | libc::EPERM as u32
        );
        assert_eq!(
            evaluate(&filter, libc::SYS_write as u32 | 0x40000000, AUDIT_X86_64),
            0x80000000
        );
        assert_eq!(
            evaluate(&filter, libc::SYS_write as u32, 0x40000003),
            0x80000000
        );
        assert!(compile_filter(&["unknown_native_syscall".into()]).is_err());
        assert!(compile_filter(&["write".into()]).is_err());
        assert!(compile_filter(&vec!["write".into(); 33]).is_err());
        for syscall in ["fork", "vfork", "clone", "clone3"] {
            assert!(
                compile_filter(&["execveat".into(), "exit_group".into(), syscall.into()]).is_err()
            );
        }
    }

    #[test]
    fn descriptor_aliases_survive_closed_stdio() {
        const CHILD: &str = "KATA_FINAL_FD_ALIAS_TEST";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "final_task::tests::descriptor_aliases_survive_closed_stdio",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        unsafe {
            libc::close(0);
            libc::close(1);
            libc::close(2);
        }
        let root = std::fs::File::open("/").unwrap();
        let file = std::fs::File::open("/proc/self/exe").unwrap();
        let prepared = PreparedExec::new(ExecInputs {
            root: root.as_fd(),
            cwd: root.as_fd(),
            executable: file.as_fd(),
            args: &["/entry".into()],
            env: &["HOME=/".into()],
            uid: 1000,
            gid: 1000,
            syscalls: &["execveat".into(), "exit_group".into()],
            stdio: [file.as_fd(), file.as_fd(), file.as_fd()],
        })
        .unwrap();
        assert!(
            prepared.root.as_raw_fd() >= 128
                && prepared.cwd.as_raw_fd() >= 128
                && prepared.executable.as_raw_fd() >= 128
        );
        assert!(prepared.stdio.iter().all(|fd| fd.as_raw_fd() >= 128));
        unsafe { libc::_exit(0) };
    }
}
