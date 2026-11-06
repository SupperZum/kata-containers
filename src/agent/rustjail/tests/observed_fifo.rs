// SPDX-License-Identifier: Apache-2.0

//! Test container FIFO release with a temporary FIFO and a mock cgroup manager.
//! Namespace, mount, VM, network and kata-agent listener setup is unnecessary.

#![cfg(feature = "exec-observer")]

use nix::{
    errno::Errno,
    fcntl::{self, FcntlArg, OFlag},
    sys::{
        signal::{self, Signal},
        stat::Mode,
        wait::{waitpid, WaitStatus},
    },
    unistd::{self, Pid},
};
use oci_spec::runtime::Spec;
use runtime_spec::ContainerState;
use rustjail::{
    cgroups::mock::Manager,
    container::{BaseContainer, ContainerStatus, LinuxContainer, EXEC_FIFO_FILENAME},
    specconv::CreateOpts,
};
use std::{
    collections::HashMap,
    ffi::CString,
    os::fd::OwnedFd,
    path::Path,
    path::PathBuf,
    task::Poll,
    time::{Duration, SystemTime},
};

fn fixture() -> (LinuxContainer, tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let spec = Spec::default();
    let manager = Manager::new("/unused-fifo-fixture", &spec, None).unwrap();
    let container = LinuxContainer {
        id: "fifo-fixture".into(),
        root: dir.path().to_str().unwrap().into(),
        config: CreateOpts {
            cgroup_name: String::new(),
            use_systemd_cgroup: false,
            no_pivot_root: false,
            no_new_keyring: false,
            spec: Some(spec),
            rootless_euid: false,
            rootless_cgroup: false,
            container_name: String::new(),
        },
        cgroup_manager: Box::new(manager),
        init_process_pid: -1,
        init_process_start_time: 0,
        uid_map_path: String::new(),
        gid_map_path: String::new(),
        processes: HashMap::new(),
        status: ContainerStatus::new(),
        created: SystemTime::now(),
        logger: slog::Logger::root(slog::Discard, slog::o!()),
    };
    let fifo = dir.path().join(EXEC_FIFO_FILENAME);
    unistd::mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
    (container, dir, fifo)
}

#[tokio::test(flavor = "current_thread")]
async fn observed_fifo_dead_reader_is_bounded() {
    let (mut container, _dir, fifo) = fixture();
    let path = CString::new(fifo.to_str().unwrap()).unwrap();
    let mut ready = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Only async-signal-safe syscalls after fork. The sole reader exists
        // before the parent kills and reaps this child.
        unsafe {
            libc::close(ready[0]);
            libc::alarm(5);
            let reader = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK);
            if reader < 0 || libc::write(ready[1], b"R".as_ptr().cast(), 1) != 1 {
                libc::_exit(125);
            }
            loop {
                libc::pause();
            }
        }
    }
    unsafe { libc::close(ready[1]) };
    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 1) },
        1
    );
    unsafe { libc::close(ready[0]) };
    signal::kill(Pid::from_raw(pid), Signal::SIGKILL).unwrap();
    assert!(matches!(
        waitpid(Pid::from_raw(pid), None).unwrap(),
        WaitStatus::Signaled(_, Signal::SIGKILL, _)
    ));
    eprintln!("fifo-regression-path: {}", container.root);
    eprintln!("fifo-regression: sole reader reaped; entering actual release");
    let ret = container.exec_observed(Duration::from_millis(50)).await;
    assert!(format!("{:#}", ret.unwrap_err()).contains("timed out"));
    assert_eq!(container.status(), ContainerState::Created);
    assert_eq!(container.init_process_start_time, 0);
}

#[tokio::test(flavor = "current_thread")]
async fn observed_fifo_success_releases_exactly_one_byte() {
    let (mut container, _dir, fifo) = fixture();
    let reader = fcntl::open(
        &fifo,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    container
        .exec_observed(Duration::from_secs(1))
        .await
        .unwrap();
    let mut bytes = [0xff; 2];
    assert_eq!(unistd::read(&reader, &mut bytes).unwrap(), 1);
    assert_eq!(bytes[0], 0);
    assert_eq!(container.status(), ContainerState::Running);
    assert!(container.init_process_start_time > 0);
    assert!(container
        .exec_observed(Duration::from_secs(1))
        .await
        .is_err());
    assert_eq!(unistd::read(&reader, &mut bytes).unwrap(), 0);
}

fn full_fifo(fifo: &Path) -> (OwnedFd, usize) {
    let reader = fcntl::open(
        fifo,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let writer = fcntl::open(
        fifo,
        OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let capacity = fcntl::fcntl(&writer, FcntlArg::F_GETPIPE_SZ).unwrap() as usize;
    assert_eq!(
        unistd::write(&writer, &vec![0x5a; capacity]).unwrap(),
        capacity
    );
    assert_eq!(unistd::write(&writer, &[0x5a]), Err(Errno::EAGAIN));
    drop(writer);
    (reader, capacity)
}

fn assert_filler_then_eof(reader: &OwnedFd, capacity: usize) {
    let mut total = 0;
    let mut bytes = [0; 4096];
    loop {
        // A leaked or detached writer gives EAGAIN instead of EOF.
        // A delayed release adds an unexpected zero byte.
        let count = unistd::read(reader, &mut bytes).unwrap();
        if count == 0 {
            break;
        }
        assert!(bytes[..count].iter().all(|byte| *byte == 0x5a));
        total += count;
    }
    assert_eq!(total, capacity);
}

#[tokio::test(flavor = "current_thread")]
async fn observed_fifo_full_write_is_bounded_and_closes_writer() {
    let (mut container, _dir, fifo) = fixture();
    let (reader, capacity) = full_fifo(&fifo);
    let ret = container.exec_observed(Duration::from_millis(50)).await;
    assert!(format!("{:#}", ret.unwrap_err()).contains("timed out"));
    assert_eq!(container.status(), ContainerState::Created);
    assert_eq!(container.init_process_start_time, 0);
    assert_filler_then_eof(&reader, capacity);
}

#[tokio::test(flavor = "current_thread")]
async fn observed_fifo_cancel_drops_writer_without_later_release() {
    let (mut container, _dir, fifo) = fixture();
    let (reader, capacity) = full_fifo(&fifo);
    let mut release = Box::pin(container.exec_observed(Duration::from_secs(1)));
    assert!(matches!(futures::poll!(&mut release), Poll::Pending));
    drop(release);
    assert_eq!(container.status(), ContainerState::Created);
    assert_eq!(container.init_process_start_time, 0);
    assert_filler_then_eof(&reader, capacity);
}

#[tokio::test(flavor = "current_thread")]
async fn observed_fifo_reader_loss_during_write_fails_closed() {
    let (mut container, _dir, fifo) = fixture();
    let (reader, _capacity) = full_fifo(&fifo);
    let mut release = Box::pin(container.exec_observed(Duration::from_secs(1)));
    assert!(matches!(futures::poll!(&mut release), Poll::Pending));
    drop(reader);
    assert!(release.await.is_err());
    assert_eq!(container.status(), ContainerState::Created);
    assert_eq!(container.init_process_start_time, 0);
}
