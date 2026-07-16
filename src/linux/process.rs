//! Process lifecycle: namespaces, limits, credentials, descriptors, and exec.

use std::env;
use std::ffi::CString;
use std::fs;

use anyhow::{Context, Result, bail};

use crate::manifest::ResourceLimits;

use super::util::syscall_ok;

pub(super) fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("cloud-hypervisor-jailer launch requires root")
    }
    Ok(())
}

macro_rules! set_limit {
    ($resource:expr, $value:expr) => {{
        let limit = libc::rlimit {
            rlim_cur: $value,
            rlim_max: $value,
        };
        syscall_ok(unsafe { libc::setrlimit($resource, &limit) }).context("set resource limit")
    }};
}

pub(super) fn apply_limits(limits: &ResourceLimits) -> Result<()> {
    set_limit!(libc::RLIMIT_NOFILE, limits.no_file)?;
    if let Some(file_size) = limits.file_size {
        set_limit!(libc::RLIMIT_FSIZE, file_size)?;
    }
    Ok(())
}

pub(super) fn join_network_namespace(fd: i32) -> Result<()> {
    syscall_ok(unsafe { libc::setns(fd, libc::CLONE_NEWNET) }).context("join network namespace")
}

pub(super) fn enter_pid_namespace() -> Result<i32> {
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWPID) }).context("create PID namespace")?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!(
            "fork PID namespace child: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(pid)
}

pub(super) fn drop_capability_bounding_set() -> Result<()> {
    let last_capability = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .context("read kernel capability limit")?
        .trim()
        .parse::<u64>()
        .context("parse kernel capability limit")?;
    for capability in 0..=last_capability {
        syscall_ok(unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0)
        })
        .with_context(|| format!("drop capability {capability} from bounding set"))?;
    }
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })
        .context("set no-new-privileges")
}

pub(super) fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    syscall_ok(unsafe { libc::setgroups(0, std::ptr::null()) })
        .context("clear supplementary groups")?;
    syscall_ok(unsafe { libc::setgid(gid) }).context("setgid")?;
    syscall_ok(unsafe { libc::setuid(uid) }).context("setuid")
}

pub(super) fn sanitize_process() -> Result<()> {
    close_inherited_fds()?;
    for (key, _) in env::vars() {
        unsafe { env::remove_var(key) }
    }
    Ok(())
}

pub(super) fn exec_cloud_hypervisor(arguments: &[String]) -> Result<()> {
    let executable = CString::new("/cloud-hypervisor")?;
    let mut argv_strings = vec![executable.clone()];
    for argument in arguments {
        argv_strings.push(CString::new(argument.as_str()).context("argument contains NUL")?);
    }
    argv_strings.push(CString::new("--seccomp")?);
    argv_strings.push(CString::new("true")?);
    let mut argv: Vec<*const libc::c_char> = argv_strings.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(std::ptr::null());
    unsafe { libc::execv(executable.as_ptr(), argv.as_ptr()) };
    bail!("exec cloud-hypervisor: {}", std::io::Error::last_os_error())
}

fn close_inherited_fds() -> Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    };
    if result == 0 {
        return Ok(());
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS) {
        bail!(
            "close inherited file descriptors: {}",
            std::io::Error::last_os_error()
        );
    }
    for fd in 3..1_048_576 {
        unsafe { libc::close(fd) };
    }
    Ok(())
}
