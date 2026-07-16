//! Linux-only privileged execution for `cloud-hypervisor-jailer`.
//!
//! This deliberately mirrors the useful process-isolation mechanics of the
//! Firecracker jailer without accepting its generic command-line interface.

use std::env;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::{Manifest, Mount};

pub(super) fn launch(manifest: &Manifest) -> Result<()> {
    require_root()?;
    let netns = manifest
        .netns
        .as_ref()
        .map(File::open)
        .transpose()
        .context("open network namespace")?;
    prepare_root(manifest)?;
    enter_mount_namespace().context("create private mount namespace")?;
    mount_resources(manifest)?;
    apply_limits(manifest)?;
    setup_cgroup(manifest)?;
    pivot_into_jail(&manifest.root)?;
    create_device_nodes(manifest)?;
    if let Some(netns) = netns {
        setns(netns.as_raw_fd()).context("join network namespace")?;
    }

    if manifest.new_pid_namespace {
        // unshare only affects subsequently-created children. The parent writes
        // the durable child PID then exits; machined validates that PID against
        // the manifest before treating it as a recovered VMM.
        syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWPID) }).context("create PID namespace")?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            bail!(
                "fork PID namespace child: {}",
                std::io::Error::last_os_error()
            );
        }
        if pid > 0 {
            fs::write("/cloud-hypervisor.pid", format!("{pid}\n")).context("write CH pid")?;
            return Ok(());
        }
    }

    drop_capability_bounding_set()?;
    drop_privileges(manifest.uid, manifest.gid)?;
    sanitize_process()?;
    exec_cloud_hypervisor(manifest)
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("cloud-hypervisor-jailer launch requires root")
    }
    Ok(())
}

fn prepare_root(manifest: &Manifest) -> Result<()> {
    fs::create_dir_all(&manifest.root).context("create jail root")?;
    fs::set_permissions(
        &manifest.root,
        std::os::unix::fs::PermissionsExt::from_mode(0o711),
    )
    .context("restrict jail root")?;
    let target = manifest.root.join("cloud-hypervisor");
    fs::copy(&manifest.exec_file, &target).context("copy cloud-hypervisor into jail")?;
    fs::set_permissions(&target, std::os::unix::fs::PermissionsExt::from_mode(0o500))
        .context("restrict cloud-hypervisor binary")?;
    chown_path(&target, manifest.uid, manifest.gid)?;
    let api_socket_parent = manifest
        .root
        .join(&manifest.api_socket.0)
        .parent()
        .context("API socket has no parent")?
        .to_path_buf();
    fs::create_dir_all(&api_socket_parent).context("create API socket parent")?;
    chown_path(&api_socket_parent, manifest.uid, manifest.gid)?;
    Ok(())
}

fn mount_resources(manifest: &Manifest) -> Result<()> {
    for mount in &manifest.mounts {
        bind_mount(&manifest.root, mount)?;
    }
    Ok(())
}

fn bind_mount(root: &Path, mount: &Mount) -> Result<()> {
    let source_meta = fs::symlink_metadata(&mount.source)
        .with_context(|| format!("stat mount source {}", mount.source.display()))?;
    if source_meta.file_type().is_symlink() {
        bail!(
            "mount source must not be a symlink: {}",
            mount.source.display()
        )
    }
    let destination = root.join(&mount.destination.0);
    let parent = destination
        .parent()
        .context("mount destination has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create mount destination parent {}", parent.display()))?;
    if source_meta.is_dir() {
        fs::create_dir_all(&destination)
            .with_context(|| format!("create mount destination {}", destination.display()))?;
    } else {
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&destination)
            .with_context(|| format!("create mount destination {}", destination.display()))?;
    }
    mount_call(
        Some(&mount.source),
        &destination,
        libc::MS_BIND
            | if source_meta.is_dir() {
                libc::MS_REC
            } else {
                0
            },
    )?;
    if mount.read_only {
        mount_call(
            None,
            &destination,
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | if source_meta.is_dir() {
                    libc::MS_REC
                } else {
                    0
                },
        )?;
    }
    Ok(())
}

fn enter_mount_namespace() -> Result<()> {
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWNS) }).context("create mount namespace")?;
    mount_call(None, Path::new("/"), libc::MS_PRIVATE | libc::MS_REC)
}

fn pivot_into_jail(root: &Path) -> Result<()> {
    mount_call(Some(root), root, libc::MS_BIND | libc::MS_REC)?;
    env::set_current_dir(root).context("enter jail root")?;
    fs::create_dir("old_root").context("create old root")?;
    let dot = CString::new(".")?;
    let old_root = CString::new("old_root")?;
    syscall_ok(unsafe {
        libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old_root.as_ptr()) as i32
    })
    .context("pivot root")?;
    let slash = CString::new("/")?;
    syscall_ok(unsafe { libc::chdir(slash.as_ptr()) }).context("chdir jail root")?;
    syscall_ok(unsafe { libc::umount2(old_root.as_ptr(), libc::MNT_DETACH) })
        .context("unmount old root")?;
    syscall_ok(unsafe { libc::rmdir(old_root.as_ptr()) }).context("remove old root")?;
    Ok(())
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = c_path(path)?;
    syscall_ok(unsafe { libc::chown(path.as_ptr(), uid, gid) })
}

fn create_device_nodes(manifest: &Manifest) -> Result<()> {
    fs::create_dir_all("/dev/net").context("create jailed dev directory")?;
    create_character_device(Path::new("/dev/kvm"), 10, 232)?;
    create_character_device(Path::new("/dev/net/tun"), 10, 200)?;
    for path in [
        Path::new("/"),
        Path::new("/dev/kvm"),
        Path::new("/dev/net/tun"),
    ] {
        let cpath = c_path(path)?;
        syscall_ok(unsafe { libc::chown(cpath.as_ptr(), manifest.uid, manifest.gid) })
            .with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(())
}

fn create_character_device(path: &Path, major: u32, minor: u32) -> Result<()> {
    let cpath = c_path(path)?;
    let mode = libc::S_IFCHR | 0o600;
    let dev = libc::makedev(major, minor);
    let result = unsafe { libc::mknod(cpath.as_ptr(), mode, dev) };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        bail!(
            "create {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn setup_cgroup(manifest: &Manifest) -> Result<()> {
    if manifest.cgroup.values.is_empty() && manifest.cgroup.parent.is_none() {
        return Ok(());
    }
    let parent = manifest
        .cgroup
        .parent
        .as_ref()
        .map(|path| path.0.as_path())
        .unwrap_or_else(|| Path::new("cloud-hypervisor"));
    let path = Path::new("/sys/fs/cgroup")
        .join(parent)
        .join(&manifest.machine_id);
    fs::create_dir_all(&path).with_context(|| format!("create cgroup {}", path.display()))?;
    for (name, value) in &manifest.cgroup.values {
        fs::write(path.join(name), format!("{value}\n"))
            .with_context(|| format!("configure cgroup {name}"))?;
    }
    fs::write(
        path.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .context("join cgroup")?;
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

fn apply_limits(manifest: &Manifest) -> Result<()> {
    set_limit!(libc::RLIMIT_NOFILE, manifest.resource_limits.no_file)?;
    if let Some(file_size) = manifest.resource_limits.file_size {
        set_limit!(libc::RLIMIT_FSIZE, file_size)?;
    }
    Ok(())
}

fn setns(fd: i32) -> Result<()> {
    syscall_ok(unsafe { libc::setns(fd, libc::CLONE_NEWNET) }).context("setns")
}

fn drop_privileges(uid: u32, gid: u32) -> Result<()> {
    syscall_ok(unsafe { libc::setgroups(0, std::ptr::null()) })
        .context("clear supplementary groups")?;
    syscall_ok(unsafe { libc::setgid(gid) }).context("setgid")?;
    syscall_ok(unsafe { libc::setuid(uid) }).context("setuid")
}

fn drop_capability_bounding_set() -> Result<()> {
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

fn sanitize_process() -> Result<()> {
    for (key, _) in env::vars() {
        unsafe { env::remove_var(key) }
    }
    // The network namespace fd has already been consumed. Keep standard I/O so
    // machined can collect CH logs; all other inherited descriptors are closed.
    let limit = 1_048_576;
    for fd in 3..limit {
        unsafe { libc::close(fd) };
    }
    Ok(())
}

fn exec_cloud_hypervisor(manifest: &Manifest) -> Result<()> {
    let executable = CString::new("/cloud-hypervisor")?;
    let mut arguments = vec![executable.clone()];
    for argument in &manifest.arguments {
        arguments.push(CString::new(argument.as_str()).context("argument contains NUL")?);
    }
    arguments.push(CString::new("--seccomp")?);
    arguments.push(CString::new("true")?);
    let mut argv: Vec<*const libc::c_char> =
        arguments.iter().map(|argument| argument.as_ptr()).collect();
    argv.push(std::ptr::null());
    unsafe { libc::execv(executable.as_ptr(), argv.as_ptr()) };
    bail!("exec cloud-hypervisor: {}", std::io::Error::last_os_error())
}

fn mount_call(source: Option<&Path>, destination: &Path, flags: libc::c_ulong) -> Result<()> {
    let source = source.map(c_path).transpose()?;
    let destination = c_path(destination)?;
    syscall_ok(unsafe {
        libc::mount(
            source
                .as_ref()
                .map_or(std::ptr::null(), |path| path.as_ptr()),
            destination.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    })
    .with_context(|| format!("mount {}", destination.to_string_lossy()))
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).context("path contains NUL")
}

fn syscall_ok(result: i32) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        bail!("{}", std::io::Error::last_os_error())
    }
}
