//! Filesystem, mount, pivot-root, and device setup.

use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::manifest::{Manifest, Mount};

use super::util::{c_path, syscall_ok};

pub(super) fn prepare_root(manifest: &Manifest) -> Result<()> {
    fs::create_dir_all(&manifest.root).context("create jail root")?;
    fs::set_permissions(&manifest.root, fs::Permissions::from_mode(0o711))
        .context("restrict jail root")?;
    let executable =
        fs::canonicalize(&manifest.exec_file).context("canonicalize cloud-hypervisor")?;
    if !executable.is_file() {
        bail!("cloud-hypervisor executable is not a regular file");
    }
    let target = manifest.root.join("cloud-hypervisor");
    fs::copy(executable, &target).context("copy cloud-hypervisor into jail")?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o500))
        .context("restrict cloud-hypervisor binary")?;
    chown_path(&target, manifest.uid, manifest.gid)?;

    let api_socket_parent = manifest
        .root
        .join(&manifest.api_socket.0)
        .parent()
        .context("API socket has no parent")?
        .to_path_buf();
    fs::create_dir_all(&api_socket_parent).context("create API socket parent")?;
    chown_path(&api_socket_parent, manifest.uid, manifest.gid)
}

pub(super) fn enter_mount_namespace() -> Result<()> {
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWNS) }).context("create mount namespace")?;
    mount_call(None, Path::new("/"), libc::MS_PRIVATE | libc::MS_REC)
}

pub(super) fn mount_resources(manifest: &Manifest) -> Result<()> {
    for mount in &manifest.mounts {
        bind_mount(&manifest.root, mount)?;
    }
    Ok(())
}

pub(super) fn pivot_into_jail(root: &Path) -> Result<()> {
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
    syscall_ok(unsafe { libc::rmdir(old_root.as_ptr()) }).context("remove old root")
}

pub(super) fn create_device_nodes(uid: u32, gid: u32) -> Result<()> {
    fs::create_dir_all("/dev/net").context("create jailed dev directory")?;
    create_character_device(Path::new("/dev/kvm"), 10, 232)?;
    create_character_device(Path::new("/dev/net/tun"), 10, 200)?;
    for path in [
        Path::new("/"),
        Path::new("/dev/kvm"),
        Path::new("/dev/net/tun"),
    ] {
        chown_path(path, uid, gid).with_context(|| format!("chown {}", path.display()))?;
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
    let source = fs::canonicalize(&mount.source)
        .with_context(|| format!("canonicalize mount source {}", mount.source.display()))?;
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
    let recursive = if source_meta.is_dir() {
        libc::MS_REC
    } else {
        0
    };
    mount_call(Some(&source), &destination, libc::MS_BIND | recursive)?;
    if mount.read_only {
        mount_call(
            None,
            &destination,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | recursive,
        )?;
    }
    Ok(())
}

fn create_character_device(path: &Path, major: u32, minor: u32) -> Result<()> {
    let path = c_path(path)?;
    let result = unsafe {
        libc::mknod(
            path.as_ptr(),
            libc::S_IFCHR | 0o600,
            libc::makedev(major, minor),
        )
    };
    if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        bail!("create device: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn chown_path(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let path = c_path(path)?;
    syscall_ok(unsafe { libc::chown(path.as_ptr(), uid, gid) })
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
