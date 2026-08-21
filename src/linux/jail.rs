//! Filesystem, mount, pivot-root, and device setup.

use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::manifest::{Device, Manifest, Mount};

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
        bind_mount(&manifest.root, mount, manifest.uid, manifest.gid)?;
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct ResolvedDevice {
    destination: std::path::PathBuf,
    major: u32,
    minor: u32,
}

/// Resolve the device identity while the host `/dev` tree is still visible.
/// Manifest validation has already constrained every path to canonical VFIO
/// names; this second check proves each selected entry is a real character
/// device rather than trusting a regular file at an allowed-looking path.
pub(super) fn resolve_devices(manifest: &Manifest) -> Result<Vec<ResolvedDevice>> {
    manifest
        .devices
        .iter()
        .map(resolve_device)
        .collect::<Result<Vec<_>>>()
}

const USERFAULTFD_PATH: &str = "/dev/userfaultfd";

/// Resolve the host `/dev/userfaultfd` identity before pivot, if the node
/// has one. Cloud Hypervisor OnDemand restore tries this device first, then
/// the `userfaultfd(2)` syscall. Recreating the character device inside the
/// jail (owned by the unprivileged VMM) is the narrow grant upstream
/// recommends, instead of `vm.unprivileged_userfaultfd=1` for every process.
pub(super) fn resolve_userfaultfd() -> Result<Option<ResolvedDevice>> {
    match fs::symlink_metadata(USERFAULTFD_PATH) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).context("stat /dev/userfaultfd"),
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
                bail!("/dev/userfaultfd is not a character device");
            }
            let device_id = metadata.rdev();
            Ok(Some(ResolvedDevice {
                destination: std::path::PathBuf::from("dev/userfaultfd"),
                major: libc::major(device_id) as u32,
                minor: libc::minor(device_id) as u32,
            }))
        }
    }
}

fn resolve_device(device: &Device) -> Result<ResolvedDevice> {
    let metadata = fs::symlink_metadata(&device.source)
        .with_context(|| format!("stat device source {}", device.source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_char_device() {
        bail!(
            "device source is not a character device: {}",
            device.source.display()
        );
    }
    let canonical = fs::canonicalize(&device.source)
        .with_context(|| format!("canonicalize device source {}", device.source.display()))?;
    if canonical != device.source {
        bail!(
            "device source changed during resolution: {}",
            device.source.display()
        );
    }
    let device_id = metadata.rdev();
    Ok(ResolvedDevice {
        destination: device.destination.0.clone(),
        major: libc::major(device_id) as u32,
        minor: libc::minor(device_id) as u32,
    })
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

pub(super) fn create_device_nodes(
    uid: u32,
    gid: u32,
    devices: &[ResolvedDevice],
    userfaultfd: Option<&ResolvedDevice>,
) -> Result<()> {
    fs::create_dir_all("/dev/net").context("create jailed dev directory")?;
    if !devices.is_empty() {
        fs::create_dir_all("/dev/vfio").context("create jailed VFIO directory")?;
    }
    create_character_device(Path::new("/dev/kvm"), 10, 232)?;
    create_character_device(Path::new("/dev/net/tun"), 10, 200)?;
    // Cloud Hypervisor's default virtio-rng device reads from /dev/urandom.
    // Expose only this non-blocking entropy device; guest workloads never
    // receive the host /dev filesystem.
    create_character_device(Path::new("/dev/urandom"), 1, 9)?;
    if let Some(device) = userfaultfd {
        create_character_device(Path::new("/dev/userfaultfd"), device.major, device.minor)
            .context("create jailed /dev/userfaultfd")?;
        chown_path(Path::new("/dev/userfaultfd"), uid, gid)
            .context("chown jailed /dev/userfaultfd")?;
    }
    for device in devices {
        let destination = Path::new("/").join(&device.destination);
        create_character_device(&destination, device.major, device.minor)
            .with_context(|| format!("create jailed device {}", destination.display()))?;
        chown_path(&destination, uid, gid)
            .with_context(|| format!("chown jailed device {}", destination.display()))?;
    }
    for path in [
        Path::new("/"),
        Path::new("/dev/kvm"),
        Path::new("/dev/net/tun"),
        Path::new("/dev/urandom"),
    ] {
        chown_path(path, uid, gid).with_context(|| format!("chown {}", path.display()))?;
    }
    Ok(())
}

fn bind_mount(root: &Path, mount: &Mount, uid: u32, gid: u32) -> Result<()> {
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
    grant_vmm_access(
        &destination,
        source_meta.is_dir(),
        mount.read_only,
        uid,
        gid,
    )?;
    if mount.read_only {
        mount_call(
            None,
            &destination,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | recursive,
        )?;
    }
    Ok(())
}

// Mounted artifacts are private to this machine but arrive from machined as
// root-owned 0600 files. Cloud Hypervisor executes as the unprivileged jail
// identity, so establish that identity's least-privilege access before a
// read-only mount is remounted and before privileges are dropped. A bind mount
// shares inode metadata with its source; this is safe because manifest sources
// are per-machine staged artifacts below machined's private artifact root.
fn grant_vmm_access(
    destination: &Path,
    is_directory: bool,
    read_only: bool,
    uid: u32,
    gid: u32,
) -> Result<()> {
    if is_directory {
        for entry in fs::read_dir(destination)
            .with_context(|| format!("read mounted directory {}", destination.display()))?
        {
            let entry = entry
                .with_context(|| format!("read mounted directory {}", destination.display()))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("stat mounted path {}", path.display()))?;
            if metadata.file_type().is_symlink() {
                bail!(
                    "mounted artifact must not contain symlink: {}",
                    path.display()
                );
            }
            grant_vmm_access(&path, metadata.is_dir(), read_only, uid, gid)?;
        }
    }
    chown_path(destination, uid, gid)
        .with_context(|| format!("chown mounted artifact {}", destination.display()))?;
    let mode = artifact_mode(is_directory, read_only);
    fs::set_permissions(destination, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod mounted artifact {}", destination.display()))
}

const fn artifact_mode(is_directory: bool, read_only: bool) -> u32 {
    match (is_directory, read_only) {
        (true, true) => 0o500,
        (true, false) => 0o700,
        (false, true) => 0o400,
        (false, false) => 0o600,
    }
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

#[cfg(test)]
mod tests {
    use super::artifact_mode;
    use super::resolve_userfaultfd;

    #[test]
    fn mounted_artifact_modes_are_minimally_permissive() {
        assert_eq!(artifact_mode(false, true), 0o400);
        assert_eq!(artifact_mode(false, false), 0o600);
        assert_eq!(artifact_mode(true, true), 0o500);
        assert_eq!(artifact_mode(true, false), 0o700);
    }

    #[test]
    fn resolve_userfaultfd_is_optional_when_the_host_has_no_device() {
        match resolve_userfaultfd() {
            Ok(None) => {}
            Ok(Some(device)) => {
                assert_eq!(
                    device.destination,
                    std::path::PathBuf::from("dev/userfaultfd")
                );
                assert!(device.major > 0 || device.minor > 0);
            }
            Err(err) => panic!("resolve_userfaultfd: {err}"),
        }
    }
}
