//! The unprivileged, versioned sandbox contract.
//!
//! A manifest is data supplied by the host orchestrator. Validation here is
//! pure: it performs no filesystem, namespace, cgroup, or process mutation.

use std::collections::{BTreeMap, HashSet};
use std::path::{Component, PathBuf};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    version: u32,
    pub(crate) machine_id: String,
    pub(crate) root: PathBuf,
    pub(crate) exec_file: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    #[serde(default)]
    pub(crate) netns: Option<PathBuf>,
    #[serde(default)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) new_pid_namespace: bool,
    #[serde(default)]
    daemonize: bool,
    #[serde(default)]
    pub(crate) arguments: Vec<String>,
    #[serde(default)]
    pub(crate) cgroup: Cgroup,
    #[serde(default)]
    pub(crate) resource_limits: ResourceLimits,
    pub(crate) api_socket: SandboxPath,
    pub(crate) mounts: Vec<Mount>,
    #[serde(default)]
    pub(crate) devices: Vec<Device>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cgroup {
    #[serde(default)]
    pub(crate) parent: Option<SandboxPath>,
    #[serde(default)]
    pub(crate) values: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceLimits {
    #[serde(default = "default_nofile_limit")]
    pub(crate) no_file: u64,
    #[serde(default)]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) file_size: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            no_file: default_nofile_limit(),
            file_size: None,
        }
    }
}

const fn default_nofile_limit() -> u64 {
    2048
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mount {
    pub(crate) source: PathBuf,
    pub(crate) destination: SandboxPath,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) read_only: bool,
}

/// A host device that may be recreated inside the jail.
///
/// The v1 contract deliberately limits this to VFIO. The launcher resolves
/// the character-device identity from the trusted host path before pivoting;
/// it never bind-mounts the host `/dev` tree or changes host device ownership.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Device {
    pub(crate) source: PathBuf,
    pub(crate) destination: SandboxPath,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub(crate) struct SandboxPath(pub(crate) PathBuf);

#[derive(Debug, Error)]
pub(crate) enum ManifestError {
    #[error("unsupported manifest version {0}")]
    UnsupportedVersion(u32),
    #[error("machine_id must be non-empty and contain only ascii letters, digits, or '-'")]
    InvalidMachineID,
    #[error("machine_id must not exceed 64 characters")]
    MachineIDTooLong,
    #[error("root must be an absolute path")]
    RootNotAbsolute,
    #[error("exec_file must be an absolute cloud-hypervisor binary path")]
    InvalidExecFile,
    #[error("uid and gid must identify an unprivileged account")]
    PrivilegedIdentity,
    #[error("network namespace path must be absolute")]
    NetNSNotAbsolute,
    #[error("sandbox path {0} must be relative, clean, and non-empty")]
    UnsafeSandboxPath(String),
    #[error("mount source {0} must be absolute")]
    SourceNotAbsolute(String),
    #[error("duplicate sandbox destination {0}")]
    DuplicateDestination(String),
    #[error("mount destination {0} overlaps the jailer's reserved device tree")]
    ReservedMountDestination(String),
    #[error("device source {0} is not an allow-listed VFIO path")]
    InvalidDeviceSource(String),
    #[error("VFIO device destination must match its source: {0}")]
    InvalidDeviceDestination(String),
    #[error("duplicate VFIO device {0}")]
    DuplicateDevice(String),
    #[error("VFIO group devices require the /dev/vfio/vfio control device")]
    MissingVFIOControlDevice,
    #[error("a jail may contain at most 65 VFIO devices")]
    TooManyDevices,
    #[error("resource limit no_file must be between 3 and 1048576")]
    InvalidNoFileLimit,
    #[error("cgroup property {0} is not an allow-listed cgroup v2 file")]
    InvalidCgroupProperty(String),
    #[error("daemonize is unsupported: machined must supervise the CH process")]
    DaemonizeUnsupported,
    #[error("manifest arguments must not override CH seccomp")]
    SeccompOverride,
}

impl Manifest {
    pub(crate) fn validate(&self) -> Result<(), ManifestError> {
        if self.version != 1 {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }
        if self.machine_id.is_empty()
            || !self
                .machine_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ManifestError::InvalidMachineID);
        }
        if self.machine_id.len() > 64 {
            return Err(ManifestError::MachineIDTooLong);
        }
        if !is_clean_absolute_host_path(&self.root) {
            return Err(ManifestError::RootNotAbsolute);
        }
        if !is_clean_absolute_host_path(&self.exec_file)
            || !self
                .exec_file
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("cloud-hypervisor"))
        {
            return Err(ManifestError::InvalidExecFile);
        }
        if self.uid == 0 || self.gid == 0 {
            return Err(ManifestError::PrivilegedIdentity);
        }
        if self
            .netns
            .as_ref()
            .is_some_and(|path| !is_clean_absolute_host_path(path))
        {
            return Err(ManifestError::NetNSNotAbsolute);
        }
        if !(3..=1_048_576).contains(&self.resource_limits.no_file) {
            return Err(ManifestError::InvalidNoFileLimit);
        }
        if self.daemonize {
            return Err(ManifestError::DaemonizeUnsupported);
        }
        if self
            .arguments
            .iter()
            .any(|argument| argument == "--seccomp" || argument.starts_with("--seccomp="))
        {
            return Err(ManifestError::SeccompOverride);
        }
        if let Some(parent) = &self.cgroup.parent {
            validate_sandbox_path(parent)?;
        }
        for key in self.cgroup.values.keys() {
            if !matches!(
                key.as_str(),
                "cpu.max"
                    | "cpu.weight"
                    | "memory.max"
                    | "memory.high"
                    | "pids.max"
                    | "io.max"
                    | "cpuset.cpus"
                    | "cpuset.mems"
            ) {
                return Err(ManifestError::InvalidCgroupProperty(key.clone()));
            }
        }
        validate_sandbox_path(&self.api_socket)?;

        let mut destinations = HashSet::new();
        for mount in &self.mounts {
            if !is_clean_absolute_host_path(&mount.source) {
                return Err(ManifestError::SourceNotAbsolute(
                    mount.source.display().to_string(),
                ));
            }
            validate_sandbox_path(&mount.destination)?;
            let destination = mount.destination.0.display().to_string();
            if mount.destination.0.starts_with("dev") {
                return Err(ManifestError::ReservedMountDestination(destination));
            }
            if !destinations.insert(destination.clone()) {
                return Err(ManifestError::DuplicateDestination(destination));
            }
        }
        if self.devices.len() > 65 {
            return Err(ManifestError::TooManyDevices);
        }
        let mut devices = HashSet::new();
        let mut has_control = false;
        let mut has_group = false;
        for device in &self.devices {
            let source = validate_vfio_source(&device.source)?;
            let expected_destination = source
                .strip_prefix("/")
                .expect("validated VFIO source is absolute");
            validate_sandbox_path(&device.destination)?;
            if device.destination.0 != expected_destination {
                return Err(ManifestError::InvalidDeviceDestination(
                    device.destination.0.display().to_string(),
                ));
            }
            if !devices.insert(source.to_owned()) {
                return Err(ManifestError::DuplicateDevice(source.display().to_string()));
            }
            if !destinations.insert(device.destination.0.display().to_string()) {
                return Err(ManifestError::DuplicateDestination(
                    device.destination.0.display().to_string(),
                ));
            }
            if source == std::path::Path::new("/dev/vfio/vfio") {
                has_control = true;
            } else {
                has_group = true;
            }
        }
        if has_group && !has_control {
            return Err(ManifestError::MissingVFIOControlDevice);
        }
        Ok(())
    }
}

fn validate_vfio_source(path: &std::path::Path) -> Result<&std::path::Path, ManifestError> {
    if !is_clean_absolute_host_path(path) {
        return Err(ManifestError::InvalidDeviceSource(
            path.display().to_string(),
        ));
    }
    if path == std::path::Path::new("/dev/vfio/vfio") {
        return Ok(path);
    }
    let Some(group) = path
        .strip_prefix("/dev/vfio")
        .ok()
        .and_then(|relative| relative.to_str())
    else {
        return Err(ManifestError::InvalidDeviceSource(
            path.display().to_string(),
        ));
    };
    if group.is_empty()
        || !group.bytes().all(|byte| byte.is_ascii_digit())
        || (group.len() > 1 && group.starts_with('0'))
    {
        return Err(ManifestError::InvalidDeviceSource(
            path.display().to_string(),
        ));
    }
    Ok(path)
}

fn is_clean_absolute_host_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
}

fn validate_sandbox_path(path: &SandboxPath) -> Result<(), ManifestError> {
    let raw = path.0.display().to_string();
    if raw.is_empty()
        || path.0.is_absolute()
        || path.0.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(ManifestError::UnsafeSandboxPath(raw));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn valid_manifest() -> Manifest {
        Manifest {
            version: 1,
            machine_id: "machine-1".into(),
            root: "/var/lib/machined/ch/cloud-hypervisor/machine_1/root".into(),
            exec_file: "/usr/bin/cloud-hypervisor".into(),
            uid: 123,
            gid: 100,
            netns: Some("/var/run/netns/machine-1".into()),
            new_pid_namespace: true,
            daemonize: false,
            arguments: vec!["--api-socket".into(), "/run/ch.sock".into()],
            cgroup: Cgroup {
                parent: Some(SandboxPath("depot/ch".into())),
                values: BTreeMap::from([("memory.max".into(), "1073741824".into())]),
            },
            resource_limits: ResourceLimits::default(),
            api_socket: SandboxPath("run/ch.sock".into()),
            mounts: vec![],
            devices: vec![],
        }
    }

    #[test]
    fn accepts_a_minimal_safe_manifest() {
        valid_manifest().validate().unwrap();
    }

    #[test]
    fn rejects_path_escape() {
        let mut manifest = valid_manifest();
        manifest.api_socket = SandboxPath("../run/ch.sock".into());
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::UnsafeSandboxPath(_))
        ));
    }

    #[test]
    fn rejects_host_path_traversal() {
        let mut manifest = valid_manifest();
        manifest.exec_file = "/usr/bin/../bin/cloud-hypervisor".into();
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidExecFile)
        ));
    }

    #[test]
    fn accepts_api_socket_created_inside_the_jail() {
        let mut manifest = valid_manifest();
        manifest.api_socket = SandboxPath("run/cloud-hypervisor.sock".into());
        manifest.validate().unwrap();
    }

    #[test]
    fn rejects_non_ch_executable_and_unexpected_cgroup_property() {
        let mut manifest = valid_manifest();
        manifest.exec_file = "/usr/bin/bash".into();
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidExecFile)
        ));

        let mut manifest = valid_manifest();
        manifest
            .cgroup
            .values
            .insert("cgroup.procs".into(), "1".into());
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidCgroupProperty(_))
        ));
    }

    #[test]
    fn rejects_a_privileged_target_identity() {
        let mut manifest = valid_manifest();
        manifest.uid = 0;
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::PrivilegedIdentity)
        ));
    }

    #[test]
    fn accepts_exact_vfio_control_and_group_devices() {
        let mut manifest = valid_manifest();
        manifest.devices = vec![
            Device {
                source: "/dev/vfio/vfio".into(),
                destination: SandboxPath("dev/vfio/vfio".into()),
            },
            Device {
                source: "/dev/vfio/42".into(),
                destination: SandboxPath("dev/vfio/42".into()),
            },
        ];
        manifest.validate().unwrap();
    }

    #[test]
    fn rejects_arbitrary_devices_and_vfio_path_aliases() {
        for source in [
            "/dev/null",
            "/dev/vfio/../../mem",
            "/dev/vfio/01",
            "/dev/vfio/1/2",
        ] {
            let mut manifest = valid_manifest();
            manifest.devices = vec![Device {
                source: source.into(),
                destination: SandboxPath("dev/vfio/1".into()),
            }];
            assert!(matches!(
                manifest.validate(),
                Err(ManifestError::InvalidDeviceSource(_))
            ));
        }
    }

    #[test]
    fn rejects_destination_remapping_and_missing_control_device() {
        let mut manifest = valid_manifest();
        manifest.devices = vec![Device {
            source: "/dev/vfio/42".into(),
            destination: SandboxPath("dev/vfio/41".into()),
        }];
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidDeviceDestination(_))
        ));

        let mut manifest = valid_manifest();
        manifest.devices = vec![Device {
            source: "/dev/vfio/42".into(),
            destination: SandboxPath("dev/vfio/42".into()),
        }];
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::MissingVFIOControlDevice)
        ));
    }

    #[test]
    fn rejects_mounts_over_the_reserved_device_tree() {
        let mut manifest = valid_manifest();
        manifest.mounts = vec![Mount {
            source: "/var/lib/machined/device-shadow".into(),
            destination: SandboxPath("dev/vfio".into()),
            read_only: false,
        }];
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::ReservedMountDestination(_))
        ));
    }
}
