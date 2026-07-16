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
        if !self.root.is_absolute() {
            return Err(ManifestError::RootNotAbsolute);
        }
        if !self.exec_file.is_absolute()
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
        if self.netns.as_ref().is_some_and(|path| !path.is_absolute()) {
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
            if !mount.source.is_absolute() {
                return Err(ManifestError::SourceNotAbsolute(
                    mount.source.display().to_string(),
                ));
            }
            validate_sandbox_path(&mount.destination)?;
            let destination = mount.destination.0.display().to_string();
            if !destinations.insert(destination.clone()) {
                return Err(ManifestError::DuplicateDestination(destination));
            }
        }
        Ok(())
    }
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
}
