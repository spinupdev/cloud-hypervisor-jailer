//! Linux launch workflow: stage resources, enter the boundary, then exec CH.

mod cgroup;
mod jail;
mod process;
mod util;

use std::fs::{self, File};
use std::os::unix::io::AsRawFd;

use anyhow::{Context, Result};

use crate::manifest::Manifest;

pub(crate) fn launch(manifest: &Manifest) -> Result<()> {
    process::require_root()?;
    let netns = manifest
        .netns
        .as_ref()
        .map(File::open)
        .transpose()
        .context("open network namespace")?;

    jail::prepare_root(manifest)?;
    jail::enter_mount_namespace()?;
    jail::mount_resources(manifest)?;
    process::apply_limits(&manifest.resource_limits)?;
    let mut cgroup_lease = cgroup::setup(&manifest.cgroup, &manifest.machine_id)?;
    jail::pivot_into_jail(&manifest.root)?;
    jail::create_device_nodes(manifest.uid, manifest.gid)?;
    if let Some(netns) = netns {
        process::join_network_namespace(netns.as_raw_fd())?;
    }

    if manifest.new_pid_namespace {
        let pid = process::enter_pid_namespace()?;
        if pid > 0 {
            if let Some(lease) = &mut cgroup_lease {
                lease.retain();
            }
            fs::write("/cloud-hypervisor.pid", format!("{pid}\n")).context("write CH pid")?;
            return Ok(());
        }
    }

    process::drop_capability_bounding_set()?;
    process::drop_privileges(manifest.uid, manifest.gid)?;
    process::sanitize_process()?;
    process::exec_cloud_hypervisor(&manifest.arguments)
}
