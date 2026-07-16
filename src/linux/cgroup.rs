//! Cgroup-v2 setup and controller delegation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::manifest::Cgroup;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub(super) fn setup(cgroup: &Cgroup, machine_id: &str) -> Result<()> {
    if cgroup.values.is_empty() && cgroup.parent.is_none() {
        return Ok(());
    }
    let root = Path::new(CGROUP_ROOT);
    if !root.join("cgroup.controllers").is_file() {
        bail!("cgroup v2 unified hierarchy is unavailable at {CGROUP_ROOT}");
    }
    let parent = cgroup
        .parent
        .as_ref()
        .map(|path| path.0.as_path())
        .unwrap_or_else(|| Path::new("cloud-hypervisor"));
    let parent_path = root.join(parent);
    let path = parent_path.join(machine_id);
    fs::create_dir_all(&path).with_context(|| format!("create cgroup {}", path.display()))?;

    let controllers = requested_controllers(&cgroup.values)?;
    for controller in controllers {
        enable_controller_path(root, &parent_path, controller)?;
    }
    for (name, value) in &cgroup.values {
        fs::write(path.join(name), format!("{value}\n"))
            .with_context(|| format!("configure cgroup {name}"))?;
    }
    fs::write(
        path.join("cgroup.procs"),
        format!("{}\n", std::process::id()),
    )
    .context("join cgroup")
}

fn requested_controllers(values: &BTreeMap<String, String>) -> Result<BTreeSet<&str>> {
    values
        .keys()
        .map(|name| {
            name.split_once('.')
                .map(|(controller, _)| controller)
                .ok_or_else(|| anyhow::anyhow!("invalid cgroup v2 property {name}"))
        })
        .collect()
}

fn enable_controller_path(root: &Path, parent: &Path, controller: &str) -> Result<()> {
    let available = fs::read_to_string(root.join("cgroup.controllers"))
        .context("read available cgroup v2 controllers")?;
    if !available.split_whitespace().any(|item| item == controller) {
        bail!("cgroup v2 controller {controller} is unavailable");
    }
    let relative = parent
        .strip_prefix(root)
        .context("cgroup parent escapes cgroup root")?;
    let mut current = root.to_path_buf();
    enable_controller(&current, controller)?;
    for component in relative.components() {
        current.push(component);
        fs::create_dir_all(&current)
            .with_context(|| format!("create cgroup parent {}", current.display()))?;
        enable_controller(&current, controller)?;
    }
    Ok(())
}

fn enable_controller(path: &Path, controller: &str) -> Result<()> {
    let subtree_control = path.join("cgroup.subtree_control");
    if !subtree_control.exists() {
        return Ok(());
    }
    let active = fs::read_to_string(&subtree_control)
        .with_context(|| format!("read {}", subtree_control.display()))?;
    if active.split_whitespace().any(|item| item == controller) {
        return Ok(());
    }
    fs::write(&subtree_control, format!("+{controller}\n"))
        .with_context(|| format!("enable cgroup controller {controller}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_unique_controllers_from_properties() {
        let values = BTreeMap::from([
            ("memory.max".into(), "1".into()),
            ("memory.high".into(), "1".into()),
            ("cpu.max".into(), "1".into()),
        ]);
        assert_eq!(
            requested_controllers(&values).unwrap(),
            BTreeSet::from(["cpu", "memory"])
        );
    }
}
