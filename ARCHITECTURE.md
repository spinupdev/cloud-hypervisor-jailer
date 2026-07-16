# Architecture

`cloud-hypervisor-jailer` separates the sandbox contract from Linux-specific
effects. This is intentional: a manifest may be validated by an unprivileged
control-plane process, while only `launch` performs privileged operations.

```text
JSON manifest -> manifest validation -> Linux launch workflow
                                          |-> jail (mounts, pivot root, devices)
                                          |-> cgroup (v2 delegation and limits)
                                          |-> process (namespaces, credentials, FDs, exec)
```

## Modules

- `src/manifest.rs` is the versioned, deny-unknown-fields sandbox contract and
  its pure invariants.
- `src/linux/mod.rs` owns operation order. It has no low-level mount, cgroup,
  or credential details.
- `src/linux/jail.rs` stages the root, applies declared bind mounts, performs
  `pivot_root`, and creates only the KVM/TUN device nodes required by CH.
- `src/linux/cgroup.rs` owns cgroup-v2 discovery, controller delegation through
  `cgroup.subtree_control`, limit writes, and process attachment.
- `src/linux/process.rs` owns namespaces, resource limits, descriptor and
  environment sanitization, capability/credential transition, and CH exec.
- `src/linux/util.rs` contains the small shared syscall/path adapters.

## Upstream comparison

Valyent's archived [`ch-jailer`](https://github.com/valyentdev/ch-jailer) is a
Cloud Hypervisor adaptation of Firecracker's jailer. Firecracker's current
source has the same broad modular shape: `env`, `chroot`, `cgroup`, and
`resource_limits`. This project adopts the useful isolation mechanics without
adopting their generic CLI contract.

Adopted or strengthened here:

- strict versioned manifest rather than caller-provided arbitrary arguments;
- bounded machine IDs, non-root target identity, path validation, and forced
  CH seccomp;
- mount and PID namespaces, `pivot_root`, netns join, KVM/TUN nodes, rlimits,
  cgroup-v2 limits, and descriptor/environment sanitization;
- cgroup-v2 controller availability checks and recursive delegation before a
  leaf cgroup is configured; and
- `close_range` with an `ENOSYS` fallback, rather than an unconditional
  expensive descriptor loop.

Intentional differences:

- daemonization is rejected because the host orchestrator must supervise the
  process, logs, and durable PID directly;
- the API socket is created by CH inside the jail, not passed as a listener FD
  or bind mounted from the host;
- Firecracker-specific userfaultfd support is not exposed; and
- `/dev/urandom` is not created because CH uses host randomness through the
  kernel, not a jailed device path.

## Remaining hardening work

Before production enablement, add privileged integration coverage on real KVM
hosts for mount rollback, cgroup-controller delegation under the deployed
parent hierarchy, network namespace/TAP behavior, and recovery cleanup. Also
replace path-based mount setup with file-descriptor-based, no-symlink
resolution if the jailer ever accepts paths from a less-trusted component.
