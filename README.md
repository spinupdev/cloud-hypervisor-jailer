# cloud-hypervisor-jailer

`cloud-hypervisor-jailer` is a Linux-only, manifest-driven privilege boundary
for one [Cloud Hypervisor](https://www.cloudhypervisor.org/) process.

It is designed for host orchestrators that need to launch Cloud Hypervisor
microVMs with a boundary comparable to Firecracker's jailer while keeping the
two launchers independently evolvable. It is currently an early release: the
manifest and operational contract may change before a production-stable major
version.

## Security model

The jailer accepts a strict JSON manifest. Before privileged work begins it
validates the manifest version, bounded machine ID, target identity,
Cloud-Hypervisor executable, sandbox-relative paths, cgroup-v2 property
allow-list, resource limits, and mount destinations.

On Linux, `launch` requires root and then:

- creates a private mount namespace and pivots into the sandbox root;
- mounts only declared non-symlink sources;
- joins a pre-created network namespace when requested;
- configures the declared cgroup-v2 values and resource limits;
- creates jailed KVM and TUN device nodes;
- creates a PID namespace when requested;
- clears inherited environment and non-standard file descriptors;
- drops the complete capability bounding set, sets `no_new_privs`, and changes
  to a non-root UID/GID; and
- execs Cloud Hypervisor with `--seccomp true` forced on.

Cloud Hypervisor creates its API socket in a writable directory created inside
the jail. The API socket is not a host bind mount.

This project does not create TAP devices, eBPF policy, cgroup controller
delegation, images, disks, or snapshots. Those remain responsibilities of the
host orchestrator.

## Build

```sh
cargo build --release --locked
cargo test --locked
```

Release tags publish a Linux x86_64 musl binary and a SHA-256 checksum on
GitHub Releases.

## Manifest

Use `validate` before handing a manifest to a privileged launcher:

```sh
cloud-hypervisor-jailer validate --manifest /path/to/manifest.json
cloud-hypervisor-jailer launch --manifest /path/to/manifest.json
```

The manifest has a versioned, deny-unknown-fields schema. See the Rust types
in [`src/main.rs`](src/main.rs) for the current canonical contract. Treat all
paths and arguments as host-orchestrator-controlled inputs; this is not a
safe interface for tenant-provided configuration.

## Status

The launcher is tested for manifest validation and compiled/tested on Linux in
CI. Production adoption additionally requires privileged integration tests on
real KVM-capable hosts for the intended Cloud Hypervisor version, cgroup
delegation layout, network setup, storage mounts, cleanup/reconciliation, and
snapshot policy.

## License

Apache-2.0. See [LICENSE](LICENSE).
