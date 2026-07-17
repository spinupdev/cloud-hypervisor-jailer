# Testing

## Standard CI

Every push and pull request runs formatting, strict Clippy, unit tests, and a
release build on native Linux amd64 and arm64 runners. These tests do not claim
to validate KVM, mount namespaces, cgroup delegation, or privileged device
creation.

## Privileged integration contract

The `privileged-integration` workflow is manually dispatched on a dedicated
self-hosted Linux/KVM runner. Its runner must provide root execution,
`/dev/kvm`, cgroup v2, `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and an isolated test
cgroup parent. It must run these scenarios against the pinned Cloud Hypervisor
release used by the consuming orchestrator:

1. Launch a Linux guest and verify the VMM is unprivileged, has no ambient
   capabilities, and sees only the declared root and mounts.
2. Join a pre-created network namespace/TAP and verify that host routes and
   unrelated namespaces are unreachable.
3. Apply CPU, memory, PID, and I/O limits; verify the process is in the
   expected cgroup-v2 leaf and all needed controllers were delegated.
4. Force each setup step to fail after cgroup attachment and verify the leaf,
   mount namespace, API socket, and staged artifacts are cleaned or reported
   for reconciler retry.
5. Create/restore a CH snapshot through the host orchestrator; verify the
   jailer does not broaden storage or device visibility.
6. On a dedicated VFIO host, pass one complete IOMMU group and verify the VMM
   sees only `/dev/vfio/vfio` plus that numeric group. Also verify arbitrary
   devices, a second unassigned group, symlinks, and mounts over `/dev` fail
   before Cloud Hypervisor execs.

The workflow is deliberately manual until a hardened dedicated runner exists.
Never run it on a shared developer host or a runner that also contains tenant
workloads.
