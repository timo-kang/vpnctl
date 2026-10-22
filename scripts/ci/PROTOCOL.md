# Private CI packet-path diagnosis (never merge this branch)

Diagnose the failed eight-candidate split-CPU job of run 39699878690. Product and
test source stay fixed at ec44c012b3ffb9629a302600fccbd28b05b591c1. Original CI
uses race instrumentation, unlike the preceding normal-build remote diagnostic.
This experiment uses race for both product and integration binaries.

Execute four fresh VMs in fixed OFF, ON, ON, OFF order on one fresh Ubuntu 24.04
GitHub runner. Freeze the runtime image once. Use the original test-vm.sh,
2-CPU/2-GiB outer container, robot CPU0 and server/measurement CPU1, eight paths,
healthy positions 0/3/7, two apps, 15-second steady interval, three cycles,
10-second freshness and one-second TCP connect deadline. The integration overlay
adds only the opt-in observer after fixture creation. All original assertions,
worker exits, validators and failures remain; no reruns or outcome-driven extension.
The script rebuilds identical source binaries for each cell; audit their manifest
hashes after collection. Go build identity verifies clean exact-source product.

ON starts four header observers in robot, relay0, relay1 and target namespaces,
inheriting measurement CPU1. AF_PACKET SOCK_DGRAM with ETH_P_ALL observes both
directions, then retains only IPv4/TCP port9192 SYN/SYN-ACK/RST headers;
no payload is persisted and promiscuous mode is not enabled. Each role retains
1024 headers with kernel receive timestamps, explicit overwrite and socket-drop
counts. Coverage includes teardown; missing records are not proof of packet loss
when overwrite, drops, startup or shutdown gaps exist. Instrumentation overhead
is part of ON. OFF is the control. No equality of historic hosts or kernel package
versions is claimed; actual boot, kernel and image identities are retained.

All raw output goes under a 0700 runner directory, then an explicit bounded
allowlist is encrypted to the existing off-runner public recipient. No private
key, mutable guest image, build checkout or plaintext artifact is uploaded.
The final experiment status preserves any cell failure. An interrupted workflow
is incomplete, not a pass. Regardless of outcome this is diagnostic evidence,
not a replacement for PR266 qualification, which remains failed/unmerged.

## Capture and preparation corrections before the second cohort

The first diagnostic workflow39720342331 completed four image-preparation
failures before any VM test ran: the private umask made cloned Python source
unreadable to the cap-free UID0 builder. Preserve that run. Use normal source
file modes inside the private parent and check Python readability before trials.

Independent audit found the old ETH_P_IP observer omitted outgoing packets.
Linux6.8 `net/core/dev.c` routes `dev_queue_xmit_nit` only to ETH_P_ALL taps;
see https://github.com/torvalds/linux/blob/v6.8/net/core/dev.c#L2117.
Remote network-none container control compared both subscriptions for eight TCP
connections: IP-only omitted all eight outgoing SYNs; ALL captured all eight,
with zero socket drops. Keep only connection-control headers to preserve the
bounded ring. Previous raw artifacts remain unchanged and cannot establish
robot egress coverage. This correction changes diagnostic coverage, not product
behavior or the fixed OFF/ON/ON/OFF qualification conditions.

## Per-cell runner readiness

Run39720850708 preserved an actual OFF/healthy7 observation-staleness failure.
Later cells could not start because the runner no longer allowed /dev/kvm access.
This is not the original TCP connect-timeout reproduction, and the cohort is
incomplete. Before the next cohort reuse the existing disposable-runner KVM
guard from selector-profile-validation: snapshot device identity/ACL and restore
only this runner user's access before each planned cell when necessary. Record
post-cell device metadata too. Reject replaced devices and non-disposable hosts.
Never retry a failed cell or change its verdict. Product code and gates remain
fixed; all prior failures and unavailable cells remain preserved.
