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
inheriting measurement CPU1. AF_PACKET SOCK_DGRAM observes IPv4/TCP port9192;
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
