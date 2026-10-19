# Exact image cross-host control (experiment only; do not merge)

Product/test source is 888b83b991c1857f9114c59a3deb3cb76cf8506a, independently
cloned with a real .git directory. CI builds one Go 1.25.0 race CLI and race
integration executable and three pinned ordinary compatibility executables.
The current pinned Dockerfile builds a new runtime once. Its kernel/packages
may differ from earlier trials; this is a new cohort, not a replay of old bytes.
The pristine runtime Docker image, guest qcow2, kernel, initrd, executable bytes,
actual build settings, controller/protocol hashes and SHA-256 inventory travel
together. The remote host MUST NOT rebuild, update packages or alter this set.

Each host runs exactly four fresh VM invocations: shared, split, split, shared.
Each invocation exercises the original 8-candidate/two-app capacity case at all
three removal positions. No API load, additional instrumentation, retry,
reorder, early stopping after product failure, or freshness/lease/ownership/
payload threshold changes. Original exits and every frozen verdict are retained.
An infrastructure failure is recorded separately; host-isolation or input hash
violations stop subsequent work, retaining an incomplete result. Watchdog is
1200 seconds per invocation, not an application recovery SLO.

Runtime constraints: 1 outer CPU/1 guest vCPU shared; 2 outer CPUs/2 guest vCPUs
split. Robot quota 0.5 CPU, split server quota 1 CPU; existing role checks apply.
Outer memory 2 GiB, no swap, PID limit 256, guest memory 768 MiB. Nonroot,
read-only root filesystem, network none, all capabilities dropped, only /dev/kvm
and its device group. Select two available host CPUs before launch and record
them in every command. Affinity is not exclusive reservation. Host CPU model,
pressure and the same preexisting running containers/boot ID are recorded.
No host network, kernel, power, clock, ACL, group or service changes.

Build on a fresh disposable CI runner (attempt 1) only. Preparation requires
24 GiB free, compiler quota 2 CPUs/4 GiB, runtime build quota 1 CPU/2 GiB.
An allowlisted archive contains the pristine bundle, manifests, setup logs,
and trial results. Mutable guest overlays, source clones, caches, private keys
and arbitrary directories are excluded. Reject symlinks/special files and
archives above 12 GiB; encrypt directly to the existing off-runner GPG recipient.
Only encrypted artifacts are uploaded; no private decryption key in CI.

Before remote launch verify archive integrity, exact manifest, runtime image ID,
all executable and guest hashes and controller/protocol hashes. Replay original
Go publication/failure validation and audit original resource/role constraints
on both hosts. Report all four outcomes per host and missing/incomplete evidence.
If hosts differ, classify residual environment sensitivity, not a proven CPU
microarchitecture or scheduler cause. Small fixed repeated cohorts do not define
an application SLO. No product optimization, race removal or merge waiver follows
from this experiment. Raw measurements remain private/encrypted.
