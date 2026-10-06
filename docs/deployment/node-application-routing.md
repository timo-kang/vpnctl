# Node application routing deployment

다른 배포 저장소는 `vpnctl` binary, [동작 계약](../architecture/node-target-application.md),
`deploy/vpnctl-node-target@.service`, `scripts/test-m3-target-application.sh`를 재사용할 수 있다.
이 저장소의 테스트 실행은 `--network none` 전용 컨테이너 안에서만 자원을 만든다.
운영 호스트의 절전·재부팅·시계·네트워크·mount를 자동 변경하지 않는다.

## 배포자 준비 항목

- [노드 승인 lease 배포](../architecture/node-approval-lease.md)의 전용 bpffs와 권한을 준비한다.
  상시 프로세스는 CAP_NET_ADMIN/CAP_BPF이며 CAP_SYS_ADMIN은 부여하지 않는다.
- 앱·prepare·supervise·reconcile은 같은 network namespace와 신원/cache를 사용한다.
  NetworkManager hotspot, Netplan RF/짐벌, udev EtherCAT 장치는 승인된 underlay만 참조한다.
- namespace의 `/proc/sys/net/ipv4/conf/all/rp_filter`와
  `/proc/sys/net/ipv4/conf/default/rp_filter`를 0으로 준비한다. 새 WG는 default를 상속한다.
  기존 물리 인터페이스의 개별 rp_filter는 원하는 정책을 명시적으로 유지한다. all을 바꾸면
  effective max(all,interface)가 달라질 수 있으므로 배포 저장소에서 각 장치 정책을 관리한다.
  혼용 환경에서 전역 정책을 바꿀 수 없다면 전용 network namespace 배치를 먼저 검증한다.
  vpnctl은 이 값을 자동 변경하지 않고 준비/감독 중 읽어 확인한다.
- 동일 target에 대한 source-only 후보는 release하고 `prepare --app-routes`로 새로 준비한다.
  모든 후보의 live lease 확인 후 target reserve, reconcile을 시작한다.
- 앱은 일반 unbound IPv4 socket을 사용한다. 명시적 bind/mark/별도 namespace 앱은 별도 설계가 필요하다.
- target당 reconcile 프로세스 하나를 두고 같은 target에 상충하는 auto/manual 프로세스를 실행하지 않는다.
  복수 target은 같은 node/cache lock을 공유한다. lock busy는 실패로 관측되며 성공을 추정하지 않는다.

서비스 template은 예시다. `/etc/vpnctl/node.yaml`, `/usr/local/bin/vpnctl`, cache/bpffs 및
supervise service 위치를 실제 배포에 맞춘 뒤 설치한다. `%i`는 catalog target ID다.
자동 target release를 ExecStop에 연결하지 않는다. 서비스 종료가 default fallback 재개로 이어지면 안 된다.

## 운영과 복구

JSONL의 최상위 `applied`, `application.state/reason/activated/guarded`, 후보별 제외 원인과
`route_changed_at`, `app_verified_at`를 함께 수집한다. `ownership_unavailable`, `switching`,
`journal_save_failed`, `kernel_conflict_or_unavailable`은 운영 조치가 필요하다.
`rolled_back`은 서비스가 이전 경로로 살아 있어도 변경 자체는 실패한 결과다.

단발성 prepare/inspect/recover/release와 target 명령이 잠금에 진입하지 못하면
`ownership_unavailable`과 함께 실패한다. 이 결과는 커널 변경·차단 완료를 뜻하지 않는다.
외부 자동화는 이 진입 전 실패만 별도 제한시간 안에서 재시도할 수 있다. 이미 진입한 작업의
오류나 불확실한 journal commit을 동일 방식으로 재실행하지 말고 inspect/recover 절차를 따른다.
`--samples 2`도 두 번의 잠금 진입 성공을 보장하지 않으므로 지속 관측에는 `--watch`를 사용한다.

중단된 변경은 같은 binary/신원/cache/netns에서 `target recover`로 차단 상태를 복구하고,
새 유효 승인을 받은 supervise와 reconcile로 재개한다. foreign 상태는 원 소유자가 정리한다.
만료/철회 후에도 reserve는 유지한다. `target release`는 운영자가 default fallback 영향을
검토하고 라우팅 소유권을 포기할 때만 실행한다. journal 삭제로 충돌을 우회하지 않는다.

구버전 binary는 새 journal field를 거절한다. downgrade는 새 binary로 앱 target과 scoped
후보를 명시적으로 release/recover한 후 수행한다. 이는 트래픽 차단과 fallback에 영향을 주므로
배포 절차에서 유지보수 구간을 정한다. 실행 중인 실험이나 다른 서비스는 중단하지 않는다.

## 검증

```sh
VPNCTL_ARTIFACT_DIR=/tmp/app-production scripts/test-m3-target-application.sh
VPNCTL_RACE=1 VPNCTL_TEST_CPUS=2 VPNCTL_ARTIFACT_DIR=/tmp/app-race scripts/test-m3-target-application.sh
```

같은 테스트를 `VPNCTL_TEST_BINARY=/path/to/vpnctl`로 외부 배포 binary에 적용할 수 있다.
production/race 결과를 구분한다. 결과에는 배치, 후보 수, phase별 실제 적용 결과, 기존 TCP 로그,
공개 kernel inventory와 binary digest가 남는다. controller/relay 동거와 분리, 후보 1/4/8,
다중 target, blackhole/릴레이 장애, controller 단절, 전체 불가, 수동 pin, SIGKILL, 만료/철회를 다룬다.
장기/물리 시험과 실제 네트워크 관리자 공존은 여기의 통과로 대체하지 않는다.

## Capacity qualification

Application CI uses 2 CPU / 2 GiB for both production and race builds, with up
to eight prepared candidates and two targets. The observer renews all leases
once per reconcile (without a second full sweep before apply), then overlaps only TCP proofs in a common 3s window. Cache/approval,
inventory, kernel checks and fail-closed changes stay serialized. A slow path
cannot force seven other TCP timeouts to run in series. All workers are joined
before releasing ownership. Public namespace inventories can be shared within
that wave only; postchecks require an inventory read that started after their
own TCP proof. Lease timers, per-interface state and approvals are never shared.
Busy watch admission uses a short jittered retry; admitted cycles retain the
configured interval and the 1s admission bound remains. The 10s freshness and
kernel lease bounds remain.

These are test profiles, not minimum hardware or failover-SLO guarantees.
`observation_budget_exhausted` means the bounded work could not establish enough
fresh evidence. It must not trigger accepting stale observations, extending lease
lifetimes, or removing the target reservation. A partial observation may select
only a candidate with new valid confirmations and the usual apply-time checks.

Use `diagnostics` on reconcile results and `observation_diagnostics` on selections
for monotonic/BOOTTIME elapsed time, phase calls and external kernel/inventory
command counts. Phase and command durations are sums; concurrent phases can
exceed the operation elapsed time; nested phases overlap too. They contain no command arguments, output or
credentials, and provide no authorization. BPF syscalls are not external commands.

The original 2 CPU race capacity failure and 4 CPU interim validation remain in
[issue #162](https://github.com/timo-kang/vpnctl/issues/162). Reproduction, mixed
healthy/slow paths, CPU profiles and remaining qualification limits are described
in [observation capacity validation](../validation/m3-observation-capacity.md).
