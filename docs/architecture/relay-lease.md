# 릴레이 승인 감독과 커널 lease (#124)

`relay supervise`는 이미 적용한 relay peer를 감독한다. 새 `relay apply`는 peer를
사용 가능하게 만들기 전에 endpoint 전용 nftables 규칙과 WireGuard TC 송수신 BOOTTIME 차단을 설치한다. 감독이 없어도
정상적으로 진행하는 게스트 시계에서 마지막 커널 통과 허가는 최대 10초 뒤 만료된다.
VM 전체 pause처럼 모든 게스트 시계가 멈추는 조건은 외부 시간 상한이 아니며,
[VM 검증·사전 차단 계약](../testing/relay-vm-boundaries.md)을 따른다. 명령을 한 번 실행한 뒤 무기한 사용하는
방식에서 상시 감독을 요구하는 방식으로 바뀐다.

```sh
vpnctl relay refresh --config relay.yaml --relay-id relay-a
vpnctl relay supervise --config relay.yaml --relay-id relay-a --refresh-interval 5s
# 다른 터미널/배포 작업에서 같은 UID, cache, network namespace를 사용한다.
vpnctl relay apply --config relay.yaml --relay-id relay-a --endpoint-id lan \
  --key-file /var/lib/vpnctl-relay/keys/relay.key --key-generation 1 --listen-port 51820
```

감독은 private key를 읽거나 peer를 새로 설치하지 않는다. 인증서 갱신은 별도의
`relay sync-credentials`, 승인 TTL 연장은 관리자 catalog 갱신이 맡는다. 감독은
요청마다 디스크의 mTLS credentials를 다시 읽으며, 인증서 갱신만으로 승인 TTL을
연장하지 않는다. 최초 cache가 없으면 `refresh`로 초기화해야 한다.
만료 lease의 첫 재허가는 새 인증 요청 시작부터 최대 5초까지만 연다. 커널에서 그 짧은
허가가 실제 활성임을 읽어 확인하면, 같은 작업 안에서 일반 연속 갱신을 한 번 수행한다.
연속 갱신에는 fresh 승인을 넘기지 않으며 nft의 이전 원소 조건과 BPF의 이전 세대·기한
CAS를 다시 통과해야 한다. 그 사이 정지·만료가 발생하면 새 허가로 바꾸지 않는다.
다중 endpoint 검사 순서를 한 바퀴 기다리다가 같은 짧은 허가가 반복 만료되는 문제를
피하면서, 정상 lease의 최대 10초와 fresh 재가동 창의 5초를 각각 유지한다. 게스트의 상대 clock이 진행하는 프로세스 지연 조건에서 요청 시각은
monotonic 성분을 보존해 저장/검사 지연과 작은
wall clock 역행으로 재허가 창이 늘어나지 않게 한다. nft 타이머 준비와 경로 선택을
분리하여 지연된 선택 명령은 이미 만료된 타이머를 다시 시작할 수 없다(#136).
S3와 시계 역행이 겹쳐 nft timer가 만료되지 않는 조건(#138)은
`lease_version=3`의 독립 BOOTTIME packet guard가 차단한다. 전체 게스트 시계가 멈추는
VM pause는 외부 사전 차단 계약이 계속 필요하다.
재허가 창이 소진되거나 nft 재확인 중 잔여 시간이 0초/만료로 표시되면 정상 규칙의
차단 상태와 link를 유지하고 다음 새 응답을 기다린다. 규칙 누락·소유자 변조·기한
불일치는 정상 만료로 취급하지 않고 기존 차단/복구 오류를 유지한다.
nft JSON은 초 미만 원소를 `timeout: 0, expires: 0`으로 표시할 수 있다. 이 표현은
비활성으로 판독하며 자원 충돌로 link를 내리거나 캐시만으로 재허가하지 않는다.

## 시간과 실패 처리

| 조건 | 동작 |
| --- | --- |
| 유효 승인, 정상 커널 | 1초 간격으로 검사하고 최대 10초 lease 갱신 |
| timeout/EOF/429/일반 5xx | 기존 lease가 아직 활성이고 승인이 유효한 동안 갱신 |
| 401/403, 승인 폐기·disabled·키/peer 변경 | cache 정책에 따라 거절/새 view를 기록하고 모든 해당 endpoint 차단·회수 시도 |
| SIGKILL/SIGSTOP, 쓰기/잠금/I/O 실패 | 갱신 중단; 이미 설치된 커널 규칙이 마지막 허가 기한에 차단 |
| 만료된 lease + 통신 오류 | cache에 유효 승인이 있어도 자동 재개 금지 |
| 만료된 lease + 새 인증 승인 응답 | 기존 peer/key/route가 일치할 때만 다시 허가 |
| peer가 회수되었거나 link가 내려감 | 감독이 재설치하지 않음; 충돌 해결 후 명시적 release/apply 필요 |

인증 조회 기본 주기는 5초이고 `--refresh-interval`은 1~20초다. HTTP 요청은 1초,
감독 cycle의 커널 명령 context는 5초로 제한한다. 파일 I/O 자체의 정지까지 context가
해제하지는 못한다. 이 경우에도 lease는 갱신되지 않는다. cache lock은 cycle마다
해제하고, namespace 적용 lock을 얻은 뒤 실제 HTTP 호출을 시작한다. 잠금 대기로
fresh 응답의 재가동 창을 소진하거나 오래된 응답에 새 시각을 붙이지 않는다.
cache와 namespace 잠금 경합은 기존 cycle 예산 안에서 25ms마다 재시도한다.
짧은 CLI가 반복되어 1초 간격의 cache 획득이 계속 충돌하더라도 중간 해제 기회를
이용한다. 다른 오류는 재시도하지 않는다. CLI는 기본 fail-fast이며, 명시적
`apply|inspect|release|recover --lock-wait`만 작업 기한 안에서 최대 5초 대기한다. 작업이 1초보다
길어져도 잠금을 해제한 뒤 다음 주기까지 최소 50ms를 두어 다른 supervisor에 획득
기회를 준다. 공정한 FIFO 대기열이나 과부하 상태의 무중단을 보장하지는 않는다.

정상 wall clock에서 통과 기한은 `min(승인 expires_at, 갱신 계산 시각+10초)`를 초 단위로
내림한 값이다. 따라서 승인 시각보다 최대 1초 일찍 닫힐 수 있다. 새 패킷의 통과 여부를
평가하는 기한이며 이미 hook을 통과한 패킷을 회수하거나 기존 TCP socket을 종료하지는 않는다.
차단 뒤에도 WG interface/peer 또는 conntrack 항목은 남아 있을 수 있다.

한 감독 주기는 endpoint의 소유권·WireGuard 설정·경로·forwarding 정책을 갱신 직전에
확인하고, 같은 잠금 안에서는 그 결과를 재사용한다. 마지막에는 lease 상태와 승인 유효성을
다시 읽는다. 이전 주기의 검사 결과를 재사용하지 않는다. 커널 전체의 원자적 snapshot을
뜻하지 않으며 외부 변경은 다음 검사에서도 다시 확인한다. 명시적 `inspect`와 `apply`의
최종 검사는 항상 새 inventory를 읽는다. WireGuard 설정은 bounded `wg show … dump`
한 번으로 확인하며 private-key/PSK 열을 로그나 오류에 포함하지 않는다.
[출력 형식 근거](https://git.zx2c4.com/wireguard-tools/tree/src/show.c).

## 커널 규칙과 배포 경계

endpoint마다 `vl` + interface hash의 `inet` table을 만들고 소유 alias를 각 rule에 기록한다.
input/iif, forward/iif·oif, output/oif에 소유 ifindex 조건을 붙인다. 처음에는 timed set이
비어 있고 cutoff가 과거이므로 차단된다. v3에서는 세 조건 모두 통과해야 한다.

1. 실제 wall time이 절대 cutoff보다 작다.
2. 선택된 `iface_index` timed set에 소유 ifindex가 살아 있다.
3. TC BPF map의 소유 BOOTTIME 기한보다 현재 BOOTTIME이 작다.

`lease_version=2`부터 nft 갱신은 다음 두 트랜잭션으로 나뉜다.

1. 매번 난수 128bit 이름의 새 set을 생성하고 timeout 원소를 넣는다. 이 set은 아직
   어떤 경로에서도 참조하지 않으므로 준비 명령만 지연되거나 재실행되어도 통신을 열지 않는다.
2. 준비 ACK 후 `max(monotonic 경과, CLOCK_BOOTTIME 경과) + timeout + 100ms`가
   최초에 계산한 잔여 승인/재허가 시간 이내인지 검사한다. 준비 비용으로 1초를 미리
   남긴다. 따라서 보통 timer는 절대 cutoff보다 약 1초 먼저 닫히며, 준비가 약 900ms를
   초과하면 후보를 선택하지 않는다. 안전 여유를 제외한 가용성을 보장하는 실시간 SLO는 아니다.
3. 별도 nft batch는 기존 규칙을 새 set 참조로 바꾸고 이전 set을 삭제한다. timeout을
   설정하거나 원소를 추가하지 않는다. 기존 활성 lease의 연장에서는 먼저 기존 원소의
   조건부 delete를 요구하므로 이미 만료된 연장을 새 허가로 바꾸지 않는다. 새로운 승인
   없이 실패한 연장을 재허가로 재시도하지 않는다.

경로 선택 batch가 오래 지연되면 후보 timer 자체가 먼저 만료된다. 따라서 wall clock을
뒤로 돌려도 늦은 commit이 timer를 새로 시작하지 못한다. 이전 set 삭제는 오래된 batch의
재전송도 거절하며, 다음 갱신은 새로운 난수 이름을 사용한다. 검사 직후 프로세스가
정지하더라도 선택 batch에는 수명을 연장할 연산이 없다. 같은 namespace의 적용 잠금도
유지한다. 중단 후 남은 준비 set은 최대 하나까지 엄격히 검증하고 다음 준비에서 회수한다.
차단은 선택 set과 준비 set 모두 비워 지연된 선택이 빈 set을 열지 못하게 한다.

절대 cutoff는 suspend/시계 전진을, timed set은 시계 역행을 각각 제한한다. set은 kernel
jiffies로 만료를 판단하므로 tick 오차 100ms 미만인 플랫폼을 요구한다(검증 Linux HZ≥100).
Linux nft transaction 처리 자체에 대한 hard realtime 보장은 하지 않는다. 전체 게스트
clock이 멈추는 VM pause/스냅샷 복원 한계(#135)는 그대로이며 외부 사전 차단 계약을 따른다.
v2에서는 S3와 wall rollback이 겹치면 두 nft 조건을 우회할 수 있었다(#138).
v3는 모든 소유 WireGuard 인터페이스에 하나의 TC BPF 프로그램을 ingress/egress 양쪽에
부착하고 `bpf_ktime_get_boot_ns`로 패킷마다 별도 절대 기한을 검사한다. 이 시계는 S3
시간도 포함한다. map은 최초 차단 상태로 만들고 두 부착점을 검증한 뒤 link를 올린다.

갱신은 네트워크에 부착하지 않은 별도 BPF 프로그램의 `BPF_PROG_TEST_RUN`으로 한다.
spin lock 안에서 전체 128bit 소유자, 예상 세대, 이전 BOOTTIME 기한을 확인한다.
이미 만료되었다면 인증 요청 전에 얻은 BOOTTIME 관측부터 5초 이내의 새 승인만
허용하며 새 기한도 이 창을 넘지 못한다. 활성 연장도 계산 당시 BOOTTIME+최대 10초인
고정 제안을 사용한다. 늦게 실행되는 syscall에 현재 시각을 더해 수명을 새로 만들지 않는다.
반영한 세대는 증가하고 같은 제안 재생은 실패한다. nft 경로 선택 전에 갱신하며,
이후 선택이 늦어져도 TC gate는 절전 시간을 포함하여 독립 만료한다.

기한 map과 packet 프로그램은 배포가 준비한 `/run/vpnctl-bpf`의 소유자 전용 pin으로
유지한다. 프로세스가 전역 객체 ID로 재개방하면 CAP_SYS_ADMIN이 필요하므로 이 방식을
사용하지 않는다. pin 경로는 전체 128bit 소유 토큰으로 구분하고 bpffs 종류, UID,
디렉터리 0700·파일 0600, symlink와 조상 경로의 쓰기 권한을 검사한다. 필요한 두 pin만
열며 전역 객체 목록은 열거하지 않는다. 소유 WG link를 제거한 다음 program pin과 map
pin 순서로 회수하고, 완료 전까지 journal을 보존하여 중단된 정리를 반복할 수 있게 한다.
제품은 filesystem을 마운트하지 않으며 준비가 누락되면 적용에 실패한다. 검사 시 두 부착점과
프로그램 명령어 태그, map 구조·소유자·기한을 검증하며 불일치를 보호 없는 준비 완료로
표시하지 않는다. time namespace의 boottime/monotonic offset이 0이 아니면 userspace와
커널 helper의 시간 영역이 달라지므로 적용·갱신을 거절한다.
cache의 영속 관측 시각과 30초 역행 거절 정책도 유지한다.

nft 규칙의 property·순서·owner·set timeout을 모두 판독해 비교하고 소유 table만
갱신/제거한다. host ruleset이나 다른 interface를 flush하지 않는다. 기존 TCP도 filter
hook을 통과하므로 lease를 적용받는다. flowtable은 forwarding hook을 우회할 수 있어
같은 namespace의 nft flowtable이 하나라도 있으면 생성/갱신/준비 완료 판정을 거절한다.
운영자는 소유 TC guard 외의 XDP/TC/hardware offload 등 별도 우회 경로를 사용하지 않아야 한다.
root/CAP_NET_ADMIN이 규칙을 삭제하는 상황을 격리하는 보안 경계는 아니다.

지원 기준은 Linux `CLOCK_BOOTTIME`, nftables `meta time`, comment가 있는 timed
`iface_index` set, 조건부 원소 삭제, JSON listing이다. v3는 추가로 Linux 5.8 이상에서
`CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`, `CONFIG_NET_SCH_INGRESS`, BTF map의
`bpf_spin_lock`, `BPF_PROG_TEST_RUN`, `bpf_ktime_get_boot_ns`가 필요하다. 버전 번호만으로
충족했다고 가정하지 않고 실제 설치와 readback이 성공해야 한다. CAP_NET_ADMIN 및
CAP_BPF, 커널 설정에 맞는 memlock 한도가 필요하다. 기본 서비스 템플릿은 64MiB를
설정한다. helper/권한/자원이 부족하면 적용을 취소하며 nft만으로 자동 하향하지 않는다.
실제 검증은 test-netns 이미지의 Debian bookworm nftables 1.0.6과 실행 호스트 커널에서
수행한다. 다른 nft/kernel 조합은 동일 시험으로 확인한다. 시간은 UTC로 판독한다.
규칙 표현이 다르거나 지원되지 않으면 보호 없이 적용하지 않고 실패한다.
[nftables 공식 매뉴얼](https://www.netfilter.org/projects/nftables/manpage.html),
[Linux timekeeping](https://docs.kernel.org/core-api/timekeeping.html),
[Linux 6.8의 set 만료 검사](https://github.com/torvalds/linux/blob/v6.8/include/net/netfilter/nf_tables.h),
[BOOTTIME helper 계약](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/bpf.h),
[객체 ID 재개방 권한과 FD 정보 검사](https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/syscall.c).

## 관측과 복구

JSONL에는 `observed_at`, `cycle_ms`, `state`, `reason`, `refresh`, `approval_state`,
`approval_valid`, `approval_expires_at`, `last_refresh_at`, `last_success_at`, `kernel`을 기록한다.
커널 검사 성공 시 endpoint별 `lease.active`, `lease.deadline`,
`lease.boottime`의 `deadline_ns`, `observed_ns`, `generation`, `program_id`, `map_id`를 제공한다.
`active`는 nft와 BOOTTIME 조건을 모두 만족해야 한다.
`expiry_enforcement=kernel_lease`는 이 방식의 보호 계약이며 서버 uplink 건강 증거가 아니다.
`uplink_health=unknown`을 유지한다. `degraded`나 kernel 정보 누락은 차단 완료의 증거가
아니므로 마지막 deadline과 실제 패킷 관측을 함께 확인한다. 로그 쓰기가 막히면 다음
갱신도 멈추며 lease가 만료된다. 로그 보존량은 journald/수집기의 회전 설정으로 제한한다.

외부 peer/route/PSK가 추가되어 interface 제거가 불가능해도 소유 guard를 먼저 닫는다.
guard 자체가 변조되면 타인 규칙을 덮어쓰지 않고 소유 link 차단을 시도하며 실패를 노출한다.
모든 endpoint를 순회하므로 한 충돌 때문에 다른 endpoint의 차단 시도를 생략하지 않는다.
회수 실패가 있어도 최신 승인과 동일한 다른 endpoint의 lease 갱신은 계속한다.
회수 실패로 journal에 남은 과거 endpoint를 갱신하지 않으며, cache 읽기 실패나 journal
저장 불확실 상태에서는 갱신을 진행하지 않는다. 전체 결과는 계속 `degraded`로 보고한다.

이전 journal의 `lease_version`은 0(lease 없음), 1(단일 갱신 batch), 2(nft 준비/선택 분리)이다. 새 버전이 이를 읽으면 이전 endpoint를
차단·회수하고 새 apply를 요구한다. 구형 binary로 downgrade하여 새 journal을 열 수 없다.
업그레이드 전 기존 endpoint release, 새 binary 설치, refresh/supervise/apply 순서를 권장한다.
rollback은 새 binary로 endpoint를 release한 후 이전 배포로 복귀한다. guard/journal만
삭제하는 우회 절차는 사용하지 않는다. 같은 boot에서 namespace를 폐기하기 전에도
원래 namespace에서 release한다. namespace만 지우면 private pin은 남을 수 있으므로
원래 domain을 복구해 회수하거나 배포 절차에서 전용 bpffs 수명을 함께 관리해야 한다.
다른 domain의 journal을 임의로 채택하거나 이름 패턴만으로 pin을 일괄 삭제하지 않는다.

boot ID 또는 namespace가 바뀌면 journal을 자동 채택하지 않는다. 재부팅 후 nft/WG
규칙을 독립적으로 자동 복원하는 서비스와 함께 쓰지 않는다. 이전 domain의 자원이
없는지 확인하고 전체 cache를 보존·격리한 뒤 fresh approval로 재설치한다. 프로세스
재시작은 같은 domain에서 새 승인으로 정상 applied 자원의 lease만 재개할 수 있다.

## 검증과 남은 gate

`TestNetns_M3PathTopology`는 두 relay × 두 underlay에 제품 peer를 설치하고 실제 TCP를
통과시킨다. SIGSTOP/SIGKILL, 가득 찬 1MiB tmpfs의 ENOSPC, 컨트롤러 503, 새 mTLS
credentials, 실제 expires_at을 주입한다. 기존 TCP와 새 연결을 구분하며, 커널 peer를
남겨 둔 채 자동 차단을 확인한다. `m3-lease-*` artifact에 감독 JSONL, TCP event,
fault/expiry 결과가 남는다. 비밀키/인증서 cache는 artifact에 복사하지 않는다.

단위/race는 각 변경 단계의 저장 실패·중단, 시계/high-water·승인 만료, journal domain
불일치, 오래된 세대/변조, 외부 자원 충돌, lease 만료 후 cache만으로 재개 금지,
구형 journal, 감독 실패/종료를 다룬다. 실제 규모 시험은 1/3/8/32 node × 4 path의
peer/route 설치 검증이며 전체 fleet 통신 SLO나 endpoint 상한 동시 감독 판정은 아니다.

```sh
go test -race ./internal/relayapply ./internal/relaycache ./cmd/vpnctl
VPNCTL_RACE=0 scripts/test-netns.sh -test.run='^TestNetns_M3(PathTopology|RelayDeploymentScale)$'
```

실제 controller 기반 네 경로 권한 전이, 1/8 endpoint 규모, 동시 요청 및 과부하 검증은
[릴레이 승인 검증 계약](../testing/relay-lease-matrix.md)에 별도로 정의한다.
격리 VM reboot·suspend·wall clock step 조합과 재현 방법은
[VM 경계 검증](../testing/relay-vm-boundaries.md), 운영 환경의 최악 지연/SLO는
#124의 후속 qualification이다. 이 변경만으로 #124/#114/M3 최종 gate를 닫지 않는다.

## 다른 배포 저장소에서 사용하기

[systemd template](../../deploy/vpnctl-relay-supervise@.service)을 가져가 경로·UID·netns를
배포 환경에 맞춘다. 전용 mount 템플릿 `deploy/run-vpnctl\x2dbpf.mount`를 함께
배포하고 relay 시작 전에 준비한다. 마운트 준비에 필요한 관리자 권한은 배포 단계에서
사용하며 상시 relay 서비스에는 CAP_SYS_ADMIN을 부여하지 않는다. CLI와 감독은 같은
mount namespace의 bpffs를 사용한다. 별도 경로가 필요하면 모든 관련 명령에
`VPNCTL_BPF_ROOT`를 동일하게 설정하고 전용 mount를 그곳에 준비한다. 같은 relay의 명령들은 동일 UID, 영속 cache, network namespace를
사용해야 한다. host filesystem에 0700 cache 디렉터리, 0600 일반 파일을 유지한다.
`ip`, `wg`, `nft`, CAP_NET_ADMIN·CAP_BPF와 writable cache가 필요하다.
저장소의 서비스 파일은 배포 템플릿이며 편집만으로 현재 머신에 설치되지는 않는다. 서비스에 PrivateNetwork를
설정하면 실제 peer namespace와 달라지므로 사용하지 않는다. 신뢰된 absolute PATH를 쓴다.

감독 종료는 즉시 endpoint 삭제 명령이 아니다. 즉시 회수하려면 supervisor를 중지하고
각 endpoint에 `relay release`를 실행한다. supervisor 정지만으로도 lease는 만료된다.
네트워크 준비 순서, controller 도달 경로, source/target firewall과 SNAT/반환 route는
[배포 네트워크 계약](../deployment/relay-network.md)의 책임으로 남는다.

## 다중 감독기의 fresh 승인 요청 순서 (#143)

감독기는 cache lock과 namespace lock을 취득한 뒤 실제 인증 요청을 수행한다. 다른 감독기를
기다린 시간을 승인 재가동의 5초 창에 포함시키지 않으며, 승인 시각은 여전히 실제 HTTP 요청
직전에 읽은 realtime/BOOTTIME이다. 오래된 응답의 시각을 다시 찍어 사용하지 않는다.
namespace를 보유한 요청은 최대 1초이고 lock 대기·요청·커널 작업 전체의 5초 cycle 예산은
유지한다. 실패 응답 뒤에도 Maintain을 호출하며 프로세스 중단은 독립 kernel lease가 차단한다.
배포 source/target 정책 검사로 cycle 비용이 늘어도 이 순서를 유지해야 한다.
