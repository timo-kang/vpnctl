# 릴레이 승인 감독과 커널 lease (#124)

`relay supervise`는 이미 적용한 relay peer를 감독한다. 새 `relay apply`는 peer를
사용 가능하게 만들기 전에 endpoint 전용 nftables 차단 규칙을 설치한다. 감독이 없어도
마지막 통과 허가는 최대 10초 뒤 만료된다. 명령을 한 번 실행한 뒤 무기한 사용하는
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
만료 lease의 재허가는 인증 응답 시각부터 최대 5초까지만 열며, 이후 정상 cycle이
갱신한다. 응답을 받은 뒤 오래 정지한 프로세스가 오래된 성공 표시만으로 재개할 수 없다.
재허가 창이 소진되거나 nft 재확인 중 잔여 시간이 0초/만료로 표시되면 정상 규칙의
차단 상태와 link를 유지하고 다음 새 응답을 기다린다. 규칙 누락·소유자 변조·기한
불일치는 정상 만료로 취급하지 않고 기존 차단/복구 오류를 유지한다.

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
해제하고, namespace 적용 lock은 HTTP 호출이 끝난 뒤에만 얻는다. 동시 CLI의 busy
오류는 무한 대기하지 않으며, 운영 작업은 짧은 backoff로 재시도한다.

정상 wall clock에서 통과 기한은 `min(승인 expires_at, 갱신 계산 시각+10초)`를 초 단위로
내림한 값이다. 따라서 승인 시각보다 최대 1초 일찍 닫힐 수 있다. 새 패킷의 통과 여부를
평가하는 기한이며 이미 hook을 통과한 패킷을 회수하거나 기존 TCP socket을 종료하지는 않는다.
차단 뒤에도 WG interface/peer 또는 conntrack 항목은 남아 있을 수 있다.

## 커널 규칙과 배포 경계

endpoint마다 `vl` + interface hash의 `inet` table을 만들고 소유 alias를 각 rule에 기록한다.
input/iif, forward/iif·oif, output/oif에 소유 ifindex 조건을 붙인다. 처음에는 timed set이
비어 있고 cutoff가 과거이므로 차단된다. WG·route 설정, 현재 승인 검증 후에만 원자적
nft batch로 lease를 허가한다. 두 조건 모두 통과해야 한다.

1. 실제 wall time이 절대 cutoff보다 작다.
2. 최대 10초 timeout의 `iface_index` set에 소유 ifindex가 살아 있다. 원소의 상대
   timeout도 절대 cutoff까지 남은 시간 이하로 제한한다.

절대 cutoff는 suspend/시계 전진 뒤 오래된 lease 사용을 막고, 상대 timeout은 시계
역행 때문에 무기한 열리는 것을 막는다. 시계 역행과 갱신 명령이 겹치면 상대 timeout은
커널 commit부터 10초다. 개별 명령 context는 3초지만 프로세스 전체가 멈춘 순간의
스케줄링까지 실시간 상한으로 보장하지 않는다. cache의 영속 관측 시각과 30초 역행
거절 정책도 유지한다. 실제 장비의 시계 변경·suspend 조합은 별도 VM/장비 gate가 필요하다.

nft 규칙의 property·순서·owner·set timeout을 모두 판독해 비교하고 소유 table만
갱신/제거한다. host ruleset이나 다른 interface를 flush하지 않는다. 기존 TCP도 filter
hook을 통과하므로 lease를 적용받는다. flowtable은 forwarding hook을 우회할 수 있어
같은 namespace의 nft flowtable이 하나라도 있으면 생성/갱신/준비 완료 판정을 거절한다.
운영자는 XDP/TC/hardware offload 등 별도 우회 경로를 사용하지 않아야 한다.
root/CAP_NET_ADMIN이 규칙을 삭제하는 상황을 격리하는 보안 경계는 아니다.

지원 기준은 Linux nftables의 `meta time`, timed `iface_index` set, JSON listing이다.
실제 검증은 test-netns 이미지의 Debian bookworm nftables 1.0.6과 실행 호스트 커널에서
수행한다. 다른 nft/kernel 조합은 동일 시험으로 확인한다. 시간은 UTC로 판독한다.
규칙 표현이 다르거나 지원되지 않으면 보호 없이 적용하지 않고 실패한다.
[nftables 공식 매뉴얼](https://www.netfilter.org/projects/nftables/manpage.html),
[Linux timekeeping](https://docs.kernel.org/core-api/timekeeping.html).

## 관측과 복구

JSONL에는 `observed_at`, `cycle_ms`, `state`, `reason`, `refresh`, `approval_state`,
`approval_valid`, `approval_expires_at`, `last_refresh_at`, `last_success_at`, `kernel`을 기록한다.
커널 검사 성공 시 endpoint별 `lease.active`와 `lease.deadline`을 제공한다.
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

기존 journal은 `lease_version`이 없으므로 0이다. 새 버전이 이를 읽으면 이전 endpoint를
차단·회수하고 새 apply를 요구한다. 구형 binary로 downgrade하여 새 journal을 열 수 없다.
업그레이드 전 기존 endpoint release, 새 binary 설치, refresh/supervise/apply 순서를 권장한다.
rollback은 새 binary로 endpoint를 release한 후 이전 배포로 복귀한다. guard/journal만
삭제하는 우회 절차는 사용하지 않는다.

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
실제 host reboot·suspend·wall clock step 조합은 #128, 운영 환경의 최악 지연/SLO는
#124의 후속 qualification이다. 이 변경만으로 #124/#114/M3 최종 gate를 닫지 않는다.

## 다른 배포 저장소에서 사용하기

[systemd template](../../deploy/vpnctl-relay-supervise@.service)을 가져가 경로·UID·netns를
배포 환경에 맞춘다. 같은 relay의 명령들은 동일 UID, 영속 cache, network namespace를
사용해야 한다. host filesystem에 0700 cache 디렉터리, 0600 일반 파일을 유지한다.
`ip`, `wg`, `nft`, NET_ADMIN과 writable cache가 필요하다. 서비스에 PrivateNetwork를
설정하면 실제 peer namespace와 달라지므로 사용하지 않는다. 신뢰된 absolute PATH를 쓴다.

감독 종료는 즉시 endpoint 삭제 명령이 아니다. 즉시 회수하려면 supervisor를 중지하고
각 endpoint에 `relay release`를 실행한다. supervisor 정지만으로도 lease는 만료된다.
네트워크 준비 순서, controller 도달 경로, source/target firewall과 SNAT/반환 route는
[배포 네트워크 계약](../deployment/relay-network.md)의 책임으로 남는다.
