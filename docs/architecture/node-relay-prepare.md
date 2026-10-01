# 승인 후보의 실제 준비와 복구 (#112)

`node relay prepare`는 [로컬 계획](node-relay-plan.md)을 새로 계산한 뒤 한 후보의
WireGuard 인터페이스와 암호화 전송 경로를 설치한다. `inspect`로 현재 승인이 유효하고
커널 설정·장치·주소가 일치하는지 확인하고, `release`로 소유한 후보를 해제한다.
중간에 종료된 작업은 다음 프로세스의 `recover`로 정리한다.

`prepared`와 `kernel_ready=true`는 커널 설정이 현재 승인과 일치한다는 뜻이다.
`uplink_health`는 항상 `unknown`이다. 이 단계에는 relay peer 배포, target route 선택,
자동 전환과 서버 도달성 probe가 포함되지 않는다. 서버 도달성은 별도로 검증해야 한다.

## 호출과 배포

[설정 예제](../../configs/node-relay-plan.example.yaml)의 underlay 매핑과 승인 cache를 사용한다.
cache를 소유한 동일 UID로 실행하고 대상 network namespace의 `CAP_NET_ADMIN`,
`iproute2`의 JSON/numeric 출력과 `wireguard-tools`가 필요하다. root로 바꿔 실행하는 것만으로
다른 UID의 private cache를 열 수 있지는 않다. 새 키나 별도 설정 파일을 자동 생성하지 않는다.

```sh
vpnctl node relay refresh --config node.yaml
vpnctl node relay plan --config node.yaml
vpnctl node relay prepare --config node.yaml --path-id robot-a-primary
vpnctl node relay inspect --config node.yaml
vpnctl node relay release --config node.yaml --path-id robot-a-primary
# prepare/release가 중간에 종료된 뒤, 같은 cache와 namespace에서 실행
vpnctl node relay recover --config node.yaml
```

path ID는 실제 승인 catalog의 값을 넣는다. `--cache-dir` 위치 선택은 기존 cache 명령과 같다.
prepare에는 `--controller-id`를 추가해 기대하는 controller 신원을 고정할 수 있다.
외부에서 저장한 plan JSON은 적용 입력으로 받지 않는다. 한 번에 한 후보를 준비하며 최대 8개다.
동일한 후보를 다시 준비하면 승인·관측·커널 상태를 다시 확인한다. 설정이 달라졌거나
부분 상태라면 기존 소유 후보를 먼저 해제/복구해야 한다.

## 설치 순서와 전송 경로

1. 현재 cache의 신원·세대·binding·유효시간, underlay/ifindex/source/gateway를 검증한다.
2. 기존 interface, 내부 IP, WG mark, rule priority/mask, route table 충돌을 검사한다.
   앞선 policy rule이 해당 mark를 가로챌 수 있으면 보수적으로 거절한다. builtin local lookup은 허용한다.
3. private cache의 `apply.json`에 모든 예정 자원과 임의 소유 식별자를 원자적으로 저장한다.
4. 별도 WG interface를 만들고 alias, 종결 unreachable, endpoint /32 route, mark rule,
   내부 /32 주소, WG 설정을 순서대로 설치한다. 승인과 장치를 재검사한 후 interface를 올린다.
5. 커널 주소·공개키·peer·endpoint·AllowedIPs·PSK 미설정·mark·rule·route를 읽어 대조하고 완료를 저장한다.

후보 table에는 선택한 device/source/gateway의 endpoint route와 `unreachable default`만 둔다.
endpoint route가 사라져도 mark 조회가 main table로 넘어가지 않게 한다. gateway 경로는
해당 장치를 명시한 `onlink` route로 설치한다. MTU는 초기 후보 계약에서 1280이다.
내부 주소에 `noprefixroute`를 사용하며 앱 target route를 설치하지 않는다.
각 명령은 add/delete를 사용하고 기존 테이블을 flush하거나 타인의 경로를 replace하지 않는다.

WireGuard 생성 시 alias가 보존되지 않는 커널이 있으므로 생성 요청에 저장된 임의 ifindex와
group을 함께 전달한다. alias 설정 전 중단도 이 두 값과 이름·WG 종류를 대조해 회수한다.
alias 설정 뒤에는 그 값도 검사한다. route는 protocol 186과 임의 metric을 포함한 전체 tuple,
rule은 priority/mark/mask/table/protocol을 대조한다.

## 저장·잠금·중단

- cache의 기존 0700/0600, UID·symlink·hardlink 검사와 process lock을 재사용한다.
  같은 namespace에서는 abstract Unix socket 잠금으로 다른 cache를 쓰는 적용자도 직렬화한다.
- journal은 schema, node, boot ID와 network namespace identity, checksum을 포함한다.
  checksum은 손상 탐지용이며 인증 서명이 아니다. 파일 권한이 신뢰 경계다.
  초기화 후 journal만 사라지면 새 기록으로 덮어쓰지 않고 손상으로 거절한다.
- 기록은 임시 파일 write/fsync → rename → 디렉터리 fsync 순서로 저장한다.
  저장 실패·불확실 상태에서는 같은 엔진으로 계속 변경하지 않고 다시 열어 확인해야 한다.
- cache의 개인키는 승인 재검사 후 `wg setconf`의 stdin pipe로만 전달한다.
  명령 인자, journal, 일반 오류·출력에는 포함하지 않는다. `wg show dump`를 사용하지 않는다.
  이 후보 계약은 PSK를 승인하지 않는다. 외부 PSK는 private 명령 pipe 안에서 설정 여부를
  검사하고 준비 완료·삭제를 거절한다. 읽은 PSK 값은 오류·report·artifact에 포함하지 않는다.
- 전체 작업은 최대 60초, 명령별 3초와 종료 정리 250ms, 명령 stdout 512KiB/stderr 4KiB,
  inventory 목록당 4096개로 제한한다. 초과·파싱 실패는 일부 결과로 진행하지 않는다.
  취소 시 실행 중인 명령과 자식도 종료한다. 파일 I/O의 kernel hang까지 취소하지는 못한다.
- prepare 실패 시 별도의 최대 60초 예산으로 복구를 시도한다. WG interface를 먼저 제거해
  송신을 멈춘 후 rule → endpoint route → unreachable을 지운다. 복구 실패는 journal을 보존한다.

외부 관리자는 이 후보의 자원을 동시에 변경하지 않아야 한다. 잠금은 vpnctl 적용자 간의
직렬화이며 모든 root 도구를 잠그지는 못한다. 커널 전체에 걸친 원자적 트랜잭션을 보장하지 않는다.
각 변경 전에 다시 확인하며 외부 peer/PSK/address/route나 다른 소유 식별자가 발견되면
자동 삭제를 거절한다. 외부 프로그램의 mark 재작성·라우팅 변경도 배포에서 분리해야 한다.

## 상태별 조치

| 출력/상황 | 의미와 조치 |
| --- | --- |
| `prepared`, `kernel_ready=true` | 현재 승인과 커널 설정 일치. 실제 서버 건강 상태는 별도 확인 |
| `prepare_failed_rolled_back` | 준비 실패 후 소유 변경을 회수함. 원인을 해결하고 prepare 재시도 |
| `recovery_required`, `pending_journal` | prepare/release가 미완료. 같은 cache·namespace에서 recover |
| `kernel_conflict_or_unavailable` | 읽기 실패 또는 외부 변경. 장치·table·rule·peer를 확인한 뒤 소유권이 일치할 때만 재시도 |
| `inventory_changed` | 링크·주소·gateway가 바뀜. 기존 후보를 release하고 새 plan/prepare 수행 |
| `approval_expired_or_changed` | 만료·거절·세대 변경. refresh 후 재검사하거나 release |
| `journal_save_failed`, `reopen_journal_required` | 저장 실패 또는 불확실. 저장소를 복구하고 새 프로세스에서 recover/inspect |
| boot/namespace 불일치 | 다른 실행 영역의 자원을 자동 채택하지 않음. 원래 영역과 기록을 운영자가 대조해야 함 |

recover는 미완료 `preparing/releasing` 항목을 회수하고 완료된 후보는 검사한다.
완료된 후보가 degraded여도 다른 후보로 자동 전환하거나 재설치하지 않는다.
cache 만료만으로 기존 자원을 주기적으로 제거하는 daemon도 아직 없다. `release`는 현재
승인이 만료돼도 보존된 소유 기록으로 실행할 수 있다. 호스트 재부팅 후 domain 이동·재구성과
현재 앱 경로의 유예 정책은 #23 후속 범위다. journal을 삭제해 오류를 우회하면 안 된다.

## 검증

```sh
go test -race ./internal/relayapply ./internal/relaycache ./internal/relayplan ./cmd/vpnctl
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-prepare-check \
  ./scripts/test-netns.sh -test.run='^TestNetns_M3PathTopology$' -test.timeout=8m
```

단위 검증은 8개 변경 단계의 전/후 실패·중단, 저장 실패·소유권 충돌,
1/3/8/32개의 독립 node와 최대 8 후보의 재실행·재오픈을 검사한다.
실제 netns 검증은 제품 CLI로 4개 후보와 [relay peer·반환 route](relay-peer-apply.md)를 준비하고
fixture가 forwarding/NAT와 임시 앱 route를 설치한 뒤 WG 암호화 source와 별도 서버 TCP echo를
대조한다. main table의 다른 통신망에
대체 경로를 넣어도 endpoint route 삭제/link down 시 UDP가 새지 않는지 검사한다.
실제 CLI의 생성 직후/rule 설치/WG 설정/link up 뒤 SIGKILL을 확인하고 다음 프로세스로 복구한다.
gateway는 설치/readback 범위를 검증한다. 자동 선택·relay forwarding 권한·상시 만료 차단과 전환 SLO는 후속 gate다.
완료 여부와 통과한 단계는 별도 `m3-prepare-*/report.json` artifact에 남기며 cache·journal·개인키는 포함하지 않는다.
