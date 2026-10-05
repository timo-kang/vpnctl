# Node application target reservation

`node relay target reserve`는 승인된 target으로 향하는 **로컬 발신 IPv4, mark=0 새 앱 흐름을
차단**한다. 앱 경로를 적용하기 전에 사용하는 소유권·실패 경계다. 현재 릴레이 추천은
`node relay select`로 확인하며, 이 예약 기능은 선택된 릴레이로 트래픽을 열지 않는다.
예약만 수행하면 `activated=false`다. 별도 [target reconcile](node-target-application.md) 적용 뒤의
inspect/recover는 실제 앱 연결을 재검증하여 `activated=true`를 출력할 수 있다.

```sh
vpnctl node relay target reserve --config node.yaml --target-id app
vpnctl node relay target inspect --config node.yaml --target-id app
vpnctl node relay target recover --config node.yaml --target-id app
vpnctl node relay target release --config node.yaml --target-id app
```

`reserve`에만 `--controller-id`를 지정할 수 있다. 기존 cache를 쓰며 controller 호출을
하지 않는다. 새 예약에는 유효한 catalog와 binding이 필요하다. `inspect/recover/release`는
승인이 만료되거나 철회된 후에도 journal을 이용한다. `--timeout`은 기본 1분, 최대 1분이다.
같은 cache와 network namespace에서 실행해야 한다. CAP_NET_ADMIN과 `ip`, `wg`가 필요하다.
이 기능 자체는 nft/BPF나 별도 daemon을 설치하지 않는다.

## Routing contract

Target마다 table 700000..1224287, priority 32000..32759를 controller/node/target ID로
결정한다. 이 범위는 독점 예약이 아니다. 다른 target 및 외부 설정과의 충돌은 거절하며,
충돌을 피하려고 기존 자원을 이동하거나 덮어쓰지 않는다. table에는 random metric과
protocol 186의 `unreachable default`만 설치한다. 각 승인 prefix에 다음 형태의 rule을 둔다.

```text
from all to <approved-prefix> iif lo fwmark 0/0xffffffff lookup <owned-table>
```

Linux RPDB의 `iif lo`는 로컬 발신 흐름을 제한한다. 동일 목적지로 중계되는 패킷의
경로를 바꾸지 않는다. 비영 mark, IPv6, 기존 소켓의 route cache·session 회수는 이 계약에
포함하지 않는다. 새 unbound TCP와 동일 target의 중계 TCP를 실제 시험한다.

Transport mark rule(20000..27999), 승인된 candidate source probe rule(28000..31999)이
먼저 적용된다. 명시적으로 candidate inner source를 묶은 probe는 계속 가능하다.
일반 앱은 이 source를 직접 bind하지 않아야 한다. 이 예약은 방화벽이나 프로세스별
접근 통제 기능이 아니다. main/default, DHCP, DNS, physical link, WG peer를 수정하지 않는다.

새 예약 전 table/priority 사용, 다른 target의 prefix 중첩, target과 겹치는 외부 특정
route(local address 포함), 앞선 mark-zero rule을 검사한다. journal과 정확히 일치하는
candidate probe route/rule만 예외로 인정한다. 일반 main/default는 유지하며 target의
fallback만 차단한다. UID/source/interface 등으로 제한된 외부 rule도 확실히 분리할 수
없으면 보수적으로 거절한다. source별 복잡한 정책과 실제 네트워크 관리자 공존은 후속 gate다.

## Persistence and recovery

Candidate 준비와 동일한 cache lock, namespace lock 및 `apply.json`을 사용한다.
boot ID/netns identity, digest, target ID, prefix, table, priority, protocol, random metric을
검사한다. 모든 새 kernel 자원보다 먼저 `reserving` intent를 저장한다. unreachable route를
먼저 설치하고 각 prefix rule을 추가한 후 전체 inventory를 다시 읽고 `guarded`를 저장한다.
복수 prefix rule은 순차 설치하므로 하나의 atomic transaction이 아니다. 완료 전에는 일부
prefix만 차단될 수 있다. `guarded=true`를 받은 후에만 다음 단계의 활성화 전제로 사용할 수 있다.

명령 실패·SIGKILL 후에는 `reserving`을 남기고 `recover`가 기존 정확한 자원을 재사용하여
차단 설치를 마무리한다. 일부 설치를 자동 철거하여 이미 막힌 prefix를 다시 열지 않는다.
이미 `guarded`인 상태의 자원 누락/변조는 외부 변경으로 보고하며 반복 재설치하지 않는다.
미완료 상태여도 rule 아래의 unreachable route가 사라진 경우 자동 수리하지 않는다.

`release`는 **명시적으로 라우팅 소유권을 포기하는 운영자 동작**이다. 일반 default가
다시 적용될 수 있다. `releasing`을 먼저 저장한 뒤 정확한 rule을 제거하고 마지막에
unreachable route를 회수한다. 중단 시 `recover`는 이 해제를 끝낸다. 승인 철회·controller
단절·승인 만료 처리로 `release`를 호출해서는 안 된다. 이들은 예약을 그대로 유지해야 한다.

저장 오류는 uncertain 상태로 전환하며 같은 engine의 후속 mutation을 거부한다. 다시 열어
실제 journal과 kernel을 확인해야 한다. 외부 table/rule 변경은 삭제하지 않고 conflict를
노출한다. `guarded=false`는 현재 트래픽이 열린다는 증거도, 차단됐다는 증거도 아니다.
`generation`은 예약만 있을 때 최초 승인 세대이고, 앱 활성화 후에는 마지막 검증된 적용 세대다.

검사와 netlink 명령 사이에 외부 관리자의 변경을 원자적으로 잠글 수는 없다. namespace
lock은 vpnctl의 새 relay 명령끼리만 직렬화한다. 기존 legacy up/down 전체, NetworkManager,
Netplan renderer, udev에 대한 공존 보장은 아직 하지 않는다. 외부 변경 후 inspection은
충돌을 드러내지만 이미 종료된 CLI가 계속 감시·차단해 주지는 않는다.

## Upgrade and deployment reuse

기존 `targets` 없는 journal을 읽는다. 새 field는 예약이 있을 때만 기록한다. 구형 binary는
이를 알 수 없어 journal을 거절한다. downgrade 전 새 binary로 모든 target 예약을 명시적으로
release해야 한다. 먼저 target fallback 영향과 별도 차단 대책을 확인한다. journal 파일만
삭제하여 소유권을 우회하지 않는다. 재부팅·namespace 교체 후 다른 domain의 journal을 채택하지 않는다.

배포 저장소에서는 위 CLI와 `scripts/test-m3-target-guard.sh`를 가져다 쓸 수 있다.
테스트는 전용 network-none 컨테이너 안에서만 link/netns를 만든다. 이 머신의 설정이나
서비스·전원·시계는 바꾸지 않는다. 운영 자동 실행에는 아직 연결하지 않는다.

## Verification and remaining work

단위/race 시험은 mutation 전후 오류·SIGKILL 모델, journal 저장 전후 실패, 재시작,
반복 작업, 소유권 변조, 앞선 rule·외부 route·local address 충돌, 승인 거절 후 차단 유지를
다룬다. 격리 커널 시험은 controller colocated/separate × relay 2 × underlay 2에서
실제 기본 경로 TCP 차단, 다른 목적지 및 같은 target의 중계 TCP 보존, 네 candidate의
실제 관측, route/rule 직후 SIGKILL·복구, 외부 자원 보존 및 중복 없는 반복을 확인한다.

```sh
go test -race ./internal/relayapply ./cmd/vpnctl
VPNCTL_RACE=0 scripts/test-m3-target-guard.sh
VPNCTL_RACE=1 scripts/test-m3-target-guard.sh
```

후속 활성화에는 노드 측 BOOTTIME/kernel lease, 새 승인의 freshness 및 replay 방지,
선택 근거와 candidate 세대 재검증, 실제 target route 교체/readback/unbound 앱 payload 확인,
유효한 LKG만 복구하는 rollback이 필요하다. 릴레이 측 lease가 있다는 이유만으로 노드
경로의 만료 차단을 완료로 취급하지 않는다. 이 단계는 #23 또는 M3 최종 판정이 아니다.
