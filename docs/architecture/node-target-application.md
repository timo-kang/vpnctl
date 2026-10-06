# 목적지별 앱 경로 적용 (#159)

`node relay target reconcile`은 현재 승인·후보 관측으로 고른 릴레이를 **실제 로컬 발신 IPv4,
mark=0 앱 경로**에 적용한다. 새 소켓은 source/device/mark를 지정하지 않아도 된다.
`select`는 여전히 추천만 출력한다. 로봇 동작 제어가 아니라 서버 uplink 도달 경로 선택이다.
물리적으로 사용 가능한 uplink가 없으면 VPN도 연결을 만들어낼 수 없다.

## 준비

[노드 승인 lease](node-approval-lease.md), 전용 bpffs, 명시적인 underlay, 현재 catalog와 binding,
릴레이 forwarding/NAT 및 서버 반환 경로가 먼저 필요하다. 같은 UID/cache/netns에서 실행한다.
[배포 절차](../deployment/node-application-routing.md)를 먼저 확인한다.

```sh
vpnctl node relay refresh --config node.yaml
vpnctl node relay prepare --config node.yaml --path-id primary --app-routes
vpnctl node relay prepare --config node.yaml --path-id secondary --app-routes
vpnctl node relay supervise --config node.yaml --refresh-interval 5s
# 별도 프로세스: supervise가 실제 유효 lease를 연 뒤 실행
vpnctl node relay target reserve --config node.yaml --target-id app
vpnctl node relay target reconcile --config node.yaml --target-id app --watch
```

`--app-routes`는 `--lease --probe-routes`에 더해 **장치에 묶인 probe rule**을 준비한다.
기존 후보는 자동 변경하지 않는다. 명시적으로 release 후 새 옵션으로 준비해야 한다.
lease 없는 후보 또는 source-only probe 후보는 앱 활성화에 사용할 수 없다. 같은 target과
겹치는 source-only 후보가 하나라도 있으면 앱 적용을 거절한다.

이 구분은 기존 TCP 차단에 필요하다. 일반 앱도 연결 후에는 후보 내부 source IP를 가지므로,
source-only rule은 앱 route 삭제 후에도 기존 연결을 후보 table로 보낼 수 있다. 새 rule은
`from <inner>/32 oif <owned-WG> lookup <candidate-table>`이며 `SO_BINDTODEVICE`로 묶은
probe만 우회한다. 실제 앱은 WG 장치, 후보 source, 별도 mark를 직접 지정하지 않는다.
한 번 앱에 사용한 target은 차단 상태에서도 `application_version=1`을 유지하여 같은 prefix의
source-only 재준비를 막는다. 명시적 target release는 이 소유권도 포기한다.

장치 지정 rule은 Linux의 초기 reverse-path lookup에는 보이지 않는다. 배포자가 해당
namespace의 `conf/all/rp_filter=0`과 새 WG가 상속할 `conf/default/rp_filter=0`을 준비해야 한다.
준비 시 두 값을, 유지·적용 시 all과 해당 WG 값을 검사한다. vpnctl은 이 sysctl을 쓰지 않는다.
물리 인터페이스의 개별 rp_filter는 별도로 유지할 수 있다. 원인은
[Linux fib_validate_source 구현](https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c)의
초기 oif=0 역조회다. 잘못된 설정은 conflict이며 준비/활성화 성공으로 표시하지 않는다.

## 트랜잭션과 복구

기존 target table/rule과 `unreachable default`를 유지한다. 같은 cache/netns 잠금 안에서:

1. 현재 catalog, generation, 설치 fingerprint, underlay ifindex/source/gateway, 소유 kernel 자원,
   살아 있는 BOOTTIME/nft lease, 신선한 후보 TCP 증거를 확인한다.
2. 이전/새 경로의 정확한 tuple을 `switching` intent로 먼저 저장한다.
3. 승인 prefix마다 정확한 이전 route만 삭제하고 새 route를 exclusive add한다.
   `replace`/table flush를 쓰지 않으며 prefix 사이에도 unreachable default가 남는다.
4. 전체 route/rule을 다시 읽고 **unbound TCP connect**의 실제 source, 선택 WG RX/TX 증가,
   경로 조회, 승인·lease·소유권을 재검증한다.
5. `active`, 적용 시각, 검증 시각을 저장한 뒤에만 `applied=true, application.activated=true`를 낸다.

Target 예약의 기본 table/priority 해시가 다른 소유 target과 겹치면 제한된 대체 슬롯을
선택하고 `allocation_slot`을 intent와 함께 저장한다. 기존 예약은 이동하지 않으며, 다른
target을 삭제해도 남은 예약의 슬롯은 바뀌지 않는다. 외부 커널 자원과 충돌하면 계속 거절한다.
slot 0은 기존 배정·직렬화를 유지하고, 비영 slot을 모르는 구버전은 journal을 거절한다.

관측 JSON을 다시 입력하여 적용하는 API는 없다. `selection.applied`는 추천 계약상 false이고,
최상위 `applied`가 이번 실제 적용 결과다. `application.proof.evidence=unbound_tcp_connect`는
서버 TCP 연결 확인이며 HTTP/앱 업무 성공은 아니다. 통합 시험의 독립 클라이언트가 nonce payload와
서버에서 관측한 NAT source를 별도로 검증한다. 임의 서비스에 제품 probe payload를 보내지 않는다.

변경 실패 시 이번 정책이 허용하고 현재 승인·lease·후보 probe·실제 앱 검증을 다시 통과한
이전 경로만 rollback한다. 이때 `state=rolled_back, activated=true, applied=false`이고 명령은
실패를 반환한다. 이전 경로도 불가하면 앱 route를 삭제하여 `guarded=true`로 남긴다.
manual pin 실패는 다른 건강한 후보로 우회하지 않는다. stale/unknown/all-unavailable도 차단한다.
승인 만료·철회·후보 release는 target 예약을 해제하지 않는다.

SIGKILL 후 남은 switching intent는 감독기가 관련 후보 lease 갱신을 거절하도록 한다.
무관한 후보는 계속 유지한다. `target recover`는 중단된 변경을 차단 상태로 회수하며 과거
관측으로 활성화하지 않는다. 저장 결과가 불확실하면 관련 후보를 차단하고 journal 재열기를 요구한다.
외부 route/rule/peer/tc/nft를 지우거나 채택하지 않는다. 충돌 시 `guarded=false`는 현재 차단을
입증하지 못했다는 의미이며 운영자의 외부 설정 정리가 필요하다.

`target inspect/recover`의 active 상태는 새 앱 연결 검증까지 수행한다. 재시작한 reconcile은
관측 연속 성공을 새로 모으므로 첫 주기에 기존 경로를 차단할 수 있다. 장기 운영은 `--watch`를
사용한다. SIGSTOP으로 잠금을 오래 점유해도 후보 kernel lease는 최대 10초 안에 만료된다.
선택기 hold-down/minimum-dwell은 추천 시각이 아니라 검증된 실제 적용/rollback 시각으로 보정한다.

## 실행 예산과 한계

후보 관측의 외부 예산은 최대 20초다. 먼저 모든 후보 lease를 한 번 유지한 뒤 최대 3초의
공통 관측 구간에서 승인된 후보 최대 8개의 TCP 확인을 겹쳐 실행한다. 승인/cache, inventory,
커널 검사·차단은 직렬화하며 모든 프로브 종료를 기다린 뒤 잠금을 놓는다. 앱 적용·검증은
최대 5초, 독립 복구도 최대 5초다. 오래된 성공을 재사용하지 않으며 예산 소진은
`observation_budget_exhausted`로 진단한다. JSON 출력 전에 잠금을 놓는다. 새 프로세스의
잠금 진입은 최대 1초다. 기본 관측 간격은 각 주기 종료 후 2초다. 고정 failover 지연 SLO를
주장하지 않는다. 8 prefix 변경은 순차적이며 동시에 원자적으로 바뀌지 않는다.

대상은 namespace 안의 mark=0, 장치에 묶이지 않은 로컬 IPv4 앱이다. IPv6, forwarded 앱,
프로세스별 접근 제어, 임의 소켓 mark, 기존 TCP 세션의 릴레이 간 무중단 이동은 지원 범위가 아니다.
릴레이/후보 source가 바뀌면 앱이 재연결해야 할 수 있다. 새 연결 성공과 기존 연결의 차단을
별도로 검증한다. 네트워크 관리자와의 경쟁을 원자적으로 막는 전역 lock도 아니다.

실제 NetworkManager/Netplan/udev 공존, 물리 절전/재부팅 및 guest clock freeze, 다중 node 부하의
failover SLO는 별도 gate다. 이 구현과 시험 통과가 #23 전체 또는 M3 최종 승인을 뜻하지 않는다.
