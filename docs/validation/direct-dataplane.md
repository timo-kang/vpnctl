# 실제 direct WG 확인과 controller 독립 복구 (#20)

## 시험 계약

`TestNetns_DirectDataplane`은 Docker `--network none` 안에서 실제 mTLS controller,
커널 WireGuard hub, 독립 relay probe 프로세스(51901), 가변 node를 시작한다. 시험 전용 relay 예열은 하지 않는다.
제품의 사전 relay 확인, 모든 방향의 direct 승격을 확인한 뒤 controller 프로세스만
종료한다. hub의 커널 중계와 독립 probe는 남겨 둔다. A↔B WG UDP만 nft로 차단하고 UDP responder는
열어 두어, UDP 성공과 WG 통신 성공을 혼동하는 구현을 검출한다.

5초 이내에 소유 direct peer 제거와 **실제 VPN nonce 왕복**을 요구한다. cooldown보다
길게 장애를 유지하고 잘못된 active가 없는지 검사한 뒤, 차단을 풀어 재검증을 확인한다.
외부 IPv4/IPv6 route/rule 보존, concurrent `up` 거절, agent SIGKILL 후 **node serve**
오프라인 재시작에서 소유 peer 정리와 relay/route 보존도 검사한다. IPv6 DAD가 끝난
뒤 전체 경로 snapshot을 비교하며 커널 자동 주소 추가를 제품 변경으로 오인하지 않는다.

```sh
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
VPNCTL_DIRECT_SIZES=2,3,8,32 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-direct-production \
./scripts/test-netns.sh -test.run='^TestNetns_DirectDataplane$' -test.timeout=8m

VPNCTL_RACE=1 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
VPNCTL_DIRECT_SIZES=2,3,8 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-direct-race \
./scripts/test-netns.sh -test.run='^TestNetns_DirectDataplane$' -test.timeout=8m
```

CI는 이 두 profile을 독립 실행한다. 다른 suite와 공유하는 누적 timeout으로 시험을
취소하지 않는다. binary SHA256, source commit/dirty, image, kernel, size, CPU/memory,
과정별 판정·fallback 초·공개 WG snapshot·cgroup memory/CPU 기록을 남긴다.
서비스 로그의 bootstrap token은 기존 helper에서 제거한다. raw `wg dump`는 공개하지 않는다.

## 자체 리뷰에서 수정한 결함

- 커널의 keepalive `off`를 숫자로만 읽어 초기 peer snapshot을 거절하던 파서 수정.
- relay 세션이 한 번도 생성되지 않아 direct 제거 뒤 전달을 못 하던 경우를 발견하고,
  제품에 실제 relay packet 사전 확인 추가. 시험 예열로 가리지 않는다.
- 저장 실패 뒤 모든 cleanup까지 막아 다른 소유 peer를 남기던 경로 수정. 신규 설치는
  차단하고, 커널 소유권이 일치한 peer는 회수하되 journal intent를 보존한다.
- concurrent `up`이 kernel 잠금 전에 설정 파일부터 바꾸던 경로를 함께 잠금.
- `node serve` 재시작에서 기존 syncconf가 다른 peer를 지울 수 있던 경로를 journal 복구로 변경.
- WG endpoint roaming 후 소유 peer를 정리하지 못하던 경우 수정. 옛 검증은 폐기하고 회수한다.
- 32-node에서 peer마다 실행하던 명령/readback/fsync가 포화되는 문제를 일괄 intent와
  peer 목록 명령으로 수정. 실패한 trial에도 확인 시간을 늘려 통과시키지 않는다.
- 취소한 검증의 늦은 성공과 후보 만료, STUN의 부당한 캐시 갱신, key 변경을 통한 cooldown
  우회, 32 peer 반복 장애를 race 단위 검사에 포함했다.

## 자원 실패를 구분해 보존

2026-10-04의 첫 2CPU/2GiB **race 32-process mesh**는 초기 수렴 중 실패했다.
컨테이너 `vpnctl-netns-3782660`에서 Docker OOM 이벤트 3회(UTC 16:05:10/21/31)가
기록됐고 controller 접속이 장애 주입 전에 끊겼다. 동일 실행의 2·3·8 node는 통과했다.
이를 제품 32-node 성공이나 정상적인 controller 장애 주입으로 처리하지 않는다.

같은 자원의 배포 바이너리도 최초 시도에서는 OOM 없이 CPU 포화·반복 cooldown으로
수렴에 실패했다(`memory.peak=455000064`, OOM=0). 설치·회수 batch 이후에도
반복 실패가 남아 진단을 확장했다. UDP `SndbufErrors`/IP discard가 증가했지만,
소켓 send buffer를 2MiB까지 확보해도 해결되지 않아 버퍼 변경을 제거했다.

32개 namespace의 동적 underlay/NOARP 이웃이 같은 커널에 모이는 시험에서는
전역 neighbour GC 한도(1024)에 부딪힐 수 있다. 호스트 sysctl을 바꾸는 대신 **시험이
소유한 namespace에만** 고정 MAC underlay와 NOARP VPN 이웃을 permanent로 준비했다.
그 뒤 동일 2CPU/2GiB의 32-node는 20.08초에 통과했고 SndbufErrors=0,
실제 fallback=1.832883657초였다. 이 fixture는 정적 네트워크에서 WG 경로를 검증하며
동적 ARP/NDP 장애 시험을 대신하지 않는다. 전체 neighbour population을 공유하는
한 커널에서 여러 로봇을 모사할 때의 시험 전제이며, 제품이 host GC 설정을 바꾸지 않는다.

진단 중 시도한 6초 handshake 유예는 제거했다. 장애 상태의 반복 trial도 실제 packet으로
감시하고 5초를 넘는 연속 손실은 실패 처리한다. 기존 모든 실패 실행은 보존한다.

race 계측과 배포 바이너리의 자원 계약을 분리하고, 이후 report에는 cgroup `memory.events`,
`memory.peak`, `cpu.stat` 전후값도 저장한다. 작은 race mesh, 최대 규모의 배포 바이너리,
전체 단위 race를 함께 판단한다. race 32-node/2GiB 지원은 이 결과로 주장하지 않는다.

추가 32-node 실행에서는 controller 프로세스에 같이 붙은 relay responder까지 종료한
상태에서, 30초 증거 만료 뒤 `relay_baseline_unverified`로 재승격이 거절됐다. 최초 fallback과
반복 장애 중 packet 통신은 유지됐지만 “API만 중단”과 “relay health도 중단”을 혼동한 fixture였다.
최종 fixture는 relay probe를 별도 프로세스로 유지하고, 응답기까지 없으면 정상 direct는
유지하되 새 trial은 거절한다는 조건을 단위 회귀로 검증한다. 해당 실패 원본도 보존한다.

## 판정 범위

5초는 이 격리된 node-to-node 시험의 assertion이다. 앱 서버 uplink, 실제 RF/LTE 지연,
NAT 재바인딩·DHCP/NetworkManager/Netplan 재적용, 서로 다른 relay 선택, 장시간 loss/jitter
분포의 보장 SLO는 아니다. trial 중 트래픽 전환 영향과 비대칭 방향 표시는 추가 검증 대상이다.
#20/#23/#24 및 M3 최종 gate는 해당 남은 조건을 충족하기 전까지 열어 둔다.
M2의 기존 24시간 성공 기록과 판정은 이 짧은 시험으로 대체하지 않는다.
