# 실제 direct WG 확인과 controller 독립 복구 (#20)

## 시험 계약

`TestNetns_DirectDataplane`은 Docker `--network none` 안에서 실제 mTLS controller,
커널 WireGuard hub, 독립 relay probe 프로세스(51901), 가변 node를 시작한다. 시험 전용 relay 예열은 하지 않는다.
제품의 사전 relay 확인, 모든 방향의 direct 승격을 확인한 뒤 controller 프로세스만
종료한다. hub의 커널 중계와 독립 probe는 남겨 둔다. A↔B WG UDP만 nft로 차단하고 UDP responder는
열어 두어, UDP 성공과 WG 통신 성공을 혼동하는 구현을 검출한다.

5초 이내에 소유 direct peer 제거와 **실제 VPN nonce 왕복**을 요구한다. cooldown보다
길게 장애를 유지하고 잘못된 active가 없는지 검사한다. 마지막 손실 구간도 장애를
유지한 채 첫 성공 응답까지 측정한 뒤, 차단을 풀어 재검증을 확인한다. 실패 probe의
마감 시각만으로 손실을 계산하지 않는다.
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
  새 baseline 설정이 조용히 무시되지 않도록 공개 설정 digest 불일치도 명시적으로 거절한다.
- WG endpoint roaming 후 소유 peer를 정리하지 못하던 경우 수정. 옛 검증은 폐기하고 회수한다.
- 32-node에서 peer마다 실행하던 명령/readback/fsync가 포화되는 문제를 일괄 intent와
  peer 목록 명령으로 수정.
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

후속 반복에서는 UDP discard 없이도 두 worker가 약 1.1초 어긋나며 1초 trial과
고정 cooldown이 계속 엇갈리는 제품 결함을 확인했다. 초기 설치의 3초 미만에만 peer를
유지해 양쪽 설치 창이 겹치게 하고, 이미 active인 경로의 실패는 즉시 회수한다.
더 큰 시차도 같은 재시도 주기로 고정되지 않도록 local key·상대 key·시도 횟수에 따라
5~7초 cooldown을 분산한다. 2초 초기 창은 handshake가 nonce deadline 직전에
끝나 한쪽만 첫 검사를 통과하고 다른 쪽이 회수하는 사례가 남아, 다음 검사 주기까지
포함하는 3초 창으로 수정했다. 이 실패 실행도 별도 보존한다. 연속
2회 성공 조건, 5초 fallback/반복 손실 assertion, 60초 최초 수렴/15초 복구 제한은 유지한다.

2026-10-04 PR #154의 후속 M2 production CI `37182579527`에서는 5~7초 전체
구간의 jitter도 충분하지 않은 사례를 확인했다. node-0/node-2가 약 5초 어긋난 채
각각 3초 시도와 6~7초 대기를 반복했다. 06:28:25~06:30:18 UTC의 양방향 기록에
각각 `overlay_probe_timeout_no_handshake` 24회가 있고, 저장 WG 표본은 peer를
누락한 상태로 `monitor_restart` 뒤 기존 150초 기한을 넘었다. 고정 코드 timeline에는
삭제/파싱/읽기 누락이 없었다. 새 selector는 이 fixture에서 실행되지 않는다.

1초 worker에서 cooldown이 정수 주기로 반올림되는 것을 포함한 짧은 모델 검사도
수정 전 `keys=1/17, skew=2.25s`에서 1분 동안 probe-sized 설치 창이 겹치지 않아
실패했다. key 순서로 양방향을 5~5.25초 미만과 6.75~7초 미만의 별도 구간에 배치하고,
구간 내 jitter를 유지하도록 수정했다. 256 key 쌍 × 41개 시작 위상에서 검사하며,
3초 trial·5~7초 cooldown·즉시 active 실패 회수·연속 두 번 증거 조건은 변경하지 않는다.
모델 통과는 실제 kernel 복구 SLO 합격을 대신하지 않는다. 수정 후 실제 통신 결과는
후속 CI와 별도 artifact로 확인한다. 최초 CI `37181524329`에는 이유 timeline이
없어 그 실패까지 같은 원인으로 확정하지 않는다.

수정 소스 `81bf863`은 2 CPU/2 GiB의 실제 kernel fixture에서 2·8노드 각각 2회,
총 4회 통과했다. fallback은 1.928~2.037초, 모든 report의 `completed=true`,
foreign peer 보존과 실제 overlay 왕복을 확인했다. 기존 15초 재복구 조건도 통과했다.
artifact는 `/tmp/vpnctl-direct-retry-bands-netns`에 보존한다. 관련 directpath/agent/direct
전체 race 3회 및 selector/relayapply/CLI race도 통과했다. 실제 CI 커널의 장기 cadence
복구 판정은 후속 M2 production 결과로 확인한다.

이 첫 수정의 CI `37183485105`는 production-32 job 중 **3노드**에서 15초 재복구를,
race-8 job 중 8노드에서 반복 손실 5.058초를 초과했다. 32노드 subcase 자체는 통과했다.
실제 timeline은 cooldown 시작 뒤 peer 제거/readback/저장에 걸린 시간으로 5초 직후의
짧은 지연이 한 worker 주기 일찍 충족되는 경우를 보여준다. 이 경과 시간을 포함한
회귀도 `shorter=5.023s, longer=6.808s, removal=100ms/0s`에서 수정 전에 실패했다.
짧은 구간을 **5.75~6초 미만**, 긴 구간을 **6.75~7초 미만**으로 옮기고 제거 후
0/20/100/500ms의 재개 시차에서도 한 주기의 차이를 유지하는지 검사한다. 기존
3초 trial·5초 손실·15초 재복구·150초 M2 판정은 완화하지 않는다. 이 모델의 시간
범위보다 큰 scheduler 지연을 보장한다고 해석하지 않으며 실제 커널 검증을 계속한다.

경계 보강 소스 `13f4804`의 2 CPU/2 GiB 실제 kernel 시험은 production 2·3·8·32노드
각 2회(8/8), race 2·3·8노드 각 3회(9/9) 통과했다. 최대 fallback 2.051초,
반복 trial 중 최대 관측 손실 4.492초였고 15초 재복구와 foreign peer 보존도 모두
통과했다. artifact는 `/tmp/vpnctl-direct-retry-tick-production` 및
`/tmp/vpnctl-direct-retry-tick-race-netns`다. 실제 Engine의 journal 저장에 100ms가
걸린 뒤 다섯 번째 tick에서 조기 재설치되는 회귀도 이전 구현에서 실패를 재현하고
수정 후 통과했다. 최종 CI의 동일 판정 조건도 별도로 확인한다.

CI 승인 단축 시험은 refresh 시작(16:36:39.617 UTC) 뒤 apply(39.659), 보고 완료(39.777)
순서로 이전 승인 결과를 소비해 실패했다. 보고 시각뿐 아니라 새 승인 만료 시각을
확인한 뒤 controller를 중단하도록 수정했다. 실제 60초 만료 조건은 그대로 둔다.

race 계측과 배포 바이너리의 자원 계약을 분리하고, 이후 report에는 cgroup `memory.events`,
`memory.peak`, `cpu.stat` 전후값도 저장한다. 작은 race mesh, 최대 규모의 배포 바이너리,
전체 단위 race를 함께 판단한다. race 32-node/2GiB 지원은 이 결과로 주장하지 않는다.

추가 32-node 실행에서는 controller 프로세스에 같이 붙은 relay responder까지 종료한
상태에서, 30초 증거 만료 뒤 `relay_baseline_unverified`로 재승격이 거절됐다. 최초 fallback과
반복 장애 중 packet 통신은 유지됐지만 “API만 중단”과 “relay health도 중단”을 혼동한 fixture였다.
최종 fixture는 relay probe를 별도 프로세스로 유지하고, 응답기까지 없으면 정상 direct는
유지하되 새 trial은 거절한다는 조건을 단위 회귀로 검증한다. 해당 실패 원본도 보존한다.

## 로컬 최종 검증 (2026-10-04)

- production 2CPU/2GiB, 2·3·8·32 node 각 3회: 12/12 통과.
  첫 성공 응답과 장애 해제 전 마지막 손실 구간까지 포함한 계측에서 최대 최초 fallback
  2.034초, 반복 장애 중 최대 관측 손실 4.437초.
- race 2CPU/2GiB, 2·3·8 node: 3/3 통과. 성공 응답까지 포함한 최대 최초 fallback
  2.038초, 반복 장애 중 최대 관측 손실 4.480초. 최종 CI도 두 profile을 독립 실행한다.
- controller 동거/분리 실제 만료 시험 각각 2회 통과. 60초 승인 만료와
  supervisor 종료 후 커널 lease 차단 조건을 바꾸지 않았다.
- 전체 기본 단위 race(기존 장기/규모 전용 job 제외), 변경 패키지 race,
  vet·binary build·integration 진단 단위 검사 통과.
- 이전 2초 초기 창의 재가입 시험은 네 번 복구 후 다섯 번째에서 실패했다.
  원본을 보존했고 3초 창/재시도 분산 코드의 집중 재가입 시험은 6회 복구로 통과했다.
  실제 workload는 6분 이상이며 전체 fixture 실행은 451.75초였다.
  정해진 상태·오류 코드 **건수만** 추가 산출물로 기록하며 원본 서비스 로그를 내보내지 않는다.
  24시간 gate를 대체하지 않는다.

손실 계측 자체도 리뷰해 첫 성공 응답까지의 간격과 장애 제거 전 마지막 손실 구간을
포함하도록 보강했다. 아직 실제 성공이 없는 초기 probe의 deadline은 kernel 설치 시작부터
계산한 잔여 시간으로 제한한다. 이전 4.931초 기록은 실패 probe의 마감까지만 계산한
계측이므로 최종 손실 판정으로 사용하지 않는다.

원본은 `/tmp/vpnctl-direct-complete-loss-window`,
`/tmp/vpnctl-direct-hard-trial-integration-race`,
`/tmp/vpnctl-direct-final-rejoin`, `/tmp/vpnctl-direct-approval-barrier`에 있다.
이전 실패 및 중간 검증 디렉터리도 그대로 보존한다.

## 재시도 중 relay 경로 보존 보강 (2026-10-07, #191)

3초 동안 `/32`를 먼저 설치하던 구현은 양 끝의 독립적인 worker 시각과
제거·journal 지연이 겹치면 5초 응답 공백을 넘었다. 창을 2초로 줄이고 빠르게
재검사하는 것만으로는 15초 재연결 조건을 만족하지 못했다. 현재 구현은 다음
순서로 통신 경로를 준비한다.

1. journal v2에 staging 의도를 저장하고, application AllowedIPs가 **없는** peer와
   1초 keepalive를 설치한다. 이 상태에서는 송수신 application prefix를 relay가
   계속 소유한다. WireGuard handshake·RX·TX가 관측될 때까지 `handshaking`이다.
2. relay의 30초 검증 cache가 오래되었으면 갱신하고, 인터페이스·relay baseline과
   다른 peer의 prefix 충돌을 다시 확인한다. `activating` 의도를 저장한 뒤에만
   `/32`와 설정된 keepalive를 부여한다.
3. kernel 변경 시작부터 최대 2초 안에 별개의 nonce 응답과 RX/TX 증가를 두 번
   확인해야 `active`다. 요청은 기존처럼 최대 1초이며 남은 초기 창으로 제한하고,
   worker 재검사 간격은 250ms다. 후보의 초기
   만료가 이미 active인 다른 peer의 온전한 1초 검증 시간을 줄이지 않는다.
4. 실패·withdrawal·재시작은 phase별로 확인 가능한 소유 peer만 제거한다. prefix,
   PSK, keepalive가 외부 설정으로 바뀌었으면 지우지 않는다. 저장 실패를 무시하거나
   handshake만으로 application 도달을 주장하지 않는다.

빈 AllowedIPs 상태에서도 keepalive로 transport를 준비할 수 있는 근거는
[WireGuard Linux netlink](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/netlink.c),
[send 구현](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/send.c),
[wg 설정 파서](https://git.zx2c4.com/wireguard-tools/tree/src/config.c)다.

32노드 실제 VM과 CI에서는 다른 후보의 느린 요청 때문에 첫 성공을 받은 후보가
두 번째 검증 기회를 얻기 전에 만료되는 별도 결함도 재현했다. 단일 쌍의 시간
모델만으로는 이 공유 대기 문제를 발견하지 못했다. 검증 중인 요청이 남아 있으면
250ms 간격으로 완료 결과를 함께 조회하고, 초기 후보마다 다음 nonce를 보낸다.
각 요청 직전의 RX/TX를 별도로 저장하여 이전 요청의 counter 증가를 두 번 세지
않는다. 이미 active인 후보의 요청 시간과 단독 정상 경로의 두 snapshot 검증은
그대로 유지한다. 1개 후보 대조군, 2·32개 후보 재현, counter 재사용 거부 검사를
추가했다. 수정 전 실제 실패는 `/tmp/vpnctl-fix191-direct-prod-v2`와
[CI 37595610104](https://github.com/timo-kang/vpnctl/actions/runs/37595610104)에 보존한다.

journal v1은 기존 소유권 검증을 거쳐 v2로 승격한다. 구버전 바이너리는 v2를 읽지
못하므로 단순 실행 파일 교체로 downgrade하지 않는다. 현재 버전으로 서비스를
종료하고 소유 peer 회수를 확인한 뒤, 전용 baseline과 상태 파일을 명시적으로
재구성하는 운영 절차가 필요하다. 실패한 저장 파일을 삭제해서 복구 권한을
추측하지 않는다.

공유 호스트에서의 실제 네트워크 검증은 기존 netns 명령을 직접 실행하지 않고
격리 VM wrapper를 이용한다. 각 case는 별도 guest이며 기존 5초 fallback/응답 공백,
12초 이상 장애 관측, 15초 재연결 기준을 그대로 적용한다.

```sh
VPNCTL_VM_RACE=0 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-direct-vm-production \
  scripts/test-vm.sh --case direct-2 direct-3 direct-8 direct-32 \
    direct-inner-2 direct-inner-3 direct-inner-8 direct-inner-32
VPNCTL_VM_RACE=1 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-direct-vm-race \
  scripts/test-vm.sh --case direct-2 direct-3 direct-8 \
    direct-inner-2 direct-inner-3 direct-inner-8
```

`direct-inner-*`는 양 끝의 암호화된 비어 있지 않은 WireGuard data만 차단한다.
handshake와 빈 authenticated keepalive는 통과하며, post-fault handshake·RX/TX와
각 방향의 payload drop/keepalive/handshake nft counter를 모두 요구한다. 같은
`wg0`의 평문 nonce를 차단하면 relay fallback까지 막으므로 그 방식은 사용하지
않는다. CI에서는 원래 `outer-wg`와 `inner-nonce`를 production/race별 독립 job으로
실행한다. CI의 netns 명령은 전용 runner용이며 공유 호스트에서는 VM wrapper를 쓴다.

검증기는 worker 종료 코드, 정확한 node 수·fixture·fault mode, 필수 완료 조건과 개별 nonce
기록을 함께 확인한다. 요약 수치만 양호하거나 `completed=true`인 report만 있어서는
합격하지 않는다. 최초 VM 실행은 네 크기 모두 기능 조건에 도달했지만 선택적
`wmem_max` 진단 파일 부재로 종료 코드 1이었다. 이 실패 원본은
`/tmp/vpnctl-fix191-direct-prod-v1`에 보존하며 합격 근거로 사용하지 않는다.

## 판정 범위

5초는 이 격리된 node-to-node 시험의 assertion이다. 앱 서버 uplink, 실제 RF/LTE 지연,
NAT 재바인딩·DHCP/NetworkManager/Netplan 재적용, 서로 다른 relay 선택, 장시간 loss/jitter
분포의 보장 SLO는 아니다. trial 중 트래픽 전환 영향과 비대칭 방향 표시는 추가 검증 대상이다.
#20/#23/#24 및 M3 최종 gate는 해당 남은 조건을 충족하기 전까지 열어 둔다.
M2의 기존 24시간 성공 기록과 판정은 이 짧은 시험으로 대체하지 않는다.
