# Direct 탐사 세대와 결과 수락 (#20)

`P2PReady`는 세대/token으로 보호한 UDP 탐사 준비 신호다. node는 이를 직접
경로의 시험 허가로만 사용하며, 별도 로컬 감독자가 실제 WireGuard handshake와
VPN IP 왕복 통신을 확인한 뒤 `active`로 기록한다. 앱 서버 uplink 도달성과
다중 릴레이 선택의 최종 판정은 #21~#24에서 계속 검증한다.

## 발급과 결과 수락

`/register`와 `/candidates`의 각 peer에 `direct_generation`과 `probe_token`을 제공한다.
세대는 두 node 사이의 현재 탐사 입력을 식별하고 token은 한 방향의 후보 snapshot에서
진행한 탐사 결과 한 번에만 사용한다. node와 `direct test` CLI는 **탐사 전에 받은 원래
token**을 `/direct-result.probe_token`으로 반환한다. 결과를 측정한 뒤 새 token을 받아
과거 결과에 붙이지 않는다. token은 해당 controller 프로세스의 HMAC으로 보호되고
발신자·상대 node·세대·발급 시각·순번에 묶인다. mTLS node authorization은 그대로
별도로 적용한다. token이 다른 인증서의 node 권한을 주지는 않는다.

서버는 token 발급 후 2분 미만의 결과만 수락한다. 같은 방향에서 이미 수락한 순번 이하의
결과, token 재사용·변조·누락, 이전 세대와 이전 controller 프로세스의 결과는 HTTP 409다.
수신 시각으로 과거 측정을 새롭게 만들지 않도록 준비 유효 시간은 token 발급 시각부터
계산한다. 시계 역행으로 발급 시각이 미래가 된 token과 준비 기록도 수락하지 않는다.

실패를 수락하면 양방향의 과거 성공과 세대를 함께 폐기한다. 다른 방향에서 진행 중이던
이전 성공도 새 세대를 다시 받아 탐사해야 한다. 새 token 발급만으로 같은 세대의 기존
탐사 round를 취소하지 않는다. 세대만 변경돼도 이미 시작한 UDP 측정은 원래 token으로
마칠 수 있지만 controller가 이전 세대의 결과를 거절한다. 한 쌍의 실패가 다른 모든
peer의 탐사를 반복 취소해 굶기지 않도록 하기 위함이다. 실제 주소·key·NAT 등 측정
입력 변경과 준비 상태 철회는 기존 취소·drain 장벽을 유지한다. 측정 결과가 직접
WG peer를 설치하지 않으며 새 후보의 준비 상태만 설치 판단에 사용한다.

## 경로 입력 변경과 발행

WG public key, VPN IP, 광고 endpoint, public/probe address, NAT 종류, probe port,
등록 pending 상태가 **실제 registry에 발행될 때** 해당 node가 포함된 세대를 폐기한다.
일반 heartbeat는 보존하며 실패한 저장은 기존 상태를 유지한다. 파일 교체가 보이지만
디렉터리 sync가 실패한 경우는 새 상태를 발행하므로 기존 세대도 폐기한다. A→B→A
변경을 거쳐도 최초 A의 token을 다시 수락하지 않는다.

광고 endpoint가 없는 node는 후보 조회 시 실제 WG 관측 endpoint를 사용한다. 관측의
변경·소실·조회 실패는 이전 준비 상태를 무효화한다. 늦게 완료된 이전 조회가 새로 완료된
관측을 덮어쓰지 못하도록 조회 순번을 비교한다. 조회 중 registry mutex를 잡지 않는다.
명시적으로 광고한 endpoint가 있으면 관측 endpoint보다 우선한다. 이 동작은 후보 조회
시의 검사이며 상시 커널 이벤트 감시나 WG 데이터 통신 검증을 대신하지 않는다.

## 혼용 배포와 남은 자동전환 범위

이전 node는 token을 보내지 않으므로 새 controller에서 direct 성공을 발행할 수 없다.
새 node는 세대/token이 없는 이전 controller의 `P2PReady`로 direct peer를 설치하지 않는다.
controller와 node를 함께 업그레이드하고 정상적인 후보 조회·새 탐사를 거친다. 이전
버전과 혼용하는 동안 direct 승격은 사용하지 않으며 기존 relay 경로를 유지한다.

자동 direct 감독자는 `ApplyPeers`의 전체 syncconf/table flush를 사용하지 않는다.
아래 journal로 소유한 peer만 변경한다. 수동 `up`/`down`과 최초 baseline 생성은
계속 전용 WG/table을 전제로 한다. [네트워크 소유권 계약](../deployment/network-ownership.md)에
따라 실제 관리 프로그램의 DHCP/reload/restart 조합까지 검증한 뒤 운영 공존을 판정한다. #21의 릴레이 선택과 #22의 underlay 변경 처리는
[전체 경로 계약](m3-path-control.md)에 따른다.

## 로컬 dataplane 감독

- IPv4 literal WG endpoint와 VPN `/32`, 유효한 양방향 후보 세대/token만 받는다.
  한 node의 direct 후보 상한은 32다. 중복 key/ID/VPN 주소와 relay prefix 밖의
  목적지는 집합 전체를 거절한다. DNS endpoint/IPv6 direct는 이 단계에서 사용하지 않는다.
- 첫 direct 설치 전에 relay의 VPN probe를 인터페이스와 source IP에 고정해 보내고,
  relay handshake 및 RX/TX 증가를 확인한다. 기존 health 계약처럼 첫 non-default
  IPv4 VPN prefix의 첫 usable 주소와 `server_probe_port`(기본 51900)를 사용한다.
  다른 배치에서는 이 주소에 responder를 제공해야 한다. controller API가 중단돼도
  새로운 direct trial을 허용하려면 relay responder를 독립 운영한다(예: relay의
  `vpnctl direct serve --listen :51901`, node의 `server_probe_port: 51901`). 기존처럼
  responder가 controller와 같은 프로세스이면 함께 종료될 수 있다. 증거는 30초만 재사용하며,
  초기 relay 또는 만료된 증거를 갱신할 responder가 확인되지 않으면 새 direct를 설치하지 않는다.
  이미 검증된 정상 direct는 이 이유만으로 회수하지 않고 자체 VPN 왕복으로 감독한다. 이 검사는 원격 앱의 건강이나
  relay 뒤의 모든 peer 도달성을 보장하지 않는다.
- `/32` peer 설치는 즉시 해당 VPN 목적지의 트래픽을 옮긴다. 이 단계는 사용자 트래픽과
  완전히 분리된 무중단 사전 검증이 아니다. 넓은 relay AllowedIPs와 기존 route/rule은
  그대로 두고, 짧은 trial 동안 실패하면 자신이 설치한 `/32`만 제거한다.
- WG interface/source에 묶인 nonce 왕복 응답, 해당 peer의 handshake, 검사 전후 RX/TX
  증가를 **2회 연속** 확인해야 `active`다. 단순 UDP 성공이나 커널 설치만으로 승격하지 않는다.
- 로컬 확인 주기는 1초, 각 VPN probe 제한은 1초, 한 작업 예산은 4초다. controller
  요청과 분리한다. peer probe는 최대 32개를 병렬 실행한다. 초기 설치 후 3초 미만에는
  상대 worker 시차를 허용하며 `probing`을 유지한다. 실패는 연속 성공 수를 초기화하고
  이 유예를 연장하지 않는다. 아직 실제 성공이 없는 probe는 kernel 설치 시작부터 계산한
  초기 예산의 남은 시간까지만 실행하며 새 1초 요청으로 유예를 넘기지 않는다.
  이미 active였거나 초기 유예가 끝난 peer는 실패 시 회수하고
  `relay_unverified`를 기록한다. 제거만으로 relay 통신 성공을 선언하지 않는다.
- 같은 peer ID는 실패 후 5~7초 cooldown을 거친다. key/generation 교체로 우회하지 못한다.
  양쪽 key의 정렬 순서로 5.75~6초 미만/6.75~7초 미만 구간을 나눠, 1초 worker가
  지연을 반올림해도 양방향의 재시도 주기가 계속 같아지지 않게 한다. 각 구간 안에서는
  시도별 jitter를 사용한다. peer 제거·readback·저장이 cooldown 시작 뒤에 수행되는
  시간을 고려해 정수 초 경계 직후의 지연을 피한다. 이것은 재시도 일정이며 정상 경로의
  증거는 실제 WG/nonce 검사다.
  복구에도 2회 확인이 필요하다. endpoint drift는 이전 증거를 폐기한다. WG roaming으로
  endpoint만 바뀐 경우에도 journaled peer는 회수할 수 있으며 다시 시험한다.
- controller에서 마지막으로 받은 후보는 2분까지만 사용한다. STUN 갱신은 이 시간을
  연장하지 않는다. monotonic·wall·절전을 포함한 BOOTTIME 경과를 검사하며 역행/만료는
  다음 reconcile에서 회수한다. 이는 userspace 정리이며 릴레이의 커널 lease guard를
  대신하지 않는다. 검증 중 후보가 바뀌면 이전 작업을 취소·join하고 늦은 성공을 버린다.

설치와 회수는 peer 목록을 묶은 한 journal intent/명령/readback으로 처리한다.
전체 interface syncconf는 사용하지 않는다. 일부 peer에서만 명령이 반영되어도 전체
intent가 남아 재시작 복구가 가능하다. 외부 충돌 peer는 보존하면서 다른 소유 peer는 회수한다.

상태는 peer ID·generation별 구조화 로그 `direct dataplane`에 남는다. `pending`은
새 후보 대기, `probing`은 초기 설치 유예 또는 연속 확인 미완료, `active`는 연속 확인 완료, `relay_unverified`는
직접 경로 미사용(릴레이 실제 도달 미판정), `cooldown`은 재시험 대기, `blocked`는 커널/
journal 충돌이다. 새로운 fleet API·metric과 target별 비대칭 표시 통합은 #23의 잔여 범위다.

## 소유권과 재시작

`<wg_config_path>.direct.json`(0600)에 boot/netns/interface index/alias/public key,
relay key, 공개 baseline 설정 digest와 설치할 peer의 공개 속성을 먼저 기록한 뒤 `wg set ... peer`를 실행한다.
비밀키·PSK·probe token은 저장하지 않는다. digest는 손상 검출이며 권한 서명이 아니다.
재시작에서는 journal·커널 정적 속성이 일치한 peer만 정리한다. endpoint는 WG roaming
속성이므로 달라져도 회수 가능하지만 key/prefix/PSK/keepalive 충돌은 외부 상태로 보존한다.

`node run`과 `node serve` 모두 controller 등록/동기화 전에 복구한다. `serve`는 설치된
journal baseline이 있으면 전체 syncconf를 반복하지 않는다. interface가 없는 최초 생성/
재부팅 복원은 기존 baseline 생성 절차를 따른다. 새 interface에 옛 peer key가 있으면
자동 채택하지 않는다. journal이 없는 기존 direct peer도 자동 소유하지 않는다.

namespace 내 interface 잠금은 agent와 `up`/`down`/controller 적용을 직렬화하며,
거절된 `up`은 WG 설정 파일도 바꾸지 않는다. 외부 root나 네트워크 관리자는 이 잠금을
따르지 않는다. 읽기와 변경 사이의 외부 경쟁까지 원자적으로 막는 장치가 아니므로 같은
WG peer를 다른 관리자가 쓰지 않도록 배포에서 예약해야 한다.

journal 쓰기/fsync 실패 후에는 신규 설치를 차단한다. 소유권을 확인할 수 있는 기존
peer는 저장 장애 중에도 커널에서 회수하고 durable intent는 남겨 둔다. 저장소를 복구한
뒤 서비스를 재시작해 intent 정리를 마친다. 손상/소유권 충돌에서 journal을 삭제해
우회하지 않는다. 공개 key·prefix·ifindex와 해당 interface의 실제 소유 주체를 먼저 대조한다.
주소/endpoint/MTU/route 등 baseline 설정이 달라지면 복구는 명시적으로 거절한다.
변경을 조용히 무시하거나 기존 interface에 전체 syncconf를 재적용하지 않는다. 해당 WG/table이
전용임을 확인하고 기존 서비스를 정상 종료해 소유 peer를 정리한 뒤, 명시적인 `down`/`up`으로
baseline을 재생성하고 서비스를 시작한다. 다른 peer/route를 함께 쓰는 interface에는 이 절차를
실행하지 않고 외부 소유자와 먼저 이관한다. 인증서·controller URL·probe 주기 변경은 baseline
재생성을 요구하지 않는다. 자동 journal 이관은 지원하지 않는다.

재현 명령과 제한은 [dataplane 검증 기록](../validation/direct-dataplane.md)에 둔다.
