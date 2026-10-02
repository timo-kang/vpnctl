# Direct 탐사 세대와 결과 수락 (#20)

이 단계는 UDP direct 탐사의 오래된 성공이 다시 준비 상태를 만드는 결함을 막는다.
WireGuard handshake·VPN IP end-to-end 확인, controller 중단 중 로컬 fallback,
cooldown/hysteresis 및 통신 복구 SLO는 #20의 다음 단계다. 현재 `P2PReady`는 UDP
탐사 준비 신호이며 실제 WG 경로나 앱 도달성을 보장하지 않는다.

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

현재 legacy `ApplyPeers`는 전용 WG interface와 policy table을 전제로 한다. 공유
NetworkManager/networkd/WG 자원을 자동으로 가져오는 근거로 사용하지 않는다.
[네트워크 소유권 계약](../deployment/network-ownership.md)에 따라 #23에서 새 경로
적용·충돌 거절·rollback을 통합하고, 실제 관리 프로그램의 DHCP/reload/restart와 함께
검증한 뒤 자동전환 운영 판정을 한다. #21의 릴레이 선택과 #22의 underlay 변경 처리는
[전체 경로 계약](m3-path-control.md)에 따른다.
