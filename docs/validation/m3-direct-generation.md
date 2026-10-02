# M3 direct 탐사 세대 검증 (#20)

## 변경과 판정 범위

UDP 탐사 성공 이력이 endpoint/NAT/key 변경 뒤에도 남거나, 실패보다 늦게 도착한
이전 성공이 준비 상태를 다시 만드는 문제를 막는다. 후보 조회 시 방향·세대·발급 시각·
순번에 묶인 일회성 HMAC token을 발급하고, 결과는 탐사 전에 받은 token으로만 제출한다.
HTTP mTLS 권한 검사는 별도로 유지한다. 상세 계약은
[direct readiness](../architecture/direct-readiness.md)에 있다.

이 검증은 UDP 탐사의 유효성에 관한 것이다. 실제 WireGuard handshake/overlay packet,
controller 단절 중 로컬 fallback, 전환 cooldown/hysteresis, blackhole SLO 및 다른
네트워크 관리 프로그램과의 실제 공존은 #20~#24의 미완료 조건이다.

## 자체 리뷰에서 수정한 결함

- registry 저장 전에 준비 상태를 폐기하지 않는다. 성공 또는 파일 교체가 이미 보이는
  불확실한 commit에서만 기존 세대를 폐기한다. 변하지 않은 heartbeat는 보존한다.
- WG 관측 endpoint를 준비 판정 뒤에 채우지 않는다. 먼저 변경/소실을 반영한다.
  늦게 완료된 이전 WG 조회가 더 최근에 완료된 조회를 덮어쓰지 못하게 한다.
- 내부 등록 처리에서 모든 pair의 미사용 token을 만들지 않고 HTTP 후보 응답에서 발급한다.
- 최초 구현의 전체 round 취소는 32노드에서 앞 8개 peer만 반복 측정하는 회귀를 만들었다.
  취소 시 cursor를 바꾸는 것만으로도 전체 관측을 회복하지 못했다. 승인 세대만 바뀌면
  원래 token으로 측정을 마칠 수 있게 하고 서버에서 stale 결과를 거절한다. 실제 측정
  입력 변경과 준비 철회의 취소/drain 장벽은 유지한다. 결과 자체가 WG를 변경하지 않는다.
- CLI는 결과 제출이 거절됐는데도 준비 상태가 승인된 것처럼 성공 종료하지 않는다.

## 재현과 검증

- endpoint/public address/NAT/probe port/key 변경, A→B→A, 실제 NAT API 갱신,
  관측 endpoint 변경/소실, 실패 뒤 늦은 성공: 양방향 이전 token 거절과 새 탐사 복구.
- token 누락/변조/다른 node·peer/만료/시계 역행/controller 재시작/재전송/역순 결과 거절.
- 수신 지연이 준비 상태의 2분 유효 기간을 연장하지 않음.
- mTLS API에서 정상 양방향 성공 → 실패 → 늦은 성공 거절을 30회 반복.
  다른 인증서의 제출은 기존 node authorization에서 거절.
- 실제 agent worker에서 승인 세대 변경 시 진행 중 측정의 원래 token을 유지하고,
  구형 controller의 세대 없는 준비 상태로 peer를 설치하지 않음.
- `go test -race ./internal/controller ./internal/agent ./cmd/vpnctl -skip
  '^TestPathChurn|^TestMonitorAndDirectRealProducersVariableScale$' -count=1 -timeout=10m`
  통과(controller 190.590초, agent 34.296초, CLI 40.381초).
- 실제 monitor/agent 생산자: schema 5/6/7/8/9 × node 1/3/8/32의 20개 조합 통과
  (140.307초). 기존 schema 5의 작은 전역 저장 예산은 quota accounting을 검사하고,
  나머지 schema에서는 두 source의 모든 peer 관측 관계 수렴을 확인한다.
- 최종 worker 단순화 후 관련 direct race 및 schema 6/32노드 재검증 통과
  (agent 3.517초, controller 20.894초). 관련 vet와 diff 검사 통과.

로컬 시험은 합성 endpoint와 실제 UDP/HTTP/mTLS 생산자 검증이다. real-kernel routing
검증을 대신하지 않는다. 최종 CI 결과와 병합 커밋은 해당 PR에서 별도로 확인한다.
