# #79 monitor 실제 생산자 자체 검토

## 구현 판단

명시적인 `--history-config`로 monitor의 실제 개별 UDP echo 결과를 인증된 중앙 이력에
연결한다. 새로운 `/monitor/peers`·`/monitor/metrics` 계약이 full key/IP/등록 identity를
검사한다. 큐는 공통 구현을 사용하고 결과별 sender가 당시의 binding을 고정한다.
기존 local-only 실행, direct 생산자, history schema 5/6/7의 저장 정책은 유지한다.

## 발견하고 조치한 내용

1. 화면 Subscribe는 오래된 snapshot을 버리므로 이력 전달 수단으로 부적합했다.
   완료된 개별 결과를 로컬 SQLite 쓰기 전에 큐에 넣는다. 미소비 UI·닫힌 로컬 DB 시험에서
   모든 완료 표본이 전달되는지 검사했다.
2. WG 표시 이름은 신원이 아니며 key/IP만 비교해도 A→B→A 재사용을 검출하지 못했다.
   random binding epoch를 registry에 저장하고 재시작 시 검증한다. legacy registry는
   결정적인 초기 binding을 사용한다. 키 변경/되돌리기, 다른 IP, 삭제/tombstone,
   reporter 사칭/폐기, 잘못된 경로 주장을 실제 mTLS API로 검증했다.
3. cycle 끝 시각을 모든 peer에 붙이면 빠른 probe 시각이 느린 peer에 끌려간다.
   개별 완료 시각을 기록하고 재시도 시 유지한다. RTT µs→ms 변환과 역순 수용을 확인했다.
4. 로컬 소켓 권한·자원 오류가 네트워크 실패로 기록될 수 있었다. 해당 오류는
   `collector_unavailable` unknown으로 구분하고 실제 시도 분모에서 제외했다.
   잘못된 target, WG discovery 오류, timeout, 종료 취소도 별도로 시험했다.
5. TUI는 로그를 숨기므로 경고 로그만으로 전송 상태를 알 수 없었다. TUI/watch/HTTP에
   mapping·전달·quota 누락을 표시하고 고정 reason label의 Prometheus 계수를 추가했다.
6. 새 테스트가 32노드의 첫 16개 stream 조회만 읽어 나머지를 누락으로 오판했다.
   모든 cursor를 순회하도록 수정했다. 제품의 페이지 한도는 변경하지 않았다.
7. kernel fixture의 기존 `cli-ping` 정확한 6표본 검사에 monitor 표본이 섞일 수 있었다.
   기존 계약 검사는 source를 구별하고 실제 monitor 성공·차단 실패·재시작 보존을 별도로
   검사한다. 임시 direct WG peer는 원상 복구한 후 기존 uplink-only 검증을 계속한다.

## 검증 근거

- 단위 및 실제 UDP: 고정 ID/시각/binding 재시도, 다른 준비된 표본의 진전, 재시작 ID,
  잘못된 catalog, 미등록 server, 매핑 만료/오류, queue 256개 한도와 종료 계수.
- 실제 mTLS: 성공/2초 timeout/invalid target, 인증서 자동 갱신, 폐기, 삭제, key ABA,
  응답 유실 후 동일 관측 재전송과 저장 중복 방지, quota/seal 동안 다른 peer 전달과
  1초 controller 등록 응답, 실제 연결 단절 중 로컬 측정 지속.
- 1/3/8/32노드 × schema 5/6/7에서 실제 agent와 monitor 생산 경로 실행.
  schema 6/7의 32노드 full mesh는 source별 992개 관계(합계 1,984개)를 확인한다.
  schema 5의 32노드는 수용 한도 합격이 아니라 명시적 quota 거절 시험이다.
  schema 7 조회에 coverage가 반드시 있고 source가 섞이지 않음을 확인한다.
- 관련 패키지 race 검증 통과. `go vet ./...`, `go build ./cmd/vpnctl`, `git diff --check` 통과.
- `VPNCTL_NETNS_SIZES=3 VPNCTL_RACE=0 scripts/test-netns.sh
  -test.run '^TestNetns_(PKILifecycleUplink|MonitorQuality)$'` 통과.
  배포 CLI의 실제 WG discovery→UDP→mTLS→history/CLI와 실제 차단,
  graceful/crash controller 재시작 후 보존까지 포함한다.
- 전체 일반 race와 별도 path churn race, 가변 kernel fleet, tiered capacity/fuzz,
  약 2천만 raw 전환은 PR의 기존 5개 CI job으로 최종 확인한다.

## 한계와 후속

- 메모리 큐의 전송은 best effort다. 초기 mapping, 장기 단절, 종료·재시작에 누락이
  가능하며 producer 누락은 DB의 과거 경로 회수 coverage와 별개다.
- 일반 registry 밖의 controller/server는 중앙 monitor 이력 미지원 신호를 표시한다.
  실제 WG에 있는 등록 피어만 발견한다. hub 뒤 원격 노드 목록을 만들어 probe하지 않는다.
- source는 보고자의 주장이다. 이번 endpoint의 binding 검사는 실제 route 증명이 아니다.
  path는 unknown이며 VPN echo 도달성을 서버 uplink 성공으로 확대하지 않는다.
- registry의 새 optional field는 구형 strict reader와 호환되지 않는다. 배포 전 전체
  controller backup과 구형 복귀 시 일관된 restore 절차를 배포 문서에 명시했다.
- #70의 p50/p99/jitter·handshake/transfer 공통 schema, #71/#74의 결합 장시간 soak,
  M3 다중 relay/underlay 전환 및 그 최종 판정은 별도다.
