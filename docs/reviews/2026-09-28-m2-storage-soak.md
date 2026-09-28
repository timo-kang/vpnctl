# M2 저장 상태와 복합 실행기 자체 리뷰

## 확인 및 수정

- 기존 tiered history 응답의 저장 통계는 존재하지만, legacy/WG 포함 상태를 독립적으로
  scrape할 cached 경로가 없었다. 단일 bounded read-only reader와 API/CLI/HTML/metric을 추가했다.
- query가 붙을 때마다 SQLite를 열거나 scrape에 무거운 count를 넣지 않는다. 2초 제한의
  background collection과 30초 cadence, 90초 read-time freshness, unknown/null/NaN을 적용했다.
- health는 무결성 검사나 filesystem 여유 공간이 아니다. metadata·파일 stat의 의미와
  수집 간격 사이 peak를 놓치는 한계를 명시했다. raw cutoff backlog는 기존 seal backlog와 분리했다.
- 처음 smoke의 uplink cadence 2초는 제품의 30초 최소 계약에 의해 거절됐다. 시험을 수정했다.
- 첫 복합 trial은 controller/underlay/target/monitor 장애를 통과한 뒤, 제거된 ID 재사용이
  403으로 거절됐다. 삭제 tombstone 보호를 유지하고 새 ID/key의 교체로 고쳤다.
- 장애 주입만 하고 성공하는 허술한 검사를 막기 위해 실제 API 실패와 정확한 server_endpoint
  분류를 요구한다. 삭제된 credential 반복 요청, CA rollback, heartbeat age 검사도 추가했다.
- 정상/SIGTERM 중단에서 공개 artifact와 private 임시 생성 파일을 구분하고, 불완전 verdict를 통과로
  해석하지 않게 했다. 순환 smoke를 단일 프로세스 24시간 soak라고 표기하지 않는다. SIGTERM 시험은 종료 143, 컨테이너·private work 제거와 성공 verdict 부재를 확인했다.
- 삭제로 WG 전송 경로도 끊어진 상태의 timeout을 인증 거절로 인정하지 않는다. 새 identity/key로 전송 경로를 복구하고 정상 credential의 API 성공을 확인한 뒤, 폐기 credential에 HTTP 403을 요구한다.
- 순차 종료가 나머지 node의 heartbeat를 늦췄다고 오판하지 않도록 모든 최종 snapshot을 먼저 수집한 뒤 생산자를 종료한다.

- WG 저장 기능이 아직 활성화되지 않은 DB의 metric이 0으로 출력되는 계약 불일치를 수정했다. JSON의 enabled=false와 함께 Prometheus도 NaN을 유지한다.

## 검증과 남은 범위

저장 health의 10개 schema 조합, snapshot 소유권/race, cancel/DB 누락/회복, compaction
대기량, mTLS 폐기, 종료 취소, CLI/HTML 및 Prometheus unknown을 검사했다. 실제 mixed
run은 8분/3노드의 7가지 장애·복구 모두 통과했다(총 544.56초). 이후 최종 snapshot 순서, 공개 artifact 소유권, 삭제 수 확인의 최종 head 검증은 CI에 포함한다. 일반 전체 race, vet/build와 SIGTERM 정리도 통과했다. 최종 CI 근거는 #91과 PR에 기록한다.

M2는 아직 미완료다. 24시간 실제 경과, 대표 환경, 혼합 저장 압력, 전체 population/timeline
분석과 제어 latency 검토를 #19에 연결해야 한다. 실행기가 끝났다는 사실만으로 이
최종 gate를 닫지 않는다. 다중 relay/underlay 전환은 M3다.
