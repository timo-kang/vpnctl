## 문제와 영향 — P1 / M1 runtime 후속 결함

`internal/agent/agent.go:132-232`의 direct sweep은 heartbeat/candidates/health와 같은 select goroutine에서 모든 peer를 순차 처리한다. peer마다 최대 2초 probe 후 API 보고도 동기 실행한다. STUN의 종료 교착을 고친 #37/#40과는 별개의 starvation 경로다.

응답 없는 peer가 N개이면 probe만 약 2N초, API 실패 대기까지 더해질 수 있다. 32노드에서 나머지 31개 peer가 응답하지 않으면 probe 대기만 약 62초다. 이는 실측 32노드 수치가 아니라 현재 순차 실행 코드에서 도출한 값이다. 그동안 heartbeat, candidates 갱신, hub health check와 failover 판단도 실행되지 않는다.

## 재현 근거와 CI 사각지대

`TestReviewDirectSweepMustNotStarveHeartbeat`에서 실제 agent.Run, loopback HTTP 및 응답하지 않는 UDP peer 3개를 구성했다. heartbeat 주기를 1초로 설정했지만 direct sweep 시작 후 3초 동안 다음 heartbeat가 한 번도 실행되지 않았다. race 모드 3회 반복에서 같은 결과였다.

현재 1/3/8/32노드 PKI 실커널 matrix는 `DirectMode: "off"`, `HealthCheckIntervalSec: 3600`을 명시한다 (`tests/integration/pki_network_test.go:175-176`). 그 통과 결과는 이 default-auto starvation을 검증하지 않는다. 별도 direct netns 테스트는 두 노드의 정상 peer injection 확인이며 silent fleet/fallback 시험이 아니다.

## 집중 작업

- direct 측정을 bounded concurrency/별도 worker로 분리하고 heartbeat·health·controller 제어 루프의 진행을 보장한다.
- 전체 sweep budget, 최대 동시 요청, 결과 제출/backpressure 정책을 정의한다.
- 늦은 응답/취소가 다음 generation의 desired state를 덮어쓰지 못하게 한다.
- 저장된 candidates 규모 및 반복 unreachable/flap 조건에서 취소·자원 상한을 검사한다.

## 완료 판단 기준

- [ ] 1/3/8/32개 silent peer 환경에서 heartbeat·health의 지연 상한을 정하고 실제 충족한다.
- [ ] direct_mode=auto 및 기본 health 설정을 사용하는 실제 커널 시나리오가 있다.
- [ ] controller 응답 지연까지 겹쳐도 제어 루프가 peer 수에 비례해 정지하지 않는다.
- [ ] 재시도/취소/종료에서 goroutine·FD·pending map이 유한하며 기준치로 돌아온다.
- [ ] stale result·동시 apply·fallback에 관한 #20/#23의 계약과 충돌하지 않는다.

Refs #37, #13, #20, #23, #24. direct readiness의 기존 TTL 무효화 결함 #20과 중복이 아니라 스케줄링 결함이다.
