# 개별 probe percentile 자체 리뷰

대상: #84 / 부모 #70. 세 percentile을 live·raw·압축 이력에서 계산하고 API/CLI/HTML/
monitor HTTP·watch·TUI·Prometheus까지 연결했다. 입력 관측이나 품질 판정 임계값은 추가하지 않는다.

## 검토 및 조치

1. 실패와 unknown을 RTT 0으로 추가하면 낮은 percentile이 낙관적으로 바뀐다. 계산 입력을 성공
   표본으로 한정하고 null과 측정된 0을 구분한다. 100개 성공+10개 실패+5개 unknown의 직접
   계산 기대값 49/94/98을 raw·live·압축·복원에서 검증한다.
2. 집계 구간별 percentile 평균은 전체 percentile이 아니다. 기존 정확한 RTT 빈도 분포에서
   누적 빈도로 세 rank를 선택한다. 저장 형식과 checksummed payload는 그대로다.
3. 초기 구현은 replay의 모든 중간 상태마다 정렬했다. hysteresis 상태 전이는 모두 실행하되,
   percentile 정렬은 마지막 snapshot에 한 번만 수행하도록 수정했다. live/replay의 모든 prefix
   비교로 최적화가 품질·통계 결과를 바꾸지 않는지 검증한다.
4. 새 pointer 필드도 Clone에서 분리했다. subscriber/HTTP 소비자의 변경이 다른 snapshot을
   오염시키지 않는다.
5. 과거 압축 live JSON에는 percentile이 없고 정확한 live 모집단을 복원할 수 없다. 이런 필드는
   null이다. 스키마 버전을 올리거나 시간별 통계로 대신하지 않는다. 구형 JSON/digest, Check,
   재시작 검증을 추가했다. 시간별 aggregate에서는 기존 분포로 새 percentile을 복원한다.
6. API만 변경하고 운영 화면을 누락하지 않도록 fleet CLI, 상태 HTML, monitor watch/TUI와
   Prometheus를 함께 연결했다. JSON/ms, Prometheus/seconds, 미측정 null/-/NaN 규칙을 유지한다.
7. 규모 시험의 독립 기대값에도 세 percentile을 추가했다. 기존 p95-only oracle로 수행한 초기
   전체 실행은 새 필드 누락으로 실패했으며, 직접 정렬/rank 기대값 보완 후 최종 재실행한다.
   공통 구현 함수를 oracle에서 호출하지 않는다.

## 검증

- 성공/실패/unknown, measured zero, empty, lower window edge, stale, clock regression.
- 중복 제출/역순 도착, stream/underlay 격리, live/replay 동등성.
- schema 5/6/7 원시·압축·재시작·backup/restore, 구형 live JSON 호환.
- HTTP/CLI/HTML/Prometheus 단위·null 및 snapshot 포인터 분리.
- 전체 일반 race, 실제 mTLS 생산자 행렬, 24회 경로 전환, CI의 대규모 전환·kernel 회귀.
  최종 실행 링크와 결과는 PR에 기록한다.

## 범위 제한

jitter·handshake age·전송 counter는 아직 공통 계약을 완료하지 않았다. 특히 기존 archive는 순서를
보존하지 않으므로 jitter를 계산할 근거가 없다. #70은 OPEN을 유지한다. 대규모 시험의 통과도
24시간 운영 soak, 무손실 수집, 실제 다중 릴레이/망 전환의 합격을 뜻하지 않는다.
