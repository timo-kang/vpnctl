# 개별 probe jitter 자체 리뷰

대상: #87. 기준 main: `6995978`. 구현 계약: [probe-jitter.md](../validation/probe-jitter.md).

## 확인하고 조치한 결함

1. 기존 RTT histogram에는 순서가 없어 jitter를 계산할 수 없었다. v2 summary에 합계·쌍 수와 경계 그룹/쌍을 보존하고, v1 혼합은 명시적인 계산 불가로 표시했다.
2. 동일 timestamp가 512행 배치를 넘어가면 기존에 계산한 경계 쌍을 그대로 더할 위험이 있었다. timestamp 그룹 전체를 장애물로 취급하고 양쪽 경계 쌍을 취소한다. 독립 oracle의 모든 분할에서 확인한다.
3. 역순 aggregate 병합에서 앞쪽 population 전체가 동일 timestamp이고 뒤쪽 population도 같은 timestamp로 시작하면 첫 timestamp만 비교하는 순서 판정이 정상 병합을 거절했다. 마지막 timestamp까지 비교하고 512개 tie 뒤 추가 표본을 병합하는 재현 테스트를 추가했다.
4. 기존 스키마 그대로 v2를 쓰면 구형 binary가 지원하지 않는 데이터에 접근할 수 있었다. 백업/ownership을 요구하는 명시적 v8/v9 전환을 추가하고 v6/v7은 기존 저장 형식을 유지한다.
5. 원시 RTT 순서를 사용하지 않던 조회를 명시적으로 정렬하고, 구형 live snapshot의 누락 필드가 정상 0처럼 표시되지 않도록 정규화했다.

## 검증 증거

- 전체 일반 회귀 테스트 통과. jitter 고정 사례, 무작위 모든 분할/결합, 부분 압축·rollback·재시작·복원, legacy 혼합, CLI migration, HTTP/CLI/HTML/Prometheus 계약 통과.
- `go vet ./...`, build, `git diff --check` 통과.
- race, 실제 생산자 matrix, 가변 mesh/경로 회수, 전체 CI 결과는 실행 완료 후 이 문서와 PR에 기록한다.

## 판정 범위

측정 모집단은 보존된 보고 관측이다. 누락 표본과 실제 경로를 추정하지 않는다. live unknown reset과 history bucket의 모집단 차이는 기존 계약을 유지한다. 경로 회수는 기존 coverage를 통해 계속 표시한다. #88 handshake/RX·TX, 장기 soak 및 M3 실제 다중 relay/통신망 전환은 이번 구현의 완료 판정에 포함하지 않는다.
