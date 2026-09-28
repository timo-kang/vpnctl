# 개별 probe jitter 자체 리뷰

대상: #87. 기준 main: `6995978`. 구현 계약: [probe-jitter.md](../validation/probe-jitter.md).

## 확인하고 조치한 결함

1. 기존 RTT histogram에는 순서가 없어 jitter를 계산할 수 없었다. v2 summary에 합계·쌍 수와 경계 그룹/쌍을 보존하고, v1 혼합은 명시적인 계산 불가로 표시했다.
2. 동일 timestamp가 512행 배치를 넘어가면 기존에 계산한 경계 쌍을 그대로 더할 위험이 있었다. timestamp 그룹 전체를 장애물로 취급하고 양쪽 경계 쌍을 취소한다. 독립 oracle의 모든 분할에서 확인한다.
3. 역순 aggregate 병합에서 앞쪽 population 전체가 동일 timestamp이고 뒤쪽 population도 같은 timestamp로 시작하면 첫 timestamp만 비교하는 순서 판정이 정상 병합을 거절했다. 마지막 timestamp까지 비교하고 512개 tie 뒤 추가 표본을 병합하는 재현 테스트를 추가했다.
4. 기존 스키마 그대로 v2를 쓰면 구형 binary가 지원하지 않는 데이터에 접근할 수 있었다. 백업/ownership을 요구하는 명시적 v8/v9 전환을 추가하고 v6/v7은 기존 저장 형식을 유지한다.
5. 원시 RTT 순서를 사용하지 않던 조회를 명시적으로 정렬하고, 구형 live snapshot의 누락 필드가 정상 0처럼 표시되지 않도록 정규화했다.

6. 최초 full-mesh CI의 기존 용량 후보가 한 노드의 모든 stream을 한 응답에 담아 7일 JSON이 약 17.76 MB로 16 MiB 한도를 넘었다. 운영 API의 16-stream 페이지 계약을 후보 검증에도 적용했다. 페이지를 만들기 전에 stream 수를 제한하고, 모든 페이지의 합산 표본 및 노드 전체 8초 기준은 유지한다.

## 검증 증거

- 전체 일반 회귀 테스트 통과. jitter 고정 사례, 무작위 모든 분할/결합, 부분 압축·rollback·재시작·복원, legacy 혼합, CLI migration, HTTP/CLI/HTML/Prometheus 계약 통과.
- `go vet ./...`, build, `git diff --check` 통과.
- 2 CPU 일반 전체 race 통과(controller 188.397초, history 167.487초). 추가 jitter/CLI/monitor 계약 race 통과.
- schema 5/6/7/8/9 × 1/3/8/32 실제 생산자 20조합 race 통과(161.613초). 새 v8/v9의 32노드는 23.34/24.73초로 기존 45초 기준 안에 수렴했다. v5의 32노드는 full-mesh 수용 판정이 아닌 기존 quota 검증이다.
- 이전 main `6995978`을 별도로 빌드해 v8/v9 DB의 inspect/backup 거절을 확인했다. 새 binary는 jitter/reclamation 설정을 올바르게 인식한다.
- 수정한 legacy 용량 후보의 32노드 star/full-mesh 전체 통과(68.367초). full-mesh 7일 약 2천만 표본 합계가 일치하고 최대 페이지 JSON은 1,146,645 bytes, 노드 전체 조회·JSON은 최대 210.091ms였다. 이 fixture는 기존 aggregate를 직접 seed하며 실제 v2 저장 전환 증거와 구분한다.
- 최종 규모·경로 회수·kernel 및 CI 실행 증거는 [PR #89](https://github.com/timo-kang/vpnctl/pull/89)에서 확인한다. 최초 실패 실행은 [36384773307](https://github.com/timo-kang/vpnctl/actions/runs/36384773307)이며 원인은 위 6번에 기록했다.

## 판정 범위

측정 모집단은 보존된 보고 관측이다. 누락 표본과 실제 경로를 추정하지 않는다. live unknown reset과 history bucket의 모집단 차이는 기존 계약을 유지한다. 경로 회수는 기존 coverage를 통해 계속 표시한다. #88 handshake/RX·TX, 장기 soak 및 M3 실제 다중 relay/통신망 전환은 이번 구현의 완료 판정에 포함하지 않는다.
