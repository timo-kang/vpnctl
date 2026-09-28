# 개별 probe RTT percentile 계약

`/fleet/status`, `/fleet/history`, monitor HTTP 품질 응답은 `p50_rtt_ms`,
`p95_rtt_ms`, `p99_rtt_ms`를 제공한다. 기존 schema 응답에 추가하는 nullable 필드이며
DB schema 5/6/7 또는 aggregate encoding version을 변경하지 않는다.

## 계산

- 같은 `(node, peer, path, relay, uplink, source)`의 개별 **성공 probe** RTT만 사용한다.
- microsecond 단위로 저장·정규화한 값을 정렬하고 `ceil(p × 성공 수 / 100)`번째 값을
  선택하는 nearest-rank 방식이다. JSON과 CLI 단위는 ms이다.
- 예: 성공 RTT 0~99 ms 100개, 실패 10개, unknown 5개이면 p50=49, p95=94, p99=98 ms이다.
  시도 수는 110, unknown 수는 5이고 percentile 모집단은 100이다.
- 실패/unknown/빈 구간은 RTT 0으로 채우지 않는다. 성공 표본이 없으면 null이며,
  실제 0 ms 성공만 있는 구간은 0이다. 성공 한 개의 세 percentile은 모두 그 값이다.
- 원시 시간 이력과 압축 시간 이력은 같은 모집단에서 동일한 값을 낸다. 압축된 RTT별
  빈도에 가중치를 적용한다. 시간별 percentile끼리 평균하지 않는다.
- stream/source/경로별로 계산한다. 중앙 이력의 같은 ID 재전송은 추가 표본이 되지 않는다.
  역순 도착은 timestamp와 ID 순서로 replay하며 미래 관측 거절은 기존 규칙을 유지한다.

## 실시간 창과 표시

실시간 품질은 기존 기본 60초 `(observed_at-window, observed_at]` 창을 사용한다.
unknown 수집 결과와 시계 역행은 기존 품질 창 초기화 규칙을 유지한다. stale 읽기는
마지막 수치를 보존하면서 stale/unknown 및 이유를 표시한다. percentile은 품질 등급의
새 판정 임계값이 아니며 표본 수가 적을 때도 실제 값과 sample_count를 함께 제공한다.

시간 이력 bucket은 요청된 `(start,end]` 구간이다. 실시간 창과 bucket 모집단이 다르면
숫자도 다를 수 있다. 사용자 지정 monitor 창도 응답의 window와 함께 해석한다.

- fleet status/history CLI와 상태 HTML: ms, 미측정 `-`.
- monitor watch/TUI: `p50/p95/p99(ms)=.../.../...`, 미측정 `-`.
- monitor Prometheus: `vpnctl_quality_rtt_p50_seconds`, `_p95_seconds`, `_p99_seconds`.
  단위는 초이고 미측정은 NaN이다. 기존 `vpnctl_quality_stale`와 관측 timestamp를 함께 사용한다.
- JSON: nullable 숫자 그대로 제공하며 모든 snapshot의 포인터는 소비자별로 분리한다.

## 이전 자료와 복구

이전 raw와 시간별 aggregate에도 개별 RTT 또는 정확한 빈도 분포가 있으므로 새 percentile을
재계산할 수 있다. 이미 압축된 **이전 실시간 snapshot**에는 percentile이 없을 수 있다.
그 snapshot의 정확한 60초 모집단은 시간별 분포로 되살릴 수 없으므로 세 필드는 null이다.
새 관측이 들어오면 다시 계산한다. 시간 이력의 percentile 조회에는 이 제한이 없다.

새 live snapshot은 percentile을 함께 저장·검증하고 backup/restore 뒤에도 보존한다.
재시작으로 stale을 해제하지 않는다. 기존 배포·중지·backup/restore 절차를 그대로 따른다.

## 범위 및 다음 단계

이 계약은 개별 probe 기반 공통 관측 경로에 적용한다. legacy CSV `stats`의 batch 평균 요약은
이 모집단과 다르며 개별 RTT percentile로 해석하지 않는다.

#70에서 jitter와 handshake/transfer의 공통 수집·저장 계약은 아직 남아 있다. 기존 시간별
RTT 분포는 순서를 저장하지 않으므로 연속 표본 차이인 jitter를 복원할 수 없다. 후속 변경은
연속 성공/실패/unknown, 시간창·경로 변경 경계를 정하고 순서 요약 및 이전 자료의 unavailable
처리를 포함해야 한다. WG counter는 reset과 관측 시각을 포함해야 한다. #19의 장기 soak와
M3 다중 relay/underlay 전환 판정도 별도로 유지한다.

후속 개별 probe RTT jitter의 순서·저장 이관·계산 불가 계약은 [probe-jitter.md](probe-jitter.md)에 정리한다.
