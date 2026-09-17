# Monitor 품질 계약 v1 — M2 #14

## API 변경과 측정 의미

`vpnctl monitor --metrics-port <port>`의 `GET /network/quality`는 schema version 1의
object를 반환한다. **기존 버전 없는 배열 응답과 호환되지 않는다.** 기존 소비자는
최상위 배열 대신 `peers`를 읽고 `schema_version == 1`을 확인해야 한다.
`Cache-Control: no-store`이며 지원하지 않는 HTTP method는 405다.

API, TUI, `--watch`, Prometheus는 동일한 Monitor snapshot의 계산 결과를 사용한다.
기존 API/화면의 마지막 probe 한 번과 Prometheus의 SQLite 1분 통계 혼용을 제거했다.
현재 값은 프로세스 시작 후 모은 표본으로 계산하며, SQLite는 history 저장소다.
저장 오류는 `storage_error`로 표시하고 현재 network 품질 계산에 실패 표본으로 더하지 않는다.
기존 `fleet status/history` 및 중앙 fleet API의 통일은 후속 #15 범위다.

예시(최근 10회 중 8회 성공, 2회 실패):

```json
{
  "schema_version": 1,
  "observed_at": "2026-09-17T00:00:50Z",
  "window": 60,
  "stale_after": 17,
  "min_samples": 3,
  "recovery_samples": 3,
  "stale": false,
  "error_reason": "",
  "storage_error": "",
  "peers": [{
    "peer": "10.7.0.2",
    "quality": "poor",
    "rtt_ms": 12.5,
    "loss_pct": 20,
    "observed_at": "2026-09-17T00:00:50Z",
    "window": 60,
    "sample_count": 10,
    "last_success_at": "2026-09-17T00:00:40Z",
    "stale": false,
    "error_reason": "probe_timeout"
  }]
}
```

| 필드 | 의미·단위 |
| --- | --- |
| `observed_at` | UTC RFC3339. peer는 해당 probe cycle 완료 시각, 최상위는 최근 discovery/probe cycle 결과 시각. 시작 전은 null |
| `window` | 초. 해당 peer의 `(observed_at - window, observed_at]` 구간 |
| `sample_count` | 구간 안 실제 유효 대상 probe 시도 수. 성공과 실패 모두 포함 |
| `loss_pct` | 실패 수 / 전체 시도 수 × 100. 미측정은 null |
| `rtt_ms` | 성공 표본만의 평균 RTT, 밀리초. 실패 RTT를 0으로 평균에 섞지 않음. 성공 표본이 없으면 null |
| `last_success_at` | 이 프로세스가 해당 identity/IP/probe-port 조합에서 마지막으로 성공한 시각. 현재 window 밖일 수 있음. 성공 이력이 없으면 null |
| `stale` | 오래됐거나 discovery 실패로 현재 상태로 사용할 수 없음 |
| `error_reason` | 아래의 한정된 상태/오류 코드. raw endpoint나 시스템 오류 문자열을 포함하지 않음 |
| `storage_error` | 최근 cycle의 history 저장 실패 `store_write_failed`, 또는 빈 문자열 |

window는 매 cycle 완료 때 계산한다. 수집이 멈춘 동안 과거 값의 window 종료 시각을
현재로 바꾸지 않는다. 조회 시 나이가 `stale_after` 이상이면 `stale=true`,
`quality=unknown`이 된다. 과거 RTT/loss/count는 진단용으로 남으므로 소비자는
**quality와 stale 및 최소 표본 수를 함께 확인**한다. API와 Prometheus는 요청할 때마다
freshness를 확인하고 터미널은 최대 1초 주기로 확인한다. 시계가 관측 시각보다 뒤로
돌아가면 unknown으로 처리하고 다음 cycle의 window를 새로 시작한다.

## 상태와 이유

- `unknown`: 시작 직후 표본 부족, 잘못된 probe 대상, stale 또는 discovery 실패.
- `offline`: 충분한 표본이 있고 window 안 성공이 하나도 없음. VPN 장치가 없다는 뜻은 아니다.
- `good`: 평균 RTT ≤ 50ms, 손실 ≤ 2%.
- `degraded`: 평균 RTT ≤ 200ms, 손실 ≤ 10%.
- `poor`: 유효 표본이 있으나 위 범위를 벗어남.

품질 악화는 새 표본에서 즉시 반영한다. 개선은 동일한 개선 등급이 설정 횟수만큼
연속 관측돼야 반영한다. 회복 대기 중에는 `recovering`을 표시한다. 조회/scrape 횟수는
회복 횟수에 포함하지 않는다. 따라서 회복 대기 중 `offline`이면서 새 window의
loss가 100% 미만인 과도 상태가 가능하다. 현재 raw 결과는 `vpnctl_probe_success`로
따로 제공한다. 이는 경로 전환 정책이 아니라 측정 품질 등급의 히스테리시스다.

| 이유 | 관측 근거 |
| --- | --- |
| `not_started` | 아직 cycle을 완료하지 않음 |
| `insufficient_samples` | 최소 표본 수 미달 |
| `discovery_failed` | peer source 읽기 실패. 이전 peer 결과를 unknown/stale로 즉시 발행 |
| `discovery_conflict` | source가 같은 VPN IP를 여러 peer에 배정해 결과를 구별할 수 없음 |
| `no_peers` | source/filter에서 관측할 peer가 없음. `peers: []`, 전체 network good을 의미하지 않음 |
| `stale` / `clock_regressed` | 수집 나이 초과 / 관측 이후 시계 역행 |
| `invalid_probe_target` | 유효하지 않은 IP/port. 표본 0, RTT/loss null이며 network loss로 계산하지 않음 |
| `responder_unavailable` | UDP 연결 거절을 수신 |
| `route_unreachable` | 커널이 목적지/네트워크 도달 불가를 보고 |
| `invalid_response` | 요청과 다른 echo 응답 |
| `probe_timeout` | 2초 probe 기한 만료 |
| `probe_error` | 그 외 socket 오류 |
| `recovering` | 개선 등급의 연속 표본 확인 중 |

UDP timeout만으로 tunnel, firewall, responder 중 어디가 고장났는지 확정할 수 없다.
`responder_unavailable`도 수신한 거절 응답의 분류이며 원격 프로세스 상태를 직접 읽은 것은
아니다. tunnel/underlay/target 단계별 독립 probe와 원인 판정은 #16에서 확장한다.
실제 source의 discovery 대상과 responder 지원 범위는 #18에서 별도로 정리한다.

## 설정

```sh
vpnctl monitor --interface wg0 --watch --metrics-port 9100 \
  --interval 5s --quality-window 1m --quality-stale-after 17s \
  --quality-min-samples 3 --quality-recovery-samples 3 \
  --quality-good-rtt-ms 50 --quality-good-loss-pct 2 \
  --quality-degraded-rtt-ms 200 --quality-degraded-loss-pct 10
```

`quality-stale-after`를 생략하면 `min(window, 3*interval + 2초)`다.
양수 window/최소 표본/회복 횟수와 `stale_after <= window`가 필요하다.
RTT/loss threshold는 유한한 비음수이며 good ≤ degraded, loss ≤ 100을 만족해야 한다.
window에 들어갈 수 있는 표본 수보다 최소 표본 수를 크게 잡으면 unknown이 유지된다.
설정값은 운영 요구에 맞춰 정하며 field SLA나 failover 기한으로 해석하지 않는다.

## Prometheus 계약

동일 snapshot에서 `vpnctl_link_quality`는 -1 unknown, 0 offline, 1 poor,
2 degraded, 3 good이다. **기존 0~3만 처리하던 dashboard/alert는 -1을 추가해야 한다.**
`vpnctl_probe_loss_ratio`는 `loss_pct / 100`, `vpnctl_quality_rtt_seconds`는 `rtt_ms / 1000`이다.
미측정 수치는 NaN이며 0으로 대체하지 않는다.

`vpnctl_quality_sample_count`, `vpnctl_quality_stale`,
`vpnctl_quality_observed_timestamp_seconds`, `vpnctl_quality_last_success_timestamp_seconds`도
peer label로 제공한다. `vpnctl_quality_window_seconds`, `vpnctl_quality_stale_after_seconds`,
`vpnctl_monitor_collection_ok`, `vpnctl_monitor_storage_ok`는 프로세스 단위다.
collection_ok는 현재 정상 수집(빈 peer 집합 포함)이면 1이고 network 전체 가용성 지표가 아니다.

기존 `vpnctl_probe_rtt_seconds`와 `vpnctl_probe_success`는 마지막 개별 probe 의미를
유지한다. 실패 RTT와 stale 개별 probe는 NaN이다. 성공 discovery에서 제거한 peer의
현재 gauge는 다음 scrape부터 사라진다. 누적 `vpnctl_probe_total`은 프로세스 수명 동안
유지한다. 수집 오류 때문에 제거 여부를 모를 때는 peer gauge를 unknown/stale로 남긴다.

## 검증

- 10회 중 2회 실패: API/Prometheus/TUI/watch 모두 동일한 20% 및 성공 RTT 평균.
- 정확한 window/신선도 경계, clock 역행, 초기 표본 부족, 제거/재등장 identity 격리.
- 개선 히스테리시스와 조회 횟수 독립성, snapshot의 중첩 pointer 소유권, 동시 publish/read/scrape race.
- history 저장 실패, discovery 실패가 unread good snapshot을 대체하는지 확인.
- 실제 IPv6 UDP echo 및 오류 종류 분류.
- `TestNetns_MonitorQuality`: 실제 WG 두 namespace, 외부 바이너리 CLI, 응답기 중단/복구,
  WG interface 제거/빈 peer 집합에서 API/Prometheus 계약과 정상 종료 확인.

실행: `go test -race ./internal/monitor`와
`./scripts/test-netns.sh -test.run '^TestNetns_MonitorQuality$'`.
JSON, Prometheus 응답, SQLite history와 터미널 로그는 `monitor-quality-*` artifact에 보관한다.
