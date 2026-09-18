# M2 #17 측정·이벤트 타임라인 계약

controller의 `history.db`는 peer probe, uplink snapshot, 상태 전환 이벤트를 같은 UTC 기준으로 보존한다. 이벤트 조회는 노드별로 인증된 API를 사용한다.

## 공통 측정 봉투

모든 producer는 다음 의미를 유지한다.

| 필드 | 의미 |
| --- | --- |
| `node_id` | 보고한 로봇의 등록 identity |
| `target` | peer, server/relay target 또는 link ID |
| `relay` | 선택된 relay identity 또는 빈 값 |
| `underlay` | ethernet/wifi/lte 등 실제 관측한 링크 |
| `overlay_path` | direct/relay/unknown. 보고값이며 경로 증명으로 해석하지 않는다 |
| `timestamp` | cycle 완료 시각(UTC, microsecond) |
| `source` | `uplink-observer`, `agent`, `controller`, `monitor`처럼 고정된 producer |
| `unit` | RTT는 ms, loss/availability는 percent, transfer는 bytes |
| `validity` | `observed`, `inferred`, `unknown` |

RTT 집계는 평균과 nearest-rank p50/p95/p99를 함께 제공한다. `unknown` 표본은 손실률 분모나 availability 성공/실패 분모에 넣지 않는다. handshake age와 transfer counter는 원시 snapshot의 시각과 누적 counter에서 계산하며, counter reset은 새 시계열로 취급한다.

## 이벤트 스트림

`POST /events`는 node-bound mTLS로 한 개의 immutable event를 제출한다. uplink snapshot이 수집되면 controller가 같은 DB transaction 안에서 다음 변화를 자동 기록한다.

- `uplink_change`: underlay 또는 link controller 상태 변화
- `route_change`: target transport interface/gateway 변화
- `relay_failover`: relay 상태 또는 peer fingerprint 변화
- `probe_error`: target service/failure stage 변화
- `collector_error`: link controller 수집 실패
- `nat_remap`, `certificate`, `discovery_error`: agent/controller가 제출하는 명시적 진단 event

이벤트 ID를 생략하면 canonical 필드의 SHA-256으로 결정적으로 생성된다. 같은 ID와 같은 payload의 재전송은 성공으로 처리하고 다른 payload는 conflict로 거부한다. timestamp는 `(now-7d, now]`에 있어야 하며 이벤트·메시지·label 길이는 제한된다.

`GET /fleet/events?node_id=<id>&window=24h&limit=500`은 최신순 `schema_version: 1` 타임라인을 반환한다. `limit+1`을 확인해 `truncated`를 표시하므로 호출자는 페이지를 잘린 결과로 오해하지 않는다. timestamp가 같으면 event ID를 tie-breaker로 사용해 restart나 clock skew에서도 순서가 결정적이다.

## 보존과 용량

- peer/uplink/event 모두 7일 보존이며 실행 중 controller maintenance가 1분마다 bounded transaction으로 정리한다.
- 이벤트는 전체 1,000,000건, 노드당 50,400건으로 제한한다. uplink target series는 기존 256/노드 16 제한을 유지한다.
- `event_metadata.row_count`와 `uplink_metadata.row_count`를 실제 행 수와 비교해 backup `Check`에서 검증한다.
- node, target, kind, source는 SQLite row나 Prometheus label의 무제한 사용자 입력으로 사용하지 않는다. Prometheus 이벤트 counter는 고정 kind/severity/result만 label로 갖는다.
- controller 재시작 시 retained rows를 replay하지 않고 SQLite에서 최신 uplink와 이벤트를 읽는다. 시간창 밖의 stale snapshot은 live status에 재사용하지 않는다.

## 경보와 Prometheus

`GET /fleet/alerts?node_id=<id>`는 항상 다음 네 코드를 고정된 순서로 반환한다. 최근 전환이 없으면 `active: false`인 빈 상태를 반환한다.

| 코드 | 활성 조건 | 복구 조건 |
| --- | --- | --- |
| `no_uplink` | underlay `down` 또는 `unknown` | underlay `up` |
| `relay_failure` | relay가 `down` 또는 `unknown` | relay `up` |
| `persistent_loss` | probe service가 `down` | probe service가 `up` |
| `stale_collector` | collector가 `stale`/`down` | collector `up` |

고정 rule 예시는 다음과 같다.

```yaml
groups:
- name: vpnctl-event-health
  rules:
  - alert: VPNCTLNoUplink
    expr: vpnctl_alert_active{code="no_uplink"} == 1
    for: 2m
    labels: {severity: critical}
  - alert: VPNCTLRelayFailure
    expr: vpnctl_alert_active{code="relay_failure"} == 1
    for: 1m
    labels: {severity: warning}
  - alert: VPNCTLPersistentLoss
    expr: vpnctl_alert_active{code="persistent_loss"} == 1
    for: 2m
    labels: {severity: critical}
  - alert: VPNCTLStaleCollector
    expr: vpnctl_alert_active{code="stale_collector"} == 1
    for: 3m
    labels: {severity: warning}
```

`vpnctl events --config node.yaml --node robot-01 --window 24h`와 `vpnctl alerts --config node.yaml --node robot-01`은 이 계약을 그대로 출력한다. 알림은 동작이나 route를 변경하지 않는다. VPN은 로봇이 서버 uplink에 도달하는 underlay 선택지 중 하나이며, 이 제품은 선택된 경로를 관측하고 전환 결과를 검증할 수 있게 하는 역할만 한다.

## 검증 시나리오

1. 정상 → no uplink → relay failover → 정상의 snapshot을 제출하고 `/fleet/events`에서 pre/post event를 모두 재구성한다.
2. 동일 event/snapshot을 재시작 전후와 중복 전송하고 row count, event ID, alert state가 변하지 않는지 확인한다.
3. clock skew(동일 timestamp와 1초 역전), stale collector, NAT remap, certificate renewal, discovery/probe error를 제출해 tie-breaker와 네 가지 경보를 확인한다.
4. 7일 이상 soak에서 retention, DB 크기, WAL watermark, `event_metadata`/`uplink_metadata` 일치를 측정한다.
5. support matrix의 1/3/8/32 노드 netns smoke와 `go test -race ./...`, `go vet ./...`, `go build ./...`를 함께 통과시킨다.
