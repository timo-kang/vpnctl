# M2 #17 측정·이벤트 타임라인 계약

controller의 `history.db`는 peer probe, uplink snapshot, 상태 전환 이벤트를 같은 UTC 기준으로 보존한다. 이벤트 조회는 노드별로 인증된 API를 사용한다.

## 공통 측정 봉투

공통 `metrics.Envelope`/`Measurement` 타입은 현재 설계용이며 producer와 영속 저장 경로에 연결되지 않았다. 실제 계약은 peer `history.Observation`, uplink `uplink.Snapshot`, 진단 `history.Event`다. #17은 아직 완료되지 않았다.

- fleet peer history는 평균/p95/loss/availability를 제공한다. p50/p99는 legacy CSV summary에만 있다.
- uplink history는 target별 평균 RTT와 availability, 성공/실패/unknown 건수를 제공한다.
- handshake age·transfer counter의 공통 이력 저장, jitter·percentile 통합, downsampling, DB size/health metric 및 전체 producer를 포함한 장기 soak은 후속 구현 대상이다.
- `unknown`은 성공/실패 분모에 포함하지 않는다. `source`는 제출자가 적는 진단 메타데이터이며 신뢰된 producer임을 증명하지 않는다.

## 이벤트 스트림

`POST /events`는 node-bound mTLS로 한 개의 immutable event를 제출한다. uplink snapshot이 수집되면 controller가 같은 DB transaction 안에서 다음 변화를 자동 기록한다.

- `uplink_change`: aggregate underlay 상태 변화
- `route_change`: target overlay/transport 상태·interface·source·gateway·destination 변화. previous/current는 JSON 문자열이다
- `relay_failover`: relay 상태·expected relay ID·실제 peer fingerprint 변화. previous/current에 교체 전후 식별자를 보존한다
- `probe_error`: target service/failure stage 변화
- `collector_error`: link controller 도달성 변화와 복구 (collector freshness 경보와 별개)
- `nat_remap`, `certificate`, `discovery_error`: API로 수동 제출 가능한 진단 종류. 자동 producer 연결은 아직 없다

target 삭제는 `current: removed`로 기록한다. snapshot 전환은 writer 직렬화 이후의 직전 committed snapshot과 비교하며, 늦게 도착한 과거 snapshot은 현재 상태를 되돌리지 않는다. 자동 이벤트 ID에는 snapshot ID도 포함한다.

이벤트 ID를 생략하면 canonical 필드의 SHA-256으로 결정적으로 생성된다. 같은 ID와 같은 payload의 재전송은 성공으로 처리하고 다른 payload는 conflict로 거부한다. timestamp는 `(now-7d, now]`에 있어야 하며 이벤트·메시지·label 길이는 제한된다.

`GET /fleet/events?node_id=<id>&window=24h&limit=500`은 최신순 `schema_version: 1` 타임라인을 반환한다. `limit+1`을 확인해 `truncated`를 표시하므로 호출자는 페이지를 잘린 결과로 오해하지 않는다. timestamp가 같으면 event ID를 tie-breaker로 사용해 restart나 clock skew에서도 순서가 결정적이다.

## 보존과 용량

- peer/uplink/event 모두 7일 보존이며 실행 중 controller maintenance가 1분마다 bounded transaction으로 정리한다.
- 자동 이벤트 저장 한도 초과 시 snapshot은 저장하고 해당 이벤트를 생략한다. `vpnctl_events_total{result="capacity_dropped"}`로 확인해야 하며 타임라인을 완전한 감사 로그로 사용하면 안 된다. 수동 제출은 503/ErrCapacity로 실패한다. 이 counter는 프로세스 재시작 시 초기화되므로 외부 Prometheus 보존이 필요하다. 경보는 snapshot으로 계산하므로 이벤트 누락으로 장애가 가려지지 않는다.
- monitor는 시작 시 및 1분마다 1,000행 단위로 정리한다. 정리 작업은 10초 제한이며 누적 backlog가 있으면 다음 주기에 계속한다.
- 이벤트는 전체 1,000,000건, 노드당 50,400건으로 제한한다. uplink target series는 기존 256/노드 16 제한을 유지한다.
- `event_metadata.row_count`와 `uplink_metadata.row_count`를 실제 행 수와 비교해 backup `Check`에서 검증한다.
- node, target, kind, source는 SQLite row나 Prometheus label의 무제한 사용자 입력으로 사용하지 않는다. Prometheus 이벤트 counter는 고정 kind/severity/result만 label로 갖는다.
- controller 재시작 시 retained rows를 replay하지 않고 SQLite에서 최신 uplink와 이벤트를 읽는다. 시간창 밖의 stale snapshot은 live status에 재사용하지 않는다.

## 경보와 Prometheus

`GET /fleet/alerts?node_id=<id>`는 다음 네 코드를 반환한다. `known: false`는 증거 부족이며 정상 판정이 아니다. 경보는 최신 committed snapshot 3개로 계산하고 재시작 시 같은 표본을 복원한다. 수동 진단 이벤트는 경보 상태를 변경하지 않는다. `targets`는 장애 대상 목록이며 하나의 target 복구가 다른 target 장애를 지우지 않는다.

| 코드 | 활성 조건 | 복구 조건 |
| --- | --- | --- |
| `no_uplink` | fresh underlay `down` | fresh underlay `up` (`unknown`은 판정 불가) |
| `relay_failure` | fresh target 중 relay `down`이 하나 이상 | 모든 configured relay probe가 `up` |
| `persistent_loss` | 동일 target/protocol의 최근 3회 연속 service `down`; 표본 간격은 설정 주기의 0.5배 이상, 3배 미만 | 새 service 성공 또는 연속 실패 조건 해제 |
| `stale_collector` | 마지막 관측 이후 설정 주기 3배 경과 또는 controller 시각 역전 | fresh snapshot 수신 |

과거 관측이 stale이면 다른 세 경보는 unknown으로 표시한다. 한 번도 보고하지 않은 노드는 네 경보 모두 unknown이다. `first_seen`은 판정에 사용한 가장 오래된 증거의 시각이며 장애 시작 전체 이력을 뜻하지 않는다.

`vpnctl_alert_active{code,severity}`는 scrape 시점에 계산한 **활성 경보를 가진 등록 노드 수**다. `vpnctl_alert_unknown`은 증거 부족 노드 수다. API 호출 순서에 영향을 받지 않으며 label은 네 code와 고정 severity뿐이다. 노드별 상세는 인증된 alerts API를 사용한다.

고정 rule 예시는 다음과 같다.

```yaml
groups:
- name: vpnctl-event-health
  rules:
  - alert: VPNCTLNoUplink
    expr: vpnctl_alert_active{code="no_uplink"} > 0
    for: 2m
    labels: {severity: critical}
  - alert: VPNCTLRelayFailure
    expr: vpnctl_alert_active{code="relay_failure"} > 0
    for: 1m
    labels: {severity: warning}
  - alert: VPNCTLPersistentLoss
    expr: vpnctl_alert_active{code="persistent_loss"} > 0
    for: 2m
    labels: {severity: critical}
  - alert: VPNCTLStaleCollector
    expr: vpnctl_alert_active{code="stale_collector"} > 0
    for: 3m
    labels: {severity: warning}
```

`vpnctl events --config node.yaml --node robot-01 --window 24h`와 `vpnctl alerts --config node.yaml --node robot-01`은 이 계약을 그대로 출력한다. 알림은 동작이나 route를 변경하지 않는다. VPN은 로봇이 사용 가능한 물리 링크와 relay를 통해 서버 uplink에 도달하는 방법 중 하나이며, 이 제품은 선택된 경로를 관측하고 전환 결과를 검증할 수 있게 하는 역할만 한다.

규칙에 `increase(vpnctl_events_total{result="capacity_dropped"}[5m]) > 0`와 `vpnctl_alert_unknown > 0`도 포함해 타임라인 누락·관측 미설정을 구분해야 한다.

## 검증 시나리오

1. 정상 → no uplink → relay failover → 정상의 snapshot을 제출하고 `/fleet/events`에서 pre/post event를 모두 재구성한다.
2. 동일 event/snapshot을 재시작 전후와 중복 전송하고 row count, event ID, alert state가 변하지 않는지 확인한다.
3. clock skew(동일 timestamp와 1초 역전), stale collector, NAT remap, certificate renewal, discovery/probe error를 제출해 tie-breaker와 네 가지 경보를 확인한다.
4. 7일 이상 soak에서 retention, DB 크기, WAL watermark, `event_metadata`/`uplink_metadata` 일치를 측정한다.
5. support matrix의 1/3/8/32 노드 netns smoke와 `go test -race ./...`, `go vet ./...`, `go build ./...`를 함께 통과시킨다.
