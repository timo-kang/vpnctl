# M2 #17 측정·이벤트 타임라인 계약

controller의 `history.db`는 peer probe, uplink snapshot, 상태 전환 이벤트를 같은 UTC 기준으로 보존한다. 이벤트 조회는 노드별 스트림과 컨트롤러 전역 스트림을 구분하는 인증된 API를 사용한다.

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
- `nat_remap`: 노드 shared UDP 소켓의 첫 STUN 관측과 public address/NAT 유형 변경. previous/current는 `{address,type}` JSON 문자열이다. STUN 전부 실패 시 mapping을 추정하거나 지우지 않고 별도 discovery 오류를 기록한다.
- `certificate`: 컨트롤러 발급/갱신/폐기/CA 전환/identity 제거 결과 및 노드 trust·갱신 credential 설치와 sync 실패/복구
- `discovery_error`: 실제 register, server-config 조회, candidates 조회, STUN, NAT 보고의 첫 관측과 up/down 전환. 캐시 설정 조회는 통신 성공으로 기록하지 않는다.

target 삭제는 `current: removed`로 기록한다. snapshot 전환은 writer 직렬화 이후의 직전 committed snapshot과 비교하며, 늦게 도착한 과거 snapshot은 현재 상태를 되돌리지 않는다. 자동 이벤트 ID에는 snapshot ID도 포함한다.

이벤트 ID를 생략하면 canonical 필드의 SHA-256으로 결정적으로 생성된다. 같은 ID와 같은 payload의 재전송은 성공으로 처리하고 다른 payload는 conflict로 거부한다. timestamp는 `(now-7d, now]`에 있어야 하며 이벤트·메시지·label 길이는 제한된다.

`GET /fleet/events?node_id=<id>&window=24h&limit=500`은 최신순 `schema_version: 1` 타임라인을 반환한다. `limit+1`을 확인해 `truncated`를 표시하므로 호출자는 페이지를 잘린 결과로 오해하지 않는다. timestamp가 같으면 event ID를 tie-breaker로 사용해 정렬이 결정적이다. 이 정렬이 서로 다른 프로세스의 인과 순서나 clock skew 이전의 실제 발생 순서를 증명하지는 않는다.

## 자동 생산자와 소유권

`GET /fleet/events?scope=controller&window=24h&limit=500` 또는
`vpnctl fleet events --config node.yaml --controller --json`으로 컨트롤러 PKI 스트림을 조회한다. 일반 fleet 조회와 동일한 mTLS 인증 및 응답 직전 재인증을 적용한다. `node_id`와 `scope=controller`는 함께 지정할 수 없다. 응답은 기존 schema_version 1에 `scope: controller`를 추가한다.

- 컨트롤러 전역 스트림은 DB의 빈 node 키를 사용한다. `POST /events`는 빈 node_id를 거부하며 event 안의 node_id 대신 인증된 요청의 node_id를 사용한다. 등록되지 않았거나 제거된 identity의 발급·폐기 결과도 전역 스트림에 남길 수 있다.
- 노드 스트림의 `source`는 여전히 제출자의 주장이다. source 문자열만으로 컨트롤러가 생산한 증거라고 판단하면 안 된다. 전역 스트림에 쓸 수 있는 주체는 컨트롤러 내부 생산자뿐이다.
- 컨트롤러 `current`는 `issue:success`, `renew:denied`, `pki.revoke:success`, `ca.prepare:failed`, `identity.remove:uncertain` 등의 operation/result다. 성공한 발급/갱신은 generation과 fingerprint, CA 전환은 generation/phase/CA 식별자를 message에 기록한다. raw 오류, CSR, PEM, 토큰, 개인 키를 이벤트에 넣지 않는다.
- 성공은 해당 PKI 작업의 반환 결과다. `issue:success`는 인증서 발급이 저장되었다는 의미이며 이후 registry/WG 반영, 응답 수신, 로봇의 설치까지 증명하지 않는다. 노드의 `target=renew|trust,current=installed`는 로컬 SaveCredentials가 성공한 뒤에만 발생한다. `target=sync,current=up`은 trust acknowledgement까지 성공했음을 뜻한다.
- rename 이후 directory fsync 실패는 `uncertain`/`validity=unknown`으로 기록한다. 이미 바뀐 보안 상태를 이벤트 저장 실패 때문에 되돌리지 않는다. 정책 거부는 `denied`, 일반 처리 실패는 `failed`다. 인증 전 차단, 잘못된 입력, 최초 PKI 초기화는 이 스트림의 완전한 감사 대상이 아니다.
- PKI 작업 호출마다 새 event ID를 사용한다. 같은 CSR로 수행한 성공적인 API 재호출은 별도의 작업 결과일 수 있다. 하나의 이벤트를 전송 재시도할 때는 ID와 payload를 바꾸지 않아 SQLite의 `(node,id)` 중복 제거가 적용된다.
- 노드 실행과 `node serve`는 프로세스 소유 작업자로 생산·전송한다. 등록/터널 복구 재시도에는 큐와 직전 관측 상태를 유지하고, identity/controller/PKI 경로 변경 시 기존 작업자를 종료한 후 새 큐를 만든다. 재시작 후 첫 관측의 previous는 비어 있으며 재시작 사이의 전환을 추정하지 않는다.

## 전달 한계와 손실 관측

자동 이벤트는 보안 감사 로그가 아닌 best-effort 진단이다. 생산 경로는 DB/네트워크 I/O를 기다리지 않는다. 별도 작업자 하나가 64건 대기 큐와 1건 전송 중 이벤트를 처리한다. 각 이벤트는 최대 5회, 회당 3초, 1/2/4/8초 backoff로 제한한다. 개별 전달 작업은 최대 약 30초이며 꽉 찬 큐의 마지막 항목은 지속 실패 시 약 32.5분 뒤 처리될 수 있다. 새 이벤트가 큐 용량을 넘으면 그 새 이벤트를 버린다.

HTTP 400/404/409/413 또는 로컬 history invalid/conflict는 즉시 폐기한다. 401/403, 연결 장애, 저장 용량/일시 오류는 제한 횟수 안에서 재시도한다. timestamp는 발생 시각 그대로 유지하므로 미래 시각(clock skew)은 거부되며 폐기 지표가 증가한다. timestamp를 전송 시각으로 바꾸어 실패를 숨기지 않는다. 반복된 같은 상태는 합치므로, 손실된 전환이 나중에 자동 재생된다고 보장하지 않는다.

종료와 설정 변경은 진행 중 I/O를 취소하고 남은 메모리 큐를 폐기한다. 디스크 spool은 없으며 비정상 종료 시 미전송 이벤트와 메모리 counter를 잃는다. 커밋 후 응답만 유실된 경우 재시도는 중복 행을 만들지 않는다. 큐 ID는 producer별 난수와 순번을 조합해 재시작·동일 timestamp 충돌을 피한다.

`vpnctl_diagnostic_delivery_total{role="controller|node",result}`의 result는
`queued`, `delivered`, `retry`, `overflow_dropped`, `shutdown_dropped`,
`stopped_dropped`, `rejected_dropped`, `exhausted_dropped`, `state_capacity_dropped`다.
node/target/error를 label로 쓰지 않는다. controller는 기존 Prometheus endpoint에서 이 값을 노출한다. 독립 `node serve`는 Prometheus HTTP endpoint를 제공하지 않으므로 노드 손실은 `diagnostic timeline incomplete` 로그(role, producer, 누적 dropped)를 수집한다. 별도 monitor 프로세스의 metric이 node serve counter를 포함한다고 가정하면 안 된다. 작업자는 손실 로그를 약 10초마다(진행 중 재시도 후) 및 종료 시 남긴다. 완전한 손실 집계를 위해 외부 로그/지표 보존이 필요하다.

영속 schema v4부터 빈 node 키의 컨트롤러 소유권을 정의한다. 현재 v5는 공통 probe source/unknown 확장을 포함하며 v1~v4 자동 전환과 backup/check/restore를 지원한다([fleet 계약](fleet-history.md)). 구버전 바이너리는 지원 범위 밖 schema를 거부한다. 배포 전 백업을 보존하고 롤백 시 호환되는 DB 복사본을 사용해야 한다. `PRAGMA user_version`을 수동으로 낮추어 덮어쓰면 안 된다.

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

`vpnctl fleet events --config node.yaml --node robot-01 --window 24h`와 `vpnctl fleet alerts --config node.yaml --node robot-01`은 이 계약을 그대로 출력한다. 알림은 동작이나 route를 변경하지 않는다. VPN은 로봇이 사용 가능한 물리 링크와 relay를 통해 서버 uplink에 도달하는 방법 중 하나이며, 이 제품은 선택된 경로를 관측하고 전환 결과를 검증할 수 있게 하는 역할만 한다.

규칙에 `increase(vpnctl_events_total{result="capacity_dropped"}[5m]) > 0`와 `vpnctl_alert_unknown > 0`도 포함해 타임라인 누락·관측 미설정을 구분해야 한다.

## 검증 시나리오

1. 정상 → no uplink → relay failover → 정상의 snapshot을 제출하고 `/fleet/events`에서 pre/post event를 모두 재구성한다.
2. 동일 event/snapshot을 재시작 전후와 중복 전송하고 row count, event ID, alert state가 변하지 않는지 확인한다.
3. clock skew(동일 timestamp와 1초 역전), stale collector, NAT remap, certificate renewal, discovery/probe error를 제출해 tie-breaker와 네 가지 경보를 확인한다.
4. 7일 이상 soak에서 retention, DB 크기, WAL watermark, `event_metadata`/`uplink_metadata` 일치를 측정한다.
5. support matrix의 1/3/8/32 노드 netns smoke와 `go test -race ./...`, `go vet ./...`, `go build ./...`를 함께 통과시킨다.

## 자동 생산자 회귀 검증

- `internal/diagnostic`: 저장 성공 후 응답 유실/동일 payload 재전송, 최대 5회 종료, 영구 거부, 800회 동시 제출의 큐 상한, 취소/종료/재시작 식별자 검증
- `internal/agent`: 실제 UDP STUN 주소 변경·응답 중단·복구, candidates 실패/복구, 등록 실패 후 동일 queue 유지, identity 변경, 캐시 성공 오판 방지
- `internal/controller`: 실제 mTLS 발급/CA prepare·activate/갱신·폐기 → API 조회, 저장 경로 실패에서 phantom success 방지, history writer 차단 + 100회 반복 거부 중 폐기 및 정상 조회 유지, 컨트롤러/타 노드 스트림 쓰기 차단
- `internal/history`: v3→v4 전환, 전역 이벤트 backup/check/restore, 재시작 중복 제거, 늦게 도착한 과거 및 미래 clock skew 검증
- `tests/integration/renewal_retry_test.go`: 초기 등록 실패 중 8초 인증서 만료를 넘어 갱신하고 실제 WG 경로의 CLI로 전역 갱신 성공·로봇 설치·등록 복구 이벤트 확인

공통 measurement envelope 생산자, 통계/handshake/transfer 통합, downsampling, DB 상태 지표와 이벤트를 포함한 24시간 soak은 #17에 남는다. 이 변경만으로 M2 또는 다중 릴레이 전환을 완료 판정하지 않는다.
