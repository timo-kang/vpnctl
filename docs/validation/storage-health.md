# 실행 중 중앙 이력 저장 상태 (#91)

`GET /fleet/storage`와 `vpnctl fleet storage --config node.yaml --json`은 같은 cached
snapshot(schema_version=1)을 반환한다. 기존 fleet API와 같은 mTLS·등록·폐기·삭제
장벽을 사용한다. `/status`와 `/prom/metrics`도 같은 snapshot을 읽는다. 일반 fleet
이력 응답의 `storage` 및 controller를 정지해야 하는 `history inspect`와 구별된다.

별도 background reader가 즉시 한 번, 이후 30초마다 최대 2초의 read-only transaction으로
수집한다. upload writer와 public query slot을 잡지 않으며, 동시에 하나만 실행한다.
API/HTML/scrape에서 SQLite 작업을 수행하지 않는다. 수집은 controller 종료 시 취소하고
drain한다. 새로운 schema를 만들거나 retention/compaction을 실행하는 동작이 아니다.

- `validity=observed`는 성공한 상태 수집을 뜻하며 DB 무결성 합격이나 용량 여유를 뜻하지 않는다.
- 시작 전은 `unknown/not_collected`, 실패는 `unknown/collection_failed`이며 `values=null`이다.
- 90초 이상 지난 표본 또는 clock 역행은 read 시점에 unknown/stale 또는 clock_regressed로
  바뀌고 values는 null이다. 이전 정상값을 0이나 현재 정상 상태로 재사용하지 않는다.
- `observed_at`은 최근 시도 시각, `last_success_at`은 마지막 성공 시각이다. 실패 중에도
  마지막 성공 시각은 유지하며 process restart 시 새로 시작한다.
- `database_bytes`는 WAL에 있는 commit도 포함한 SQLite page count × page size다.
  `database_file_bytes`와 `wal_bytes`는 수집 시 파일 크기다. 파일 stat과 SQLite snapshot이
  물리적으로 같은 순간이라고 보장하지 않으며, 30초 간격 관측은 사이의 peak를 놓칠 수 있다.
- `free_bytes`는 재사용 가능한 DB page 공간이며 파일시스템 가용 공간이 아니다.
- raw/stream/uplink/event는 저장 metadata 및 제한된 stream count다. 지속적인 전체
  무결성 스캔이 아니므로 최종 검증에는 별도 `history.Check`/backup 검사를 사용한다.
- tiered 기능이 켜졌을 때 `compaction_eligible_rows`는 현재 시각에서 6시간을 뺀 UTC-hour
  cutoff 이하의 raw 수, `oldest_compaction_eligible`은 그 중 최초 시각이다. 해당 값이
  없을 때 0 지연으로 추정하지 않는다. 기존 `tiering.pending_samples`는 durable seal 이하의
  대기 raw로 의미가 다르다. 마지막 compaction이 오래됐다는 이유만으로 backlog를 단정하지 않는다.
- 회수 건수와 WG 삭제 범위는 기존 fleet 범위의 persisted 값이다. 보존 행 수와 수집·전송
  drop은 다르며, node/monitor producer의 delivery 신호도 함께 수집해야 한다.

`vpnctl_history_storage_*`는 고정 이름·무 label의 gauge다. unknown/stale 및 적용되지 않는
기능은 NaN이며 collection_valid는 0이다. lifetime reclaimed 값도 gauge이고 복원 시
되돌아갈 수 있다. JSON의 WG uint64 문자열이 정확한 값이며 Prometheus float64는
2^53 초과 정수를 근사할 수 있다. 기존 quota/sealed/maintenance 및 각 producer의 drop
counter를 함께 사용한다. 다음은 실제 scrape job 이름에 맞춰 적용할 경보 예시다.

```yaml
- alert: VpnctlStorageObservationUnavailable
  expr: vpnctl_history_storage_collection_valid{job="vpnctl-controller"} == 0
  for: 2m
  labels: {severity: warning}
  annotations:
    summary: "중앙 저장 상태 수집 실패 또는 정체"
- alert: VpnctlStorageObservationAbsent
  expr: absent(vpnctl_history_storage_collection_valid{job="vpnctl-controller"})
  for: 2m
  labels: {severity: warning}
  annotations:
    summary: "중앙 저장 상태 metric 수집 경로 없음"
```

검증: schema 5..9/15..19, 동시 snapshot 소유권, public query/writer slot과 독립된 수집,
DB 누락 시 생성 금지, 실패/취소 후 회복, compaction 대기→집계 변화, mTLS 폐기,
종료 취소, CLI/HTML 및 unknown/stale Prometheus 계약.
