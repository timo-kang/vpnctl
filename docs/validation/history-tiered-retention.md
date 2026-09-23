# Full mesh 이력의 계층 보존 후보와 활성화 조건

후속 구현: [schema v6 운영 저장 계약과 활성화/복구](history-tiered-storage.md).
아래 내용은 #75에서 수행한 독립 후보 실험의 기록이다. 기본 DB의 v5 동작은 유지하며,
후속 명령으로 명시적으로 활성화한 DB만 v6를 사용한다.

상태: #71의 **집계 형식과 저장 예산 검증 단계**. `ProbeAggregate`와 별도 SQLite fixture를
구현했다. production `Store`, API v2, schema v5, 7일 원본 보존, 16/256 stream quota는
아직 변경하지 않았다. 이 문서는 새 기능이 이미 운영에서 켜져 있다는 뜻이 아니다.

## 목표 부하와 선택한 후보

| 항목 | 후보 계약 / 실험 입력 |
| --- | --- |
| topology | 1/3/8/32노드, hub 관계 `2×(N−1)` 및 full mesh `N×(N−1)` |
| source | `agent-direct`, `monitor-overlay` 2개. 후자는 #70에서 연결할 생산자의 예약 부하 |
| 32노드 full mesh | 992개 방향성 관계 × 2 source = 1,984개 active stream |
| 경로 이력 | uplink label 4세대가 시간에 따라 바뀜. 실제 표본 수를 4배로 늘리지 않음 |
| 보존 stream 수 | full mesh의 7,936개까지 조회. 현재 production quota에서는 수용 불가 |
| 관측 cadence | 관계/source별 60초. readiness probe 자체를 sampling하거나 줄이지 않음 |
| 총 보존 | 7일, 19,998,720개 관측의 population |
| 최근 원본 | UTC hour 경계에 맞춘 최근 6시간, 714,240행 |
| 이전 구간 | 1시간 단위 집계 321,408행(162시간 × 1,984개 active stream) |
| 병행 저장 | 32노드 × 4 target, 60초 주기의 7일 uplink snapshot 322,560개와 결과 행 |
| DB 목표 | 위 부하에서 768 MiB 이하. 1 GiB 중 256 MiB는 이벤트·metadata·증가 여유로 남김 |
| 조회 목표 | 한 reporter의 24h/7d UTC-hour 조회 + JSON 생성 8초 이하, JSON 16 MiB 이하 |

source가 추가되거나 경로 세대·표본 빈도가 증가하면 예산을 다시 검증해야 한다. 256 MiB
여유는 이벤트 최대 100만 행과 모든 다른 quota를 동시에 채워도 된다는 보장이 아니다.
category별 보존 예산과 DB 전체 사용량의 admission 정책은 production 전환의 필수 항목이다.
물리 LTE/Wi-Fi/VPN 전환이나 실제 relay 경유 검증은 이 용량 fixture로 증명하지 않는다.

선택한 방향은 최근 원본과 오래된 분포의 분리다. 7일 원본 전체를 유지하면 단일 source도
약 천만 행이며 현재 4백만 행/1 GiB 한도를 넘는다. 관계 일부를 장기 배제하는 sampling은
관측 공백과 수집 순서 편향을 만든다. p95 값끼리 평균 내는 집계도 전체 p95를 보존하지 못한다.

## 집계 형식과 정확도

`internal/history/rollup.go`는 성공 RTT의 **microsecond 값별 빈도**와 실제 시도/unknown
건수를 저장한다. 정렬된 RTT 차이와 빈도를 unsigned varint로 인코딩한다. 버전 prefix와
CRC32를 포함하고, 비정규 varint·중복 키·음수가 될 수 있는 overflow·잘못된 분모·손상 및
초과 크기를 거절한다. CRC는 사고로 인한 손상 검출이며 인증/서명의 대체물이 아니다.

- 성공/실패/unknown 수, 성공 RTT 합계와 평균, nearest-rank p95가 원본 조회와 같다.
  수신 순서와 집계 분할 순서는 결과를 바꾸지 않는다. percentile의 평균을 사용하지 않는다.
- 0ms 성공은 유효한 측정이다. unknown은 실제 시도 분모에 넣지 않고, 빈/unknown-only
  bucket은 RTT·loss·availability가 null이다. 표본 공백을 정상으로 추정하지 않는다.
- 집계는 sample ID, 개별 timestamp, reason, 시계열 순서를 보존하지 않는다. 부분 시간
  구간의 percentile, 연속 표본 기반 jitter, quality hysteresis는 복원할 수 없다.
- ID 멱등성은 집계 함수의 기능이 아니다. 저장 계층이 deduplicate한 서로 겹치지 않는
  population만 전달해야 한다. source/peer/path/relay/uplink가 다른 자료도 섞으면 안 된다.
- 한 집계의 distinct RTT 최대 65,536개, 표본 최대 4백만 개, 인코딩 최대 1 MiB로 제한한다.
  초과 Add/Merge는 기존 집계를 바꾸지 않는다. 한 시간에 10Hz라면 최대 36,000개 RTT다.
  긴 query bucket이나 과거 고밀도 데이터는 별도 처리/명시적 거절 계약이 필요하다.

## 재현과 증거의 한계

```sh
# 기존 production quota/전송 경로 재검증
go test -race ./internal/observation -count=10
go test -race ./internal/agent ./internal/controller \
  -run 'Test(ProbeHistoryCapacity|HistoryQuota|AutomaticProbeHistoryOverMTLS|SilentFleetDoesNotStarve)' -count=2

# 원본 SQLite query와 집계 결과 비교, 경계/손상/한도 및 작은 topology matrix
go test -race ./internal/history -run 'Test(Aggregate|TieredHistoryCandidate)' -count=1
go test ./internal/history -run '^$' -fuzz '^FuzzProbeAggregateDecode$' -fuzztime=30s -parallel=2

# 32노드 hub/full mesh, 실제 7일 입력과 병행 uplink 저장
VPNCTL_HISTORY_TIERED_SCALE=1 go test ./internal/history \
  -run '^TestTieredHistoryCandidate$' -count=1 -v
```

raw ID는 실제 128-bit 난수의 22자 base64url이며 timestamp 도착 순서를 섞는다. 성공 RTT는
0~60,000ms 범위의 microsecond 분포이고 실패/unknown에는 64-byte reason을 사용한다.
오래된 구간은 후보 집계 형식으로 직접 생성한다. 원본 2천만 행을 저장한 다음 compaction한
시험이 아니다. 재시작 후 디스크에서 읽어 관계/source/경로별 population을 전부 대조한다.
query는 한 reporter씩 수행하고 모든 reporter의 결과를 검증한다. 전체 fleet을 한 응답으로
반환하는 API의 8초 SLO를 주장하지 않는다. JSON 수치도 fixture의 label 길이에 대한 값이다.

최초 실규모 시험에서 한 시간치 raw를 한 transaction으로 넣으면 probe fixture WAL이
76,310,672 bytes로 64 MiB를 넘었다. 쓰기를 작은 배치로 나누고 **각 commit 직후** 측정하도록
수정했다. probe fixture의 WAL 예산은 pinned reader·동시 writer·compaction 또는 uplink seed의
WAL 상한을 증명하지 않는다. 기존 production pinned-WAL 시험과 새 compaction 부하 시험이
모두 필요하다. 새 fixture를 연결하면서 기존 uplink seed의 `streams`를 노드별 `DISTINCT`로
바꿨다. 이전의 노드당 1 stream 가정은 full mesh에서 중복 충돌을 일으켰다.

## Production 전환의 다음 구현 단위

후속 #74에서 다음 항목을 코드와 회귀 증거로 갖춘 뒤 schema 전환을 활성화한다. 이번 실험 통과만으로
#71, #70, #17 또는 M2 gate #19를 닫지 않는다.

1. **seal과 멱등성**: 집계로 옮길 UTC hour 경계와 단조 증가하는 durable cutoff를 정의한다.
   같은 transaction에서 집계를 갱신하고 해당 raw만 삭제한다. 그 경계 이전 새 표본/재전송은
   명시적인 응답으로 거절하거나 별도의 ID ledger를 유지해야 한다. ID가 없는데 중복을 새
   관측으로 더하지 않는다. 응답 유실·시계 역행·controller 중단·재시작을 시험한다.
2. **경계와 API**: 최근 원본 구간은 기존 세밀한 조회를 유지한다. 집계 구간의 요청 경계가
   hour에 걸치면 지원 가능한 경계와 실제 범위를 응답에 명시하거나 요청을 거절한다.
   겹치는 hour 전체를 몰래 포함하거나 일부 count를 비례 추정하지 않는다. 필요하면 history
   응답 버전을 올린다. raw/aggregate resolution, partial window, 누락을 소비자가 구별해야 한다.
3. **조회량**: 노드·source·stream filter와 결과 크기 제한/paging을 설계한다. 현재처럼 모든
   stream의 빈 bucket까지 한 번에 만들면 7,936 × 168 = 1,333,248개 bucket이 된다. 32개의
   node query가 각각 8초 안에 끝난다는 사실은 fleet 한 응답의 안전성을 증명하지 않는다.
4. **상태와 제어 분리**: live quality의 마지막 raw window와 last-success metadata를 보존한다.
   시간 단위 분포를 live hysteresis에 넣지 않는다. compaction은 작은 commit 단위로 취소할
   수 있게 하며 heartbeat·PKI admission·route 제어를 장시간 기다리게 하지 않는다.
5. **quota와 운영 신호**: active 관계, 과거 경로 세대, raw/aggregate bytes와 행 수, ID ledger,
   이벤트/uplink 예산을 함께 제한한다. 물리 DB/WAL 및 유효/빈 페이지, maintenance 지연,
   source별 누락을 노출한다. 다중 relay/망 변경은 보존 중인 stream 수를 늘리므로 고정된
   1,984 stream만 가정해 quota를 올리지 않는다.
6. **이관과 복구**: v1~v5의 실제 schema에서 준비 상태/밀도/공간을 사전 검사하고, 부분 commit
   이후에도 재개 가능한 이관을 구현한다. backup/restore는 집계와 cutoff의 일관성·참조·수치·
   인코딩을 검증해야 한다. production 전환 후의 구버전 롤백은 해당 버전의 백업과 함께 한다.
   현재 이 PR 단계는 schema를 변경하지 않아 기존 v5 동작과 백업을 그대로 사용한다.

배포 저장소에는 위 fixture 명령과 향후 이관 도구를 독립 실행 가능한 형태로 제공한다.
운영 중인 controller DB에서 이 실험용 schema를 실행하거나 `user_version`을 바꾸지 않는다.
