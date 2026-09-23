# 시간 집계 저장소의 운영 계약

#74의 schema v6 저장 경로다. 기존 DB는 자동으로 활성화되지 않는다. 기본은 schema v5의
7일 raw 보존이며, 아래 명령을 실행한 DB에서만 최근 원본 + 시간 집계를 사용한다.
#70의 monitor 생산자 연결과 M2 전체 완료 판정은 별도다. 두 source를 제출하는 통합 시험은
실제 monitor가 자동 생산하고 있다는 증거가 아니다.

## 활성화와 복구

controller를 중지하고, 같은 사용자/볼륨에서 실행한다. 명령은 controller 소유권 잠금을
획득하고 **기존 DB의 검사된 백업을 먼저 만든다**. 이미 존재하는 백업 파일을 덮어쓰지 않는다.

```sh
vpnctl controller history inspect --config controller.yaml
vpnctl controller history enable-tiering --config controller.yaml --out pre-tiering.db
vpnctl controller history inspect --config controller.yaml
```

`inspect`는 파일 생성·schema 변경·보존 정리를 하지 않는 읽기 전용 명령이다. 활성화는
원본 ID를 나중에 지우는 일방향 전환이다. 구버전 바이너리로 돌아가려면 controller를 중지하고
현재 DB와 WAL/SHM을 함께 보관한 뒤, **구버전에서 지원하는 활성화 전 백업**을 복원한다.
v6 파일의 `user_version`을 낮춰서 구버전으로 열면 안 된다. v1~v4 백업은 먼저 현재 바이너리가
v5로 이관할 수 있고, v6 활성화는 그 뒤의 별도 transaction이다.

```sh
# 대상 history.db가 없는 복구 디렉터리를 가리키는 config 사용
vpnctl controller history restore --config recovery-controller.yaml --file pre-tiering.db
```

활성화 transaction은 시간 경계, 집계 테이블/색인, 원본으로 재생한 live snapshot을 함께
커밋한다. 취소·과밀 표본·공간 부족은 v5 원본을 남기고 거절한다. 현재 preflight는 한 stream의
한 시간당 65,536개 초과 표본을 보수적으로 거절한다. 새 색인의 공간까지 포함해 실제 사용
페이지가 768MiB 이상이면 활성화하지 않는다. 기존 1GiB 가까운 DB는 별도 보관/보존 정리로
먼저 공간을 확보해야 한다. 백업 생성 또는 이관이 실패하면 명령은 성공을 출력하지 않는다.

controller를 재시작하면 분 단위 maintenance가 오래된 원본을 점진적으로 전환한다.
시작 과정에서 전체 이력을 한 transaction으로 바꾸지 않는다. `pending_samples`가 남아 있는
동안에도 원본과 집계가 함께 조회되며, 같은 표본을 두 번 더하지 않는다.

## 원본, seal, 집계와 멱등성

- 구간 포함 규칙은 기존과 같은 `(start,end]`다. 정각 표본은 그 시각에 **끝나는** 시간에 속한다.
- `sealed_until`은 `floor_UTC_hour(now - 6h)`로 전진한다. 수집 유효기간 안에서 seal 이하의 batch는 새 자료와 재시도
  모두 HTTP 409 / `code=history_sealed`로 전체 거절한다. 204로 조용히 폐기하지 않는다.
  agent는 409를 재시도하지 않고 기존 delivery/drop 계수에 반영한다.
  7일 밖의 자료나 미래 시각 등 기본 검증 위반은 기존처럼 400으로 거절한다.
- seal보다 새로운 원본은 `(stream,id)` 멱등성과 payload 충돌 409를 유지한다. 원본이 지워진
  뒤에는 개별 ID ledger를 보관하지 않는다. 삭제된 ID의 timestamp를 새 구간으로 바꿔 제출하면
  과거 ID와의 충돌을 탐지할 수 없다. 이는 7일 전체의 영구 ID 멱등성 계약이 아니다.
- 한 transaction은 같은 UTC hour의 최대 512개 원본을 읽고, source/peer/path/relay/uplink가
  다른 stream을 별도로 집계한 뒤, 해당 원본만 삭제하고 row/byte/population metadata를 갱신한다.
  부분 시간 집계와 남은 원본은 서로 겹치지 않는다. 실패 시 둘 다 rollback한다.
- 한 maintenance 호출은 최대 64개 compaction batch를 처리하며 batch 사이에 writer를 양보한다.
  집계에 앞선 만료 삭제는 raw/rollup 각각 최대 10,000행 단위로 커밋해 긴 중단 후에도 회수가 진행된다.
  미완료 작업은 다음 호출에서 이어간다. seal은 전환 진행률과 별개이며 시계 역행으로 후퇴하지 않는다.
- 만료 경계도 UTC hour로 내림하고 후퇴하지 않는다. 마지막 불완전 hour는 최대 1시간 더
  물리적으로 보존될 수 있다. 이미 만료한 구간 요청은 빈 성공으로 위장하지 않고 거절한다.
- 성공 RTT 분포·평균·nearest-rank p95와 성공/실패/unknown 수를 보존한다. unknown은 시도 분모에
  포함하지 않고 빈 구간을 정상으로 추정하지 않는다. 이유별 상세와 jitter/개별 ID는 집계로 복원하지 않는다.
- live quality는 별도로 저장한 snapshot과 최근 개별 표본으로 계산한다. 시간 집계로 hysteresis를
  재생하지 않는다. stream의 마지막 raw가 없어져도 마지막 관측/성공 시각을 보존하고 stale을 표시한다.
  durable seal보다 시계가 뒤로 돌아가면 옛 snapshot이 정상 품질로 되살아나지 않게 `clock_regressed`로 표시한다.

## API v3와 CLI

활성화된 controller의 `/fleet/history`는 schema v3를 반환한다. 비활성 DB는 기존 v2다.
업데이트된 client는 둘 다 읽으며, 구버전 client는 v3를 명시적으로 거절한다.

```sh
vpnctl fleet history --config robot.yaml --node robot-00 --window 7d --json
vpnctl fleet history --config robot.yaml --node robot-00 --window 7d --source agent-direct --json
# 다음 페이지: window/node/bucket/source 조건을 유지하고 응답의 cursor 사용
vpnctl fleet history --config robot.yaml --node robot-00 --window 7d --cursor '<next_cursor>' --json
```

최근 raw만 조회하면 기존 분 단위 해상도를 유지한다. seal을 걸치는 긴 조회는 whole-hour window와
bucket을 요구한다. 기본 bucket은 최소 1시간이 되고 end를 마지막 완결 UTC hour로 내린다.
`start/end`는 실제 범위, `tiering.requested_start/requested_end`는 요청 범위이며 `aligned`로
차이를 알린다. 예: 12:37의 24h 요청은 전날 12:00~오늘 12:00을 조회한다. 최신 37분은 별도의
최근 1h 조회에서 확인한다. 명시적인 15m bucket/7h1m window 등 지원 불가능한 요청은 400이다.

페이지는 최대 16개 stream, 최대 200 buckets/stream이다. 최대 길이 label의 JSON escaping도
응답 예산에 포함한다. `tiering.next_cursor`가 있으면 더 있다.
JSON 최대 16MiB, 한 요청의 조회·상태 수집·인코딩 제한은 8초다. client/CLI가 모든 페이지를
한 번에 메모리에 모으지 않는다. CLI 텍스트는 범위 조정과 후속 cursor를 출력한다. HTML 상태
화면은 저장 모드 및 최근 품질과 시간 이력의 차이를 표시한다.

cursor는 첫 요청의 시간/조건을 고정하며 조건 변경 시 거절한다. **페이지별 DB snapshot**이다.
전체 fleet을 읽는 동안의 수집·만료·stream 변경까지 동결하지 않는다. 두 페이지 사이에 만료
경계가 요청 시작을 지나면 성공으로 누락시키지 않고 오류를 반환한다. 각 페이지는 조회 전과
응답 직전에 인증을 확인하므로 인증서 폐기/노드 제거 뒤 계속 읽을 수 없다.

## 예산과 운영 신호

v6는 node당 256 / 전체 8,192 retained stream을 허용한다. 32×31 관계×2 source×4 uplink 세대의
7,936 stream을 포함하지만 무제한 경로 churn을 보장하지 않는다. 5번째 이상의 세대, source나
cadence 증가에는 용량을 다시 산정해야 한다. 만료된 raw/aggregate/live 참조가 모두 없어져야
stream을 회수하며, 집계만 남았다는 이유로 삭제하지 않는다.

원본 4백만 행, 집계 524,288행/인코딩 합계 256MiB, 물리 DB 1GiB를 상한으로 한다.
v6 수집은 과거 시각의 backfill도 stream당 한 시간 최대 65,536개로 제한한다. 현재 live window
밖의 고밀도 표본이 미리 승인된 뒤 compaction을 막는 상황을 방지한다. 여러 시간을 한 query
bucket으로 합치면서 RTT 종류가 codec 상한을 넘으면 오류를 반환하므로 더 작은 bucket으로 조회한다.
신규 probe는 전체 DB의 사용 페이지가 768MiB에 도달하면 `history_quota`로 거절해 공유 category와
maintenance 공간을 남긴다. 이미 저장된 동일 ID 재시도는 이 논리 공간 한도에서 계속 멱등적이다.
반환된 free page가 확보되면 신규 수집도 회복한다. 다른 category가 남은 256MiB를 모두 동시에
채울 수 있다는 보장은 아니다. SQLite의 최종 1GiB 상한과 각 category 한도는 여전히 적용된다.

각 v3 응답의 `storage`와 중지 상태의 `history inspect`에서 raw/rollup 행 수, rollup payload bytes,
DB 사용/빈 페이지 bytes, WAL bytes, seal/만료 경계, 누적 compacted samples, pending samples,
마지막 compaction 시간을 확인한다. WAL 64MiB 초과와 pinned reader는 일시 backpressure로
처리한다. 단일 bounded transaction이 watermark를 넘을 수 있어, watermark를 절대 파일 상한으로
해석하면 안 된다. maintenance 실패는 로그와 `vpnctl_history_maintenance_total{result="failure"}`,
sealed 거절은 `vpnctl_probe_history_sealed_rejected_total`로 관측한다. 프로세스 metric은 재시작 시 초기화된다.
pending이 계속 늘거나 last_compaction이 멈추면 수집 누락/공간/고밀도 오류를 조사해야 한다.

## 검증 범위

```sh
go test -race ./internal/history -run '^TestTiered' -count=1
go test -race ./internal/controller -run '^TestTieredHistoryOverMTLSVariableTopology$' -count=1
VPNCTL_HISTORY_TRANSITION_SCALE=1 go test ./internal/history \
  -run '^TestTieredStorageTransitionScale$' -count=1 -timeout 30m -v
```

실규모 fixture는 19,998,720개 관측을 모두 production schema의 raw로 먼저 쓰고 실제 compactor로
전환한다. SQL staging으로 HTTP 부하 생성을 생략하며 집계 payload를 직접 만들지 않는다.
각 raw/compaction commit 뒤 WAL을 측정하고 모든 관계/source/uplink/hour의 통계, 페이지 조회,
재시작, 병행 uplink 저장을 검증한다. uplink fixture의 큰 seed transaction은 해당 WAL 측정에
포함하지 않는다. mTLS 행렬은 별도로 1/3/8/32노드 hub/full mesh, 두 source·네 uplink 세대를
제출하고 중복 재전송·집계·페이지·폐기 인증서를 검증한다.

commit 직전/직후 실제 프로세스 종료, 원본+부분 집계 혼합, 정각/unknown/빈 구간, 시계 역행,
live snapshot, v1~v5 업그레이드, preflight 거절, 백업 손상, pinned WAL과 취소도 회귀 시험에 포함한다.
이 결과를 실물 무선망의 다중 relay/underlay 전환(M3) 완료나 monitor 자동 수집(#70) 완료로 해석하지 않는다.
