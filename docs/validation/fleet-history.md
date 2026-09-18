# 중앙 fleet 관측 계약 v2

`/fleet/status`, `/fleet/history`는 `schema_version: 2`를 반환한다. controller의
`data_dir/history.db`에 실제 개별 probe를 저장한다. `ping --config node.yaml`은
기본 `--submit=true`이고, `node serve`의 자동 direct 후보 탐색도 기존 probe 결과를
중앙에 전송한다. direct 후보의 public UDP 응답은 설치된 VPN 경로의 품질 증거가 아니다.
독립 `monitor`의 로컬 DB는 아직 자동 업로드하지 않는다(#70 후속).

```sh
vpnctl ping --config node.yaml --peer robot-b --path relay --count 12 --interval 5s
vpnctl fleet status --config node.yaml
vpnctl fleet status --config node.yaml --json
vpnctl fleet history --config node.yaml --window 24h --node robot-a --bucket 15m
vpnctl fleet history --config node.yaml --window 7d --json
```

fleet 조회에는 **등록된 노드의 mTLS 설정**이 필요하다. controller 전용 YAML은 client
인증 정보를 제공하지 않는다. 로봇의 동작 명령과 무관하며, 여기서 관측하는 것은 보고한
peer까지의 통신이다. 로봇 → 릴레이 → 서버 uplink의 각 구간 진단은 #16, 여러 relay와
underlay 사이의 실제 경로 선택·전환 검증은 M3의 범위다.

## Ingestion

등록된 노드의 인증서로 `POST /metrics`에 제출한다. controller의 기존 1 MiB 요청 제한에
더해 요청당 최대 256개이며 한 요청은 전부 commit되거나 전부 거절된다.

```json
{
  "node_id": "robot-a",
  "observations": [{
    "id": "producer-generated-unique-id",
    "source": "cli-ping",
    "validity": "observed",
    "timestamp": "2026-09-17T05:00:00.123456Z",
    "peer_id": "robot-b",
    "path": "relay",
    "relay_id": "controller",
    "uplink": "wlan0",
    "success": true,
    "rtt_ms": 12.5
  }]
}
```

- `node_id`는 인증서의 등록 identity와 같아야 한다. peer는 다른 등록 노드여야 한다.
  relay는 다른 등록 노드, `controller`, 또는 미확인인 빈 문자열이다.
- `(node_id, peer_id, path, relay_id, uplink, source)`를 하나의 stream으로 구분한다. 서로 다른
  peer/경로/망 표본을 한 품질 값으로 섞지 않는다. path는 `direct|relay|unknown`이다.
- ID는 stream 안에서 고유하다. 같은 ID와 같은 정규화 내용의 재전송은 204로 응답하되
  한 번만 집계한다. 같은 ID의 내용이 바뀌면 409이며 같은 batch의 다른 신규 표본도
  저장하지 않는다. 보존 기간 밖 timestamp는 거절하므로 삭제된 ID의 오래된 replay도
  재집계되지 않는다. 다른 ID로 만든 허위 측정은 인증만으로 판별할 수 없다.
- timestamp는 UTC microsecond로 정규화한다. `(수신 현재 시각 - 7일, 현재 시각]`만
  허용한다. 순서가 뒤바뀐 정상 표본은 수용하며 최신 시각 기준으로 품질을 재계산한다.
  생산자와 controller 시계가 동기화되어야 한다. 미래 표본은 400으로 거절한다.
- `source`는 `legacy-probe|cli-ping|agent-direct|monitor-overlay`다. 생략한 구형 요청은
  `legacy-probe`로 저장한다. `monitor-overlay`는 후속 생산자를 위한 허용값이며 현재 자동
  생산자가 아니다. source 역시 인증된 노드의 보고값으로 별도 원격 검증을 뜻하지 않는다.
- 완료된 probe는 `success: true|false`, `validity: observed`다(구형 요청은 validity 생략 가능).
  성공은 유한한 RTT `[0,60000]` ms가 필수이고 실패는 RTT가 `null`이어야 한다.
  미실행/수집 불가는 `success: null`, `rtt_ms: null`, `validity: unknown`과 비어 있지 않은
  `reason`(제어문자 없는 64 bytes 이하)을 보낸다. unknown은 실패/성공 분모에서 제외한다.
  0 ms 성공과 미측정을 구별하며 저장 RTT는 microsecond 반올림이다.
- ID와 label은 128 bytes 이하이며 제어문자를 허용하지 않는다. 한 노드 최대 16개,
  전체 최대 256개의 보존 stream을 허용한다. 최근 2분 replay는 stream당 1,200개까지다.
- 잘못된 요청은 400, 다른 identity는 403, ID 충돌은 409, 용량/저장/시간 제한은 503이다.
  오류를 204로 숨기지 않으며 저장 성공 후에만 현재 상태를 게시한다. 수정 없이 재시도할
  때 ID를 유지한다. CLI는 제출 오류를 stderr와 nonzero exit로 알린다.

`ping`은 최대 16개, 완료된 probe 기준 약 5초 또는 마지막 표본에서 batch를 제출한다.
`--path relay`는 VPN IP를 probe 대상으로 선택했다는 뜻이다. 실제 kernel route가 특정
릴레이를 통과했음을 증명하지 않는다. ping은 확인할 수 없는 relay/uplink를 빈 문자열로
보낸다. API로 제출한 relay/uplink 역시 **노드의 보고값**이다. 실제 selected relay/uplink의
검증된 자동 수집으로 해석하지 않는다.

## 현재 상태와 시간 이력

품질의 계산 코드는 독립 `internal/quality`에 두고 monitor와 중앙 history가 함께 사용한다.
기본값은 60초 window, 최소 3개, stale 17초, 개선 3개 연속 확인이다. RTT 평균에는 성공
표본만, loss에는 성공과 실패 모두를 사용한다. window는 마지막 관측 시각에 끝나며
읽기만으로 hysteresis가 진행하지 않는다. 재시작과 늦게 도착한 표본은 최근 2분을 순서대로
replay한다. `last_success_at`은 보존 중인 전체 성공 표본의 마지막 시각이다.

`status`는 heartbeat/enrollment 상태(`pending|enrolled|online|offline`)다. `quality`는
측정한 경로의 품질(`unknown|good|degraded|poor|offline`)이므로 별개다. heartbeat가
최근이어도 표본이 없으면 `unknown`, RTT/loss는 `null`이다. 측정이 오래되면 마지막
숫자를 보존하되 `stale: true`, `quality: unknown`, 이유를 표시한다. 최신 측정 실패가
충분히 쌓여 성공이 없는 window는 RTT `null`, loss 100, quality `offline`이다.

노드 행의 수치는 가장 최근 stream의 측정이다. `measurements` 배열은 모든 보존 stream을
최근 순으로 제공한다. 동시 시각은 stream label 순으로 안정적으로 정렬한다. 상태 페이지와
CLI는 API와 같은 snapshot/숫자 포맷을 사용한다. CLI JSON은 nullable 원형을 보존하며
텍스트/HTML은 미측정을 `-`로 표시한다.

history는 controller가 잡은 `(start,end]` snapshot을 조회한다. 기본 window는 1h이며
최대 168h(`7d` 별칭)를 허용한다. 기본 bucket은 1h 이하 1m, 24h 이하 15m, 그 밖에는
1h다. `bucket`은 1분의 정수배이고 window 이하이며 stream당 최대 200개여야 한다.
`node_id`로 보고 노드를 제한할 수 있고 미등록 노드는 404다.

- 각 bucket의 `time`은 열린 하한이며 상한은 `min(time + bucket_seconds, end)`이다.
- `sample_count`(실제 시도), `success_count`, `unknown_count`(미실행/수집 불가), 성공 RTT 평균, 성공 RTT의 **정확한 nearest-rank p95**,
  `loss_pct`, `availability_pct`를 반환한다. p95는 batch 평균의 percentile이 아니다.
- availability는 `성공 probe / 실제 시도 probe × 100`이다. unknown과 표본 공백은 분모에서 제외한다. 시간 가동률이나 수집 공백의
  도달 가능성을 추정하지 않는다. 모든 빈 bucket의 측정값은 null이다.
- 보존된 stream에는 빈 시간 bucket도 반환한다. 표본이 전혀 없는 노드는 `buckets: []`다.
- query는 read transaction 하나로 일관된 snapshot을 읽는다. 긴 SQLite 읽기는 인증 상태
  잠금을 잡지 않는다. 조회 전과 결과 게시 직전에 각각 재인증하므로, 그 사이 인증서 폐기
  또는 노드 제거가 끝나면 결과를 공개하지 않는다. 이미 송신 중인 응답은 기존 admission
  규칙대로 보안 상태 전환 전에 drain한다.

## 용량, retention, 배포와 복구

영속 schema v5 (v1~v4에서 자동 전환), application ID `0x76706368`, SQLite 4096-byte page, FULL 동기화의 WAL을
사용한다. modernc SQLite v1.46.2 (SQLite 3.51.3)와 해당 릴리스의 libc v1.70.0을 사용한다.
긴 read snapshot 동안에도 새 표본을 commit할 수 있다. 빈 v0 DB는 v1 초기화 후 v2로, 기존 v1 DB는 v2로 원자적 단계 이관한다. 알 수 없는 미래 버전이나 다른 제품의
DB를 덮어쓰지 않는다. DB는 0600이며 파일이 아닌 경로와 symlink는 거절한다.

| 한도 | 정책 |
| --- | --- |
| 보존 | 원본 probe 7일; downsampling 없음. p95 원본 정확도를 유지 |
| 원본 수 | 최대 4,000,000개. 초과 batch는 거절, 임의 최신 표본 삭제 없음 |
| DB 본체 | 최대 1 GiB. SQLite page cap, 복원 시 파일/page 크기도 확인 |
| WAL | 64 MiB watermark를 넘으면 checkpoint 후 쓰기. reader가 막으면 503으로 backpressure; 한 bounded transaction은 watermark를 넘어설 수 있음 |
| 조회 | 동시 1개, 대기 포함 8초 context budget. 초과 시 503, 부분 성공 없음 |
| 쓰기 | HTTP 수신 후 3초 context budget, SQLite 잠금 대기 최대 약 1초 |
| retention | 시작·수집 시 및 실행 중 1분 주기. 10,000개 단위 commit으로 취소 뒤에도 삭제 진행분 유지 |
| 시작 복구 | 30초 budget. 장기 중단 뒤 만료 자료 정리는 평소 재시작보다 오래 걸릴 수 있음 |

retention은 DB의 페이지를 재사용하게 만들며 파일 크기를 즉시 줄이는 보안 삭제가 아니다.
취소된 정리의 나머지는 다음 유지보수에서 계속한다. 읽기는 물리 정리와 무관하게 요청
기간의 상·하한을 적용한다. DB 본체 외 WAL/SHM, 복원 staging, 백업 공간이 필요하다. 실행 중인 DB 파일만 복사하면
아직 checkpoint되지 않은 WAL의 데이터를 잃을 수 있으므로 반드시 아래 백업 명령을 쓴다.
배포 저장소는 로컬 writable volume에 최소 3 GiB 여유와 별도 백업 보관 정책을 마련한다.
성능/용량 한도는 controller 전체의 무제한 fleet 지원을 의미하지 않는다.

개별 history 작업은 PKI 보안 백업과 분리한다. 인증서/registry 백업에 대형 DB를 넣어
보안 상태 전환을 지연시키지 않는다. **controller를 정상 종료한 뒤** 같은 사용자로 실행한다.
CLI는 `data_dir`의 controller ownership lock으로 실행 중 작업을 거절한다.

```sh
vpnctl controller history backup --config controller.yaml --out /backups/history-20260917.db
# PKI/registry 복원을 마친, 아직 history.db가 없는 data_dir의 설정을 사용한다.
vpnctl controller history restore --config restored-controller.yaml --file /backups/history-20260917.db
```

backup은 SQLite `VACUUM INTO`의 일관된 복사본을 0600 임시 파일에 만든 뒤 fsync하고
새 이름으로 게시한다. 기존 destination은 덮어쓰지 않는다. restore는 schema, quick_check,
참조/수치/건수/용량을 검증하고 staging 복사본에서 retention과 replay를 확인한 뒤 게시한다.
실패하면 기존 DB를 변경하지 않는다. 동일 registry identity와 함께 복원해야 하며 삭제된
노드의 보존 이력은 현재 fleet API에서 노출하지 않는다. 복원 전에 기존 DB가 있다면
운영자가 별도 백업/이관 절차로 보존하고 목적지를 비워야 한다.

[SQLite VACUUM 문서](https://www.sqlite.org/lang_vacuum.html)의 snapshot 기능과
[page count 제한](https://www.sqlite.org/pragma.html#pragma_max_page_count)을 사용한다.
SQLite의 [WAL-reset 수정](https://www.sqlite.org/wal.html#walreset)을 포함한 버전으로 고정해
동시 읽기/쓰기를 활성화했다. backup/restore와 local monitor도 같은 드라이버로 검증한다.

기존 `/metrics.samples` 요약/CSV 형식은 계속 수신하지만 Warning header를 반환한다.
성공 횟수와 개별 RTT가 없고 perf의 RTT 0은 미측정이므로, 이를 임의로 probe로 변환하거나
정상 품질로 이관하지 않는다. 기존 CSV는 보존되며 중앙 DB의 7일 정책 대상이 아니다.
기존 생산자를 전환하고 CSV 회전/보관을 배포에서 관리한다. 기존 fleet consumer는 v2의
nullable 숫자와 `availability_pct`로 전환해야 한다. 새 client는 버전이 없거나 v2가 아닌
fleet 응답을 명시적으로 거절하여 구버전 서버의 가짜 0을 표시하지 않는다. `online_pct`는 제공하지 않는다.

로컬 `fleet --interface`는 계속 local monitor DB의 기간 요약을 사용하며 중앙 node identity/
relay 의미를 갖지 않는다. 미래 timestamp를 제외하고 성공이 없으면 RTT `-`를 표시한다.

## 검증 재현

```sh
go test -race ./...
VPNCTL_HISTORY_SCALE=1 go test ./internal/history -run '^TestHistoryScale$' -count=1 -v
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 ./scripts/test-netns.sh
```

387만 표본 성능 시험은 32개 stream, 5초 주기, 7일로 생성한다. 저장 한도 1 GiB,
24시간/7일 query 각각 8초, target snapshot 322,560개를 포함한 전체 만료 cleanup 60초를 검사한다. routine race 시험은 같은
쿼리에 더 작은 표본을 사용하고 CI는 별도로 전체 규모 시험을 실행한다. kernel suite는
3/8/32 노드에서 차단 probe 3개 + 허용 probe 3개 → mTLS ingest → API/CLI/HTML 값 일치 → graceful/crash restart
후 동일 이력을 확인한다. 1 노드 구성은 측정 peer가 없으므로 기존 uplink 검증을 유지한다.

## Staged uplink extension

The uplink tables introduced in database schema 2 store separate robot → target
snapshots and target/protocol summaries. The fleet peer API remains schema 2.
See [uplink observation](uplink-observation.md) for the new opt-in automatic
producer, endpoint schema 1 API, shared capacity budgets and migration/rollback
procedure. Startup maintenance for the combined datasets has a 60-second budget.

## 자동 direct 생산자와 운영 한계

`node serve` 및 agent 실행은 추가 probe 없이 같은 direct 결과를 `source: agent-direct`,
`path: direct`로 전송한다. `probe_timeout`, `responder_unavailable`, `route_unreachable`은
실제 시도 실패다. 잘못된 대상/포트는 `invalid_probe_target`, DNS·로컬 socket/자원 오류나
송신 이전 timeout은 `collector_unavailable`, round 예산 때문에 미실행한 대상은
`round_budget_exhausted` unknown이다. 종료 또는 새 후보 목록으로 취소된 진행 중 작업은
네트워크 실패로 기록하지 않는다. readiness 제어용 `/direct-result`와 raw 이력 전송은 별도다.

public UDP 성공만으로 WireGuard, relay 또는 서버 uplink가 정상이라고 판정하지 않는다.
이 source의 fleet `quality`는 항상 `unknown`이고, 완료된 표본은 `candidate_probe_only`를
표시한다. 관측 RTT/loss와 시각·source는 그대로 확인할 수 있다. 수집 불가 표본은 live
품질 판단을 초기화하며 RTT/loss는 null이 된다. 시간 bucket은 보존된 성공·실패의 분모를
계속 제공한다. status의 17초 신선도와 60초 품질 window는 기존 계약을 유지한다.

프로세스별 큐는 최대 256개 대기 + 1개 전송 중이며 표본마다 128-bit 난수 ID를 부여한다.
프로세스 재시작도 ID를 재사용하지 않고, 재전송은 ID/UTC microsecond timestamp/본문을
변경하지 않는다. 한 표본 최대 5회, 요청당 3초, backoff 1/2/4/8초다. 400/404/409/413은
즉시 폐기하며 401/403/503 및 네트워크 실패는 유한 재시도한다. 인증 정보는 기존 credential
client로 매 요청 갱신한다. 이 큐는 heartbeat·PKI 갱신·route apply를 기다리게 하지 않는다.

메모리 큐이므로 종료·overflow·거절·retry 소진에 따른 손실은 가능하다. 이력은 전달된
표본의 집계이며 수집 공백을 시간 가동률 100%로 바꾸지 않는다. 손실은 node 로그의
`probe history incomplete` 누계와 `vpnctl_probe_history_delivery_total{result}`에 기록한다.
result는 queued/delivered/retry 및 overflow_dropped/stopped_dropped/shutdown_dropped/
rejected_dropped/exhausted_dropped로 고정한다. node serve 자체는 Prometheus HTTP
listener를 제공하지 않으므로 현 배포의 기본 운영 신호는 node 로그다.

7일·4백만 raw rows·노드당 16/전체 256 stream·1 GiB 한도는 유지한다. source별로 별도
stream을 사용하므로 legacy와 새 source가 공존하면 둘 다 quota를 소비한다. 32노드 시험은
노드당 1 stream × 5초 표본의 예산이며 32×31 full mesh 관측 보장과 다르다. 31-peer 자동
탐색은 기본 60초 간격이어도 7일에 천만 건 수준이므로 현재 모든 raw 표본을 보존할 수
없다. 초과는 503/큐 손실로 명시되며 무제한 메모리·디스크 증가로 우회하지 않는다.
생산자 cadence/선택 정책, downsampling, 용량 health 및 모든 peer의 공정한 관측은
#71에서 집중 처리하며 #17/#70 후속 검증과 연결한다.

기존 node의 선택적 `metrics_path` CSV는 성공 표본만 보존하는 호환 출력이다. 자동 agent는
중앙 legacy `/metrics.samples`로 같은 성공 표본을 이중 저장하지 않으며 중앙 조회는
`fleet history`를 사용한다. perf 등 다른 legacy 생산자와 기존 CSV 파일은 유지된다.

배포 전 controller를 정지하고 위 명령으로 v1~v4 백업을 보관한다. 최초 새 바이너리 실행은
stream ID와 모든 probe를 보존하며 작은 streams 표만 재구성하고 raw probe에 validity/reason
열을 추가한다. unknown도 retention/row quota에 포함된다. 구버전 바이너리는 v5 DB를
거부하므로 롤백은 정지 상태에서 구버전 바이너리와 해당 버전의 DB 백업을 함께 복원한다.
`user_version`을 강제로 낮추지 않는다.
