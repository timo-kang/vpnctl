# 관측 결과의 연속 신선도 증거 (#217)

기존 관측 나이·proof 간격 검사(v1)는 두 읽기 사이에 만료되고 회복된 공백을
놓칠 수 있다. 관측 T, 다음 관측 T+9초, 다음 완료 T+10.3초, 다음 읽기
T+10.5초이면 기존 검사는 통과하지만 최소 300ms 동안 새 완료 결과가 없었다.
v2는 이 공백을 별도 검사한다. 과거 PASS/FAIL과 10초 freshness, 3초 wave,
승인·철회·nft/BOOTTIME·실제 payload 기준은 바꾸지 않는다.

## 시간의 의미와 판정

| 시각 | 의미 |
| --- | --- |
| `record.candidate.observed_at` | 선택 경로 proof의 wall 시각 |
| `record.finished_at` | 생산자 reconcile 완료; 게시 가능 시점의 하한 |
| `received_at` | stdout 개행까지 받고 원본 로그에 기록·JSON 해석한 시각; 게시 시점의 상한 |
| `started_at` / `ended_at` | 수신기 lock 안에서 고정한 앱별 qualification 시작·종료 |

`received_at - finished_at`에는 출력·스케줄링·파이프·파일 쓰기·해석 지연이
모두 포함된다. 이를 네트워크 RTT나 순수 reader CPU로 해석하지 않는다.
생산자의 실제 stdout 게시 시각은 측정하지 않는다.

이전 선택 proof의 만료를 E=observed_at+10초라고 할 때:

- 다음 완료가 E 이후이면 `fail/completion_gap`: 이전 proof 만료부터 다음
  완료까지의 확정 공백을 기록한다. qualification 시작 이전 부분은 잘라낸다.
- 완료는 E 이내이나 수신이 E 이후이면 `inconclusive/receipt_gap`: 게시가
  제때였는지 확정할 수 없다. 이 불확실성을 정상 연속성으로 승격하지 않는다.
- 다음 완전한 행을 E 이내에 받으면 갱신 구간의 연속성이 입증된다. 정확히
  E에서 교체하는 것은 허용하며 +1ns는 허용하지 않는다.
- 마지막 수신 proof가 종료 전에 만료되면 그 만료부터 종료까지 수신 공백을
  남긴다. 종료 후 복구·cleanup 출력은 이 판정을 고치지 못한다.

새 행의 applied/정책/선택 증거가 잘못되면 `record_invalid`, proof가 완료
시점부터 이미 오래됐고 그 완료가 구간 안이면 `completion_stale`로 실패한다.
시작 전 이미 오래된 baseline은 구간 안 확정 공백의 증거가 아니므로 수신
공백으로 구분한다. 잘못된 baseline은 `baseline_invalid` 불확정이다.
시각 모순·레코드 순서·상한 초과·잘못된 입력·baseline
없음은 불확정이다. 원인별 첫 실패와 첫 불확실성을 각각 보존한다.

## 수집과 범위

두 앱의 stdout만 선택적으로 exec 파이프와 copy goroutine을 거친다. stderr는
원래 로그에만 쓴다. 자식이 stdout을 상속해도 producer 종료 후 pipe drain은
2초로 제한하며, 불완전한 종료는 성공으로 처리하지 않는다.
추가 goroutine과 JSON 해석 비용은 시험 worker의 자원
그룹에 속하며, 같은 VM의 전체 CPU 제한에는 포함된다. 로봇 프로세스 전용
그룹에는 포함되지 않는다. 새로운 시간 측정은 진단 오버레이 없이 수행한다.

완결 행을 한 번씩 해석하며 한 행 256KiB, 총 32MiB, 512행으로 제한한다.
오류·상한 초과 이후에는 입력을 배출하되 증거를 정상으로 되돌리거나 메모리를
늘리지 않는다. 개행 없는 JSON은 부분 행이다. 부분 행 자체는 이전 proof의
유효성을 없애지 않으므로 남은 bytes를 표시하고, 기존 proof가 만료되면
수신 공백으로 판정한다. 입력/원본 로그의 재읽기로 수신 이력을 재구성하지
않으므로 파일 잘림이나 뒤늦은 완결 행이 이미 수신한 증거를 지우지 못한다.

baseline count와 선택 행, 시작 시각은 같은 lock에서 고정한다. 첫 시작부터
종료까지 모든 완결 행을 검사하고 시작 전 과거 공백은 제외한다. 시작 실패는
`not_started`, qualification 중 조기 실패는 그 시점에서 창을 닫는다. 정상
종료에서는 마지막 기존 검사 직후 고정하며, 프로세스 종료와 cleanup 전에
증거를 복사한다. 원본 배열/후보 포인터를 보관하지 않는다.

앱과 측정기는 동일 guest wall clock을 전제로 한다. 수신 time.Time의 monotonic
간격과 wall 간격이 10ms 넘게 어긋나거나, 시작/완료/수신 순서가 모순이면
불확정이다. 이 허용치는 freshness 예산에 더하지 않는다. JSON 시각에는
monotonic 정보가 없으며, 수신 사이 잠깐 바뀌었다 돌아온 생산자 wall clock까지
검출한다고 주장하지 않는다. clock 변경 시험의 검증 계약과는 별개이다.

보고서의 `publication_continuity.app|app2`는 `contract_version=2`, 창의 경계,
baseline count/행, 정제된 모든 수신 행, 부분 bytes, 전체 bytes/write 수,
수집 소요 시간, 첫 실패·불확실성을 담는다. 수집 소요는 수신기 lock 대기와
해석을 포함한 wall 시간이며 pipe·파일 쓰기 등 전체 추가 비용은 아니다.
주소·키·raw ID·proof·임의 diagnostics는 새 증거에 저장하지 않는다.

`sampled_qualification_status`는 기존 qualification의 pass/fail/incomplete를
따로 남긴다. 기존 구간이 통과해도 v2가 fail/inconclusive이면 통합 시험은
실패한다. 기존 실패가 있으면 `continuity_failure` 입력 스냅샷도 그대로 남는다.
최종 `completed`는 전체 통합 판정이다. v2 성공도 실제 배포 용량이나 M3 전체
완료를 뜻하지 않는다.

## 검증

```sh
GOMAXPROCS=2 go test -p=2 -race -tags=integration ./tests/integration \
  -run '^TestApplicationContinuity|^TestLatestApplication' -count=1
```

독립 회귀는 기존 PASS 재현, ±1ns 경계, 시작·종료 경계, 복구 이후 첫 증거
보존, 완료 지연과 수신 지연, 잘못된 시각/정책/순서, 임의 chunk·UTF-8·부분
JSON·상한·동시 snapshot을 검사한다. 핵심 완료 공백 조건을 제거하면 회귀가
실패하는 mutation 검증도 수행한다. 기존 CI의 ApplicationContinuity 범위에
포함된다. 실행 결과는 #217에 source/image/CPU/race 및 고정 4/8경로 조건과
함께 남긴다. 시험 실패를 재실행으로 대체하거나 과거 결과를 재판정하지 않는다.
