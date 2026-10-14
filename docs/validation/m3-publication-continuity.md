# 관측 결과의 연속 신선도 증거 (#217)

관측 나이·proof 간격 표본 검사는 두 읽기 사이에 만료되고 회복된 공백을
놓칠 수 있다. 관측 T, 다음 관측 T+9초, 다음 완료 T+10.3초, 다음 읽기
T+10.5초이면 기존 검사는 통과하지만 최소 300ms 동안 새 완료 결과가 없었다.
publication v2는 이 공백을 별도 검사한다. 과거 PASS/FAIL과 10초 freshness, 3초 wave,
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

`sampled_qualification_status`는 표본 qualification의 pass/fail/incomplete를
따로 남긴다. 표본 구간이 통과해도 publication v2가 fail/inconclusive이면 통합 시험은
실패한다. 기존 실패가 있으면 `continuity_failure` 입력 스냅샷도 그대로 남는다.
최종 `completed`는 전체 통합 판정이다. v2 성공도 실제 배포 용량이나 M3 전체
완료를 뜻하지 않는다.

## 표본 검사 입력과 시각의 일치

`sampled_contract_version=2`는 완결 행 수신기의 같은 잠금 안에서 기록과
평가 시각을 고정한다. 기존 수신기가 있는 용량 시험에 적용한다.
과거 파일 읽기 방식은 T+9.8초에 이전 행만 읽고, T+9.9초에 새 행을
받은 뒤, T+10.1초에 이전 행을 평가하여 정상 갱신을 실패로 표시할 수 있었다.
수신기 입력을 직접 평가하면 이 파일 읽기와 평가 시각의 불일치를 제거한다.
baseline을 얻기 전 두 앱의 Applied 행 수신도 확인한다. 따라서
`first_payload_seconds`는 TCP payload 확인과 이 수신 준비 조건을 함께 만족한
표본의 경과 시간이며, 순수 최초 TCP 응답 시간이나 이전 계약과 동일한 지연
측정값으로 비교하지 않는다.

표본용 입력에는 모든 후보의 경로 식별자·상태·자격·관측 시각과 검사에 필요한
applied/정책/완료 시각만 메모리에 보관한다. 전체 로그를 매 표본마다 재해석하지
않는다. 수신기의 기존 행/byte 상한을 공유하고 오류 후 정상으로 복구하지 않는다.
입력은 보고서에 직렬화하지 않으며 실패 증거는 기존 allowlist를 사용한다.
새 `continuity_failure.schema_version=2`의 `checked_at`은 이 잠금 안에서 고정한
시각이다. 파일 읽기를 하지 않으므로 `read` 필드는 없다. 이전 schema 1의
파일 읽기 시간과 실패는 원래 의미로 보존하며 과거 판정을 재작성하지 않는다.

10초 ±1ns 경계, baseline부터 모든 후보의 과거 간격, 정책·applied 검사,
최초 실패 보존은 유지한다. 부분 행은 완결된 관측으로 사용하지 않는다.
표본 사이 공백은 여전히 publication v2가 별도 검사한다. 이 변경으로 기존
completion gap이나 실제 갱신 지연이 해소됐다고 판단하지 않는다.

## 긴 복구 시험의 단계별 보관

`PreparationRecovery`의 독립 앱도 같은 원자적 수신 표본 검사를 사용한다.
7개 단계에 각 120초를 허용하므로 `continuity_window_contract_version=1`은
전체 실행의 누적 한도 대신 단계별 512행/32MiB 한도를 적용한다. 다음 단계에
들어갈 때 같은 잠금 안에서 이전 활성 창의 모든 행을 검사한 뒤, 마지막 완결
행과 아직 덜 받은 다음 행을 넘긴다. carry 행은 후보 전부와 원래 관측·완료·수신
시각을 유지하며, 행 index만 0으로 바꾼다. 새 byte 예산에는 carry 행의 개행과
부분 행 bytes도 포함한다. 한 단계 안의 과도한 입력은 기존처럼 실패한다.

수신된 Applied 행으로 준비 완료를 확인한다. 처음 활성 창을 시작할 때만
초기 준비 중의 이전 행을 baseline 앞에 둘 수 있다. 이후 모든 창은 baseline 1로
검사하며, 잘못된 입력이나 이미 기록된 최초 실패가 있으면 이력 전환을 거부한다.
각 단계의 복구 통신 확인 직후 마지막 행까지 재검사해 적용 주기 수와 최대 관측
간격을 확정한다. 마지막 단계도 다음 단계 시작에 의존하지 않고 검사한다.

보고서에는 현재 `independent_continuity_window`와 단계별 같은 번호,
`independent_applied_cycles`, 기존 최대 간격을 남긴다. 실패 행 index는 해당
활성 창 기준이며 최초 `continuity_failure`는 이후 전환으로 지워지지 않는다.
표본 검사 범위는 마지막 복구 단계의 종료 검사까지이다. 이후 explicit release의
4초 구간은 기존처럼 경로 재생성 금지와 두 앱 payload를 확인한다.
이 시험에 publication v2의 연속 게시 판정을 새로 추가한 것은 아니다.

기존 용량 시험은 단계별 이력 전환을 사용하지 않고 원래 실행 전체 상한을 유지한다.

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
