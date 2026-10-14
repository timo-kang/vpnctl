# 최신 관측 유지 실패의 검사 입력 보존 (#212)

`applicationContinuity`가 실패하면 보고서의 `continuity_failure`에 **그 검사에
사용한 입력**을 보존한다. 기존 `failure_diagnostics`는 cleanup 진입 후 최대
10초 동안 수집한 후속 cycle·커널 증거이며, 실패 당시 입력과 구분한다.
이 변경은 통합 시험의 진단을 보강한다. 관측 지연이나 배포 용량을 해결한
것으로 판정하지 않으며 #185/#186 및 M3 완료를 의미하지 않는다.

## 보존하는 값

- `schema_version=1`, 고정 `reason`, 검사 시각 `checked_at`, 기준 인덱스
  `baseline`, 검사에 사용한 유효 레코드 수 `record_count`.
- 호출자가 지정한 고정 역할 `role=app|app2`. 다른 문자열은 `other`로 기록한다.
- `read.started_at`, `read.finished_at`, `read.elapsed_ns`: 해당 로그의 읽기와
  JSON 해석 시작·완료 시각 및 monotonic 소요 시간. 검사 시각은 이 입력을
  읽은 뒤 기존과 같이 평가 직전에 취한다. OS 파일 읽기만의 시간은 아니다.
- `record`: 실패한 행의 0부터 시작하는 인덱스, 적용 여부, 실제 정책의
  MaxAge/Successes, 고정 선택 이유·적용 상태, 행의 `finished_at`, 후보 수와
  검사한 후보 인덱스. 행 인덱스는 완결된 schema-v1 JSON 행을 걸러낸 배열의
  인덱스이며 원본 파일의 물리적 줄 번호가 아니다.
- 후보가 있으면 eligible, 고정 상태, `observed_at`, 검사 시각에서 계산한
  `age_ns`를 복사한다. 후보 없음은 인덱스 -1과 후보 필드 없음으로 구분한다.
  zero 관측 시각의 age는 생략하며 실제 age 0과 구분한다.
- 간격 실패는 `previous`의 이전 행·후보와 `gap_ns` 양쪽 피연산자를 남긴다.
  간격 검사는 기존처럼 모든 eligible 후보를 검사하므로 이 후보가 항상
  현재 선택된 경로인 것은 아니다. gap 0도 실패 증거로 보존한다.

원본 slice나 candidate 포인터를 보관하지 않고 필요한 scalar만 복사한다.
첫 실패를 저장한 후 새 로그·복구·후속 실패가 발생해도 덮어쓰지 않는다.
주소·인터페이스·키·raw target/path ID·proof·임의 diagnostics는 추가하지 않는다.
알 수 없는 상태/이유는 `other`로 기록하고 `Error()`도 고정 실패 이유만 출력한다.

## 실패 이유와 유지하는 판정

| reason | 의미 |
| --- | --- |
| `baseline_missing` | 유효한 기준 행이 없음 |
| `selected_missing` | 최신 입력에서 선택 후보를 찾을 수 없음 |
| `selected_ineligible` | 선택 후보가 eligible하지 않음 |
| `selected_unreachable` | 선택 후보 상태가 reachable이 아님 |
| `observation_zero` | 관측 시각 없음 |
| `observation_future` | 관측 시각이 검사 시각보다 미래 |
| `observation_stale` | 선택 관측 나이가 10초 초과 |
| `continuity_not_applied` | 검사 구간에 미적용 행이 있음 |
| `continuity_policy` | 검사 구간의 MaxAge/Successes가 기존 기준과 다름 |
| `freshness_gap` | 연속된 관측 간격이 0 이하 또는 10초 초과 |

baseline → 최신 관측 → 구간의 applied/policy → 관측 간격 순서와 기존
cycles/maxGap 반환값을 유지한다. 10초는 포함하고 10초+1ns는 실패한다.
최신 후보 반복문은 진단 분류 때문에 조기 반환하지 않는다. 3초 wave,
승인·철회, nft/BOOTTIME lease, 실제 payload/독립 앱 검사도 변경하지 않는다.

`record.finished_at`은 생산자 작업 완료 시각이며 stdout 쓰기 완료나 시험기가
받은 시각이 아니다. JSON에서 읽은 관측 시각에는 Go의 monotonic 성분이 없다.
나이는 기존과 동일하게 그 wall timestamp로 평가하며 읽기 소요 시간과
구분한다. 사후 정상 기록만으로 원래 실패를 오탐으로 바꾸지 않는다.

## 검증

```sh
GOMAXPROCS=2 go test -p=2 -race -tags=integration ./tests/integration \
  -run '^TestApplicationContinuity|^TestLatestApplication' -count=1
```

독립 회귀는 기준 코드에서 오류 JSON에 검사 증거가 없음을 재현한다. 회귀는
이유 분류, 정확한 시각·인덱스·피연산자, 시간 경계, 민감 정보 제외, 원본 변이,
부분/잘린 로그, 후속 복구, 중복 후보의 기존 반복문 의미를 확인한다.
기존 CI의 `^TestApplicationContinuity` 실행 범위에 새 회귀가 포함된다.

실제 VM은 기존 `scripts/test-vm.sh --case application-capacity-4
application-capacity-8`로 검증한다. 자원을 줄인 원인 수집 실험에서 원래 용량
검사가 실패하면 실패로 유지하며, 진단의 완전성과 용량 합격 여부를 각각 기록한다.
호스트 network/kernel/clock/power를 변경하지 않는다. 최종 실행·리뷰·CI 결과는
[#212](https://github.com/timo-kang/vpnctl/issues/212)에 연결한다.

별도 [lease 전역 flowtable 검사 계약](m3-lease-flowtable-contract.md)은 소유 테이블
밖의 flowtable도 각 경계에서 검출하는 실제 커널 회귀를 정의한다. 이 시험의
성공은 관측 지연이나 용량 판정을 대신하지 않는다.
