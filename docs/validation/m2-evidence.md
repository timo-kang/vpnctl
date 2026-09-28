# M2 실행 결과 분석과 혼합 저장 압력 (#94)

`vpnctl-lab-report`는 실행기와 분리된 오프라인 CLI다. 하나의 공개 결과 디렉터리만
읽으며 controller, private DB, 인증서에 접근하지 않는다. 배포 리포지토리에서도 빌드한
Linux 바이너리와 해당 실행의 manifest/JSON 파일을 가져와 사용할 수 있다.

## 실행과 종료 코드

```sh
go build -o /tmp/vpnctl-lab-report ./cmd/vpnctl-lab-report

# 새로운 실행의 실제 종료 코드를 실행 직후 별도 보존한다.
# 기존 실행에는 이 명령을 재실행하거나 종료 코드 0을 만들어 넣지 않는다.
export VPNCTL_ARTIFACT_DIR=/path/to/new-results
status=0
./scripts/test-m2-soak.sh || status=$?
printf '%s\n' "$status" > "$VPNCTL_ARTIFACT_DIR/process-exit.txt"

# 정확히 한 실행을 선택한다. 여러 실행의 trace/verdict/manifest를 섞지 않는다.
/tmp/vpnctl-lab-report --dir /path/to/new-results/m2-soak-123 \
  --manifest /path/to/new-results/run-example.txt \
  --exit-file /path/to/new-results/process-exit.txt > analysis.json
```

분석 CLI 종료 0은 **해당 실행의 증거 계약 충족**이며 M2 합격이 아니다.
종료 1은 실패/모순/잘못된 입력, 종료 2는 불완전한 증거다. `m2_gate`는 항상
`pending_review`다. 실행 중에는 `--exit-file`을 생략하여 진행 자료를 읽을 수 있으나,
파일들이 동시에 추가되므로 일관된 최종 snapshot이 아니며 partial tail도 발견될 수 있다.
최종 판정은 생산자가 종료하고 결과 보존이 끝난 뒤 다시 분석한다. 다른 supervisor의
JSON 종료 기록은 독립적으로 그 의미를 확인한 뒤 정수 코드로 변환한다.

다음 내용을 검증하거나 집계한다.

- 시작/종료 시각, 실제 workload 경과시간, 요청 시간, configured node 수,
  최종 모든 노드 관측, 실행기 verdict와 독립 종료 코드의 일치.
- 7가지 장애의 시작/복구 쌍과 지속시간. controller/underlay의 실제 오류,
  application endpoint의 `server_endpoint`, 삭제 직후 registry 감소 기록을 요구한다.
  CA 내부 작업, 삭제 credential replay, 최종 DB 무결성은 trace만으로 재검증할 수 없어
  실행기 검사의 성공과 종료 코드에 의존한다.
- 정상 구간 registry/heartbeat, cached 저장 상태/파일 예산, steady/final WG freshness,
  direct+monitor source 존재, 7개 읽기 API latency와 2초 예산.
- phase·operation별 표본 수와 nearest-rank p50/p95/p99/max, 장애 복구 시간.
  작은 표본의 p99를 운영 SLO나 연속 최대 지연으로 해석하지 않는다.
- 30초 초과 정상 trace 공백, 자원 기록 5초 초과 공백·역행·시작/끝 누락.
  cached DB/WAL과 cgroup memory의 **관측된** 최고값이며 CPU/IO 시계열 원본은 보존한다.
- 노드별 monitor counter의 관측 증가량 하한, 관측된 감소, 이벤트 page truncation.
  처음 본 counter 값과 관측 사이 숨은 reset은 승인량으로 복원하지 않는다.
- 입력 basename, 읽은 bytes, SHA256와 `hash_scope`. JSONL당 1GiB, 줄당 16MiB,
  trace 100,000건, resource 750,000건, 작은 문서 1MiB로 제한한다.
  한도를 넘으면 통과하지 않는다. hash는 읽은 자료의 식별자이지 서명이나 진위 보증이 아니다.

이전 CI의 8분 완료 자료에서 7가지 장애와 480초 경과를 재분석했다. 누락/변조된
verdict, 종료 부재, 시간 역행, 관측 없는 장애, stale/unknown, 자원 공백, 정상 API 오류,
counter reset은 별도 회귀 검사로 검증한다. `population_reconciliation`은 항상
`not_reconcilable_from_soak_trace`다. window 표본 수와 제한된 조회 페이지를 전체
생산량으로 오인하지 않도록 자동 완료 대상에서 제외했다.

## 독립 혼합 WAL 압력 fixture

```sh
VPNCTL_M2_PRESSURE=1 \
VPNCTL_M2_PRESSURE_ARTIFACT_DIR=/path/to/pressure-results \
go test -race ./internal/controller -run '^TestM2MixedWALPressureAccounting$' \
  -count=1 -timeout=5m -v
```

기존 24시간 실행을 건드리지 않는 별도 temp DB와 실제 mTLS 서버에서 legacy와
reclamation/jitter-enabled tiered 모드를 각각 검사한다. ordinary CI에서는 opt-in이며
전용 job이 race로 수행한다. SQLite read transaction을 실제로 유지한 채 별도 BLOB을
넣어 WAL 64MiB watermark를 넘긴다. OS disk-full이나 WG 128MiB quota 시험은 아니다.

1. direct와 monitor에 성공/실패/unknown을 각각 전송하고 WG/uplink/event도 기록한다.
2. 압력 중 각 종류의 신규 ID를 두 차례 재시도하여 HTTP 503 transient rejection을
   확인한다. `history_quota` 영구 거절이나 timeout을 성공적인 backpressure로 인정하지 않는다.
3. pin 해제 **전** 조회로 거부 요청이 저장되지 않았음을 검사한다. 해제 후 같은 ID를
   재시도하고 다시 replay하여, 승인 수와 unique ID 수를 분리하고 중복 저장을 검출한다.
4. baseline/pressure/recovery 동안 heartbeat, candidates, WG config, cached storage,
   history page 및 실제 `SyncCredentials` 갱신·설치·ACK를 수행한다. 각 작업 2초 제한이며
   새로운 인증서가 설치되어야 한다. fixture는 10분 인증서와 9분59초 renewal window를
   사용하고, 1.05초 갱신 시점 대기는 RPC 측정에서 제외한다. 운영 PKI 정책 우회는 없다.
5. 독립 입력 원장과 전체 probe cursor 조회의 success/failure/unknown을 source별 대조한다.
   WG/uplink/event의 ID 집합 및 중복도 비교한다. tiered는 시간을 앞으로 옮겨 실제
   compaction 후 다시 검증하고 마지막에 DB 무결성을 확인한다.

각 mode의 JSON에는 요청별 category/ID/결과 원장, 시도/거부/unique 승인 건수,
기대·실측 보존량, 실제 WAL 크기, control latency 분포와 완료 여부를 남긴다.
fixture 최종 기대값은 source별 probe 9건(성공/실패/unknown 각 3), WG/uplink/event 각 3건이다.
실패 실행은 `completed=false`이며, 파일 생성 전 실패하면 artifact가 없을 수 있으므로
테스트 프로세스 종료 코드도 반드시 확인한다.

## 최종 판정에 연결하는 범위

이 fixture는 **고정된 입력 집합**에 대한 accounting이다. 실제 kernel 생산자 전체의
누적 승인/보존/회수/expiry/drop 원장을 대체하지 않으며 다중 relay 전환도 검증하지 않는다.
압력 동안 지속적인 API 읽기와 PKI 갱신을 함께 검사하지만 독립 단기 실험이다.
장기 kernel 생산자 부하에 압력과 control latency를 결합한 실행, 7일 expiry 경계,
대표 배포 profile, 화면/경보 의미 대조는 [M2 gate](m2-gate.md)의 남은 조건이다.
기존 24시간 baseline은 그대로 완료시켜 별도 근거로 보존한다.

## 장애 복구 판정 보강 (#95)

기존 실행기는 장애 이전 90초 내의 정상 WG 값과 node 0만으로 복구를 인정할 수 있었다.
새 실행기는 장애 해제 이후 수집한 WG와 uplink, 현재 peer identity를 모든 노드에서
검사한다. 전체에 공통 150초 deadline을 적용하며 최종 snapshot도 readiness를 검사한다.
정상 복구 표본은 fault phase에 함께 기록한다. 단기 smoke는 새 표본 대기와 7가지 장애를
모두 포함하도록 12분으로 구성했다. API 2초·복구 150초 예산은 유지한다.
기존 실행 파일로 수행한 baseline을 이 수정 후의 실행으로 소급 분류하지 않는다.
