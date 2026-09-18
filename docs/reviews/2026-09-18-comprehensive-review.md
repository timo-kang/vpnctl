# 누적 변경 자체 검증 — 2026-09-18

기준 main: `fd7c480` (#56). M1의 PKI/registry/재시작/명령 수명주기, M2의
quality/fleet history/uplink/event/alert를 요구사항·코드·기존 회귀 테스트와 대조했다.
아래 재현 결함은 이번 변경에서 수정했다. 전 기능 무결함 또는 M2 완료 판정은 아니다.

## 재현한 결함과 조치

1. **P1: 다른 target 복구가 장애를 지움.** 이벤트 종류별 마지막 한 건만 보므로
   target A가 계속 down인데 B의 up 이벤트가 relay/probe 경보를 해제했다.
   최신 committed snapshot의 각 target을 평가하고 장애 target 목록을 반환한다.
2. **P1: 경보 scrape가 API 호출에 의존.** `/fleet/alerts` 호출이 전역 gauge를
   덮어써 마지막으로 조회한 노드만 남았다. controller 전용 collector가 scrape마다
   등록 노드의 활성/unknown 개수를 계산한다. 조회 순서·삭제 노드 회귀 테스트를 추가했다.
3. **P1: 수집 중단 미감지와 unknown 오판정.** 전환 이벤트가 없으면 silence가
   stale로 바뀌지 않고 unknown relay/underlay는 장애로 표시됐다. 3주기 경과와
   clock reversal을 읽을 때 평가하며, 증거 부족은 `known:false`로 분리한다.
4. **P1: 단발 실패를 지속 손실로 판정.** 같은 target/protocol의 최근 3회 연속
   실패만 활성화한다. 표본 간 최소 간격과 최대 공백으로 재전송·동일 timestamp를
   제외하며 주기 jitter를 허용한다. 재시작 시 동일 3개 표본을 복원한다.
5. **P1: 진단 이벤트가 경보를 조작.** 수동 up 이벤트가 실제 down 관측을 덮어썼다.
   경보 입력을 uplink snapshot으로 제한했다. reporter 자신의 snapshot 신뢰성까지
   보증하는 것은 아니며 controller의 실제 경로 검증과 구분한다.
6. **P1: 이벤트 quota가 관측 수집까지 중단.** 같은 transaction에서 event capacity
   오류가 snapshot을 rollback했다. 자동 진단 이벤트만 생략하고 fixed-label
   `capacity_dropped` counter를 기록한다. 한도 50,400건을 채운 상태에서 실제
   snapshot 저장·장애 경보·DB integrity를 검증했다. 타임라인은 quota 초과 시
   완전한 감사 로그가 아니며 counter의 외부 보존이 필요하다.
7. **P2: 동시 제출 시 이전 상태 오선택.** writer 획득 전에 읽은 cache가 오래되어
   전환 이전 값이 틀렸다. writer 직렬화 뒤 읽고, 40개 동시/역순 제출의 전환 연결과
   재시작 판정을 비교한다. 늦은 과거 snapshot은 현재 상태를 되돌리지 않는다.
8. **P2: 릴레이 교체·overlay route 유실.** relay fingerprint가 달라도 `up→up`만
   기록했고 route는 transport interface/gateway만 비교했다. expected relay ID,
   실제 fingerprint, overlay/transport source/destination/상태를 보존한다.
   target 삭제와 controller probe 복구도 기록한다.
9. **P2: rollback 이벤트도 accepted 집계.** counter 갱신을 commit 뒤로 옮겼다.
   취소된 transaction이 counter를 바꾸지 않는 테스트를 추가했다.
10. **P2: 장기 retention과 백업 검사 공백.** monitor 기본 7일 설정에서 정리가
    7시간 간격이었으며 무제한 DELETE와 동시 SQLite writer가 충돌할 수 있었다.
    1분 주기, 1,000행 batch, 10초 예산, 단일 connection으로 바꿨다. 10,001개
    만료 행 정리 중 400개 probe 저장·취소를 검증한다. event cleanup도 batch별
    WAL 한도를 검사한다. backup은 모든 event 필드의 실제 ingestion 규칙을 검사한다.
    v1 migration fixture가 v3 event table을 남기는 문제도 수정했다.

## 미완료 범위와 판정

- **#17 재개 필요:** 공통 Envelope 타입은 producer에 연결되지 않았다. p50/p99는
  legacy CSV에만 있고 공통 jitter/handshake/transfer history는 없다. NAT·PKI·discovery
  event는 자동 생산하지 않는다. downsampling, DB metric, event 포함 24시간 가속
  soak도 아직 없다. 계약 문서를 실제 구현 수준으로 수정했다.
- **#18:** backend 지원, responder 안내, 시작 시 진단을 다음 작업으로 진행한다.
- **M3:** 현재 kernel sandbox의 1/3/8/32는 단일 controller/relay에 연결된 fleet 규모다.
  여러 relay 사이의 자동 선택·전환·rollback을 검증했다는 의미가 아니다.
- **CI 원인 미확정:** run `35299442539` artifact `10529501421`의 nodes8 rotation에서
  7개 HTTPS 요청이 1초 deadline을 넘겼다. handshake는 약 435–523ms였고 모든 요청은
  전송 후 응답 header를 받지 못했다. TCP/UDP 무중단과 이후 성공은 이 지연의 원인을
  설명하지 않는다. runner 변동으로 단정했던 앞선 설명을 철회한다. 느린 PKI 영속화와
  CPU/I/O 제한 환경에서 TLS/admission/authorization 지연을 분리 측정해야 한다.

## 검증 근거

- 수정 전 `TestReview*`로 경보 6개 경계, rollback counter, relay/route 유실 재현.
- `go test -race ./...`, `go vet ./...`, CLI build 통과. 추가 jitter/clock reversal
  수정 후 history/controller/monitor race 재검증 통과.
- `VPNCTL_HISTORY_SCALE=1 ... TestHistoryScale`: 32노드, uplink 322,560 snapshots,
  peer 3,870,720 rows, DB 641,658,880 bytes; uplink query 약 53ms, 24h peer query 약
  460ms, 만료 삭제 약 21초. 수치는 해당 실행의 측정값이다. 이벤트 soak 증거가 아니다.
- 실제 kernel WireGuard/PKI/relay fault 전체 suite의 결과는 PR validation에 기록한다.
