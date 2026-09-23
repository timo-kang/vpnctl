# #74 시간 집계 저장 경로 자체 리뷰

기준 main: `482651b` (#75). 기본 DB는 schema v5를 유지하며, 명시적 offline 명령으로
활성화한 DB에서만 schema v6를 사용한다. 운영 DB나 인증서를 이 작업 중 변경하지 않았다.

## 구현과 불변식

- schema/live snapshot/seal을 한 번에 커밋하는 일방향 활성화와 사전 백업.
- `(start,end]` 시간 의미, 단조 seal/만료 경계, 512개 raw 단위 집계·삭제·count 갱신 transaction.
- 부분 집계와 raw의 분리, 재시작 후 재개, 집계만 남은 stream의 참조 보존.
- sealed batch는 명시적 409, 최근 ID는 충돌 검증 및 멱등성 유지.
- 시간별 고밀도 backfill admission 제한, DB 사용 페이지와 rollup 행/byte 예산.
- v3 응답의 실제/요청 시간 범위와 16-stream cursor, 16MiB 응답 상한, source/node 필터.
- raw 관측에 기반한 live snapshot과 last-success 보존; 시간 집계로 quality hysteresis를 재생하지 않음.
- backup/restore/open의 codec·참조·count·live digest 검사, CLI/HTML/API/metric 운영 표시.

## 찾아서 수정한 결함

1. **새 관계 등록의 반복 전체 스캔.** 32노드 full mesh의 248-stream batch가 기존 HTTP 3초 제한을
   초과했다. 첫 신규 stream에서 한 번만 quota를 계산하고 transaction 안에서 증가시킨다.
   이미 존재하는 stream만 제출하면 그 전체 스캔도 하지 않는다. 제한을 늘리지 않고 mTLS 행렬을 재검증했다.
2. **집계 transaction 수와 검색 비용.** 한 stream/hour마다 별도 commit하면 실규모에서 수십만
   transaction이 필요했다. 시간/stream 색인을 추가하고 같은 hour의 여러 stream을 512개 raw 배치로 묶었다.
   group별 분포는 별도로 유지하며 삭제 집합과 읽은 집합이 일치하는지 검사한다.
3. **snapshot 복원과 시계 역행.** 부분 compaction 후 남은 raw로 옛 quality window를 다시 계산하면
   다른 값이 될 수 있다. sealed 구간은 durable live snapshot을 사용한다. JSON에 빠지는 내부 quality
   enum도 복원하며, seal에 비해 역행한 시각에서 오래된 good 판정이 되살아나지 않게 한다.
4. **미래 compaction을 막는 늦은 고밀도 입력.** 최신 2분 replay만 검사하면 2~6시간 전 구간에
   과도한 고유 RTT를 쌓을 수 있었다. 승인 시점에 모든 새 표본의 stream/hour별 행 수를 검사한다.
   실패는 batch 전체 rollback이며 `history_quota`의 `hour_samples`로 표시한다.
5. **공간 상한에서 동일 ID 재전송.** 저장 공간을 중복 확인 전에 검사하면 이미 저장된 요청도
   거절했다. 공간 quota는 실제로 추가된 raw가 있을 때 검사하여 멱등 재전송을 유지한다.
6. **공유 DB 정리 순서.** 집계 공간 할당 실패가 만료된 event/uplink의 회수도 가로막지 않도록
   다른 category의 만료 정리를 먼저 수행한다. raw/rollup의 만료 삭제도 bounded batch로 재개한다.
7. **가변 노드 fixture의 잘못된 count.** 기존 uplink seed가 실제 노드 수와 관계없이 metadata에
   32배를 기록했다. 실제 distinct node 수로 count와 로그를 계산한다.
8. **불완전한 v3 응답 수락.** 전체 회귀 시험이 metadata 없는 v3 응답의 수락을 잡아냈다.
   client는 tiering/storage metadata가 없는 v3를 거절하며, 정상 v2/v3와 cursor 전달을 별도로 검증한다.
9. **점검 명령의 부수 효과.** inspect에서 Open을 호출하면 기존 schema 이관/retention이 실행될 수
   있었다. 읽기 전용 연결을 사용하는 별도 inspection으로 변경했다.
10. **최대 label의 응답 크기.** JSON escaping이 문자열을 최대 6배로 키울 수 있다. 200 bucket을
    갖는 최악의 label 조합도 읽을 수 있도록 최종 페이지 상한을 32에서 16 stream으로 낮췄다.

## 확보한 증거

- 전체 `go test -race ./...` 통과(history 151.303초, controller 152.211초), `go vet ./...` 및 build 통과.
  이후 손상 오류 분류·16-stream 페이지 경계·최대 escaped label을 대상으로 추가 race 회귀 통과.

- 원본 query oracle과 혼합 raw/부분 집계/전체 집계의 통계 일치, 정각·0ms·unknown·빈 bucket 검증.
- SQLite write 도중 commit 전 및 commit 직후 실제 하위 프로세스 강제 종료 후 복구/재개.
- snapshot 보존, 시계 역행, sealed batch 원자성, 잘못된 cursor/조건/해상도 거절.
- v1~v5 시작 상태의 업그레이드, 취소/고밀도 preflight 거절, 손상된 payload/metadata/snapshot의
  open/backup/restore 거절, controller 소유권 잠금과 활성화 전 백업 유지.
- pinned reader가 만든 실제 64MiB 초과 WAL에서 backpressure, 해제/취소 후 회복.
- 실제 mTLS로 1/3/8/32노드 hub/full mesh, 2 source×4 uplink 세대의 제출·동일 재전송·집계·조회.
  32노드 full mesh에서 7,936개 stream의 관측 보존과 인증서 폐기 후 조회 거절 확인.
- 로컬 실규모 전환: 19,998,720 raw 관측을 실제 compactor로 처리, raw 714,240 + rollup 321,408.
  uplink 322,560 snapshot 병행 후 DB 649,760,768 bytes, raw/compaction commit의 peak WAL 6,666,192 bytes,
  초기 32-stream 페이지 query+JSON 최대 17.495ms, 전체 전환/검증 587.15초. 최종 16-stream
  페이지와 개별 CI 수치는 PR에 별도 기록한다.
- 실규모 최종 fixture의 기대 통계는 집계 구현을 호출하지 않고 raw 표본의 정렬/합계로 계산한다.
  한 reporter의 전체 페이지와 oracle 검증도 8초 예산에 포함하며, 공유 공간 압력에서 기존 ID 재시도와
  신규 거절·공간 회수 후 복구를 추가했다. 최종 CI에서 이 추가 항목의 결과를 확인한다.

## 판정 범위와 남은 검증

기본 설정을 자동 전환하지 않는다. 실제 full mesh 저장 전환과 인증된 API 경계의 증거를 각각
확보했지만, 실규모 fixture의 raw staging은 SQL이고 실제 monitor 자동 생산자는 아직 #70 범위다.
개별 ID의 영구 ledger, 시간 집계에서 사라지는 reason/순서/jitter 복원은 제공하지 않는다.
시간 경계를 넘는 재전송과 지원되지 않는 조회 범위를 명시적으로 거절하는 계약을 택했다.

4세대를 넘는 지속적인 경로 churn의 admission 공정성, 실제 생산자와 controller 재시작·등록/삭제·
고부하·PKI/route 작업이 겹치는 장시간 검증은 #71/#74 완료 판단에 계속 남긴다.
실물 다중 릴레이/underlay 전환(M3), monitor 자동 수집(#70), M2 gate는 이 변경으로 닫지 않는다.
배포/활성화/복구 절차: `docs/validation/history-tiered-storage.md`.
