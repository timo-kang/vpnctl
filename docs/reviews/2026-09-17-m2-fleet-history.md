# 2026-09-17 M2 중앙 fleet history 자체 리뷰

대상은 #15이며, 기반 main은 `f97a5cd6776763a03587e7cb4e33ad865a574861`이다.
`implementation-lead`, `test-strategist`, `quality-gatekeeper` 기준으로 구현·실패 재현·수정을
진행했다. 다른 에이전트에게 검토를 위임하지 않았다.

## 확인한 결함과 조치

| 중요도 | 확인된 결함 | 조치와 근거 |
| --- | --- | --- |
| 높음 | heartbeat가 최근이라는 사실만으로 good, metrics 미연결 숫자 0, history 공백 | 개별 probe 저장/공통 window 평가/nullable v2, API·CLI·HTML의 동일 snapshot 검증 |
| 높음 | 긴 history reader 동안 INSERT commit이 `SQLITE_BUSY`로 실패 | `TestIngestDoesNotWaitForHistoryReadSnapshot` 수정 전 실패 확인. patched SQLite WAL/FULL, 실제 reader snapshot을 유지한 채 writer commit 검증 |
| 높음 | 긴 history가 admission read lock을 잡으면 실제 CA 전환/노드 제거와 다음 reader를 지연 | 조회 전후 재인증, DB query는 admission 밖 실행. 조회 중 제거를 완료하고 응답은 403인 회귀 테스트, 20회 race 반복 |
| 중간 | 대량 만료 DELETE가 시간 초과 시 전부 rollback되어 정리가 반복 실패할 수 있음 | 10,000개씩 commit해 진행분 유지, 실제 387만 행 전체 만료 삭제 시험 |
| 중간 | 재시작/중복·늦은 batch가 sample count/품질을 다르게 만들거나 실패 batch 일부만 게시 | 원자적 dedup/충돌, commit 뒤 cache 게시, 순서 재생, 최근 window 밖 마지막 성공 복구, 재시작·백업/복원 동등성 검사 |
| 중간 | local monitor SQL에 종료 시각이 없어 미래 표본을 포함하고 실패 RTT를 0으로 표기 | `(start,end]` SQL, 성공 개수 제공, local fleet RTT `-`, 미래/전부 실패 회귀 검사 |
| 중간 | 구버전 fleet 서버의 가짜 0을 새 client가 그대로 표시 | 버전 없는/v1/v3 응답 거절, v2만 허용하는 client 검사 |
| 중간 | CLI upload 오류와 buffered CSV flush 오류가 숨겨짐 | nonzero exit/flush 결과 전달, 실제 CLI 정상·실패 probe/서버 503 및 writer 실패 검사 |

WAL은 SQLite의 2026년 WAL-reset 수정이 포함된 modernc v1.46.2/SQLite 3.51.3을 사용하며
해당 module에 맞춰 libc v1.70.0을 고정했다. 동시 reader가 WAL을 pin하면 64 MiB watermark
후 backpressure를 적용하고, reader 해제 후 checkpoint와 재전송 성공을 실제 SQLite로 검사했다.

## 검증

- `go test -race ./...`, `go vet ./...`, `go build ./cmd/vpnctl`: 통과.
- query/ingest 동시성, query 도중 제거: 각각 20회 race 반복 통과.
- identity/peer/relay 위조, mixed format, batch/stream/density/row 한도, 미래·잘못된 수치,
  100회 ID 충돌, 저장 실패, 읽기 freshness, 백업 취소/기존 파일 보호, foreign/future schema 검사.
- 32 streams × 5초 × 7일: 3,870,720 표본, DB 285,753,344 bytes. WAL 구현에서
  24h query 0.476초, 7d query 3.342초(각 8초 한도), restart replay 3.0ms,
  전체 만료 삭제 12.518초(30초 한도). 개발 호스트 한 번의 측정이며 CI도 같은 기준을 실행한다.
- full 규모 검사는 일반 race suite와 분리했다. 작은 fixture의 race 검사와 실제 배포 빌드의
  전체 용량 검사를 각각 실행하므로 race 계측 비용을 운영 query 예산과 혼동하지 않는다.

## 범위와 남은 판단

중앙 이력/현재 관측의 #15 판정만 다룬다. 자동 수집이 추가된 것으로 설명하지 않는다.
현재 producer는 명시적인 `ping --config` 또는 ingestion API다. peer/relay/uplink는 보고된
label이며 실제 kernel selected path의 보증이 아니다. #16에서 target server와 구간별 collector,
#17에서 event timeline/alert/장기 운영, #18에서 responder/backend 지원 범위를 완료해야 한다.
M2 gate #19와 M3/M4 판정은 아직 열려 있다.

legacy summary CSV는 sample count/개별 RTT가 없어 정상 probe로 이관하지 않는다. 기존 파일은
유지하며 별도 회전 정책이 필요하다. v2 nullable 전환, 7일 원본 보관, 고정 용량 한도,
controller 정지 후의 history backup/restore 조건은 관측 계약 문서에 명시했다.

## 커널 통합 및 판정

2 CPU 제한의 Linux kernel sandbox 전체 suite가 통과했다. 1/3/8/32 노드의 계획된 PKI
구간 합계 139,231회 요청에 실패 0회였다. 직접 주입한 packet loss, forwarding/return-route/
firewall/uplink/SNAT 실패는 별도로 감지하고 복구를 확인했다. 새 fleet 검사는 uplink 전용
방화벽의 peer 차단을 실패 3개로 기록한 다음, 두 노드 사이 UDP 51900만 허용하고 성공 3개를
추가했다. 혼합 window loss 50%, 성공 RTT 평균, JSON/CLI/HTML 일치와 두 controller 재시작
뒤 6개 표본 유지가 확인됐다.

로컬 원본: `/tmp/vpnctl-m2-history-wal-netns`의 실행 manifest/노드별 JSONL/telemetry와
`fleet-status-blocked.json`, `fleet-status.json`, `fleet-status.html`, `fleet-history-*.json`.
최종 commit의 CI는 같은 suite와 별도 전체 규모 history 검사를 실행한다. 병합 commit의
main CI 결과와 이슈 완료 판정은 PR/#15의 검증 기록에 연결한다.

자체 리뷰 판정: #15 구현 범위 승인. 확인된 결함은 회귀 테스트와 함께 조치했다.
병합은 PR CI 통과 후, #15 종결은 main CI 확인 후 진행한다. M2 제품 전체 완료 판정은 아니다.
