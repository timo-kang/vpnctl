# #77 경로 교체 이력 회수 자체 리뷰

기준 main: `b167aa9` (#76). 사용자가 현재 경로의 관측을 우선하고 과거 비활성 이력의 삭제
범위·건수를 표시하는 정책을 선택했다. 기존 v5/v6는 자동 전환하지 않으며 schema 7을 명시적으로
활성화한다. 운영 DB/인증서/로봇의 경로 설정은 이 작업에서 변경하지 않았다.

## 수정한 결함

1. **과거 경로의 신규 관측 배제.** 256개 stream을 실제 compaction한 후 raw가 없어도 새 경로가
   quota로 거절됐다. node/global 한도에 도달했을 때 오래된 비활성 경로를 회수한다. 해당 노드의
   quota를 다른 노드의 이력 삭제로 해소하지 않는다. 전체 한도에서는 자기 과거 경로를 우선한다.
2. **같은 배치의 재활성 경로 회수.** 최초 후보 목록을 재사용하면 뒤에서 갱신한 경로가 후보로
   남았다. `[새 경로, 기존 경로 갱신, 새 경로]`는 FK 오류로 거절됐고 갱신을 마지막으로 옮기면
   필요한 두 경로 대신 세 경로의 이력이 지워졌다. 전체 incoming batch의 모든 stream을 먼저
   보호한다. 세 가지 순서와 동일 배치 재시도로 raw 3개/회수 2개 및 기존 경로 집계 보존을 확인했다.
3. **부분 이력의 정상 응답 위장.** 새 API v4는 node/source/window 전체의 회수 population과 시간
   경계 metadata를 필수로 보낸다. client가 모순/누락을 거절하고 CLI가 PARTIAL HISTORY를 출력한다.
   구형 저장소 Query는 손실을 표현할 수 없는 경우 오류를 반환한다. 부분 이력을 100% 성공으로
   보충하거나 다른 경로의 품질과 합치지 않는다.
4. **stream ID 재사용과 페이지 중간 삭제.** v7 ID는 단조 증가하고 회수 epoch가 바뀌면 기존 cursor를
   거절한다. 다른 노드의 회수도 무효화하는 보수적 정책이며 지속 회수 중 조회 완료를 보장하지 않는다.
5. **회수와 새 승인 사이 실패.** 집계 삭제/손실 ledger/count/신규 raw/live를 같은 transaction으로
   묶었다. 중간 쓰기 실패, context 취소, 내용 충돌, commit 전후 실제 process 종료, mTLS 응답
   유실 후 새 client의 동일 ID 재시도에서 rollback 또는 정확히 한 번의 저장을 확인했다.
6. **live snapshot의 공유 공간 계산 누락.** v6의 raw 공간 검사 이후 저장되는 live 페이지가 최종
   예산 검사에 빠져 있었다. live 저장 후에도 사용 페이지를 검사한다. 실제 768MiB DB 압력과
   live INSERT trigger의 추가 할당으로 새 요청 rollback, 같은 ID 재시도, 공간 회수 후 복구를 확인했다.
7. **손실 ledger 손상 검출.** 남은 손실 행 수만 검사하면 양수인 population 변경을 놓칠 수 있다.
   만료 population도 누적해 `retained_loss + expired_loss = cumulative_loss`를 검사한다.
   손상된 count/ID/source/hour/population은 Check/Open/Restore에서 거절한다.
8. **회수 후보와 quota의 불필요한 fleet 스캔.** 자체 node quota는 해당 노드만 탐색하고 node count는
   prefix index를 사용한다. 최초 전체 24세대 race 시험은 8분을 초과했으나 이 변경 후 같은 행렬은
   393.79초에 통과했다. 이후 일반 suite는 32노드 5세대로 상한 초과를 검증하고, CI 별도 단계가
   24세대 전체를 검증한다. 제품의 3초 ingest/8초 query 예산은 늘리지 않았다.
9. **byte 작업 상한의 잘못된 진단.** 4MiB 초과도 1,024행 제한으로 표시했다.
   `reclamation_work_bytes`와 실제 byte limit를 반환하도록 고쳤다. 고밀도 분포를 가진
   유효 집계 fixture로 행 상한 이하에서 byte 한도를 넘기고, 전체 rollback 및 배치를
   나눈 후 정확한 population 회수를 검증했다.
10. **CI 누적 race 실행 시간 초과.** run `36365489111`의 history 패키지가 600초에 종료됐다.
    controller는 308.970초에 통과했고, history는 기존 손상 복구 시험을 실행 중이었다.
    로컬 전체 suite 통과와 개별 fault/규모 검증을 확인한 뒤 CI에서 새 `TestPathChurn*`를
    별도 runner로 분리했다. 기존 job의 skip과 새 job의 run은 서로 보완하며 모든 시험을
    유지한다. 디스크 crash/WAL 검증과 개별 API·조회 예산, 패키지 10분 제한도 유지한다.

## 검증 근거

- 최종 전체 회귀·정적 분석·빌드와 CI 결과는 이 변경의 PR에 기록한다. 본 문서의 개별 수치는
  아래 시험의 로컬 실행 결과이며 hosted runner 성능이나 실환경 장시간 보장을 뜻하지 않는다.
- 실제 Ingest/Maintain/QueryPage, 두 source, uplink 24세대, relay label 3개, 1/3/8/32노드:
  32노드에서 승인 47,616 / 보존 8,192 / 보고된 회수 39,424개가 정확히 일치했다.
  DB 6,139,904 bytes, 최대 ingest 24.03ms, reporter 전체 페이지+JSON+독립 oracle 최대 51.05ms.
  결과의 모든 bucket을 원본 Observation에서 계산한 성공/실패/unknown/RTT 통계와 비교했다.
- 배치 실패/취소/프로세스 종료 전후 reopen, backup/restore, 기존 v6의 quota 유지,
  최근 raw/자체 node quota 보호, 8,192-stream 전체 quota에서 신규 노드 승인,
  악의적 256회 경로 변경 후 정상 기존 경로 업로드, 1,024행 회수 작업 상한의 전체 rollback.
- 65,536행 손실 ledger 경계에서 신규 회수 전체 rollback, bounded expiry 후 누적 수 보존,
  동일 시점의 필터·cursor·coverage 일관성. ledger 경계 fixture는 SQL staging이며 생산량 증거가 아니다.
- 실제 mTLS commit 후 소켓 종료 → client 재생성 → 같은 ID 재시도, source별 coverage와
  stale cursor 거절. 64회 연속 회수 업로드와 heartbeat/candidates/WG config/status/인증서
  동기화를 병행하여 개별 제어 요청 1초 예산을 검사하고, 인증서 폐기 후 403을 확인했다.
- 768MiB 사용 공간에 실제 파일을 채워 shared-space 거절과 회복, live 저장 중 초과 시
  raw/live 동시 rollback을 확인했다. 기존 20M 전환 CI의 공유 공간 단계에도 같은 검사를 연결했다.

## 판정과 제한

이번 기능의 판정은 **명시적으로 활성화한 이력 저장소의 과거 경로 점유 해소**에 한정한다.
raw가 남은 최근 경로 자체가 256/8,192개를 채우면 quota가 계속 발생한다. 영구 ID ledger나
삭제한 경로별 상세 통계 복원, 전체 기간 무손실 보존, source별 별도 admission 몫은 제공하지 않는다.

실제 monitor 생산자(#70), 생산자·등록/삭제·PKI·route가 함께 움직이는 장시간 검증(#71/#74),
M2 gate와 M3 물리 다중 relay 전환은 계속 미완료다. 시간 압축 저장 시험과 실제 mTLS API 시험을
실제 7일 soak나 커널 다중 릴레이 전환의 증거로 해석하지 않는다.
활성화/복원 및 외부 배포 저장소에서 사용할 명령은
[운영 계약](../validation/history-path-reclamation.md)에 있다.
