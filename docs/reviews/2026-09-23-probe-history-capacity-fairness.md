# Probe 이력 quota 분류와 전송 대기 검증

범위: #71 중 용량 거절의 재시도 분류, 준비된 표본의 전송 순서, 큐 자원 상한 및 운영 신호.
기준 main: `3415835f1c9e06547a7af8074f339e76fa70a503`.

## 수정한 결함

1. 노드/전체 stream, raw row, replay density 초과와 일시적 WAL backpressure가 모두 같은
   `ErrCapacity`/503이었다. 새 `history.QuotaError`만 `history_quota` 응답 code로 전달한다.
   기존 `errors.Is(err, ErrCapacity)` 호출은 호환된다. 실제 WAL reader 해제 뒤 회복하는
   오류는 재시도 대상으로 남긴다. 문구 검색으로 판정하지 않는다.
2. 한 표본이 실패하면 같은 worker가 1/2/4/8초 backoff를 전부 기다렸다. 뒤의 정상 peer도
   최대 5회의 요청/대기를 함께 기다리는 문제가 있었다. 실패한 표본은 같은 ID/본문으로
   재시도 시각을 예약하고, 그동안 준비된 다른 표본을 처리한다. 동시 전송은 여전히 1개다.
3. 새 스케줄러의 재시도 보관소를 별도 무제한 큐로 만들지 않았다. 대기·지연 재시도·전송
   중을 합한 256개 상한으로 제한하고 종료·overflow·quota 거절을 각각 계수한다.
4. node 로그의 `quota_dropped`와 controller `/prom/metrics`의 고정 resource label counter로
   명시적인 quota 거절을 확인할 수 있다. DB 사용량/누락 구간을 제공하는 신호는 아니다.

## 검증

- `go test -race ./...`: 전체 통과. agent 약 32.8초, controller 약 62.5초.
- `go vet ./...`, `go build -o /tmp/vpnctl-history-fairness ./cmd/vpnctl`, `git diff --check`: 통과.
- 503 quota/구형 문구/알 수 없는 code/손상 JSON/403/500/삭제 peer를 섞은 실제 HTTP 시험:
  정상 peer가 750ms 이내 전달, 재시도 분류와 ID/본문 보존 확인. race 모드 5회 반복 통과.
- 실제 mTLS + SQLite에서 16개 stream quota를 채운 뒤 32회 신규 stream 거절을 앞에 넣음:
  이미 허용된 stream은 약 194ms 안에 API 조회로 확인됨(완료 기준 2초). 거절된 stream은
  게시하지 않고 unknown을 성공/실패로 바꾸지 않음. 기존 batch 재전송도 멱등성 유지.
- 실제 생산자 + UDP의 1/3/8/32 peer × 즉시 quota/응답 정지 조합: 기존 heartbeat 2.5초,
  터널 장애 감지 4초 기준 및 goroutine/fd 회수 검사 통과. 이력 endpoint를 실제 호출했는지
  별도 확인하여 장애 경로를 거치지 않은 통과를 방지함.
- 큐 재시도 대기 중 새 표본의 wakeup, 5회 제한, 256개 지연/전송 중 작업에 800개 identity
  유입, 종료 시 1,056개 정확한 손실 계수, 응답 유실 뒤 실제 SQLite 중복 제거 확인.
- 네 가지 storage quota의 타입/한도, rollback, global quota에서 기존 stream 수용 확인.
  기존 전체 규모 CI의 실제 WAL pressure 시험에도 논리 quota로 오인하지 않는 assertion 추가.

새 큐 테스트 첫 race 실행에서 테스트 결과 slice의 읽기/쓰기 동기화 누락을 발견했다.
결과 전달을 채널로 고치고 큐 전체 race를 다시 통과했다. 운영 문서 작성 과정에서 메트릭
경로와 인증 여부도 실제 router와 대조해 `/prom/metrics` 및 기존 무인증 scrape로 수정했다.

## 자체 판정과 남은 범위

이 변경 범위에서 해결하지 않은 차단 결함은 확인하지 못했다. PR CI의 전체 규모 저장소
시험 및 kernel WireGuard/PKI 시험 통과를 병합 조건으로 둔다. CI 실행 결과는 PR에 기록한다.

256개 큐가 지속해서 가득 차면 새 관측은 여전히 손실될 수 있고, 진행 중인 3초 요청은
다른 표본을 지연시킬 수 있다. 모든 peer의 수집/보존 공정성이나 전체 전달 시간 SLO를
보장하지 않는다. 구 controller는 code 없는 503을 반환하므로 유한 재시도를 유지한다.
보존 schema v5, quota, query 계산식은 바꾸지 않았다.

#71은 계속 열린 상태로 둔다. 32×31 관계와 실제 source 수를 반영한 7일 raw/aggregate 정책,
128-bit 난수 ID·역순 도착·최대 reason의 용량 fixture, DB/WAL 사용량 및 공백 신호,
등록/삭제·source churn·재시작을 포함한 모든 관계의 선택 정책 검증이 남는다.
#70 monitor 연결, #17 관측 제품, #19 M2 gate와 M3 다중 relay/underlay 전환도 완료 판정하지 않는다.
