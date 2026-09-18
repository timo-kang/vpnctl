# 자동 direct probe 이력 연결 자체 리뷰

범위: #70의 첫 구현 단위인 공통 성공/실패/unknown 계약과 자동 agent 생산자 연결.
최신 main `2fbc7ac`에서 시작했다. monitor 자동 업로드, p50/p99/jitter 및 handshake/transfer
공통 수집은 이번 변경의 완료 범위에 포함하지 않는다. #70/#17/#19는 계속 열어 둔다.

## 발견과 조치

1. **성공 표본만 중앙 legacy CSV에 제출**: `/direct-result`의 성공/실패는 readiness와
   Prometheus에만 반영되었다. 기존 실행한 probe 결과를 재사용하여 원래 관측 시각과 ID로
   raw history에 제출한다. 실패·미실행을 누락하거나 성공 통계로 대체하지 않는다.
2. **생산자 혼합**: public 후보 UDP와 VPN IP ping이 같은 stream으로 합쳐질 수 있었다.
   source를 stream key/API/CLI/HTML에 포함하고, 후보 probe만으로 VPN quality를 healthy로
   올리지 않는다. 실제 경로 증명은 M3의 별도 계약이다.
3. **수집 불가를 통신 실패로 계산할 가능성**: shared socket 오류에 송신 여부를 남겨
   DNS/로컬 자원/송신 이전 timeout을 unknown으로 보존한다. loss/availability에는 실제
   시도만 포함하며 all-unknown과 빈 bucket의 수치는 null이다.
4. **관측 변경이 제어에 미칠 수 있는 회귀**: unknown 분류 때문에 기존 readiness 해제를
   생략할 수 있던 구현을 리뷰에서 수정했다. 로컬 오류의 보수적인 `/direct-result` 실패
   보고는 유지하고, history에서만 실제 통신 실패 분모와 분리한다. 닫힌 실제 socket으로
   두 경로를 동시에 확인하는 회귀 테스트를 추가했다.
5. **동기 전송과 재시도 시 중복/시간 왜곡**: 별도 256개 유한 큐, 1개 in-flight, 최대 5회
   재시도, immutable 원시 표본, 재시작 간 독립적인 128-bit 난수 ID를 적용했다. 등록 재시도
   중 큐를 보존하고 identity 변경 시 분리한다. overflow/종료/거절/소진은 누계 로그 및
   고정 result label counter로 남긴다. durable spool로 주장하지 않는다.
6. **마이그레이션 테스트의 거짓 전제**: 이전 일부 테스트는 최신 DB의 버전 숫자만 낮췄다.
   실제 v1~v4 schema에 데이터를 넣어 v5 전환/백업/복원을 검증하도록 수정했다. 작은 stream
   표만 ID를 보존해 재구성한다. broken reference에 대한 전체 rollback, 변조한 validity,
   reason/source의 복원 거절을 검증한다. 구버전 바이너리는 v5를 거절한다.
7. **32노드 성능 fixture의 과소한 row 크기**: 짧은 정수 ID 대신 실제 생산자 길이인 22자 ID와
   성공/실패/unknown reason을 넣었다. 3,870,720 peer rows + 322,560 uplink snapshots는
   884,465,664 bytes, 24h 조회 544.5ms, 7d 조회 3.971s, 전체 만료 정리 24.56s로 측정됐다.
   이 결과는 32개 stream에 대한 용량이며 full mesh 전체 관계의 보장은 아니다.

## 검증

- 전체 `go test -race ./...`, `go vet ./...`, CLI build 통과 후 리뷰 변경에 대해 영향 package
  race 검사를 추가 수행했다.
- 실제 UDP 응답/무응답/잘못된 target → 자동 agent → mTLS controller → history API를 확인했다.
  peer 삭제와 인증서 폐기 뒤 업로드가 거절되고 후보 성공이 VPN quality good을 만들지 않는다.
- controller 응답 손실 뒤 재전송·저장 오류·caller pointer 변경·동시 큐 과부하·종료·재시작 ID·
  역순 관측·미래 시각·unknown null/분모·DB quota와 migration/backup/restore를 확인했다.
- `VPNCTL_HISTORY_SCALE=1 go test ./internal/history -run '^TestHistoryScale$' -count=1 -v`로
  1 GiB DB, 8초 조회, 60초 retention 정리 예산 및 실제 WAL backpressure를 검증했다.
- kernel suite의 `TestNetns_AutoSilentFleet`에 실제 자동 실패 표본의 중앙 API 검증을 추가했다.
  1/3/8/32 규모, 인증서/relay/uplink 장애와 종료·복구는 PR 및 main의 reliability CI로도
  검증한다. 최종 run 링크와 결과는 PR에 기록한다.

## 남은 완료 조건

full mesh의 992 stream과 기본 주기 기준 약 천만 raw rows/7일은 현재 한도를 넘는다.
source가 늘면 관측 기회 불균형도 커진다. #71에서 cadence/공정성/downsampling/용량 신호와
거절된 peer가 다른 peer 전송을 지연시키는 문제를 처리한다. #70의 monitor 및 고급 통계,
#17의 DB health/downsampling, #19의 장시간 최종 gate를 완료하기 전 M2 통과로 판정하지 않는다.
배포·rollback과 API 세부 계약은 [중앙 fleet 관측 계약](../validation/fleet-history.md)에 있다.
