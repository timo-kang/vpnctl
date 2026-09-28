# 실제 monitor의 중앙 이력 전송

`vpnctl monitor --history-config /etc/vpnctl/node.yaml`은 이미 완료한 UDP echo 결과를
`monitor-overlay` source로 중앙에 전송한다. 추가 probe나 화면 snapshot 재수집을 하지
않는다. 옵션을 생략하면 기존 로컬 monitor만 실행한다. 이 기능은 peer 통신 관측이며,
서버 uplink의 최종 도달성이나 로봇 동작을 제어하지 않는다.

## 외부 배포 저장소에서 사용

1. controller를 먼저 업데이트한다. 변경 전 `controller backup`으로 controller 전체
   상태를 보관한다. 새 registry의 선택적 `observation_epoch` 필드는 구형의 엄격한
   YAML decoder와 호환되지 않는다. 구형 바이너리로 되돌릴 때는 중단 후 함께 보관한
   registry/PKI/history 백업을 복원한다. 필드를 지워서 운영을 계속하지 않는다.
2. 기존 `node join`으로 노드를 등록하고 인증서를 설치한다. node YAML의 `name`,
   명시적인 `https://` controller 주소, 절대 경로 `pki_dir`을 사용한다. 인증서 identity가
   name과 달라지거나 자격 증명이 없으면 시작을 거절한다. monitor는 bootstrap하지 않는다.
3. 동일 노드의 실제 WireGuard 인터페이스에서 실행한다. 상대는 등록된 노드이며 full
   public key와 VPN IP가 registry와 일치해야 한다. 상대 UDP responder도 실행되어야 한다.

```sh
vpnctl monitor --interface wg0 --watch \
  --history-config /etc/vpnctl/node.yaml \
  --data /var/lib/vpnctl/monitor.db --metrics-port 9090
vpnctl fleet history --config /etc/vpnctl/node.yaml --node robot-a --window 1h --json
# schema 6/7을 명시적으로 활성화한 controller에서는 source 조회 지원
vpnctl fleet history --config /etc/vpnctl/node.yaml --node robot-a \
  --window 1h --source monitor-overlay --json
curl -fsS http://127.0.0.1:9090/network/quality
```

`deploy/vpnctl-monitor-history.conf.example`은 기존 monitor systemd 서비스에 적용할
선택적 drop-in이다. interface/config/data 경로를 배포 환경에 맞춘다. 서비스 계정은
WireGuard 조회 권한, 로컬 DB 쓰기 권한, `pki_dir`의 읽기/원자적 갱신 권한이 필요하다.
node agent와 monitor는 동일한 credential 저장소의 CAS 갱신을 공유한다. 전달 실패와
별도 goroutine에서 인증서 유지·갱신을 진행하며, 프로세스 종료 때 이를 취소하고 합류한다.
구형 controller는 새 endpoint가 없으므로 mapping 오류를 표시하며 로컬 측정은 계속한다.

## 신원과 경로 계약

- `GET /monitor/peers?node_id=...`는 mTLS identity와 일치하는 등록 노드만 사용할 수 있다.
  응답 schema 1, 최대 1,024개 peer다. self, 등록 미완료, key/IP 없는 노드는 제외한다.
- full WG key + VPN IP를 node ID와 매핑한다. key 앞 8자리인 표시 이름은 사용하지 않는다.
  5초마다 catalog를 갱신하고 3초 timeout을 적용한다. 실패 즉시 기존 map을 무효화한다.
  15초 이상 오래되거나 시계가 뒤로 간 map도 사용할 수 없다. 중복 ID/key/IP, 잘못된
  epoch와 schema는 전체 catalog 오류로 처리한다.
- 측정 시작 시 peer와 `epoch`를 고정한다. `POST /monitor/metrics`는 한 observation과
  해당 binding을 받고 저장 직전에 현재 registry와 정확히 비교한다. 이미 바뀐 key/IP,
  삭제된 peer, key A→B→A의 이전 binding은 409 `monitor_binding_changed`로 거절한다.
  heartbeat는 epoch를 바꾸지 않는다. 기존 registry는 deterministic legacy binding을
  사용하다 최초 key/IP 변경부터 random epoch를 저장한다. epoch는 재시작/백업에 보존한다.
- registry 변경과 관측 admission이 겹치면 검사 시 유효했던 요청은 기존 identity로
  완료될 수 있다. 삭제/폐기는 기존 mutation drain을 따른다. 삭제 identity의 재등록은
  tombstone으로 거절하며 대체 장비는 새 node ID로 등록한다. 큐 내용을 새 peer로 바꾸지 않는다.
- controller/server 자체는 일반 node registry의 peer가 아니므로 이번 생산자는 중앙
  제출을 지원하지 않는다. `peer_not_registered` 누락 신호를 남기고 로컬 측정은 유지한다.
  hub 하나만 WG peer인 노드에서는 이 신호만 발생할 수 있다. WG에 없는 원격 노드를
  자동으로 생성하거나 relay 뒤 모든 노드를 측정하지 않는다.
- source는 `monitor-overlay`, path는 `unknown`, relay/uplink는 빈 값이다. UDP 응답은
  발견한 VPN 주소의 echo 도달성만 나타낸다. 실제 direct/relay/underlay는 단정하지 않는다.
  기존 `/metrics`의 source label은 계속 인증된 보고자의 주장이다. binding 검증은 새
  monitor endpoint의 계약이지 모든 source label에 대한 독립적인 원격 증명이 아니다.

## 표본과 오류

각 개별 probe 완료 시각을 UTC microsecond로 보존한다. 로컬 RTT µs를 중앙 ms로 변환하고
동일 결과를 로컬 저장·품질·중앙 전달에 사용한다. 화면 Subscribe의 유실은 전달에 영향을
주지 않는다. 중앙 큐에 먼저 넣으므로 로컬 DB 쓰기 오류가 이미 완료된 결과를 막지 않는다.
DB 오류는 별도 `storage_error`이며 성공한 통신을 실패로 바꾸지 않는다.

| 상황 | 중앙 observation | 로컬 실제 시도 분모 |
| --- | --- | --- |
| 정상 echo | observed / true / RTT ms | 포함 |
| 2초 timeout, responder 거절, 잘못된 echo, 경로 도달 불가 | observed / false / RTT null | 포함 |
| 잘못된 IP/port, 소켓 권한·자원 부족 | unknown / success·RTT null / 이유 | 제외 |
| WG discovery 오류·충돌 | 이전에 발견하고 아직 매핑 가능한 peer만 unknown | 제외 |
| 종료로 취소한 cycle | 새 실패 표본 없음 | 제외 |
| 매핑 실패·미등록 peer | 중앙 표본을 만들 수 없어 mapping drop 표시 | 로컬 측정 자체는 유지 |

로컬 SQLite는 실제 시도한 성공/실패만 보관하며 unknown은 live quality와 중앙 이력에
표시한다. 현재 구독자가 없거나 느려도 모든 완료 결과가 큐로 전달된다. 초기 catalog가
준비되기 전의 cycle, mapping 갱신 실패, 프로세스 재시작 사이에는 중앙 공백이 생길 수 있다.
중앙 품질의 threshold/window는 controller 계약을 따르므로 사용자 설정이 다른 monitor
품질 등급과 항상 동일하지 않다. 동일 표본의 성공·실패·unknown/RTT 의미는 같다.

## 전달 예산과 누락 확인

- 기존 공통 큐의 총 256개 예산(진행 중 1개와 지연 재시도 포함), 요청당 3초,
  최대 5회 시도, 1/2/4/8초 backoff를 재사용한다. 준비된 다른 표본은 backoff를 기다리지 않는다.
- 재시도에는 동일 ID, timestamp, 결과, binding을 사용한다. 재시작한 큐는 새 random ID를
  만든다. timestamp를 갱신해서 seal을 우회하지 않는다. 메모리 큐이며 재시작 복구용 spool이 아니다.
- 400/404/409/413, 명시적 `history_quota` 503은 즉시 폐기한다. quota는 별도 계수다.
  `history_sealed` 409도 폐기한다. 다른 503, transport/인증 오류는 제한된 횟수만 재시도한다.
- `/network/quality`의 `history`와 watch/TUI에서 mapping readiness, 마지막 성공 catalog
  시각, 오류 이유, `mapping_dropped`, `last_mapping_drop`, `delivery.pending/delivered/dropped/
  quota_dropped`를 확인한다. mapping drop은 측정 시작 시 매핑 불가 후보 수다. delivery
  drop과 별개이며 RTT loss 분모가 아니다. 계수는 프로세스 단위이고 재시작 시 초기화한다.
- Prometheus `vpnctl_monitor_history_mapping_dropped_total{reason}`과 공통
  `vpnctl_probe_history_delivery_total{result}`를 수집한다. 전송 누락은 중앙 DB가 받은
  표본 밖의 공백이다. schema 7 `coverage`는 DB에 입장한 과거 경로의 회수를 기록하며,
  producer에서 버린 표본까지 포함하는 지표가 아니다.
- 종료 시 I/O를 취소하고 남은 메모리 큐를 폐기·계수·로그한다. 응답 유실 직후 종료하면
  이미 commit된 표본도 전달 미확인으로 계수될 수 있다. delivered는 서버 확인 횟수다.

schema 5의 16 streams/node·256 total은 32노드 full mesh 두 source의 1,984개 stream을
수용하지 못한다. quota 신호를 확인하고 필요하면 문서화된 오프라인 schema 6/7 전환을
선택한다. monitor 옵션이 저장 예산이나 회수 정책을 자동으로 변경하지 않는다.

## 재현 검증

```sh
go test -race ./internal/monitor ./internal/observation ./internal/controller -run 'TestMonitor'
VPNCTL_NETNS_SIZES=3 VPNCTL_RACE=0 scripts/test-netns.sh \
  -test.run '^TestNetns_(PKILifecycleUplink|MonitorQuality)$'
```

controller 테스트는 실제 mTLS API, 1/3/8/32노드의 실제 agent와 monitor UDP 생산 경로,
스키마 5/6/7, 갱신/폐기/키 ABA/삭제, 재시도·quota·seal 격리를 검사한다. 커널 시험은
출하 CLI의 WG discovery부터 echo, 중앙 이력, 차단 실패, 재시작 후 보존을 검사한다.
가변 peer 수 단기 시험은 모든 생산자·경로 변경·PKI의 장시간 soak 합격을 대체하지 않는다.
