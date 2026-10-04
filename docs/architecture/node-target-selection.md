# 실제 target 관측과 경로 선택 판단 (#21/#153)

`node relay select`는 준비된 `(relay, underlay, target)` 후보의 실제 TCP 도달성을 검사하고
목적지별 **목표 경로**를 출력한다. `desired_path_id`는 적용 권한이나 적용 완료 증거가 아니다.
`applied=false`이며 앱 route를 바꾸지 않는다. 앱 경로 stage/commit/rollback은 #23의 다음 단계다.

## 준비와 호출

등록된 node의 승인 cache, 명시적인 underlay 매핑, relay peer/반환 경로와 target 서비스가 필요하다.
LTE 없이도 승인된 Ethernet/Wi-Fi 후보를 사용한다. `CAP_NET_ADMIN`과 Linux kernel WireGuard,
iproute2, wireguard-tools를 사용하며 시스템 필터·DNS·DHCP·default route를 변경하지 않는다.

```sh
vpnctl node relay refresh --config node.yaml
# 각 승인 후보마다 실행한다. 기존 prepare 후보는 먼저 release 후 새로 준비한다.
vpnctl node relay prepare --config node.yaml --path-id robot-a-primary --probe-routes
vpnctl node relay prepare --config node.yaml --path-id robot-a-secondary --probe-routes
vpnctl node relay select --config node.yaml --target-id app
vpnctl node relay select --config node.yaml --target-id app --watch
# 수동 pin은 장애 시 다른 경로로 우회하지 않는다.
vpnctl node relay select --config node.yaml --target-id app --mode manual --path-id robot-a-primary
```

`--probe-routes`는 기존 후보 전송 table 안에 승인 target prefix들의 WG route와
**후보 내부 주소 /32를 source로 지정한 rule**을 설치한다. 그러므로 명시적으로 그 내부 주소를
bind한 socket만 이 경로를 사용한다. 일반 unbound 앱의 경로는 생기지 않는다. 동일한 table의
endpoint 경로와 종결 `unreachable default`는 유지한다. 일반 앱의 고정 source 제공·세션 보존은
이 기능의 계약이 아니다.

초기 시험에서는 앱 경로를 제거하자 `rp_filter=2`가 TCP 반환 패킷을 버렸다. source rule은
후보별 reverse lookup도 가능하게 한다. 필터를 끄는 우회는 하지 않는다. source rule priority는
28000..31999, 기존 transport mark rule 뒤/main rule 앞이다. 충돌·앞선 source 가로채기 rule은
거절하며 숫자 범위의 독점 예약을 가정하지 않는다. source가 같지만 다른 target인 트래픽도 이
rule을 조회하므로, 후보 내부 주소는 승인 target 통신 전용으로 사용해야 한다.

이 자원은 기존 apply journal의 `probe_routing` 의도로 기록한 뒤 추가한다. 준비가 중단되면
`node relay recover`가 소유 WG interface → source rule → transport rule/endpoint/guard를
회수한다. link 제거로 해당 target route도 함께 제거된다. 외부 peer·route·rule을 발견하면
자동 삭제하지 않는다. 기존 journal은 그대로 읽으며, probe 옵션 없이 준비했던 후보를 조용히
확장하거나 축소하지 않는다. 새 옵션을 쓴 journal은 구버전 binary에서 거절되므로 downgrade
전에 새 binary의 release/recover를 완료해야 한다.

## 관측 의미

- 현재 승인·binding·journal과 kernel의 key, peer, endpoint, address, table/rule 소유권을 검사한다.
- underlay ifindex/source/gateway와 TCP target의 source/device 경로를 확인한다.
- TCP socket을 후보 WG device(`SO_BINDTODEVICE`)와 내부 IPv4 주소에 고정한다. DNS를 사용하지 않는다.
- TCP connect 성공, 해당 승인 peer의 nonzero handshake와 **관측 구간 RX/TX 증가**를 함께 요구한다.
  handshake 시각만으로 건강을 판단하지 않는다. local target/gateway/다른 device 경로는 거절한다.
- 관측 뒤 kernel·inventory·승인을 다시 검사한다. 관측 시각은 probe 종료 시각이며 후처리로 새롭게 만들지 않는다.

`reachable`은 catalog의 `probe_address:port`에 TCP 연결이 성립했다는 뜻이다. HTTP 응답,
앱 의미 검증, target의 모든 prefix/주소/port 도달성, 이미 실행 중인 앱의 실제 경로를 보장하지 않는다.
추가 payload는 보내지 않는다. timeout/refused/unreachable은 `unreachable`, 권한/명령/자원 오류,
미준비·외부 변경·장치 변화는 `unknown`이다. unknown을 실제 통신망 단절이나 packet loss로 세지 않는다.

[Linux IPv4 routing 구현](https://github.com/torvalds/linux/blob/master/net/ipv4/route.c)의
output device 지정과 실제 source/device route readback을 사용한다. bind만으로 반환 경로가
완성됐다고 가정하지 않으며 준비된 source rule도 소유권 검사한다.

## 선택 정책 v1

| 입력 | 기본값과 의미 |
| --- | --- |
| mode | `auto`; manual은 명시한 path만 허용 |
| max-cost | `-1`, 제한 없음. 0..65535로 비용 상한 지정 |
| successes | 같은 승인·설치 fingerprint로 연속 2회 성공 후 선택 가능 |
| max-connect-time | 1초. TCP connect 소요시간 상한; RTT 순위 경쟁으로 흔들지 않음 |
| hold-down | 15초. 더 선호하는 후보의 연속 건강 확인 기간 |
| minimum-dwell | 30초. 현재 건강한 목표 경로의 최소 체류시간 |
| max-age | 10초. 오래된 관측은 즉시 제외 |

건강한 후보를 priority 낮은 순 → cost 낮은 순 → path ID 순으로 정렬한다. 현재 후보 실패·unknown은
체류시간을 기다리지 않고 추천을 철회하거나 이미 확인된 대안으로 이동한다. 현재 후보가 건강하면
minimum-dwell과 더 선호하는 후보의 hold-down을 모두 만족한 뒤 변경한다. 단 한 번의 실패/unknown,
설치 fingerprint 변화, 관측 간격 초과는 해당 후보의 연속 성공을 초기화한다. 재시작 시 증거를 다시 모은다.

후보별 최근 16회의 TCP 시도 횟수·실패 비율을 출력한다. 이 값은 **TCP connect 실패 비율**이며
패킷 손실률이 아니다. unknown은 분모에서 제외하고 지연 상한 초과는 connect 실패로 세지 않는다.
이 비율을 점수 가중치로 사용하는 적응형 정책과 passive 품질 모델은 후속 범위다.

## 출력·승인·실행 예산

stdout은 JSON lines다. 정책, 세대, 후보별 증거/제외 원인, desired/previous path,
변경 여부·시각, `valid_until`을 포함한다. 추천 철회 시에도 `desired_path_id`는 생략하지 않고
빈 문자열을 명시한다. 각 줄은 완전한 snapshot이며 소비자는 새 객체로 디코딩해야 한다. `selection_ready`는 선택 판단 완료이며,
`no_verified_path`는 검사한 target 연결들이 실패했다는 뜻이다. 이것만으로 물리 `no_uplink`를 선언하지 않는다.

한 프로세스는 target 한 개, 최대 8개 승인 후보를 순서대로 검사한다. 기본 2회 검사 후 종료하며
마지막에 추천이 없으면 exit 1이다. `--samples 2..1000`, `--watch`, `--interval 100ms..1m`,
`--probe-timeout 10ms..2s`를 제공한다. 기본 interval은 **각 관측 주기가 끝난 뒤** 2초다.
전체 관측 주기 최대 20초, kernel command 최대 3초이며 늦은 앞쪽 관측은 max-age로 제외한다.
따라서 고정 2초 failover SLO를 주장하지 않는다. 원자적 kernel snapshot도 아니다.

매 주기 cache/namespace 잠금을 열고 닫아 refresh·prepare와 공존한다. busy·손상·승인 거절은
추천을 철회하는 unknown/blocked다. 노드마다 한 observer 프로세스로 시작하고 다중 target
상시 수집의 자원 배분은 후속 supervisor에서 처리한다. `select`는 controller에 접속하지 않는다.
외부 refresh가 새 승인 세대를 저장하면 해당 prepared 후보의 prepare 재검증도 필요하다.

만료되거나 승인 변경이 관측된 batch의 과거 성공은 사용하지 않는다. 같은 실행에서는 wall clock,
monotonic elapsed, suspend를 포함하는 BOOTTIME 예산을 모두 제한한다. 같은 세대의 관측 반복으로
승인 시간을 늘리지 않는다. 출력 `valid_until` 뒤에는 추천이 유효하지 않다. 이는 **선택 판단의
시간 제한**이며 node의 kernel peer를 상시 회수하는 보장은 아니다. relay의 기존 kernel lease
차단과 구분한다. 만료 승인으로 앱 경로를 새로 적용해서는 안 된다.

## 검증과 후속 gate

```sh
go test -race ./internal/relayapply ./internal/relayselect ./cmd/vpnctl
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-target-selection ./scripts/test-m3-target-selection.sh
VPNCTL_RACE=1 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-target-selection-race ./scripts/test-m3-target-selection.sh
```

실제 시험은 controller 동일/별도 namespace, relay 2개 × underlay 2개를 사용한다. 정적 fixture
앱 route를 제거하고 제품 CLI로 probe 경로를 준비한다. controller 중단, underlay UDP blackhole,
relay uplink 중단, 전체 target 불가, 복구, 외부 peer 보존, manual pin, 새 준비 단계 직후 SIGKILL과
recover를 검사한다. 선택 명령 전후 route/rule이 같고 일반 unbound 앱에는 여전히 경로가 없음을
확인한다. 운영 호스트의 network/clock/suspend/reboot를 건드리지 않는다.

1/3/8/32 node × 최대 8후보의 반복 flap·bounded history는 선택기 단위 검증이며,
32-node 실제 dataplane 부하 실증은 아니다. #23의 실제 앱 route 적용/rollback, #22의 underlay
세대 변경·복구, #24의 NAT source·기존/새 세션 및 SLO, 실제 네트워크 관리자 공존은 남아 있다.
