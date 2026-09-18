# Backend 지원과 responder 계약 (#18)

지원은 아래 vpnctl 구현과 테스트 범위에 대한 판정이다. 다른 VPN 제품이
WireGuard 암호 프로토콜을 사용한다는 사실만으로 `wg show <interface> dump`
호환성을 가정하지 않는다.

| 조합 | 판정 | 전제·권한 | 제공 범위와 검증 |
| --- | --- | --- | --- |
| Linux kernel WireGuard + vpnctl controller/node | 지원 | `ip`, `wg`, interface/route 변경 권한; 배포의 forwarding·반환 경로 설정 | 관리, PKI, peer 품질, 선택적 uplink 관측; 1/3/8/32 node kernel suite |
| 기존 Linux kernel WireGuard + monitor/ping/perf/discover | 지원 | IPv4 interface, `wg` 상태 읽기 권한(CAP_NET_ADMIN 또는 root), target host AllowedIPs/endpoint, UDP responder | RTT/loss/quality, handshake 시각, 로컬 SQLite/HTTP/Prometheus; 실제 두 노드 CLI smoke |
| Linux wireguard-go + `wg` 호환 interface | 제한·미검증 | daemon/socket 접근 권한, `wg show dump`, `ip` IPv4 조회가 모두 가능해야 함 | 같은 discovery 경로를 시도할 수 있으나 kernel suite가 userspace daemon을 검증하지 않음 |
| Tailscale의 OS interface 사용 모드 | 직접 관측 미지원 | 전용 PeerSource adapter 없음 | 같은 호스트에서 별도 kernel WG interface를 관측하는 공존만 가능; Tailscale peer/status 수집을 보장하지 않음 |
| Tailscale userspace networking 모드 | 직접 관측 미지원 | 전용 adapter 및 peer 경로 연동 없음 | vpnctl `--interface` 지원 대상 아님 |
| Nebula tunnel | 직접 관측 미지원 | 전용 PeerSource adapter 없음 | 별도 kernel WG interface와 공존 가능; Nebula peer/status 수집을 보장하지 않음 |

controller uplink 관측은 node 설정에서 명시적으로 활성화한다. monitor의 로컬 DB는
controller history로 자동 업로드되지 않는다. monitor handshake는 WG metadata이며,
transfer counter/jitter/모든 percentile의 공통 영속화는 #17의 미완료 범위다.

`monitor`는 기존 interface/route/peer 설정을 변경하지 않는다. `node serve`, `up`,
controller의 `wg_apply`는 관리 명령이므로 기존 VPN과 interface·주소·route 소유권을
분리해야 한다. 다중 relay 선택/전환은 M3 검증 대상이며 이 지원 표로 완료를 주장하지 않는다.

## Responder

| 프로세스 | UDP echo 제공 | 포트 |
| --- | --- | --- |
| `vpnctl monitor` | 제공하지 않음 | `--probe-port`는 원격 target 포트 |
| `vpnctl direct serve --listen <vpn-ip>:51900` | 제공 | 반드시 고정 listen 주소/포트를 명시; 기본 `:0`은 임의 포트 |
| `vpnctl node serve --config ...` | 제공 | node의 `probe_port`; 관리 모드 수명주기에 종속 |
| 실행 중인 vpnctl controller | 제공 | controller의 `probe_port` |

monitor/ping/perf는 대상 responder가 필요하다. discovery와 handshake 조회는 responder
없이 가능하다. monitor는 `vpnctl-echo:` 접두사가 붙은 UDP payload의 정확한 echo를
검증한다. 응답 없음은 tunnel 장애와 responder 중단을 단독으로 구분하지 못한다.
`responder_unavailable`, `probe_timeout`, `invalid_response`를 함께 확인해야 한다.
필요한 UDP 포트는 VPN 주소에서 접근 가능해야 한다. 이 responder는 인증 API가 아니며
인터넷에 노출할 필요가 없다.

## 두 노드에서 첫 표본 얻기

전제: 기존 `wg0` 양 끝의 IPv4가 A=`10.7.0.1`, B=`10.7.0.2`이고 각 상대가
host AllowedIPs(`/32`)와 유효 endpoint로 설정되어 있다. 두 VPN IP 사이 UDP 51900이
허용돼 있어야 한다. VPN 설치/라우팅 자체는 [배포 계약](../deployment/relay-network.md)을 따른다.

각 노드에서 responder를 별도 terminal 또는 supervisor로 실행한다.

```sh
# 노드 A
vpnctl direct serve --listen 10.7.0.1:51900
# 노드 B (별도 호스트)
vpnctl direct serve --listen 10.7.0.2:51900
```

다른 terminal에서 실행한다. 아래 `sudo`는 WG 상태를 읽을 권한이 이미 있으면 생략한다.

```sh
# 노드 A
sudo vpnctl monitor --interface wg0 --peers 10.7.0.2 --watch \
  --probe-port 51900 --metrics-port 9100 --data /tmp/vpnctl-monitor-a.db
# 노드 B
sudo vpnctl monitor --interface wg0 --peers 10.7.0.1 --watch \
  --probe-port 51900 --data /tmp/vpnctl-monitor-b.db
```

첫 성공 표본은 RTT로 확인한다. 기본 quality 판정에는 3표본이 필요하므로 약 10초 후
상태를 확인한다. A에서 `curl http://127.0.0.1:9100/network/quality`의 sample_count,
rtt_ms, loss_pct, error_reason과 `/metrics`를 비교한다. metrics HTTP는 인증이 없으므로
관리 네트워크에서만 접근 가능하도록 배포한다.

## 시작 진단과 실행 중 실패

- interface 이름·port 범위를 검사한다. `ip -4 addr show dev` 실패는 도구/장치,
  IPv4 없음은 주소 설정, `wg show dump` 실패는 도구/권한/backend 오류로 안내한다.
  각 명령은 취소 가능하고 시작 검사 전체는 10초 제한이다. private key가 포함될 수 있는
  `wg dump` stdout을 오류 메시지에 출력하지 않는다.
- 유효 interface에 peer가 없으면 명시적으로 안내하며 실행을 유지한다. endpoint가 없거나
  host IPv4 target을 결정할 수 없는 peer는 사용 가능한 probe target이 아니다.
- responder 필요 명령을 시작할 때 출력하고 첫 실제 probe cycle에서 도달성을 검사한다.
  모든 responder가 꺼져 있어도 monitor를 종료하지 않아 복구를 관측할 수 있다.
- 요청한 metrics port를 먼저 bind하고 실패하면 CLI가 nonzero로 종료한다. 실행 중에는
  HTTP timeout을 적용하고 monitor 종료 시 listener를 닫는다.
- 실행 중 interface/권한을 잃으면 기존 quality API의 `discovery_failed`/unknown으로
  전환하며 복구를 다시 검사한다.

검증: `TestMonitorCLIStartupErrors`, `TestMonitorCLIMetricsBindFailure`,
`TestMonitorPreflight`, `TestNetns_MonitorQuality` 및 관리 모드 kernel/PKI suite.
