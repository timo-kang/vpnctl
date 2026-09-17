# 별도 서버 uplink를 위한 relay 배포 계약

이 문서는 다른 배포 저장소가 가져다 쓸 네트워크 설정 계약이다. vpnctl은 WG
peer/AllowedIPs/노드 경로를 관리하고, 배포 시스템은 relay OS의 forwarding,
방화벽, 서버 반환 경로 또는 SNAT를 관리한다. 아래 예제는 IPv4 전용이며 주소와
interface 이름은 배포 설정으로 바꾼다. 이 저장소는 운영 호스트에 자동 적용하지 않는다.

## 입력과 소유권

| 입력 | 예제 | 관리 주체 |
| --- | --- | --- |
| 로봇 VPN subnet | `10.77.0.0/24` | controller 설정/IPAM |
| relay WG interface | `wg0` | vpnctl |
| relay uplink interface/IP | `uplink0`, `198.18.0.1/30` | 배포 저장소 |
| target server/IP/service | `198.18.0.2`, 실제 앱의 TCP/UDP 포트 | 서버 배포 저장소 |
| server의 relay 다음 홉 | `198.18.0.1` | 배포 저장소 |
| 반환 모드 | 명시적 route 또는 SNAT | 배포 저장소 |

로봇에 LTE가 없어도 Wi-Fi/Ethernet 등으로 relay의 WG endpoint에 도달하면 된다.
VPN이 물리 연결을 만들어 주지는 않는다. 이 예제에서 로봇에는 target으로 가는
underlay/default route가 없고, relay에만 target으로 가는 uplink가 있다.

controller 설정에 overlay subnet과 target을 포함한다. 기존 허용 주소가 있다면
보존하고 추가한다. 실행 중 설정 변경의 배포/재시작 절차는 배포 저장소에서 관리한다.

```yaml
controller:
  server_allowed_ips:
    - "10.77.0.0/24"
    - "198.18.0.2/32"
```

노드에서 `ip route get 198.18.0.2` 결과가 의도한 WG 경로인지 확인한다. policy routing을
쓰면 실제 앱의 source address/mark에 맞춰 `ip rule`과 해당 routing table도 확인한다.
서버에는 서비스가 해당 주소/포트에 listen하고 있어야 한다.

## Relay forwarding과 방화벽

배포 저장소가 다음 sysctl 파일을 설치하고 변경 전 값을 기록한다.
`ip_forward` 변경은 다른 IPv4 설정을 기본 host/router 값으로 바꿀 수 있으므로,
필요한 interface별 설정은 forwarding 변경 뒤에 적용한다.
[Linux IP sysctl 계약](https://docs.kernel.org/networking/ip-sysctl.html).

```ini
# /etc/sysctl.d/60-vpnctl-relay.conf
net.ipv4.ip_forward = 1
```

적용 예: `sysctl -p /etc/sysctl.d/60-vpnctl-relay.conf`. 여러 경로가 있는 실제 배포는
reverse-path filtering 및 policy routing을 함께 검토한다. 이 예제를 위해 host의
`rp_filter`를 전역으로 끄지는 않는다.

아래 규칙은 배포 저장소가 소유하는 **기존 forward chain에 통합할 규칙 조각**이다.
운영 ruleset을 통째로 비우거나 별도 accept chain만 추가하는 방식으로 적용하지 않는다.
다른 base chain의 drop은 앞선 accept 이후에도 적용될 수 있다.
[nftables chain 평가 규칙](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains).

```nft
# 실제 앱에 필요한 protocol/port 조건을 추가해 좁힐 수 있다.
iifname "wg0" oifname "uplink0" ip saddr 10.77.0.0/24 ip daddr 198.18.0.2 counter accept
iifname "uplink0" oifname "wg0" ip saddr 198.18.0.2 ip daddr 10.77.0.0/24 ct state established,related counter accept
```

이 조각만으로 전체 방화벽 정책이 완성되지는 않는다. 기본 forwarding 정책,
다른 peer 간 통신, WG UDP listen 포트와 controller API의 input 정책은 배포 환경의
전체 ruleset에 속한다. 생성한 전체 파일을 `nft -c -f <file>`로 검사한 뒤
`nft -f <file>`로 적용하고 실제 트래픽/counter로 확인한다.

## A. 반환 경로를 설정할 수 있는 서버

서버 또는 서버 측 라우터에 VPN subnet 반환 경로를 설치한다. 다음 명령은 예제
서버의 interface가 `eth0`일 때다. 이미 있는 경로를 덮어쓸 경우 변경 전 값을 저장한다.

```sh
ip route replace 10.77.0.0/24 via 198.18.0.1 dev eth0
ip route get 10.77.0.2
```

서버 input 방화벽은 VPN subnet에서 오는 실제 서비스 요청을 허용해야 한다.
서버는 요청 source를 로봇 VPN IP로 관측한다. 영속 경로는 배포 환경의 networkd,
NetworkManager 등 기존 네트워크 관리자에 등록한다.

## B. 서버 반환 경로를 설정할 수 없는 경우

relay의 **기존 NAT postrouting chain**에 다음 SNAT를 통합한다. chain 유형은
`nat`, hook은 `postrouting`, 일반적인 priority는 `srcnat`다.
[상태를 사용하는 SNAT 계약](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)).

```nft
ip saddr 10.77.0.0/24 ip daddr 198.18.0.2 oifname "uplink0" counter snat to 198.18.0.1
```

이 주소는 relay uplink에 실제로 할당돼 있어야 한다. 서버는 source를 relay uplink IP로
관측한다. SNAT는 목적지 경로, forwarding, firewall 허용을 대신하지 않는다. uplink IP가
동적으로 바뀌는 환경에서의 masquerade 선택과 다중 uplink 정책은 해당 배포의 별도 계약이다.

NAT binding은 연결 추적 상태에 남는다. 규칙을 제거해도 기존 flow가 즉시 원래 source로
바뀌는 것은 아니다. 변경 검증에는 새로운 연결을 사용한다. sandbox의 namespace 내부
`conntrack -F`는 시험 정리를 위한 것으로 **운영 호스트 절차에 복사하지 않는다**.

## 적용·검증·복구 절차

1. 배포 저장소에서 vpnctl commit/tag와 이 문서 버전을 고정하고 위 입력을 명시한다.
2. 현재 관련 sysctl, route, rule, firewall 설정을 저장한다. 설정 책임과 적용 순서를 정한다.
3. forwarding, 전체 firewall, 반환 route 또는 scoped SNAT를 설치하고 영속화한다.
4. 실제 로봇 네트워크 namespace에서 서버의 **실제 앱 프로토콜**로 송수신한다.
   VPN controller API 성공과 별도로 판정한다. 서버 source IP와 relay counter를 대조한다.
5. `make test-netns`로 제공하는 반복 장애 검증을 배포 CI에서도 실행한다.
   정상/장애/복구 결과를 구분하고 설정 버전과 바이너리 digest를 보관한다.
6. 복구 시 배포 시스템이 소유한 변경만 이전 값으로 복원한다. 공유 forwarding 값을
   일괄적으로 0으로 바꾸거나, 전체 ruleset/conntrack을 비우지 않는다.

WG MTU와 앱 UDP 크기/재전송도 배포 계약에 포함한다. 현재 큰 UDP sandbox 검사는
명시적 IPv4 분할 조건이다. 기본 PMTU의 무손실이나 모든 NAT의 fragment 처리를
보장하지 않는다. 실제 LTE/Wi-Fi, IPv6와 다중 relay 전환은 별도 검증 대상이다.
