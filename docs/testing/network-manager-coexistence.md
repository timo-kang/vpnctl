# NetworkManager · Netplan · udev 공존 VM

이 시험은 #173의 가상 Ethernet 배포 조합을 검증한다. 공유 개발 머신의 NetworkManager,
Netplan, udev, Wi-Fi 모듈, clock, suspend/reboot를 변경하지 않는다.

```sh
VPNCTL_ARTIFACT_DIR=/absolute/path/new-empty-result \
  ./scripts/test-network-managers.sh
```

Linux x86-64, Docker, Go, 접근 가능한 `/dev/kvm`, 이미지 빌드 시 Ubuntu 패키지 저장소가
필요하다. 실행기는 기존 [VM runner](relay-vm-boundaries.md)의 network-none 컨테이너,
capability 0, no-new-privileges, 1 CPU/2GiB/no-swap 제한을 사용한다. 게스트는 1 vCPU,
768MiB이며 관리자가 변경하는 커널은 QEMU의 별도 게스트 커널이다. host network, tap,
host sysfs, Docker socket을 게스트에 제공하지 않는다. KVM 없음을 성공/skip으로 바꾸지 않는다.

`VPNCTL_VM_MANAGERS=1` 이미지 빌드 옵션만 manager 및 shared 모드용 dnsmasq/iptables
패키지를 추가한다. 시험의 NM firewall backend는 Ubuntu 패키지 기본 iptables이며
iptables-nft가 사용하는 nft inventory도 기록한다. 기본 lease/power
이미지의 설치 목록은 유지한다. manager 이미지에서는 NM/networkd를 미리 mask하고,
게스트 identity 검사 뒤에만 테스트가 만든 설정으로 unmask한다. guest kernel marker,
실행별 token/UUID, 다른 host/guest boot ID, 게스트 PID 1과 같은 network namespace를
함께 확인한다. 환경 변수 하나만으로 호스트 manager 명령을 허용하지 않는다.

## 명시적 시험 배포

| 역할 | 장치 | 소유자 / 조건 |
| --- | --- | --- |
| 관리 채널 | QEMU virtio NIC | 시험 agent, manager 제외 |
| 승인 uplink 1 | wan0, 가상 Ethernet | NM static profile, default 변경 없음 |
| 승인 uplink 2 | wan1, 가상 Ethernet | fixture static, NM/networkd 제외 |
| RF LAN | rf0 ↔ 별도 namespace | Netplan renderer **networkd**, 172.20.10.0/24 |
| 짐벌 LAN | gimbal0 ↔ 별도 namespace | Netplan renderer **networkd**, 172.20.20.0/24 |
| 공유망 | shared0 ↔ 별도 client | NM ipv4.method=shared, 10.42.0.0/24 |
| EtherCAT 역할/이름 | 고정 MAC의 ecat0 가상 Ethernet | 실제 udev NAME 규칙, uplink 후보 제외; EtherCAT protocol 미실행 |
| 제품 tunnel / 앱 route | vr… 및 소유 table/rule | 실제 vpnctl journal, NM/networkd 제외 |
| controller / relay / target | 서로 다른 namespace | 실제 mTLS, 두 relay × 두 underlay, TCP nonce echo |

이름 prefix로 장치 역할을 추정하지 않는다. 승인 후보는 명시한 wan0/wan1뿐이다.
시험 fixture의 두 번째 underlay에 사용하는 논리적 kind와 관계없이 실제 link는 veth다.
이 결과를 Wi-Fi 드라이버/AP/RF/roaming 검증으로 제시하지 않는다.

NM allowlist와 networkd의 명시적 LAN match 및 마지막 Unmanaged match는 **전용 VM의
전체 소유권 설정**이다. 이를 운영 머신에 그대로 복사하면 다른 연결을 비관리 상태로
바꿀 수 있다. 배포 저장소는 [자원 소유권 계약](../deployment/network-ownership.md)에 따라
실제 profile, Netplan renderer, 선행 match, udev MAC/name, uplink 허용 목록을 정한다.
networkd의 ManageForeignRoutes/ManageForeignRoutingPolicyRules 정책도 배포 소유다.
networkd drop-in과 `.network`는 서비스 UID가 읽는 0644, Netplan YAML은 0600으로
구분하며 실행 전 실제 서비스 UID로 읽기 가능 여부를 검사한다.
제품은 manager 전역 설정을 변경하지 않는다.

## 판정과 증거

- 실제 NM reload/restart/down/up, shared 활성화·해제, Netplan apply,
  networkd reload/restart, udev 장치 재생성을 실행한다.
- NM 연결 해제 중 이전 앱 경로가 적용되지 않고 payload가 실패하는지 검사한다.
  독립 underlay의 앱 payload는 유지해야 한다. 복구는 제품 watch가 새 증거로 수행한다.
- 두 앱은 각각 p00/p01을 manual pin한 채 제품의 지속 reconcile과 후보 자동 재구성을
  실행한다. 대체 경로를 자동 선택하는 failover SLO 시험과 구분한다.
  두 앱과 두 LAN에 서로 다른 TCP socket의 무작위 nonce를 연속 전송하며 서버가 본
  source도 확인한다. 각 단계의 성공/실패 건수, 최대 성공 간격과 실행 시간을 기록한다.
  LAN 또는 독립 앱의 실패는 해당 단계 실패다. 새 TCP 검증이며 기존 세션 이동 보장을 주장하지 않는다.
- 공유망 client는 실제 NM dnsmasq와 DHCP discover/offer/request/ack를 교환해 주소,
  mask, router, DNS, lease를 검사한다. UDP bootstrap을 위한 초기 시험 주소를 받은
  주소로 바꾼 후 RF target까지 실제 SNAT된 source와 payload를 검사한다.
- 설정 원본과 Netplan 생성 파일의 SHA256 보존, WG의 NM unmanaged 상태를 검사한다.
  manager package 버전, 실제 public kernel 상태와 단계별 진단을 보고서에 보존한다.
- observer는 exit=0, completed=true, 정확한 전체 단계 집합과 각 passed=true를 함께
  요구한다. skip, 중복/누락, 중간 실패는 합격이 아니다.

`run-*.txt`와 `runner.json`은 commit/dirty, 이미지·kernel·binary digest, 자원 제한을
기록한다. `verdicts.json`, 개별 `verdict.json`의 managers 항목, `observer.jsonl`에
공존 결과가 포함된다. 비밀 config/cache/WG key가 든 private disk는 공개 artifact로
내보내지 않는다. 실패한 실행의 private work는 원인 분석용으로 보존하고 다음 실행은
새 디렉터리를 사용한다. 진행 중 실험을 중단하거나 같은 evidence를 덮어쓰지 않는다.

## 남는 범위

다른 NM/systemd/Netplan 버전, Netplan의 NetworkManager renderer 조합, Wi-Fi AP/로밍,
LTE 모뎀 및 DHCP uplink renewal, 물리장치 ifindex 재사용, 외부 VPN/firewall 관리자의
전체 조합은 각각 후속 검증이 필요하다. EtherCAT 실제 frame과 cycle deadline 검증은
전용 장비에서 수행해야 하며 여기서 LAN TCP 성공으로 대체하지 않는다.
이 시험만으로 #22/#23/#24 또는 M3 운영 gate를 완료 처리하지 않는다.

자동 선택·다중 릴레이 장애·같은 시계의 전환 계측은
[자동전환 VM 매트릭스](manager-auto-failover.md)를 사용한다.
