# 네트워크 관리자와 vpnctl의 공존

NetworkManager, systemd-networkd, netplan이 생성한 설정, DHCP client, wg-quick,
다른 VPN, firewalld가 같은 자원을 관리하면 서로의 변경을 되돌릴 수 있다.
자동 전환 전에 배포 저장소에서 다음 소유권을 고정한다. 이 문서는 설치 계약이며
개발 호스트의 설정을 자동으로 변경하지 않는다.

| 자원 | 관리 주체 | vpnctl 동작 |
| --- | --- | --- |
| 물리 LTE/Wi-Fi/Ethernet 연결, 주소, DHCP, DNS, 기본 경로 | 기존 네트워크 관리자 | 읽기·변경 감지; 연결 프로파일이나 default route를 덮어쓰지 않음 |
| 승인 후보의 `vr…` WG, endpoint transport table/rule/mark | vpnctl node | journal에 기록한 자원만 생성·검사·회수 |
| `vd…` WG, peer `/32` 반환 route, `vl…` lease와 BPF guard | vpnctl relay | 승인과 커널 소유권이 일치할 때만 유지 |
| `vf…` source/target 제한 | vpnctl relay | 승인된 source와 target prefix의 조합만 허용; 외부 firewall의 차단은 계속 적용 |
| forwarding sysctl, uplink route, 외부 endpoint NAT, 앱 포트 firewall, SNAT/서버 반환 route | 배포 저장소 | 제품 설치 상태와 별도로 실제 서버 통신으로 검증 |
| 앱 target route 선택·전환 | #20~#23 후속 구현 | 범위·table·rule 우선순위를 먼저 예약하고 실제 lookup/통신으로 검증 |

`protocol=186`, interface 접두사, table 번호만으로 기존 자원을 채택하지 않는다.
소유 journal, interface index/group/alias와 실제 peer/route/rule 내용이 함께 일치해야 한다.
현재 namespace lock은 vpnctl 명령끼리의 동시 변경을 막는다. NetworkManager 등 외부
프로세스가 이 lock을 따르지는 않으므로, 잠금만으로 공존이 보장된다고 판단하지 않는다.

이 계약은 새 relay 후보/배포 journal 경로를 기준으로 한다. 기존 `up`/agent direct의
`wireguard.Manager.ApplyPeers`는 지정 WG에 syncconf를 적용하고 policy table을
재설치한다. 해당 WG/table은 전용으로 예약해야 한다. 기존 적용자까지 같은 소유권
검사로 통합하고 외부 자원 보존을 검증하는 일도 #20/#23의 잔여 조건이다.

## 배포 설정 예제

이름은 실제 `node relay plan`/`relay inspect` 결과의 interface로 치환한다. wildcard로
`vr*`/`vd*` 전체를 제외하려면 배포 전체에서 이 이름 범위를 먼저 예약해야 한다.
기존 관리자의 물리 interface 설정이나 다른 VPN 프로파일은 변경하지 않는다.

NetworkManager의 별도 drop-in 예:

```ini
# /etc/NetworkManager/conf.d/90-vpnctl-owned.conf
[keyfile]
unmanaged-devices+=interface-name:vr0123456789ab;interface-name:vd0123456789ab
```

현재 배포의 NetworkManager 버전과 최종 병합 설정을 확인한다. 기존 제외 목록에
추가하고, 해당 WG를 생성하는 connection profile/wg-quick unit이 동시에 존재하지
않게 한다. [공식 NetworkManager.conf 계약](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html).

systemd-networkd의 먼저 매칭되는 전용 `.network` 예:

```ini
# /etc/systemd/network/10-vpnctl-owned.network
[Match]
Name=vr0123456789ab vd0123456789ab

[Link]
Unmanaged=yes
```

다른 이름의 더 이른 파일이나 netplan 생성 파일이 먼저 매칭되면 이 예제는 적용되지
않는다. [systemd 255의 매칭·Unmanaged 계약](https://github.com/systemd/systemd/blob/v255/man/systemd.network.xml).
또한 networkd의 `ManageForeignRoutes`/`ManageForeignRoutingPolicyRules`는 별도의 전역
정리 동작이므로 interface 제외만으로 route/rule 보존을 추정하지 않는다.
[networkd 전역 계약](https://github.com/systemd/systemd/blob/v255/man/networkd.conf.xml)을
배포 버전에 맞게 확인하고, 공유 namespace에서 충돌 없이 예약할 수 없으면 vpnctl의
전용 network namespace와 명시적 uplink 연결을 사용한다. 제품이 이 전역 옵션을
자동으로 끄지는 않는다.

방화벽 reload는 배포 소유 table/chain만 갱신한다. `flush ruleset`, 전체 route/rule
flush, 기존 VPN interface 재생성은 vpnctl과 공존하는 절차가 아니다. `vf…`에서의
허용은 다음 base chain의 drop을 무력화하지 않는다.
[nftables verdict 계약](https://netfilter.org/projects/nftables/manpage.html).

## 자동 전환의 후속 검증 계약 (#20~#24)

1. 적용 전에 interface identity, source 주소와 gateway, 예약 table/rule/mark 충돌을
   검사한다. 더 높은 우선순위의 source/destination/mark rule, 다른 VPN의 default route,
   DNAT/방화벽 정책도 실제 target lookup과 경로별 서버 probe로 확인한다.
2. DHCP 갱신·주소 삭제·interface 재생성·Wi-Fi roaming 중 읽은 정보가 바뀌면 후보를
   다시 검증한다. 오래된 probe 성공은 새 route generation을 활성화하지 못한다.
3. 외부 관리자가 소유 자원을 변경하면 해당 후보 사용을 중단하고 conflict를 보고한다.
   외부 설정을 지우고 재설치하는 무한 경쟁을 만들지 않는다. 소유권이 확실한 자원만
   회수하며, 충돌 원인이 해소되고 새 후보 검증을 마친 뒤 복구한다.
4. 전환 후 실제 앱 source/mark의 route와 target 송수신을 확인한다. 커널 설치 성공을
   서버 연결 성공으로 표시하지 않는다. 유효한 대안이 없으면 `no-uplink`로 수렴한다.
5. 자동 전환의 완료 근거에는 실제 NetworkManager/networkd의 DHCP 갱신·재시작·reload,
   다른 VPN/rule 선점, firewall reload를 포함한다. 현재 netns의 외부 변경 주입 시험은
   이들 데몬의 실제 배포 호환성 인증을 대신하지 않는다.

현재 #114의 검증은 외부 peer/route/mark 보존과 외부 방화벽의 차단 우선권을 다룬다.
위 자동 선택·전환 및 실제 관리자 조합 검증은 #20~#24의 완료 조건으로 이어진다.
