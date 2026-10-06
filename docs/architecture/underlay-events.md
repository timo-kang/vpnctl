# Underlay 이벤트와 관측 세대

`node relay select`와 `node relay target reconcile`은 명시한 `relay_underlays`의
변경 이력을 관측한다. `--watch`뿐 아니라 유한 `--samples` 실행에서도 명령 시작부터
종료까지 같은 수집기를 유지한다. 캐시/namespace lock을 풀거나 engine을 다시 열어도
이벤트 구독과 세대는 유지된다. 이 기능은 #22의 변경 감지·증거 무효화 단계(#169)다.

## 관측 계약

- 읽기 전용 NETLINK_ROUTE socket으로 link, IPv4 address/route, nexthop 객체 변경을
  구독한 **뒤** 초기 link dump를 읽는다. 초기 dump 중단·link 변경·손상·초과 입력은
  성공 snapshot으로 인정하지 않는다. Linux의 NETLINK_ROUTE/NEXTHOP 구독 지원이
  필요하며, 구독 권한 또는 지원이 없으면 unknown으로 처리한다.
- 설정한 이름과 초기 ifindex를 연결한다. rename/delete 시 이전 연결을 폐기하고
  설정 이름의 재등장만 다시 연결한다. 같은 이름·ifindex·주소로 복원돼도 변경
  세대는 되돌리지 않는다. 미설정 RF·짐벌 LAN·EtherCAT 장치를 자동으로 채택하지 않는다.
- 링크/주소/출구가 식별되는 route는 관련 underlay를 무효화한다. 출구가 불명확한
  route(모든 table의 blackhole/throw/unreachable 포함) 및 공유 nexthop 객체 변경은
  모든 설정 underlay를 보수적으로 무효화한다. table 번호·protocol만으로 앱 소유권을
  추정하지 않는다. 다른 장치로 출구가 명확한 route는 해당 uplink의 변화가 아니다.
  앱 guard의 최초 생성·회수도 출구 없는 변경이므로 전체 재확인을 유발할 수 있다.
  정상 앱 전환은 기존 guard를 유지하고 WG 출구가 명확한 route를 쓰므로 이 경우와
  구분된다. 기존 journal/커널 소유권 대조는 계속 유지한다.
- 후보 자동 복구에서는 잠금 안에서 읽은 소유 journal의 table·임의 metric·underlay
  tuple과 정확히 일치하는 protocol 186 unreachable default만 해당 underlay로 범위를
  한정한다. 다른 속성/metric/외부 table은 여전히 전체 무효화한다. 소유 매핑을 갱신하기
  전에 대기 중인 이벤트를 이전 매핑으로 처리한다. 이는 readiness나 승인 근거가 아니다.
- 결과의 `underlay_generation`은 프로세스별 임의 epoch와 underlay별 증가 세대를
  묶은 불투명 식별자다. 승인 generation/설치 fingerprint와 별개다. 재시작·이벤트
  유실 후 다시 조회하면 이전 연속 성공을 재사용하지 않는다. 영속적인 건강 증거가 아니다.

netlink는 알림 전달을 보장하지 않는다. `ENOBUFS`, truncation, `NLMSG_OVERRUN`, 잘못된
framing, 초기 dump 오류는 unknown으로 전환하고 구독을 닫는다. 부분 읽기 결과는
성공으로 내보내지 않는다. 재구독은 1초 backoff 뒤 수행하고 초기 조회를 다시 한다.
1회 drain은 최대 128 datagram/25ms, datagram은 최대 64KiB, 초기 조회는 최대
2초/512 datagram/128 interface다. 지속 폭주도 같은 유실 경로로 처리한다.
백그라운드 수신 goroutine이나 무제한 이벤트 queue는 없다. 커널 receive buffer에서
읽으며 `NETLINK_NO_ENOBUFS`를 켜지 않는다.

[Linux netlink의 전달·ENOBUFS 계약](https://man7.org/linux/man-pages/man7/netlink.7.html),
[rtnetlink의 장치·주소·경로 메시지](https://man7.org/linux/man-pages/man7/rtnetlink.7.html).

## 선택과 적용

1. 경로 TCP 검증 전후에 같은 세대를 요구한다. 뒤쪽 후보를 검사하는 동안 앞쪽
   후보의 경로가 바뀔 수도 있으므로 관측 batch 종료 시에도 다시 대조한다.
2. 세대가 바뀌면 해당 후보의 연속 성공·회복 유지 시간을 초기화한다. 정상적인
   다른 underlay의 확인 이력은 유지한다. 새로운 연속 성공 **2회**가 필요하다.
3. 앱 적용 직전의 새 TCP 검증은 선택 당시 세대와 같아야 한다. route 쓰기 이후
   unbound 앱 검증, commit 직전 및 rollback도 같은 결정을 다시 대조한다.
   변경 후 얻은 단 한 번의 새 성공이 이전 세대의 두 번 확인을 대신할 수 없다.
4. 대기 중 관련 이벤트가 있으면 다음 제한된 주기를 앞당긴다. 이벤트 폭주를 무제한
   작업 생성으로 바꾸지 않는다. 이벤트가 없어도 기존 주기적 전체 점검은 계속한다.

기존 MaxAge 10초, BOOTTIME 커널 임대 10초, FIFO admission 최대 10초와 TCP/적용 예산은
변경하지 않는다. 이벤트 오류는 `underlay_events_unavailable`, 검증 도중 변경은
`underlay_changed_during_probe`/`underlay_changed_during_batch` 등으로 진단한다.
수집 실패를 물리 통신망 부재인 `no_uplink`로 표시하지 않는다. 앱 활성화에 실패하면
기존 quarantine/유효한 대안 검증을 따른다.

구독은 커널 변경과 route 적용을 하나의 원자적 작업으로 만들지 않는다. 변경은
이벤트 처리·기존 lock admission·검증 경계에서 발견하며, 발견 즉시 전체 데이터 경로가
차단된다는 보장은 없다. 실제 최대 탐지/차단/복구 시간과 여유 처리량은 #23/#24에서
장비·추가 부하와 함께 판정한다. 수집기만으로 커널 임대를 연장하거나 후보를 승인하지 않는다.

## 범위와 배포

물리 연결 profile, DHCP, DNS, default route, NetworkManager/Netplan/udev 설정은 읽기
대상이며 변경하지 않는다. 설정 파일 변경 시 명령을 재시작하고 새 확인을 수행한다.
source/gateway/ifindex가 실제로 달라져 설치 journal과 불일치하면 기존 보호에 따라
차단된다. 명시적으로 자동 관리를 요청한 경로는 [후보 준비/복구](node-candidate-preparation.md)의
소유권 대조·작업 예산·backoff에 따라 새로 준비한다. 수동 prepare는 자동 복구하지 않는다.

RTNETLINK만으로 BSSID가 바뀌어도 L3/link 상태가 그대로인 Wi-Fi roaming, SIM/모뎀
등록, DNS 변화를 알 수 있다고 주장하지 않는다. 이들은 nl80211/관리자별 읽기 provider와
실제 장비 시험이 필요하다. policy-rule 변경은 현재 live kernel/route 대조의 대상이며
이 단계의 이벤트 세대 구독에는 포함하지 않는다. 스냅샷만 사용하는 library 호출과
단발 `observe`/`inspect`를 지속 이벤트 감시로 해석하지 않는다.

격리 veth/dummy 시험은 실제 NetworkManager 핫스팟, Netplan renderer 재시작,
udev/EtherCAT 배포 호환성을 대신하지 않는다. [소유권 계약](../deployment/network-ownership.md)과
#22/#23/#24의 실제 관리자·운영 SLO gate는 계속 열려 있다. 호스트 Wi-Fi
드라이버/펌웨어·커널 이미지·네트워크·시계·전원을 변경하는 설치 절차는 추가하지 않는다.

## 재현

```sh
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  ./scripts/test-netns.sh \
  -test.run='^TestNetns_(UnderlayEvents|M3TargetApplicationUnderlayEvents)$'
# 동일한 격리 시나리오를 race 빌드로 검증한다.
VPNCTL_RACE=1 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  ./scripts/test-netns.sh \
  -test.run='^TestNetns_(UnderlayEvents|M3TargetApplicationUnderlayEvents)$'
```

`test-m3-target-application.sh`도 위 시나리오를 포함한다. 초기 조회 중단/유실/범람/
프레임 손상/세대 카운터 포화는 fake source·파서 fuzz로, 실제 link/address/route ABA,
같은 ifindex 재등장·rename·nexthop·2048개 알림 범람은 netns로 확인한다. 분리 controller,
2 underlay × 2 relay 및 두 실제 actuator 시험은 새 세대의 2회 확인과 payload 복구,
무관한 앱 payload/세대 유지 여부를 JSONL과 결과 JSON에 남긴다.
