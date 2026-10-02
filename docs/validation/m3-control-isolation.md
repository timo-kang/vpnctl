# Controller 배치와 relay 장애 독립성 검증

Controller는 인증·승인을 발행하고 relay는 실제 VPN 패킷을 전달한다. 역할 분리는
서로 다른 서버 배치를 강제하지 않는다. `TestNetns_M3ControlIsolation`은 같은 서버에
두 역할을 배치한 경우와 별도 서버에 배치한 경우를 실제 제품 프로세스로 시험한다.
운영 배포가 아닌, 재현 가능한 격리 통합 시험이다.

## 구성과 소유권

| 역할 | 동일 서버 배치 | 별도 서버 배치 |
| --- | --- | --- |
| Controller | relay0 namespace, `192.0.2.11:9443` | 전용 namespace, `192.0.2.254:9443` |
| Relay0/1 | 두 underlay와 target LAN에 연결 | 동일 |
| Robot | `wan0=192.0.2.10`, `wan1=198.51.100.10` | 동일 |
| Uplink 서버 | 별도 namespace, `198.18.0.2:9192` TCP nonce echo | 동일 |

Robot에는 LTE나 target으로 가는 직접 route가 없다. 2 relay × 2 underlay의 네
승인 후보로 서버에 도달한다. 별도 controller에는 WG interface, target LAN link,
IPv4 forwarding이 없다. 두 relay는 각자 등록한 mTLS 인증서와 명시적 수신 승인을
사용하며, 다른 relay의 승인을 가져오려는 요청은 명시적 권한 거절이어야 한다.

실제 controller의 catalog/API/PKI와 제품 `node relay prepare`, `relay apply`,
`relay supervise`가 승인·키·peer·반환 route·forwarding ACL·lease를 관리한다.
Underlay 주소/bridge, forwarding/NAT와 앱 source route 선택은 fixture 소유다.
프로세스와 네트워크 namespace는 별도이지만 컨테이너 파일시스템과 커널은 공유한다.
따라서 실제 다중 호스트 배포, WAN latency/NAT 또는 호스트 보안 격리를 인증하지 않는다.

## 판정

1. 네 후보 모두 실제 WG handshake와 양방향 전송량이 있어야 한다. TCP nonce가
   되돌아오고 서버 관측 source가 선택 relay의 uplink 주소와 일치해야 한다.
2. Relay0 uplink만 내리면 해당 두 후보만 실패한다. 다른 relay의 통신과 원격
   controller의 인증 API는 계속 성공한다. `kernel_ready`는 target 건강 판정이 아니다.
3. Robot의 underlay0을 내리면 그 underlay의 두 후보만 실패한다. Link-up만으로
   커널이 삭제한 transport route는 복구되지 않는다. 제품 CLI로 해당 후보를 명시적으로
   release/prepare하고 fixture 앱 route를 다시 연결한 뒤 실제 패킷 복구를 확인한다.
   이 절차를 자동 reconcile의 성공으로 집계하지 않는다.
4. Controller 프로세스만 종료한다. Supervisor가 `refresh=unavailable`을 관측한
   상태에서도 유효한 승인과 활성 lease로 네 후보의 통신을 계속 유지해야 한다.
   관측은 10초 kernel lease보다 긴 12초 이상 수행한다.
5. Controller가 없는 동안 relay0 supervisor를 강제 종료한다. 11초 뒤 해당 후보는
   차단되고 relay1은 계속 통신한다. Relay0 supervisor를 다시 시작해도 새 인증 응답이
   없으면 만료 lease를 재개하지 못한다. 유효 승인 cache만으로 되살아나면 실패다.
6. 실제 60초 승인 만료 후에는 양쪽 relay의 관리 peer가 제거되고 네 경로가 차단된다.
   호스트/컨테이너 시계를 바꾸지 않는다. 이 시험은 만료 후 상태를 검증하며 정확한
   만료 순간의 기존 연결 차단 시간은 기존 authority/lease matrix의 별도 계측을 따른다.
7. 같은 영속 DB로 controller를 다시 실행해도 만료된 승인은 연장되지 않는다.
   원격 API에서 `catalog_expired`를 확인하고 여전히 패킷이 차단되는지 검사한다.
   새 승인을 발행하고 제품 peer를 재적용한 뒤 네 후보의 통신이 모두 복구돼야 한다.

## 실행과 결과

```sh
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-control-results \
./scripts/test-m3-control-isolation.sh

# 배포 저장소에서 만든 바이너리도 같은 계약으로 검사한다.
VPNCTL_TEST_BINARY=/absolute/path/to/vpnctl \
VPNCTL_ARTIFACT_DIR=/tmp/deployment-control-results \
/path/to/pinned-vpnctl/scripts/test-m3-control-isolation.sh
```

기본은 배포 빌드, 컨테이너 전체 2 CPU/2 GiB다. `VPNCTL_RACE=1` 또는
`-test.count=2`로 반복·race 검증할 수 있다. 시험 바이너리를 호스트 root로 직접
실행하지 않는다. Wrapper는 기존 [sandbox 계약](../../tests/integration/README.md)의
Docker `--network none` 실행기만 사용한다. 호스트의 전원, 시계, mount, NetworkManager,
Netplan 또는 udev 설정을 바꾸지 않는다. Fixture 프로세스만 의도적으로 종료한다.

`run-*.txt`는 suite/제품 버전, 바이너리 digest, 커널과 자원 제한을 기록한다.
각 `m3-authority-*/control-isolation.json`에는 배치, 단계 시각, 네 경로별 실제 probe,
서버 관측 source, WG handshake/전송량, 만료·중단 시각과 최종 판정을 기록한다.
`*-supervise-*.jsonl`, `*-commands.jsonl`, `outcome.json`과 공개 커널 snapshot을 함께
보관한다. 비밀키·인증서 개인키·등록 token은 export하지 않는다. 성공 판단은 두
배치의 `completed=true`와 전체 runner exit 0을 함께 확인한다.

## 남는 범위

이 시험은 새 연결을 각 후보로 명시적으로 보내는 방식이다. 경로 자동 선택, direct
WG 검증과 로컬 fallback (#20), 다중 relay 선택 (#21), underlay 자동전환 (#22),
link-up 후 모든 소유 후보 재조정·rollback·anti-flap (#23), 전환 SLO와 기존 세션의
연속성 (#24)은 후속 조건이다. NetworkManager 핫스팟, Netplan RF/짐벌 LAN,
udev EtherCAT 이름 변경의 실제 데몬 공존 시험도 별도다. Netplan renderer를 가정하거나
제어용 EtherCAT interface를 자동 uplink 후보로 추가하지 않는다.
