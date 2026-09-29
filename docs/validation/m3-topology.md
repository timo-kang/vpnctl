# M3 정적 후보 경로 시험망 (#98)

[경로 제어 계약](../architecture/m3-path-control.md)의 초기 dataplane 가정을 실제
Linux WireGuard로 검증한다. controller catalog, 제품 자동 선택기, 수동 조작 API를
구현한 시험이 아니다. fixture가 네 후보를 만들고 route를 명시적으로 바꾼다.

## 재현

```sh
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-results ./scripts/test-m3-topology.sh
# production build를 별도로 확인할 때
VPNCTL_RACE=0 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-production ./scripts/test-m3-topology.sh
```

기본 race 활성화, CPU 2개와 2GiB 제한이며 실행 시간 상한은 5분이다.
공통 `test-netns.sh`의 Docker `--network none` 안에서만 namespace/bridge/WG/nft를
생성한다. host route/firewall을 고치지 않는다. 배포 저장소는 suite checkout을 고정해
스크립트를 재사용할 수 있다. 이 시험에는 제품 실행 파일을 호출하는 단계가 없으므로
`VPNCTL_TEST_BINARY` 지정만으로 다른 제품의 다중 relay 지원을 검증하지는 않는다.

## 구성과 검사

- namespace: robot 1개, relay 2개, WireGuard가 없는 별도 TCP server 1개.
- underlay 2개와 relay→server network 1개. robot에는 직접 server route/default route가 없다.
- `(relay, underlay)` 네 조합마다 별도 WG interface/key/inner IP/mark/table.
- relay는 지정 server TCP port에만 forwarding과 scoped SNAT를 허용한다.
- 연결마다 임의 nonce를 왕복시키고 server가 관측한 source가 선택 relay와 같은지 검사한다.
  앱 route와 전송 mark route의 interface/source도 readback한다.
- relay A uplink 장애→relay B 선택, underlay 0 장애→underlay 1 선택을 3회 반복한다.
- link-up만으로는 지워진 정책 route가 돌아오지 않는 상황을 확인한 뒤, 해당 underlay를
  쓰는 두 후보 table을 재조정하고 양쪽 relay의 복구를 확인한다.
- main table에 다른 underlay로 가는 endpoint route를 심고 선택 table의 endpoint route를
  삭제한다. 종결 unreachable route가 우회를 막는지, 명시적으로 고른 대안은 동작하는지 검사한다.

`report.json`은 실제 probe 결과, 선택 경로, 단계별 기대 도달 여부와 경과시간을 기록한다.
결과 폴더에는 테스트 키/자격증명을 복사하지 않는다. 실패한 관측은 기록하고 `completed=false`를
유지한다. 오류가 결과 폴더 생성 전에 발생하면 파일이 없을 수 있으므로 **실행 종료 코드 0,
completed=true, 전체 단계**를 함께 확인한다. manifest에는 suite commit/dirty/race와 실행
환경 식별 정보가 있어 외부 공유 전 실행 환경 정보 공개 범위를 확인해야 한다.

## 해석과 후속 gate

양성 관측은 후보 handshake/복구를 최대 약 10초 기다린다. 개별 TCP probe는 connect와
왕복 각각 1초 timeout을 가지므로 마지막 호출만큼 확인 시간이 넘을 수 있다. 이 수치는
시험 readiness 한도이며 자동 failover의 detection/decision/apply SLO가 아니다.
각 probe가 새 연결이므로 기존 TCP 세션 유지나 무중단 전환을 증명하지 않는다.

이번 시험은 **정적 topology의 구현 준비 근거**다. #21 catalog와 키/IPAM binding,
#22 link/address 변화 처리, #23 원자적 journal/rollback/reconcile, #24 controller outage,
지속 TCP/UDP/bulk·flap storm·가변 규모·실장비 검증을 별도로 통과해야 한다.
M2 장기 검증 및 최종 판정은 계속 열린 상태다.

## 자체 검증에서 찾은 결함

초기 fixture는 `link set up` 후 기존 endpoint route가 유지된다고 가정했다. 실제 커널은
link-down에서 해당 device의 정책 route를 제거해 link-up 후에도 종결 unreachable만 남았다.
대기 시간을 늘려도 복구되지 않았다. 시험을 수정해 link-up 이전/이후의 차단을 확인하고,
소유 경로를 재설치한 뒤 두 relay 모두 통신하는 것을 확인한다. 제품 구현에도 이 요구를
명시했다. 커널의 `No route to host`/`unreachable` 표현 차이는 동일한 차단 결과로 처리한다.
