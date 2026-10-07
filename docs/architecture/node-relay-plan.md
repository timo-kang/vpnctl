# 로컬 장치 매핑과 경로 준비 계획 (#109)

`node relay plan`은 승인 cache의 경로를 로봇의 현재 장치·IPv4 주소·endpoint route와
연결한다. LTE 모뎀을 요구하지 않으며 Ethernet/Wi-Fi만 있어도 승인된 조합을 계획한다.
출력의 `eligible`은 로컬 전송 입력을 만들 수 있다는 뜻이다. relay의 패킷 전달, NAT,
서버 uplink 도달성과 자동 전환 성공은 아직 확인하지 않는다. `applied=false`,
`uplink_health=unknown`을 항상 출력한다.

## 배포 설정과 호출

[예제 설정](../../configs/node-relay-plan.example.yaml)의 `relay_underlays`를 기존 enrolled
node 설정에 추가한다. ID는 [승인 catalog](relay-catalog.md)의 `underlay_id`와 같아야 한다.
최대 4개이며 ID/interface 중복, 잘못된 kind·주소, 알 수 없는 설정 필드를 거절한다.
`kind`는 운영자가 선언한 ethernet/wifi/lte 분류이며 modem 하드웨어를 발견했다는 의미는 아니다.

```sh
vpnctl node relay refresh --config node.yaml
vpnctl node relay plan --config node.yaml --timeout 10s
# 최초 승인 때 확인한 controller ID를 추가로 고정할 수 있다.
vpnctl node relay plan --config node.yaml --controller-id <approved-controller-id>
```

cache 위치는 `--cache-dir` → `node.relay_cache_dir` → `<pki_dir>/relay-cache` 순서다.
[기존 cache의 소유권·0700/0600·lock·시간 역행 계약](node-relay-cache.md)을 그대로 사용한다.
plan도 cache lock을 보유하고 만료 관측 최고 시각을 저장하므로 쓰기 권한이 필요하다.
plan/status는 상주 supervisor와 같은 FIFO 대기열에서 최대 10초 기다린다. 대기 시간은
`--timeout` 전체 기한에 포함하고, 차례를 얻은 뒤 현재 승인을 읽는다. 만료·철회를 대기 전
상태로 되돌리지 않는다. 동시 refresh는 busy로 실패한다. plan은 controller에 접속하거나
키를 새로 만들지 않는다.

IPv4가 하나면 그 주소를 선택한다. 여러 usable IPv4 주소가 있으면 `source_ipv4`를 명시해야
하며, 설정한 주소가 없어지면 다른 주소로 조용히 바꾸지 않는다. IPv6-only 장치는
`present=true`, `no_ipv4`로 구분한다. literal IPv4 endpoint를 사용하므로 DNS/modem은
`unknown/not_collected`로 보고하며 연결 여부 판정에 사용하지 않는다. modem index만으로
실제 장치와의 관계를 추정하지 않는다.

## 결과와 실패 상태

stdout은 schema version 1의 JSON이다. cache 신원·generation·시각, underlay inventory,
모든 승인 path의 상태·제외 사유, endpoint·relay/key generation·binding 공개키/주소·target,
우선순위·비용 및 후속 pin 입력을 포함한다. 개인키는 출력하지 않는다.

| 상황 | 예시 상태와 사유 |
| --- | --- |
| 한 개 이상의 준비 가능한 경로 | `state=eligible`; 각 후보에 `pin` 포함 |
| 장치 없음 | inventory `present=false`, path `interface_absent` |
| 링크 down / IPv4 없음 | `link_down` / `no_ipv4` |
| 명시한 source가 삭제됨 | `source_absent`; 다시 설정/계획해야 함 |
| 여러 주소 중 선택 불명확 | `source_ambiguous`, 전체 대안도 불명확하면 `state=unknown` |
| 수집 권한 부족·명령 없음·출력 오류 | `collector_unavailable`, `state=unknown` |
| 수집 중 삭제/재생성·rename·주소/prefix 변경 | `inventory_changed`; 오래된 pin 입력 제외 |
| 모든 준비된 활성 후보가 확인된 down이고 미준비/unknown 후보 없음 | `state=no_uplink` |
| cache 없음·만료·거절·미확정 | `state=blocked`, `cache_missing` / `cache_expired` / `cache_identity_denied` / `cache_uncertain` 등 |
| disabled/drain 또는 binding 미완료 | `disabled` / `draining` / `binding_unavailable`; 후보마다 표시 |

일부 경로가 down/unknown이어도 다른 승인 경로가 준비 가능하면 전체 상태는 eligible이다.
출력의 모든 `paths[].reason`을 함께 확인한다. 미준비 binding이나 매핑 누락을 물리적인
no-uplink 증거로 취급하지 않는다. 모든 경로가 제외되면 비정상 종료한다. 손상·권한 오류로
cache 자체를 안전하게 열 수 없으면 JSON 대신 stderr와 비정상 종료로 보고한다.

## 수집 예산과 관측 의미

- 대기와 collection을 합쳐 최대 20초(`--timeout`으로 단축), `ip` 한 명령 최대 2초와 종료 정리 여유
  250ms. 한 번에 한 프로세스만 실행하고 재시도하지 않는다. SIGINT/SIGTERM은 현재 명령과
  하위 프로세스도 취소한다. cache의 파일 I/O가 kernel에서 멈추는 상황까지 취소하는 보장은 없다.
- stdout 명령당 64KiB, stderr 4KiB, 전체 interface 목록 128개, 매핑 장치당 주소 16개,
  승인 path 8개 한도. 과대·불완전 출력은 unknown이며 잘라낸 일부를 정상으로 사용하지 않는다.
- 장치 조회는 IPv4 필터 없이 수행한다. IPv4가 없는 실제 장치를 absent로 오인하지 않기
  위해서다. 선택에는 사용 가능한 IPv4만 포함한다. deprecated/tentative/DAD 실패·만료 주소는 제외한다.
- `ip -j -4 route get <endpoint> from <source> oif <interface>`의 장치·source·gateway를 검사한다.
  직접 연결된 endpoint에는 default gateway가 필요하지 않다. 수집 전후 ifindex·link 상태·주소를
  비교하지만 전역 원자적 snapshot은 아니다. 나중에 장치가 변하면 다시 계획해야 한다.
- `valid_until`은 가장 오래된 inventory의 30초 유효시간과 catalog 만료 중 빠른 값이다.
  이 시간 안이라고 실제 uplink 건강 상태가 보장되지는 않는다.

route lookup의 `from`/`oif` 의미와 JSON 필드는 [iproute2의 공식 구현](https://github.com/iproute2/iproute2/blob/main/ip/iproute.c)을 따른다.
이 조회를 source pin의 설치·실제 패킷 증거로 해석하지 않는다.

## 후속 apply backend 계약

`pin`은 owner digest, 별도 WG interface 이름, fwmark/table/rule priority **제안값**,
endpoint /32·로컬 장치/ifindex·source·gateway, 종결 unreachable 요구를 전달한다.
owner는 controller/node/path/공개키에 묶인다. 숫자 자원은 node/controller 해시 영역과
catalog 내 path 슬롯으로 제안한다. 경로 집합이 바뀌면 슬롯도 바뀔 수 있으며 예약은 아니다.

`requires_ownership_check=true`, `terminal_unreachable=true`다. [후보 적용 backend](node-relay-prepare.md)(#112)는
승인·현재 inventory를 다시 검사하고 실제 interface/table/rule priority/mark와 mask의 충돌,
다른 관리자의 자원 및 durable journal 소유권을 확인해야 한다. 기존 table을 통째로 flush하거나
계획만 보고 기존 자원을 덮어쓰면 안 된다. target probe, relay 배포, 수동/자동 선택,
전환·복구와 SLO는 #21/#22/#23/#24의 후속 gate다.

## 검증

```sh
go test -race ./internal/relayplan ./internal/config ./cmd/vpnctl
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-plan-unique \
  ./scripts/test-netns.sh -test.run='^TestNetns_M3PathTopology$' -test.timeout=8m
```

1/3/8/32개의 독립 node와 4 underlay·8 path, 신원/만료/거절/미준비 cache의 실제 CLI,
과대 출력·실행 기한·취소와 장치/주소 변경을 검증한다. 2 relay × 2 underlay fixture에서는
실제 CLI의 장치/source/gateway와 kernel을 대조하고, 실행 전후 route/rule/link/WG 설정이
같은지 확인한다. 기존 fixture의 명시적 경로 전환 29단계는 자동 전환 제품 합격이 아니다.
