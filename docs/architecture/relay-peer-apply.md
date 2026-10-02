# 릴레이 로컬 키 검증과 peer 적용 (#114)

`relay apply|inspect|release|recover`는 영속 승인 cache를 읽어 endpoint별 전용 WireGuard
interface, 승인된 peer의 정확한 inner `/32` AllowedIPs, main table의 `/32` 반환 경로를
관리한다. 로봇이 LTE 없이 Wi-Fi/Ethernet으로 릴레이를 거쳐 서버에 도달하는 경로의 일부다.
승인된 source/target prefix 조합은 커널 정책으로 제한한다. 자동 경로 선택과 서버 통신
성공 판정은 별도다.

## 명령과 소유권

[수신 주체 승인](relay-recipient.md)과 [cache 갱신](relay-deployment-cache.md)이 선행된다.
Linux의 `ip`, `wg`, `nft`, 대상 network namespace의 NET_ADMIN·BPF 권한과
전용 bpffs 준비가 필요하다. [서비스 권한 계약](relay-lease.md)을 따른다. 동일 UID의
0700 디렉터리에 0600 단일 hardlink 일반 파일로 private key를 배포한다. symlink/FIFO,
비신뢰 상위 디렉터리, 다른 공개키, 잘못된 key generation은 적용 전에 거절한다.

```sh
vpnctl relay refresh --config relay.yaml --relay-id relay-a
# 별도 서비스로 계속 실행한다.
vpnctl relay supervise --config relay.yaml --relay-id relay-a
# 다른 터미널에서 적용한다.
vpnctl relay apply --config relay.yaml --relay-id relay-a --endpoint-id lan \
  --key-file /var/lib/vpnctl-relay/keys/relay.key --key-generation 1 --listen-port 51820
vpnctl relay inspect --config relay.yaml --relay-id relay-a
vpnctl relay release --config relay.yaml --relay-id relay-a --endpoint-id lan
vpnctl relay recover --config relay.yaml --relay-id relay-a
```

`--cache-dir`는 cache 명령과 동일한 디렉터리를 가리켜야 한다. 기본값은
`<node.pki_dir>/relay-deployments/<relay-id>`다. apply/release만 `--endpoint-id`를 받으며
apply만 key/port 인자를 받는다. private key의 X25519 공개값과 승인 public key를 대조하고,
설정은 `wg setconf /dev/stdin`의 pipe로만 전달한다. 비밀키는 argv·journal·오류에 넣지 않는다.
키 생성·회전·외부 NAT mapping의 배포 책임은 운영 시스템에 있다.

- `vd` + identity hash의 interface 이름을 사용한다. node의 `vr` interface와 분리한다.
  endpoint마다 승인된 relay key를 사용하지만 peer 목록은 해당 endpoint의 binding만 포함한다.
- route는 table 254, protocol 186, 무작위 소유 metric, 정확한 inner `/32`, 해당 interface로
  한정한다. relay peer에는 서버 target prefix를 넣지 않는다. learned WG endpoint는 정상적인
  authenticated roaming 상태로 취급한다.
- listen port는 외부 endpoint의 NAT port와 별도로 명시한다. 같은 namespace의 다른 WG
  listener가 이미 사용하는 port는 거절한다. 다른 UDP 프로그램의 bind 충돌도 적용 실패로 처리한다.
- 다른 interface/address/peer/PSK/route와 소유 index/group/alias 불일치는 보존하고 실패한다.
  승인 소유권은 root 또는 같은 UID의 악의적 커널 변경을 격리하는 보안 경계가 아니다.
- node 적용 명령과 같은 namespace lock을 공유하고 cache는 프로세스 lock으로 잠근다.
  최대 8 endpoint, catalog 상한 내 peer만 허용한다. 작업 최대 60초, 개별 커널 명령 3초,
  오류 후 복구는 독립적으로 최대 60초다. 파일 I/O 정지까지 시간 상한을 보장하지 않는다.

## 승인 만료·철회·키 변경

운영 정책은 **만료·철회를 확인하면 관리 중인 peer를 차단하고 새 유효 승인으로만 복구**다.
새 적용은 [상시 감독과 커널 lease](relay-lease.md)를 필수로 사용한다. JSON의
`expiry_enforcement: "kernel_lease"`와 endpoint별 lease 기한으로 확인한다.
감독이 멈추면 마지막 허가가 최대 10초에 만료되며 승인 만료 시각을 넘겨 허가하지 않는다.
구형 journal은 보호가 없는 기존 적용이므로 새 버전에서 회수 후 다시 적용한다.

`apply|inspect|release|recover`는 작업 전 해당 relay의 **모든 관리 endpoint**를 확인한다.
승인이 만료·철회됐거나 endpoint/peer/key 구성이 달라졌다면 기존 interface를 내리고 제거한다.
한 endpoint 작업 중 만료되어도 나머지 endpoint를 회수한다. 적용 각 단계와 최종 검사 후에도
승인을 확인한다. 빈 승인에는 peer를 유지하지 않는다. drain 상태의 기존 binding은 유지하며
disabled/제거되어 승인 view에서 빠진 binding은 회수한다. 변경된 endpoint는 새 apply가 필요하다.

`refresh|status`는 메타데이터만 처리한다. `supervise`가 갱신 실패 뒤에도 차단을 처리한다.
통신 오류만이면 활성 lease를 유효기간 내 승인으로 유지할 수 있지만,
관측한 거절은 통신 복구만으로 해제되지 않는다. 새 승인 저장 후에도 apply의 로컬 키 검증을 거친다.
인증서 갱신은 별도의 `sync-credentials`, TTL 연장은 관리자 catalog 갱신 책임이다.

외부 자원 충돌·권한 부족·I/O 불확실성 때문에 회수가 실패하면 `kernel_ready=false`와 오류를
반환한다. 이때 차단 완료로 간주하지 말고 운영자가 충돌/저장소를 해결해야 한다. metadata 오류로
cache 자체를 열 수 없으면 자동 회수는 못해도 기존 커널 lease는 만료된다.

## Journal과 복구

승인 cache 안의 `peers.json`은 버전 1, 공개 소유 정보와 typed JSON checksum만 저장한다.
`peers-initialized`가 있는데 journal이 없거나 손상됐으면 새 설치로 간주하지 않는다.
boot ID·network namespace device/inode에 고정하므로 다른 부팅·namespace의 자원을 추측해 삭제하지 않는다.

1. 소유 ifindex/group/alias, 공개 peer, route 정보와 `preparing` intent를 fsync/rename/dir-fsync한다.
2. 차단 guard 설치 → link 생성 → alias → WG 설정 → link up → 반환 route 설치를 수행하고 실제 커널을 읽어 검증한다.
3. 현재 승인으로 lease를 허가하고 `applied`를 영속 저장한다. 마지막 저장 실패 시 guard를 닫고 link를 내린다.
4. 회수는 guard 차단 → 소유 link down → `releasing` 저장 → link·guard 삭제 → journal 제거 기록이다.
   저장 실패 시 원래 intent와 내려간 link를 남겨 재개방 후 복구할 수 있게 한다.

SIGKILL 뒤 `recover`는 미완성 intent를 제거한다. 이미 `applied`인데 내려간 link는 자동으로
올리지 않는다. 충돌을 해결한 뒤 release/apply해야 한다. 삭제 실패·domain mismatch는 운영자
조사가 필요하며 marker/journal만 지워 우회하지 않는다. 재부팅 후에는 이전 namespace 자원이
없는지 확인하고 전체 cache를 보존·격리한 뒤 새 승인으로 다시 시작한다.

## 배포 경계와 검증

제품 소유: WG interface/peer, inner `/32` 반환 route, endpoint별 nft lease guard·BPF guard,
`vf…` source/target 제한 table, 승인과 소유 journal.
배포 소유: forwarding sysctl, rp_filter, 외부 endpoint/NAT mapping, 추가 앱 protocol/port firewall,
uplink route, SNAT 또는 서버의 명시적 반환 route. node의 앱 route 선택도 아직 후속 단계다.
[배포 네트워크 계약](../deployment/relay-network.md)을 같이 적용한다.

`kernel_ready=true`는 현재 journal의 설치 endpoint가 승인과 커널에 일치함을 뜻한다.
아직 설치하지 않은 모든 catalog endpoint까지 준비됐다는 뜻은 아니다. `uplink_health`는 항상
`unknown`이다. inspect는 이름과 달리 만료·변경된 소유 자원을 회수할 수 있는 명령이다.

단위/race 검사는 1/3/8/32 node × 4 path, 반복 적용·재개방, 저장 전후 실패, 각 단계 중단·만료,
철회 후 통신 단절, 로컬 키 교체/권한/링크, journal 손상을 검사한다. 실제 namespace 테스트는
두 relay × 두 underlay에서 제품 CLI peer·반환 route를 통한 WG/TCP 통신, 외부 자원 보존,
철회·새 승인 복구, guard를 포함한 6개 커널 단계 SIGKILL 후 다음 프로세스 복구를 검사한다.
별도 커널 규모 시험은 1/3/8/32 node × 4 path(최대 128 peer)의 실제 설치 수와 반복 CLI
재개방을 검증한다. 승인 발행과 forwarding/NAT/앱 route는 fixture이며 이 시험은
32대 동시 통신이나 자동 failover/SLO 판정이 아니다.

```sh
go test -race ./internal/relayapply ./internal/relaycache ./cmd/vpnctl
VPNCTL_RACE=0 scripts/test-netns.sh -test.run='^TestNetns_M3(PathTopology|RelayDeploymentScale)$'
```

#114의 source/target 제한과 부정 시험은 아래 정책에 포함한다.
[상시 만료 차단 #124](https://github.com/timo-kang/vpnctl/issues/124)의 배포 플랫폼 판정과
실제 배포 설정의 통합 판정은 남는다. 자동 선택·전환·세션 유지 검증은 #20~#24에서 이어간다.

## Source/target 정책과 외부 관리자

새 journal entry는 `policy_version: 1`과 정렬된 target/prefix/source grant를 기록한다.
`relay apply`는 link를 올리기 전에 별도 `inet vf…` table에 정책을 원자적으로 설치한다.
WG가 인증된 peer의 정확한 source `/32`를 검증하고, 정책은 해당 binding에 허용된 target
prefix만 전달한다. 반환은 해당 target에서 해당 source로 오는 established/reply 방향으로
제한한다. 승인되지 않은 목적지, 다른 binding의 source, 신규 서버발 연결, 릴레이 로컬
서비스와 IPv6 inner 통신은 허용하지 않는다. target의 probe port는 앱 허용 포트 목록이
아니므로 추가 protocol/port 제한은 배포 방화벽에서 설정한다.

ICMP destination-unreachable/time-exceeded/parameter-problem은 conntrack의 원래 source와
target이 해당 승인 조합이고 reply/related인 경우에만 전달한다. 릴레이에서 발생한 오류도
동일하게 제한한다. 임의 ICMP나 모든 related 데이터 연결은 허용하지 않는다. 중간 라우터의
ICMP source를 node WG가 수신할 수 있는지와 실제 앱의 PMTU/UDP 동작은 #24의 전체 경로
검증에 포함한다.

inspect/supervise는 table·set·rule·chain·우선순위·소유 comment를 비교한다. 외부 정책
추가/변경 시 오류를 보고하고 supervise가 기존 lease를 차단한다. 외부 변경을 덮어쓰거나
그 table을 삭제하지 않는다. 허용 rule의 `return`은 배포 방화벽의 차단을 우회하지 않으며,
정책만 설치돼도 `uplink_health`는 여전히 `unknown`이다. source/target 권한 변경은 이전
설치를 회수하고 새 명시적 apply를 요구한다.

policy가 없는 구형 entry는 새 버전에서 회수하고 새 승인·키 검증으로 apply해야 한다.
구버전 바이너리는 새 journal의 필드를 거절하므로 직접 downgrade하지 않는다. 새 버전의
release로 차단·회수를 완료하고 journal/cache를 보존한 뒤 운영 rollback 절차를 따른다.
marker나 정책 table만 지워 구형 상태를 강제로 채택하지 않는다.

SNAT 또는 서버 명시적 반환 route, forwarding과 배포 방화벽은
[배포 네트워크 계약](../deployment/relay-network.md), NetworkManager/networkd와의
공존은 [소유권 계약](../deployment/network-ownership.md)을 따른다.

정책 전환의 실제 바이너리 검증은 이전 main `0e1541845ca5086e358453b0c50c1dc300a6fb06`을
고정한다. CI는 그 checkout에서 별도 바이너리를 빌드하며, runner는 두 바이너리를 읽기
전용으로 컨테이너에 전달하고 각각의 digest를 manifest에 기록한다.

```sh
VPNCTL_RACE=0 VPNCTL_TEST_PREVIOUS_BINARY=/path/to/pre-policy-vpnctl \
  scripts/test-netns.sh -test.run='^TestNetns_M3ForwardPolicyUpgrade$'
```

새 journal에 대한 구형 inspect의 거절·무변경, 실제 구형 lease v3 설치의 새 감독기 회수,
새 승인·명시적 apply 뒤 네 경로 TCP 복구를 확인한다. 이전 바이너리를 제공하지 않은
로컬 실행은 이 검사만 skip하며, skip을 버전 호환성 통과로 기록하지 않는다.
