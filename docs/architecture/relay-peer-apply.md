# 릴레이 로컬 키 검증과 peer 적용 (#114)

`relay apply|inspect|release|recover`는 영속 승인 cache를 읽어 endpoint별 전용 WireGuard
interface, 승인된 peer의 정확한 inner `/32` AllowedIPs, main table의 `/32` 반환 경로를
관리한다. 로봇이 LTE 없이 Wi-Fi/Ethernet으로 릴레이를 거쳐 서버에 도달하는 경로의 일부다.
자동 경로 선택, 서버 통신 성공, 목적지별 forwarding 권한까지 완료한 상태는 아니다.

## 명령과 소유권

[수신 주체 승인](relay-recipient.md)과 [cache 갱신](relay-deployment-cache.md)이 선행된다.
Linux의 `ip`, `wg`, 대상 network namespace의 NET_ADMIN 권한이 필요하다. 동일 UID의
0700 디렉터리에 0600 단일 hardlink 일반 파일로 private key를 배포한다. symlink/FIFO,
비신뢰 상위 디렉터리, 다른 공개키, 잘못된 key generation은 적용 전에 거절한다.

```sh
vpnctl relay refresh --config relay.yaml --relay-id relay-a
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
이 단계의 구현 범위는 적용 명령 실행 중 관측한 승인이다. JSON에
`expiry_enforcement: "on_command"`를 명시한다. 상시 daemon/커널 만료 장치는 아직 없으므로
명령을 실행하지 않거나 프로세스가 죽은 동안의 차단 시점은 보장하지 않는다.
따라서 이 구현만으로 무인 운영의 만료 차단 gate를 통과했다고 판단하지 않는다.

`apply|inspect|release|recover`는 작업 전 해당 relay의 **모든 관리 endpoint**를 확인한다.
승인이 만료·철회됐거나 endpoint/peer/key 구성이 달라졌다면 기존 interface를 내리고 제거한다.
한 endpoint 작업 중 만료되어도 나머지 endpoint를 회수한다. 적용 각 단계와 최종 검사 후에도
승인을 확인한다. 빈 승인에는 peer를 유지하지 않는다. drain 상태의 기존 binding은 유지하며
disabled/제거되어 승인 view에서 빠진 binding은 회수한다. 변경된 endpoint는 새 apply가 필요하다.

`refresh|status`는 메타데이터만 처리한다. 배포 스케줄러는 **refresh가 실패해도 inspect를 실행**하고
inspect 비정상 종료를 점검해야 한다. 통신 오류만이면 유효기간 내 승인으로 유지할 수 있지만,
관측한 거절은 통신 복구만으로 해제되지 않는다. 새 승인 저장 후에도 apply의 로컬 키 검증을 거친다.
인증서 갱신은 별도의 `sync-credentials`, TTL 연장은 관리자 catalog 갱신 책임이다.

외부 자원 충돌·권한 부족·I/O 불확실성 때문에 회수가 실패하면 `kernel_ready=false`와 오류를
반환한다. 이때 차단 완료로 간주하지 말고 운영자가 충돌/저장소를 해결해야 한다. metadata 오류로
cache 자체를 열 수 없는 경우도 자동 회수를 보장하지 않는다. 이 한계의 보완은 후속 상시 감독 범위다.

## Journal과 복구

승인 cache 안의 `peers.json`은 버전 1, 공개 소유 정보와 typed JSON checksum만 저장한다.
`peers-initialized`가 있는데 journal이 없거나 손상됐으면 새 설치로 간주하지 않는다.
boot ID·network namespace device/inode에 고정하므로 다른 부팅·namespace의 자원을 추측해 삭제하지 않는다.

1. 소유 ifindex/group/alias, 공개 peer, route 정보와 `preparing` intent를 fsync/rename/dir-fsync한다.
2. link 생성 → alias → WG 설정 → link up → 반환 route 설치를 수행하고 실제 커널을 읽어 검증한다.
3. `applied`를 영속 저장한다. 마지막 저장 실패 시 link를 내려 불확실한 성공을 방지한다.
4. 회수는 소유 link down → `releasing` 저장 → link 삭제(소유 route 포함) → journal 제거 기록이다.
   저장 실패 시 원래 intent와 내려간 link를 남겨 재개방 후 복구할 수 있게 한다.

SIGKILL 뒤 `recover`는 미완성 intent를 제거한다. 이미 `applied`인데 내려간 link는 자동으로
올리지 않는다. 충돌을 해결한 뒤 release/apply해야 한다. 삭제 실패·domain mismatch는 운영자
조사가 필요하며 marker/journal만 지워 우회하지 않는다. 재부팅 후에는 이전 namespace 자원이
없는지 확인하고 전체 cache를 보존·격리한 뒤 새 승인으로 다시 시작한다.

## 배포 경계와 검증

제품 소유: WG interface/peer, inner `/32` 반환 route, 승인과 소유 journal.
배포 소유: forwarding sysctl, rp_filter, 외부 endpoint/NAT mapping, source/target 제한 firewall,
uplink route, SNAT 또는 서버의 명시적 반환 route. node의 앱 route 선택도 아직 후속 단계다.
[배포 네트워크 계약](../deployment/relay-network.md)을 같이 적용한다.

`kernel_ready=true`는 현재 journal의 설치 endpoint가 승인과 커널에 일치함을 뜻한다.
아직 설치하지 않은 모든 catalog endpoint까지 준비됐다는 뜻은 아니다. `uplink_health`는 항상
`unknown`이다. inspect는 이름과 달리 만료·변경된 소유 자원을 회수할 수 있는 명령이다.

단위/race 검사는 1/3/8/32 node × 4 path, 반복 적용·재개방, 저장 전후 실패, 각 단계 중단·만료,
철회 후 통신 단절, 로컬 키 교체/권한/링크, journal 손상을 검사한다. 실제 namespace 테스트는
두 relay × 두 underlay에서 제품 CLI peer·반환 route를 통한 WG/TCP 통신, 외부 자원 보존,
철회·새 승인 복구, 5개 커널 단계 SIGKILL 후 다음 프로세스 복구를 검사한다.
별도 커널 규모 시험은 1/3/8/32 node × 4 path(최대 128 peer)의 실제 설치 수와 반복 CLI
재개방을 검증한다. 승인 발행과 forwarding/NAT/앱 route는 fixture이며 이 시험은
32대 동시 통신이나 자동 failover/SLO 판정이 아니다.

```sh
go test -race ./internal/relayapply ./internal/relaycache ./cmd/vpnctl
VPNCTL_RACE=0 scripts/test-netns.sh -test.run='^TestNetns_M3(PathTopology|RelayDeploymentScale)$'
```

#114에는 [상시 만료 차단 #124](https://github.com/timo-kang/vpnctl/issues/124),
source/target별 forwarding 제한과 부정 시험, 재사용 가능한 배포 설정의
통합 판정이 남는다. 자동 선택·전환·세션 유지 검증은 #22/#23/#24에서 이어간다.
