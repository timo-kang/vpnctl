# Relay catalog v1: 승인 후보와 경로별 key/IP 원장 (#103, #21)

로봇이 서버 uplink에 도달할 수 있는 relay/underlay 후보를 관리자가 승인하고,
각 후보에 노드의 WireGuard 공개키와 전용 `/32` 주소를 묶는다. 기존 node VPN 주소와
분리된 원장이다. LTE 보유 여부를 요구하지 않으며 `underlay_id`는 Wi-Fi/Ethernet 등
노드가 나중에 실제 장치와 연결할 논리 이름이다. 현재 그 장치의 존재/가용성을 확인하지 않는다.

catalog 발행·조회와 binding 저장에 더해 [node 영속 cache와 경로 키](node-relay-cache.md),
[node 경로 준비](node-relay-prepare.md), [인증된 relay 배포 조회](relay-recipient.md)를
제공한다. relay peer 설정, forwarding·return path 적용, 경로 probe,
자동 전환/rollback은 아직 구현하지 않았다. `priority`, `cost`, `drain`, `disabled`는
승인 메타데이터다. 성공한 binding 응답은 실제 uplink 연결 성공을 의미하지 않는다.

## 사용 순서

PKI가 초기화된 controller를 실행하고 노드를 정상 enrollment한다. 관리자 명령은
기존 Unix admin socket과 OS 자격 검증을 사용하며 offline 파일 편집으로 대체하지 않는다.

1. [JSON 예제](../../configs/relay-catalog.example.json)를 복사한다. 예제의 공개키·주소는
   설명용이다. 실제 relay의 공개키, 이미 등록된 node ID, 도달할 target prefix와 probe
   주소, endpoint, underlay 이름으로 교체한다. 전용 pool은 기존 `vpn_cidr`와 겹치면 안 된다.
2. 최초 발행은 `generation=0`, 빈 controller ID를 사용한다. 그 이후에는 status에
   반환된 `relay_catalog.controller_id`와 `generation`을 명시해 교체한다.

```bash
vpnctl controller relay status --config controller.yaml
vpnctl controller relay apply --config controller.yaml \
  --file relay-catalog.json --generation 0 --ttl 1h

# 이후 갱신: 아래 두 값은 최신 status에서 읽은 실제 값으로 지정
vpnctl controller relay apply --config controller.yaml \
  --file relay-catalog.json --controller-id "$CATALOG_CONTROLLER_ID" \
  --generation "$CATALOG_GENERATION" --ttl 1h

vpnctl node relay refresh --config node.yaml
vpnctl node relay status --config node.yaml
# 아래 명령은 cache를 갱신하지 않는 저수준 조회·binding이다.
vpnctl node relay catalog --config node.yaml
# 공개키의 비밀키는 노드가 소유해야 하며, 기존 node/다른 경로의 키와 달라야 한다.
vpnctl node relay bind --config node.yaml \
  --controller-id "$CATALOG_CONTROLLER_ID" --generation "$CATALOG_GENERATION" \
  --path-id robot-a-primary --public-key "$PATH_PUBLIC_KEY"
```

관리자 apply는 전체 spec을 교체한다. 생략한 path/relay는 제거 대상이다. 실패 후 임의의
최신 generation으로 자동 재적용하지 않는다. status를 읽고 의도한 변경과 비교한다.
최초 apply 응답을 잃었다면 generation 0을 반복하기 전에 status에서 생성 여부를 확인한다.
노드 명령의 `node_id`는 config의 등록 이름에서 가져오며 인증서 identity와 같아야 한다.

## HTTP 계약

- `GET /relay-catalog?schema_version=1&node_id=...`: mTLS 인증 노드의 승인 path와 그
  path가 참조하는 relay/target, 활성 binding만 반환한다. 다른 노드와 폐기 원장은 숨긴다.
- `POST /relay-bindings`: `schema_version`, `controller_id`, `expected_generation`,
  `node_id`, `path_id`, `public_key`를 받는다. IP를 지정하는 필드는 없으며 controller가 할당한다.
- 응답은 `controller_id`, `generation`, `issued_at`, `expires_at`, `node_id`, `spec`,
  `bindings`이다. `schema_version`은 `spec` 안에 있다. Go client는 schema·시간·소유권·
  key/IP/hash 일관성과 응답 크기를 검사하고, bind 응답에서 요청한 key/path를 확인한다.
  호출 사이의 세대 역행/동일 세대 내용 변경은 `node relay refresh`의 영속 cache가 검사한다.
- plaintext/인증 identity 없음은 401, 다른 노드 또는 폐기된 자격은 403, 없는 catalog/path는
  404, invalid schema/definition은 400이다. stale CAS·만료·용량 부족은 409이며
  `relay_catalog_conflict`, `relay_catalog_expired`, `relay_catalog_capacity`로 구분한다.
- 저장 오류는 500이다. rename 이후 directory fsync 실패로 내구성이 불확실하면
  조회/status는 503 `relay_catalog_uncertain`을 반환한다. 같은 mutation을 재시도하면
  directory sync를 먼저 확인한다. 응답을 잃은 binding 재시도는 추가 IP를 할당하지 않는다.

binding은 인증된 요청 주체와 승인 path의 관계를 확인한다. WireGuard 비밀키 보유를
증명하는 handshake는 아직 수행하지 않는다. 이미 예약된 키의 타 경로 재사용은 막지만,
알려지지 않은 공개키를 먼저 제출한 공격자의 실제 비밀키 소유 여부를 증명하지는 않는다.

## 세대·수명·변경 제약

catalog identity는 최초 발행 시 생성하며 generation은 apply, 신규 binding, 수신 주체 변경,
path 또는 relay grant가 있는 node removal마다 증가한다. 레거시 heartbeat와 동일 binding 재시도는 증가시키지 않는다.
신규 binding과 apply는 최신 세대에 대한 CAS를 요구한다. 같은 path/key 재시도는 과거의
양수 세대도 수락한다. 다른 controller ID나 미래 세대는 거절한다.

유효기간은 관리자 apply 시점부터 1분~24시간이며 기본 CLI 값은 1시간이다. binding과
node removal은 유효기간을 연장하지 않는다. 만료되면 노드 조회·binding을 거절하고
관리자 status/apply는 허용한다. 자동 갱신 작업은 제공하지 않는다. 만료/폐기만으로
기존 OS peer나 트래픽이 차단되는 기능도 이 단계에는 없다.

binding 이후 해당 path의 노드·relay·key generation·endpoint·underlay·target 정의는
변경할 수 없다. `priority/cost/drain/disabled`, relay `site`는 변경할 수 있다. drain 또는
disabled인 path에는 신규 binding을 할당하지 않으며 기존 binding 조회/재시도는 허용한다.
bound path 제거는 먼저 별도 revision에서 disabled로 바꿔야 한다. 실제 flow drain이나
relay 설정 제거 완료를 검사하는 절차는 후속 dataplane 구현의 책임이다.

unbound relay 키 교체는 `key_generation`을 정확히 1 증가시킨다. bound path가 참조하는
키를 바꾸려면 새 relay/path ID로 승인하고 후속 배포 절차로 옮겨야 한다. 같은 키로
세대만 바꾸거나 과거 키를 재도입하는 요청은 거절한다.

## 주소·키와 자원 한도

- 명시적 IPv4 prefix, literal IPv4 UDP endpoint, TCP target probe 계약만 지원한다.
  DNS, IPv6, default tunnel, link-local/loopback/multicast/reserved ranges는 거절한다.
  endpoint가 VPN pool/target prefix 안에 들어가거나 target들이 겹치는 것도 거절한다.
- pool은 `/16`~`/30`이며 network/broadcast 및 최대 64개의 예약 주소를 제외한다.
  pool과 예약 주소는 초기화 후 불변이다. 모든 path는 relay가 달라도 서로 다른 IP를 가진다.
- 활성 relay 4개, target 32개, node 32개, node당 path 8개/underlay 4개,
  relay당 endpoint 8개, path당 target 8개가 상한이다. `(node, relay, underlay)`는 유일하다.
- 현재 registry 계보 전체에서 path ID 1,024개, relay ID 64개, relay key 128개가 상한이다.
  제거된 ID·키·IP는 원장에 보존한다. pool/원장 한도 도달 시 새 할당을 거절한다.
  자동 GC나 안전한 원장 초기화 기능은 없다. 한도에 맞춘 수명 계획이 필요하다.
- 공개키는 canonical X25519/base64이며 low-order 값을 거절한다. 레거시 등록 키의
  high-bit/field 표현 별칭도 같은 키로 비교해 catalog 예약을 우회하지 못하게 한다.

## 저장·백업·운영 경계

catalog와 binding은 기존 `registry.yaml`의 한 원자적 교체에 포함된다. node removal은
노드 identity 삭제, path 제거, binding 폐기를 같은 registry에 저장한다. 활성 경로의
원장만 지우는 offline removal은 거절한다. 인증서 revoke는 API 접근을 차단하지만
노드/path를 삭제하거나 이미 설치된 WireGuard peer를 제거하는 명령은 아니다.

처음 catalog를 발행하면 registry version이 1에서 2로 올라간다. catalog가 없는 기존
설치는 version 1을 유지한다. 이전 바이너리는 version 2/새 필드를 읽지 못하므로 **catalog
발행 후 바이너리만 이전 버전으로 되돌릴 수 없다**. 먼저 기존 PKI backup을 보관하고,
복원은 catalog를 지원하는 버전에서 검증한다. restore는 schema와 binding 불변식을
검사한 뒤 새 목적지에 기록한다. 기존 PKI 백업에는 catalog 원장도 포함된다.

relay 수신 주체를 처음 승인하면 registry는 version 3으로 올라간다. 마지막 grant를
철회한 뒤에도 v3을 유지하며 [수신 주체의 업그레이드 계약](relay-recipient.md)을 따른다.

백업 시점 이후 할당/폐기된 key/IP 정보는 그 백업에 없다. 오래된 백업 복원은 최신
원장과 동등하지 않으며 실제 배포된 peer와 대조해야 한다. node cache의 세대 역행 거절과
명시적 재승인 절차 없이 이전 snapshot을 최신 승인으로 자동 취급해서는 안 된다.

관리 변경은 기존 admin audit에 actor/operation/result를 남기고 신규 binding은
node/path/generation을 기록한다. 전용 catalog UI, 만료 경보, dataplane 성공 관측은
제공하지 않는다. M2 장기 검증이나 M3 자동 전환의 운영 합격을 이 구현만으로 선언하지 않는다.

## 검증

```bash
go test -race ./internal/relaycatalog ./internal/api ./internal/store ./cmd/vpnctl ./internal/controller
VPNCTL_RELAY_CATALOG_SCALE=1 go test -race ./internal/controller \
  -run '^TestRelayCatalogVariableScale$' -count=1 -timeout=5m -v
```

회귀 테스트는 mTLS/Unix IPC, 타 노드 접근·인증서 폐기, 동시 CAS·중복 요청, 저장 전
ENOSPC/rename 이후 불확실성, 재시작·백업 복원·node removal, clock 역행, 잘못된
key/CIDR/schema, pool/원장 한도를 다룬다. 별도 CI는 1/3/8/32노드, 4 relay,
node당 8개 후보의 정확한 binding 수를 확인한다. binding 기록 중 legacy registration과
catalog 조회의 2초 예산, 재시도와 PKI sync도 검증한다. 이 시험은 control plane 부하다.
실제 네트워크 전환 성능과 반환 경로 검증은 #22/#23/#24의 별도 gate다.
