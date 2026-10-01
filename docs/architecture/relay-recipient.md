# 인증된 relay 수신 주체와 승인 배포 조회 (#114)

이 단계는 controller가 **누구에게 어떤 relay의 peer 정보를 제공하는지**를 구현한다.
`vpnctl relay catalog`는 온라인 승인 조회이며 `relay refresh|status`는
[영속 승인 cache](relay-deployment-cache.md)를 관리한다. 로컬 peer 설치·forwarding 설정은
후속 단계다. 조회나 cache 갱신 성공은 WireGuard handshake나 서버 uplink 도달 성공을 뜻하지 않는다.

## 신원과 관리자 승인

기존 node PKI enrollment와 mTLS 인증서를 재사용한다. 별도의 relay 역할 인증서를
발급하지 않는다. 등록 이름, 인증서 CN/URI, relay ID 또는 WG 공개키의 일치만으로
relay 권한을 부여하지 않는다. controller의 Unix admin socket에 접근할 수 있는
관리자가 완료된 enrollment 신원을 각 relay ID의 수신 주체로 명시해야 한다.

```sh
# 기존 node join의 신뢰된 CA/token bootstrap을 완료한 relay 신원에 대해 실행한다.
# 신뢰 동기화·필요한 갱신·로컬 설치·ACK까지 끝나야 최초 grant가 가능하다.
vpnctl relay sync-credentials --config relay-identity.yaml --timeout 20s

vpnctl controller relay status --config controller.yaml

# 최신 status의 controller ID와 generation을 사용한다.
vpnctl controller relay grant --config controller.yaml \
  --controller-id "$CATALOG_CONTROLLER_ID" --generation "$CATALOG_GENERATION" \
  --relay-id relay-a --principal relay-agent-a

# node.name=relay-agent-a, node.controller 및 node.pki_dir을 갖춘 enrollment 설정.
# 조회는 노드 daemon이나 레거시 WireGuard 인터페이스 실행을 요구하지 않는다.
vpnctl relay catalog --config relay-identity.yaml --relay-id relay-a --timeout 20s

# 다시 status를 읽어 현재 generation을 확인한 뒤 철회한다.
vpnctl controller relay withdraw --config controller.yaml \
  --controller-id "$CATALOG_CONTROLLER_ID" --generation "$CATALOG_GENERATION" \
  --relay-id relay-a
```

신원 재사용 때문에 enrollment는 기존 node registry/IPAM에 항목과 VPN 주소를 만든다.
일반 node API의 기존 권한도 유지한다. 따라서 relay 전용 최소 권한 계정 모델은 아니다.
controller와 같은 호스트에서 relay를 실행하더라도 인증서·관리자 승인·WG private key의
책임은 구분한다. WG private key는 이 API나 승인 원장으로 배포하지 않는다.

relay 신원 설정에는 `node.name`, `node.controller`, `node.pki_dir`을 사용한다.
`relay sync-credentials`는 노드 daemon/WG key/인터페이스 없이 PKI 동기화만 수행하고,
결과에 신원과 완료 상태만 출력한다. 자동 갱신 daemon은 아직 제공하지 않으므로 운영
스케줄러가 이 명령을 갱신 기한 전에 반복하고 CA 전환 시 ACK를 확인해야 한다.
기존 legacy node WG key와 relay WG key는 서로 달라야 하며 TLS 전용 신원 설정에는
legacy WG key를 넣을 필요가 없다. 인증서 만료·revoke는 동기화 성공으로 보고하지 않는다.

relay마다 수신 주체는 하나다. 하나의 주체가 여러 relay를 맡으려면 각각 승인한다.
다른 주체로 교체하면 이전 주체는 새 조회에서 403을 받는다. 권한 변경은 catalog와
동일한 CAS를 사용하고 generation을 증가시키며, 승인 만료 시각은 연장하지 않는다.
현재 CAS를 사용한 동일 변경은 세대를 증가시키지 않는다. 응답을 잃으면 status로
결과를 확인한다. 과거 generation으로 재시도한 변경은 자동으로 최신 세대에 적용하지 않는다.

인증서 갱신과 CA prepare/activate/rollback은 신원이 유지되면 grant를 유지한다.
개별 인증서를 revoke하면 기존 keep-alive 연결에서도 요청마다 검증하여 거절한다.
이는 해당 신원의 모든 다른 유효 인증서를 철회하는 명령이 아니다. relay 전체 권한을
없애려면 `withdraw`, 신원 자체를 제거하려면 기존 `node remove`를 사용한다.

신원 삭제는 그 신원에 연결된 모든 grant와 node path의 폐기를 **같은 registry 변경**으로
저장한다. 그 신원이 robot path를 소유하지 않아도 grant를 제거한다. 현재 enrollment는
삭제된 이름을 영구 tombstone으로 거절한다. 다른 이름으로 재등록해도 이전 grant는
상속되지 않으며 관리자가 다시 승인해야 한다. relay descriptor 자체를 삭제해도 grant가
제거된다. catalog apply에 grant를 생략하는 것은 철회가 아니다. 별도 grant 원장을 유지한다.

## API와 응답 검증

`GET /relay-deployment?schema_version=1&relay_id=relay-a`

- 서버는 검증된 mTLS identity로 주체를 정한다. 요청에 `principal_id`를 넣거나 query를
  중복·확장하는 것은 400이다. 잘못된 HTTP method는 405다.
- 응답은 `schema_version=1`, `controller_id`, `generation`, `issued_at`, `expires_at`,
  `principal_id`, `relay_id`, `spec`, `bindings`다. 응답에 `Cache-Control: no-store`를 지정한다.
- spec은 해당 relay 하나, **bound이면서 disabled가 아닌 path**, 그 path가 참조하는 target만
  포함한다. pool CIDR은 lease 검증에 필요하다. pool 예약 주소, 타 relay descriptor와 binding,
  다른 수신 주체, 폐기 원장은 노출하지 않는다. drain은 기존 binding을 유지한다.
- 활성 peer가 0개여도 승인된 relay descriptor를 포함한 빈 deployment를 반환한다.
  이는 해당 relay에 설치할 활성 peer가 없다는 뜻이며 누락 응답이 아니다.
- Go client는 1MiB 이하의 단일 JSON, 알 수 없는 필드, schema·주체·relay·시간·path/binding
  대응·키·정확한 `/32`·definition hash를 검사한다. 잘못된 응답은 빈 결과와 오류를 반환한다.
- 신원 없음은 401, 미승인/다른 relay/존재하지 않는 relay는 동일한 403
  `relay_recipient_denied`다. 권한 없는 주체에게 catalog 존재 여부를 구분해 주지 않는다.
  폐기 인증서는 기존 PKI 403이다. 승인 만료는 409 `relay_catalog_expired`다.
  registry 내구성 불확실 시 503 `relay_catalog_uncertain`으로 승인 사용을 막는다.

권한 검사와 view 복사는 같은 committed registry snapshot에서 수행한다. 철회가 저장되기
전에 읽기 승인된 요청은 완료될 수 있다. 서버 응답 자체를 이미 전달된 메타데이터의 원격
회수로 해석하지 않는다. API는 저장된 파일이나 설치된 peer를 제거하는 push 채널이 아니다.

## 저장과 업그레이드

grant는 `relay_catalog.recipient_schema=1`과 `recipients`로 보관한다. 첫 grant에서 registry를
v2에서 **v3**으로 올리며 마지막 grant를 제거해도 v3을 유지한다. 신원 제거, grant 철회,
backup/restore, 재시작에서 이 계약을 유지한다. v0/v1/v2 registry는 계속 읽지만 처음부터
grant가 없는 것으로 취급한다. node catalog schema와 node cache 파일은 변경하지 않는다.

구버전 바이너리는 v3 registry/backup을 거절한다. downgrade를 위해 버전 숫자나 grant
필드를 수동 삭제하지 않는다. 업그레이드 전에 기존 backup을 보존하되, 과거 backup 복원은
이미 철회한 권한과 과거 generation을 복원할 수 있다는 기존 복원 경계를 지켜야 한다.
relay cache는 controller identity 고정·세대 역행·같은 세대의 내용 변경을 검증한다.

## 후속 peer 적용 단계의 필수 조건

현재 CLI는 영속 cache의 offline 유효성 판정을 제공하지만 설치된 peer의 만료 처리는 제공하지 않는다.
#114를 닫기 전에 다음을 구현하고 실제 커널에서 검증한다.

- cache 판정을 실제 적용 경로에 연결한다. 이미 설치한 peer의 만료/철회 시 차단 시점,
  갱신 주기와 감독 프로세스 자체가 중단될 때의 처리를 운영 계약으로 먼저 확정한다.
- 로컬 WG key 검증, exact source `/32`, 목적지 제한, 소유 자원 journal/복구,
  외부 peer·route·firewall 보존. AllowedIPs만으로 target 접근 권한을 제한할 수 없다.
- 2 relay × 2 underlay에서 제품 명령으로 peer를 설치하고 실제 별도 서버 TCP echo와
  SNAT/명시적 반환 경로, 승인 밖 목적지·위조 source의 차단을 검증한다.

수신 주체·API 테스트는 실제 mTLS/Unix IPC, CA 갱신/전환/rollback, 인증서 폐기,
삭제 이름 재등록 거부, CAS 경쟁과 반복 무권한 요청, rename 전후 저장 실패,
v3 재시작·backup/restore, 1/3/8/32 node의 relay별 정확한 응답 개수를 포함한다.
