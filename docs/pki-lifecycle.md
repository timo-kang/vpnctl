# PKI 수명주기와 운영 절차

대상은 로봇과 controller 사이 VPN 제어 API의 인증서·신뢰 상태다. 계획된
인증서 갱신과 CA 교체는 실행 중인 controller/agent에서 처리한다.
WireGuard 커널·다중 relay·통신망 변경에 따른 실제 서버 uplink 연속성은
M3의 별도 네트워크 검증 대상이다.

## 상태와 저장 계약

| 위치 | 내용 및 권한 |
|---|---|
| controller `pki/authority.json` | CA/server 키·인증서, 발급 metadata, 폐기, CA 전환, trust acknowledgement, 재시도용 갱신 응답. `0600` |
| controller `pki/authority.initialized` | 권한 저장소가 사라진 경우 새 CA로 초기화하지 않도록 하는 표식. `0600` |
| controller `pki/bootstrap-tokens.json` | 기존 TTL·single-use·승인 이력. `0600` |
| controller `registry.yaml` | 노드·VPN lease·영구 삭제 identity. `0600` |
| node `pki_dir/credentials.json` | CA bundle, 현재 client cert/key, trust generation, 미완료 갱신의 CSR/key. `0600` |
| node `pki_dir/credentials.initialized` | 현재 JSON 유실 시 이전 PEM 자격증명으로 돌아가지 않도록 하는 표식. `0600` |
| node `pki_dir/credentials.lock` | 여러 node/CLI 프로세스의 자격증명 갱신 충돌 방지. `0600` |

신규 PKI 디렉터리는 `0700`으로 만든다. 기존 디렉터리를 가져온 경우 소유자와
접근 권한을 함께 점검한다. node credential과 authority는 각각 하나의 파일로
교체하므로 key/cert 또는 CA/폐기 상태가 서로 다른 세대로 읽히지 않는다.
파일과 부모 디렉터리에 fsync를 수행하며 rename 이후 fsync 실패는 결과가
불확실한 오류로 보고한다. 이미 교체된 authority는 다시 읽어 메모리의 폐기
상태가 이전 값으로 되돌아가지 않게 한다.

기존 controller의 `ca.crt`/`ca.key` 및 `server.crt`/`server.key`는 최초 migration에
사용한다. 이후 실행 기준은 `authority.json`이다. 기존 PEM 파일을 수정해도
운영 상태가 바뀌지 않는다. CA cert/key 중 하나만 존재하면 자동 교체하지 않는다.
기존 파일은 권한을 제한한 migration backup으로 보관하거나 전환 검증 후 폐기한다.
퇴역 CA의 키는 authority에서 제거되지만 이전 backup/legacy 파일에는 남을 수 있다.

기존 node의 `ca.crt`/`client.crt`/`client.key`는 credentials JSON과 초기화 표식이 모두
없을 때만 읽는다.
첫 sync가 정상 완료되면 JSON으로 이전한다. 구버전 바이너리는 새 상태 형식과
폐기/전환 정책을 강제하지 못하므로 단순 실행 파일 교체로 downgrade하지 않는다.

## 설정과 자동 갱신

```yaml
controller:
  pki:
    ca_expiry: 87600h
    server_expiry: 8760h
    client_expiry: 8760h
    server_renew_before: 720h
    client_renew_before: 720h
    check_interval: 1m
    ca_overlap: 24h
    key_algorithm: ecdsa-p256
```

수명 기본값은 CA 10년, server/client 1년이며 갱신 window의 기본값은 각 수명의
1/3이다. 수명은 3초 이상, 갱신 window는 1초 이상이면서 수명보다 짧아야 한다.
controller check interval은 10 ms 이상이면서 두 window보다 짧아야 한다.
Overlap은 최소 1초이며 기본 24시간이다. 실제 배포에서는 예상 통신 단절 시간과
복구 시간을 감당할 충분한 window/overlap을 지정한다.

노드의 장기 실행 루프(`node run`, `node serve`)는 최대 1분 간격으로 신뢰 상태를
조회하고 만료가 가까워지면 더 자주 확인한다. 갱신 실패 시 1·2·4초부터 최대
1분까지 재시도 간격을 늘리되, 남은 수명이 짧으면 간격을 줄인다. 한 번 실행하고
종료하는 CLI는 최신 자격증명을 읽으며 갱신 루프를 소유하지 않는다.

발급 인증서의 만료는 서명 CA의 만료를 넘지 않는다. CA 만료 때문에 수명을 더
늘릴 수 없으면 반복적으로 새 키를 발급하지 않고 CA 교체가 필요함을 노출한다.
이 상태에서도 로컬 관리자 접속을 유지하여 교체·복구를 수행할 수 있다.

갱신은 기존 유효 identity로만 요청할 수 있다. CSR subject를 다른 노드로 지정해도
인증된 identity로 발급한다. 동일 부모 인증서/발급 CA의 재시도에는 동일 CSR을
사용해야 한다. 노드는 요청 전 CSR/key를 디스크에 저장하고 controller는 서명 결과를
발급 metadata와 함께 저장한다. 응답 유실 후 재시도는 추가 인증서를 발급하지 않는다.
다른 CSR을 반복 제출하면 거절한다. 임의의 조기 key 교체가 필요하면 관리자 token으로
재가입한다. 만료되거나 폐기된 인증서는 갱신에 사용할 수 없다.

## 최초 등록과 node key 복구

1. controller에서 짧은 TTL의 단일 사용 token을 만든다.
2. `controller pki trust`로 얻은 CA bundle을 검증된 SSH host key 또는 배포 시
   신뢰 채널로 노드에 전달한다. 접속하려는 서버로부터 검증 없이 받은 bundle을
   곧바로 신뢰하지 않는다.
3. node에서 token과 bundle을 함께 사용한다.

```bash
vpnctl controller token create --config controller.yaml --ttl 30m --single-use
vpnctl controller pki trust --config controller.yaml > controller-ca.pem
vpnctl node join --config node.yaml --token <token> --ca-cert controller-ca.pem
```

`--ca-cert`가 없거나 서버 인증서를 검증하지 못하면 token을 보내기 전에 실패한다.
설정된 `pki_dir`의 파일이 없거나 손상되어도 HTTP로 전환하지 않는다. node key 분실,
손상, 인증서 만료는 이 재가입 절차로 복구한다. 삭제되지 않은 동일 identity는
기존 VPN lease를 유지한다. 미완료 renewal과 충돌하는 재가입은 새 자격증명을
원자적으로 설치하며 이전 renewal writer는 CAS 불일치로 덮어쓰기를 중단한다.

## 인증서 폐기와 장치 분실

```bash
vpnctl controller pki status --config controller.yaml
vpnctl controller pki revoke --config controller.yaml --fingerprint <sha256>
```

폐기는 fingerprint로 지정한다. status에 serial과 fingerprint가 함께 제공되므로
운영자가 대상 인증서를 확인할 수 있다. 요청이 성공하면 이미 시작한 보호 API
요청은 종료됐고, 이후 요청은 새 TLS 연결/기존 연결 모두 거부된다. 폐기한 자식
인증서를 renewal response cache에서 다시 받는 것도 거절한다. 다른 유효한 인증서와
WireGuard key의 권한은 별개다.

장치 자체를 분실했거나 노출 범위를 확정할 수 없으면 다음을 수행한다.

```bash
vpnctl controller remove-node --config controller.yaml --name <node-id>
```

해당 identity 전체를 영구 차단한다. 교체 장치는 새 이름과 새 WireGuard key로
등록한다. `wg_apply: true`일 때 controller peer 제거까지 확인한다. controller와
단절된 원격 agent의 stale direct peer는 #20/#23/#24의 수렴 검증 범위에 포함된다.
bootstrap token 노출은 별도로 token revoke를 수행한다.

## 계획된 CA 교체

1. 최신 controller와 agent를 배포하고 `pki status`에서 현재 generation과 인증서를
   확인한다. 구버전 agent는 trust acknowledgement를 하지 못해 진행을 막을 수 있다.
2. `ca-prepare`를 실행한다. old/new root를 배포하되 server/client 발급은 old로 유지한다.
3. 모든 등록 노드가 새 bundle을 저장하고 acknowledgement를 보낼 때까지 기다린다.
   `ca-activate`는 준비되지 않은 첫 노드의 ID와 함께 409로 거절한다.
4. `ca-activate`를 실행한다. 새 server cert가 다음 TLS handshake부터 적용되고,
   노드는 issuer 변경을 확인하면 window와 무관하게 client cert를 갱신한다.
5. 최소 overlap 시간과 모든 등록 노드의 새 CA 인증서 acknowledgement를 확인한다.
   인증서에 최소 여유 수명이 남아 있지 않으면 retire가 거절된다.
6. `ca-retire`로 old CA를 제거한다. 다음 sync에서 node trust bundle도 new root만 남는다.

```bash
vpnctl controller pki ca-prepare --config controller.yaml
vpnctl controller pki ca-activate --config controller.yaml
vpnctl controller pki ca-retire --config controller.yaml
```

네트워크에서 사라진 노드라도 필요한 세대를 저장한 acknowledgement가 이미 있다면
그 증거를 사용한다. 저장 확인이 없거나 인증서가 만료/폐기된 노드는 진행을 막는다.
부재 노드를 일괄 무시하는 자동 force 옵션은 없다. 의도적으로 퇴역시키는 노드는
먼저 remove-node로 처리한다. 최소 overlap 종료만으로 CA를 자동 제거하지 않는다.

계획된 전환의 검증 기준은 **업그레이드된 정상 접속 노드에서 `/fleet/status` HTTPS
요청 실패 0건, controller/agent 재시작 0회**다. PKI 동기화 중 세대가 바뀌어
발생하는 409 응답은 재동기화 대상으로 처리한다. 1·3·8·32개 노드에서 지속적인 HTTPS
요청으로 이를 검증한다. 이 결과가 실제 WireGuard 패킷 무손실이나 partition된 망의
무중단을 증명하지는 않는다. 전환 API timeout이면 status에서 phase/generation을
조회한 후 판단한다. prepare/activate/rollback은 무조건 재실행하지 않는다.

## CA rollback

- prepared 상태에서는 `ca-rollback`이 새 CA 준비를 취소한다.
- 활성화 후에는 서명을 old CA로 되돌리되 두 root를 유지하고 overlap 시간을 다시
  시작한다. 이미 new CA cert를 설치한 노드도 계속 접속해 old CA로 갱신할 수 있다.
- 새 상태의 acknowledgement와 overlap 조건을 충족한 뒤 `ca-retire`한다.
- rollback 상태에서 같은 명령을 반복하면 서명 CA가 다시 뒤집히지 않고 거절된다.
  retire 후에는 이전 CA로 되돌리는 명령이 없다.

## CA key 노출 대응

계획된 overlap은 이전 CA가 아직 신뢰할 수 있다는 전제다. CA private key가 노출된
경우 old root를 계속 신뢰하는 overlap을 해결책으로 삼지 않는다. 기존 controller를
격리하고, 신뢰할 수 있는 새 환경과 새 CA를 준비한 뒤, 각 노드에 새 bundle을
out-of-band로 제공하고 재가입한다. 영향받은 token·node TLS key·WireGuard key도
교체한다. 이 비상 절차는 통신 중단을 수반하며 정상 CA rotation의 가용성 기준과
별도로 관리한다.

## 일관된 backup과 restore

```bash
vpnctl controller pki backup --config controller.yaml --out controller-backup.json
vpnctl controller pki restore --file controller-backup.json \
  --data-dir /var/lib/vpnctl-restored --config-out restored-controller.yaml
```

backup은 registry, token 관리, 인증서 발급/폐기, CA 변경, server 자동 갱신을 같은
controller 상태 잠금 아래에서 읽는다. 설정의 WireGuard private key까지 포함하므로
파일 전체가 비밀이다. 별도 접근 제어가 있는 저장소로 보관한다. 관측 CSV는 포함하지
않으며 필요한 경우 별도 보관한다. restore 시 명시된 CSV 경로는 새 data directory
내 `metrics.csv`로 조정한다.

restore는 live controller나 기존 데이터가 있는 경로 위에 덮어쓰지 않는다. 손상된
형식, 잘못된 key/cert 쌍, CA 전환 구조, renewal cache, registry 주소 충돌을 먼저
검증한다. `restore.pending` 표식이 있는 동안 startup을 거부한다. 중단된 restore는
같은 backup 파일로 다시 실행해 완료할 수 있다. 다른 snapshot으로 이어 쓰지 않는다.

복원 설정의 listen 주소, SAN, 인터페이스, endpoint, 라우팅을 확인하고 원본
controller를 중지한 뒤 복원본을 시작한다. 동일한 WireGuard 인터페이스를 두
controller가 제어하게 하지 않는다. backup 시점 이후 폐기한 인증서/token은 복원본에
자동 반영되지 않으므로 재적용한다. 노드가 복원본보다 높은 trust generation을 갖고
있다면 자동으로 이전 trust로 내리지 않으며 신뢰 채널을 통해 재가입한다.

## 관측과 감사

| 신호 | 의미 |
|---|---|
| `vpnctl_pki_expiry_seconds{kind="server"\|"ca"\|"client"}` | 현재 server, 신뢰 중인 CA 중 가장 빠른 만료, 로컬 client의 남은 초 |
| `vpnctl_pki_certificates{status=...}` | active / expired / revoked / retired_ca / identity_removed client cert 수 |
| `vpnctl_pki_ca_overlap` | prepared/overlap/rollback 중이면 1 |
| `vpnctl_pki_events_total` | controller/node의 발급·갱신·인증 거절·sync 실패 누적 |
| `admin operation` | UID/PID, 관리 operation, 대상 fingerprint, 결과 |
| `CA transition committed` | phase, generation, active/previous/pending CA fingerprint |
| `client PKI sync failed` | 갱신 재시도 횟수와 실패 원인 |

CA 남은 시간이 30일 미만이면 최대 한 시간마다 경고 로그를 남긴다. 노드는 갱신
실패 중 만료가 임박하면 추가 경고를 남긴다. 지표는 controller maintenance 주기와
관리 조회/변경 때 갱신되며 CA 만료·반복 실패·장기간 overlap에 운영 알림을 연결한다.
비밀 key와 token 본문은 감사 로그에 포함하지 않는다.
