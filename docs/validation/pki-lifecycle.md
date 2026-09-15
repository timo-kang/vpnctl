# M1 #12 — 인증서 수명주기 구현·검증

기준: PR #33 병합 후 `main`의 `f8a5b51` 위에서 구현한 `feat/pki-lifecycle`.
검증일: 2026-09-15. Linux 일반 사용자 환경, Go race detector 사용.

## 완료 기준별 상태

| #12 기준 | 현재 근거 | 판정 |
|---|---|---|
| 설정 가능한 임계 시점 전 client/server 자동 갱신 | 8초 인증서와 6초 renewal window, 실제 TLS 요청 및 파일 교체, 만료 연장 확인 | 통과 |
| 폐기 인증서의 모든 protected API 즉시 거부 | 요청마다 현재 CA/만료/폐기 검사, 이미 연결된 TLS 세션의 fleet 조회·renew 반복 거부 | 통과 |
| CA 교체 중 uplink 가용성 | 1/3/8/32노드에서 CA prepare → activate → retire 중 지속적인 HTTPS 요청 실패 0건 | 제어 API 통과; 실제 WireGuard 경유 패킷 검증 필요 |
| 만료·갱신 실패·폐기·CA overlap 관측 | PKI gauge/counter, 관리·갱신·CA 전환·복원 구조화 로그, 실제 HTTPS `/prom/metrics` 조회 | 통과 |
| 일관된 controller PKI/registry 복원 | 동일 상태 잠금으로 config/registry/token/authority snapshot, live·기존 경로 거부, 중단 복원 재개 및 폐기/CA 상태 보존 | 통과 |
| 짧은 수명으로 issuance → renew → revoke → CA rotate | TLS 통합, 별도 CLI 프로세스, CA rollback 및 controller/node 클라이언트 재시작 테스트 | 통과 |

실제 WireGuard 경유 가용성 기준이 남아 있으므로 #12를 자동으로 닫지 않는다.

## 자체 리뷰에서 발견하고 조치한 결함

| 문제 | 영향 | 조치 |
|---|---|---|
| static TLS config와 순차적인 key/cert 파일 쓰기 | 갱신이 실행 중 연결에 반영되지 않거나 찢어진 key/cert를 읽음 | controller handshake별 스냅샷, node 요청별 credential 세대 확인, 단일 JSON 원자 교체 |
| 유효한 연결에서 인증서를 재검사하지 않음 | 폐기/만료/CA 퇴역 후에도 keep-alive 요청 승인 가능 | 매 protected 요청에서 현재 trust와 폐기·유효기간 검증, 변경은 진행 중 요청 종료 후 승인 |
| 인증서 로드 실패 시 HTTP fallback | 손상된 PKI가 인증 없는 경로로 바뀜 | configured PKI는 HTTPS와 유효 자격증명을 필수로 요구 |
| 검증 없는 bootstrap TLS | token을 위조 controller에 노출할 수 있음 | `--ca-cert` 필수, 신뢰 채널로 배포한 root로 검증 후 token 전송 |
| trust 배포 확인 없는 CA 교체/rollback | 아직 새 root를 모르는 노드나 이미 새 cert를 받은 노드 단절 | 세대별 저장 acknowledgement, 최소 overlap, 활성 issuer 확인, rollback 중 두 root 유지 |
| 갱신 요청 무제한 발급과 응답 유실 후 새 CSR 생성 | 발급 이력 고갈 공격 또는 정상 retry의 키 불일치 | renewal window 제한, 부모 cert/발급 CA별 단일 CSR 캐시, 요청 전 pending CSR/key 영속화 |
| authority 또는 credentials JSON 유실 시 초기/legacy 상태로 복귀 | CA 재생성 또는 이전 node 키로 자동 downgrade | 초기화 표식으로 상태 유실을 구분하고 restore/re-enroll 요구 |
| CA 만료 직전 유효기간을 늘리지 못하는 반복 발급 | 불필요한 key·이력 생성, CA 교체 필요성 은폐 | CA 만료로 leaf 수명 제한, 연장 불가 시 발급 중단 및 지표/로그 제공 |
| rename 후 fsync 실패 때 메모리를 이전 값으로 복구 | 디스크에 폐기가 적용됐는데 프로세스가 계속 승인 | 정확히 교체된 authority bytes를 다시 읽어 반영하며 결과는 불확실한 오류로 보고 |
| 여러 node 프로세스의 credential 덮어쓰기 | 새 trust/key 위에 이전 결과를 저장 | 프로세스 공유 flock + 이전 snapshot digest 비교 |
| 중간까지만 복원된 controller startup | PKI·registry·token이 서로 다른 snapshot으로 서비스 | 사전 검증, restore.pending 표식, 동일 backup으로만 재개 |

## 테스트 범위

- 실제 Unix IPC와 TLS/mTLS로 bootstrap, trust 배포, client/server 자동 갱신,
  인증서 폐기, CA prepare/activate/retire/rollback을 실행한다.
- 1·3·8·32개 node credential과 지속적인 HTTPS fleet 요청으로 전환을 확인한다.
  node는 테스트 내 client이며 네트워크 네임스페이스/WireGuard 장치 수가 아니다.
- 인증서 폐기 및 3초짜리 인증서 만료를 기존 HTTP keep-alive 연결에서 검사한다.
- 인증서 64개 동시 발급/폐기 후 재시작해서 이력을 확인한다.
- 동일 renewal CSR 64개 동시 요청은 한 인증서를 반환하고, 다른 CSR 50회 반복은
  거절한다. 캐시된 자식 인증서를 폐기하면 해당 응답도 다시 받을 수 없다.
- controller가 renewal을 저장한 직후 HTTP 응답을 끊는다. node의 pending CSR/key와
  기존 자격증명이 남아 있고, 새 client 인스턴스가 같은 인증서를 회수해 설치한다.
- 저장 실패 주입(ENOSPC), rename 이후 EIO, key/cert 불일치, incomplete legacy CA,
  authority/credential 유실, stale writer CAS 충돌을 확인한다.
- CLI를 별도 프로세스로 실행해서 미지정/잘못된 CA의 bootstrap 거부, 올바른 CA의
  single-use bootstrap, CA 게이트, activate/rollback, revoke, backup/restore를 검증한다.
- backup의 live controller/기존 경로 덮어쓰기, 잘못된 snapshot, 다른 backup으로
  중단 복원 이어쓰기, 미완료 상태 startup을 거절한다.
- authority snapshot 검증기에 10초 fuzz 검사를 실행한다. 최종 실행 142,430건에서
  panic이나 테스트 실패가 없었다. 이 결과는 장시간 fuzzing을 대체하지 않는다.

## 재현 명령

```bash
go test -race ./...
go vet ./...
go build -o /tmp/vpnctl-pki-review ./cmd/vpnctl
git diff --check

go test -race -v -shuffle=20260915 -count=3 \
  ./internal/controller ./internal/pki ./cmd/vpnctl \
  -run 'Test(PKIAutomatic|PKICARotationVariable|PKIRevocation|PKIRenewalSurvives|PKICLI|AuthorityRotation|AuthorityConcurrent|RenewalRetry)'

go test ./internal/pki -run '^$' \
  -fuzz '^FuzzValidateAuthoritySnapshot$' -fuzztime=10s -parallel=2
```

전체 race 테스트, vet, CLI build, diff 검사 통과.
핵심 시나리오를 seed `20260915`로 3회 반복해 통과했다. CA 전환 동안 완료된
`/fleet/status` HTTPS 요청은 총 **23,233건 성공, 0건 실패**였다.

| 노드 수 | 3회 합산 성공 요청 | 실패 |
|---|---:|---:|
| 1 | 280 | 0 |
| 3 | 852 | 0 |
| 8 | 2,521 | 0 |
| 32 | 19,580 | 0 |

반복 검사 실행 시간은 controller 31.742초, PKI 3.208초, CLI 1.866초였다.
최종 snapshot fuzz 검사는 10초 설정에서 142,430개 입력을 실행해 통과했다.
측정 종료 시 의도적으로 취소한 요청과 PKI generation 충돌에 대한 재동기화는
업무 조회 API 오류 측정에 포함하지 않는다.

## 남은 검증과 운영 한계

- 일반 사용자 namespace 실행은 `uid_map: Operation not permitted`,
  `sudo -n unshare --net true`는 `a password is required`로 실패했다.
  호스트 네트워크를 수정하거나 인증 정보를 요구하지 않았다.
- root/CAP_NET_ADMIN이 제공되는 격리 Linux 환경에서 실제 WireGuard로 application
  uplink를 연결하고 동일 CA 전환 동안 packet loss, 연속 단절 시간, handshake,
  route/WG peer 변화, 재시작 후 복구를 측정해야 한다. 이 항목은 #12/#13의 남은 gate다.
- 네트워크 단절이 인증서 남은 수명을 넘어가면 기존 자격증명으로 자동 복구할 수 없다.
  충분한 window/overlap과 신뢰 채널을 통한 재가입이 필요하다.
- CA key가 노출된 비상 상황은 기존 root를 신뢰하는 정상 overlap 절차의 보장 범위가
  아니다. 격리·새 root 배포·재가입 절차를 별도로 수행한다.
- 전체 데이터 디렉터리의 물리 디스크 장애 및 전원 차단 내구성은 검증하지 않았다.
  fsync 호출과 오류 경로를 확인한 결과를 실제 장치 내구성 보장으로 확대하지 않는다.
- backup은 생성 시점 상태다. 이후 폐기된 인증서/token의 복구본 재적용과 node가 더
  높은 trust generation을 가진 경우의 재가입은 운영 runbook을 따른다.
