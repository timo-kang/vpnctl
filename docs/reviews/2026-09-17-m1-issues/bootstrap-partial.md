## 문제와 영향 — P2 / M1 등록 트랜잭션 누락

`internal/controller/server.go:525-535`는 bootstrap에서 registry를 먼저 커밋한 뒤 authority에 인증서 발급을 저장한다. 뒤 단계가 실패하면 실패 응답을 반환하지만 이미 registry에 들어간 node/lease/online 상태를 되돌리거나 미완료 등록으로 표시하지 않는다.

인증서가 한 장도 없는 노드가 fleet의 online node로 남고 주소를 점유한다. CA 전환은 registry의 모든 노드 acknowledgement를 요구하므로 (`pki_admin.go:38-47`, `authority.go:606-613`) 정상적인 CA activation도 이 노드에서 막힌다. 단일 사용 token 소비가 실패에도 유지되는 것은 의도된 정책이며, 여기서 수정할 것은 registry의 완료 상태와 복구 절차다.

## 재현 근거

main `a89abea`의 격리 사본에서 `TestReviewBootstrapIssuanceFailureMustNotPublishLiveNode` 실행:

1. 정상 PKI/token을 생성한다.
2. authority 저장 대상에 파일 교체 오류를 주입한다. token/registry 쓰기는 정상이다.
3. 실제 HTTPS bootstrap을 수행하면 발급 오류로 실패한다.
4. 저장 경로를 복구해도 registry에는 online node 1개, authority에는 client certificate 0개가 남는다.
5. CA prepare 성공 뒤 activate는 해당 노드의 acknowledgement 부재로 거절된다.

race 모드 3회 모두 같은 결과였다. 오류 주입은 임시 테스트 디렉터리에서만 수행했다.

## 집중 작업

- enrollment의 reserved/pending/issued/active 상태와 영속 커밋 경계를 정의한다.
- 발급 실패 시 safe rollback 또는 명시적 pending 상태·재시도·만료 정리를 구현한다.
- 성공적으로 반환하지 못한 기존 identity 재가입과 신규 등록을 구분한다.
- CA gate와 fleet online/lease 정책이 미완료 enrollment를 처리하게 한다. 실제 미갱신 기존 노드를 gate에서 무조건 제외해서는 안 된다.

## 완료 판단 기준

- [ ] registry 성공→authority 실패 및 응답 유실→재시도에서 상태가 명시적으로 일관된다.
- [ ] 발급하지 못한 신규 노드를 정상 online으로 광고하지 않는다.
- [ ] pending/실패한 등록이 정상 노드의 CA rotation을 영구 차단하지 않는다.
- [ ] single-use 소비는 유지하고 재가입 token/CSR/identity 정책을 보존한다.
- [ ] 실패 중 controller 재시작, 기존 identity 재가입, 주소 재사용/중복 및 rollback 실패 검증이 있다.

Refs #9, #11, #12, #13.
