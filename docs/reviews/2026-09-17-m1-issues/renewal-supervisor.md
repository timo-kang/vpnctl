## 문제와 영향 — P1 / M1 완료 차단

`node serve`는 cached WG 경로를 복원하고 `syncConfigOnce` 등록에 성공한 후에야 `agent.Run`을 호출한다 (`cmd/vpnctl/main.go:643-670`). 인증서 유지보수 goroutine은 `agent.Run` 안에서 시작한다 (`internal/agent/agent.go:25-32`).

따라서 서버의 registry/WG apply 경로만 일시적으로 실패하고 `/pki/trust`·`/pki/renew`는 정상인 상황에서도, node serve 초기 동기화 재시도 중에는 인증서를 갱신하지 않는다. 남은 유효기간이 지나면 재시도 가능한 등록 오류가 인증서 만료로 바뀌어 자동 복구가 불가능해진다. 갱신 가능한 경로가 있었으므로 문서상의 "망 단절이 인증서 수명을 넘는 경우 재가입 필요"와 다른 결함이다.

## 재현 근거

main `a89abea` 격리 사본의 `TestReviewNodeServeRenewsDuringRegistrationFailure`:

- 실제 production CLI subprocess, 실제 TLS와 6초 client certificate / 4초 renewal window 사용.
- WG/ip만 process-local shim으로 처리하여 호스트 네트워크에 영향을 주지 않는다.
- 등록은 503을 반환하고 PKI trust/renew/ack endpoint는 정상 처리할 수 있게 둔다.
- 3회 반복 모두 등록 53–54회 동안 trust 호출 0회, renew 호출 0회로 인증서가 만료됐다.
- race 검사에서도 같은 결함이 재현됐다.

## 집중 작업

- PKI 유지보수의 소유자를 성공한 agent 실행 단위가 아니라 node serve 수명주기와 일치시킨다.
- VPN-only 노드의 cached uplink 복원 순서를 유지하면서 등록 실패/agent 재시작/backoff 중에도 PKI가 갱신되게 한다.
- node run/serve 사이 중복 renewer, 종료 join, config 재로딩 및 credential CAS 경합을 정리한다.
- 일시 등록 실패가 해제되면 같은 identity/IP/credential 계보로 자동 재개한다.

## 완료 판단 기준

- [ ] 등록/WG 적용만 실패하는 동안 trust/renew는 계속 동작하여 인증서가 만료되지 않는다.
- [ ] 실패 해제 후 수동 rejoin 없이 등록·uplink를 복구한다.
- [ ] cached VPN 경로 없이 controller에 접근할 수 없는 구성에서도 복원→PKI 갱신 순서가 검증된다.
- [ ] 반복 agent 실패/backoff에서 유지보수 중복 실행·goroutine/transport 누수가 없다.
- [ ] SIGTERM과 credential 교체/CAS 경합 회귀를 통과한다.
- [ ] 실제 네트워크 단절이 수명을 넘는 한계는 별도로 유지한다.

Refs #12, #35, #37, #38, #13.
