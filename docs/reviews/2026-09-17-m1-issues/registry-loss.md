## 문제와 영향 — P1 / M1 완료 차단

main `a89abea` 전체 리뷰에서 확인했다. `internal/store/registry.go:35-50`는 registry 파일이 없거나 빈 YAML/null이면 빈 registry를 반환한다. `internal/controller/server.go:78-82`는 기존 controller의 상태 유실과 최초 설치를 구분하지 않는다.

이 파일에는 VPN lease뿐 아니라 `RemovedNodes`의 영구 삭제 기록이 있다. 파일 유실/빈 파일 이후 재시작이 성공하면 전체 노드·lease·삭제 기록을 잃는다. `wg_apply`가 켜진 정상 시작 경로는 빈 registry를 커널로 reconcile하므로 기존 uplink peer 제거로 이어질 수 있다. 같은 이름으로 다시 bootstrap하면 기존에 삭제된 노드의 옛 인증서가 재승인된다.

## 재현 근거

격리된 소스 사본에서 실제 loopback mTLS로 `TestReviewRegistryLossMustNotResetIdentity`를 실행했다.

1. PKI를 초기화하고 노드를 발급/등록한다.
2. `removeNode` 성공 뒤 옛 인증서의 fleet 접근 거절을 확인한다.
3. registry만 각각 삭제 / 0바이트 / YAML `null`로 바꾸고 같은 data_dir·PKI로 NewServer/InitPKI를 수행한다.
4. 세 조건 모두 시작이 성공한다. 관리 token으로 같은 이름을 재가입한 뒤 옛 인증서로 public key 변경 등록이 성공한다.

세 조건을 각각 race 모드에서 3회 반복해 같은 결과를 확인했다. 권한 부활은 별도 certificate fingerprint revoke가 아니라 node removal로 차단했던 인증서에 대한 결과다. 실제 전원 차단은 수행하지 않았다.

## 집중 작업

- 최초 설치와 기존 상태 디렉터리의 손상을 구분하는 영속 초기화/버전 계약을 도입한다.
- 기존 상태에서 registry 누락/빈 파일/null/필수 구조 누락을 fail closed로 처리하고, WG reconcile 전에 시작을 차단한다.
- 정상적인 0노드 registry, legacy migration, 중단된 초기화와 복원 절차를 함께 설계한다.
- 손상 상태의 bootstrap이 삭제 identity 또는 lease를 다시 활성화하지 못하게 한다.

## 완료 판단 기준

- [ ] 위 세 손상 조건에서 controller가 명확한 복원 필요 오류로 시작을 거부하고 WG apply를 실행하지 않는다.
- [ ] 삭제 identity의 옛 인증서는 손상/재시작/복원 경계를 지나도 권한을 되찾지 않는다.
- [ ] 최초 설치와 명시적인 정상 빈 registry는 정상 작동한다.
- [ ] migration/restore 및 중간 실패·재시도에서도 초기화 표식과 registry가 일관된다.
- [ ] 회귀 테스트가 전체 race 및 커널 복구 검증에 포함된다.

Refs #9, #10, #11, #13. #39의 HTTP 지연 수정과 별개의 M1 미완료 항목이다.
