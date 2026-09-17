## 문제와 영향 — P1 / M1 완료 차단

main `a89abea`에서 registry와 bootstrap token 저장은 임시 파일 fsync 후 rename만 하고 부모 디렉터리를 fsync하지 않는다.

- `internal/store/registry.go:93-101`
- `internal/pki/bootstrap.go:283-290`
- 같은 패턴의 node config 저장: `internal/config/config.go:192-221`

파일 내용 fsync와 rename의 원자성만으로 교체된 디렉터리 엔트리의 전원 장애 내구성을 보장할 수 없다. 성공 응답을 받은 node 삭제/lease 변경, token revoke 또는 single-use 소비가 강제 전원 장애 뒤 이전 값으로 돌아갈 가능성을 배제하지 못한다. 반면 authority/credentials의 `pki.WriteAtomic`은 부모 디렉터리를 fsync하고 있어 저장 계층 간 계약도 다르다.

## 확인 근거와 한계

기존 `TestSaveRegistry_RoundTrip` 및 `TestTokenExpiryLegacyMigrationAndFailedAdmission`을 컴파일하고 `strace -f -y -e trace=fsync,fdatasync,rename,renameat,renameat2`로 실행했다. 두 테스트는 PASS하지만 각 교체에서 관측된 순서는 임시 파일 `fsync` → `renameat`이며 이후 디렉터리 `fsync`가 없다. production 소스와 시스템 호출 양쪽에서 누락을 확인했다.

실제 전원 차단 뒤 데이터 부활을 실측한 것은 아니다. 이전 SIGKILL/저장 오류 주입 통과도 이 내구성 결함을 검증하지 않는다.

## 집중 작업

- registry/token/config의 원자 저장 계약을 통일하고 rename 이후 부모 디렉터리 동기화를 수행한다.
- 새 data directory 생성의 내구성 및 기존 파일 migration 조건도 검토한다.
- 특히 **rename은 성공했고 directory fsync가 실패한 경우**를 별도로 다룬다. 단순히 오류만 반환해 controller가 옛 WG/메모리로 rollback하면 디스크에는 새 registry가 남을 수 있다.
- 확정 실패와 결과 불확실 오류를 구분하고 메모리·디스크·WG·token admission의 재조회/복구 정책을 정한다.

## 완료 판단 기준

- [ ] 성공 반환 경로에서 파일과 부모 디렉터리 fsync를 확인한다.
- [ ] create/write/file fsync/rename/directory fsync 각 단계의 오류를 검증한다.
- [ ] rename 이후 오류에서 메모리·디스크·WG가 서로 다른 커밋으로 남지 않으며 불확실 결과를 성공으로 보고하지 않는다.
- [ ] token 소비 기록의 내구성 확인 전에 enrollment callback이 실행되지 않는다.
- [ ] revoke/removal/lease 유지와 재시작·재시도 회귀를 통과한다.
- [ ] 프로세스 종료 검증과 실제 전원 장애 내구성의 검증 한계를 문서에 구분한다.

Refs #9, #10, #11, #12, #13.
