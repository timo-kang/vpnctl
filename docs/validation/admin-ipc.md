# M1 #11 — Controller 관리 상태 일관성 검증

기준: `main`의 `2fba145` 위에서 구현한 `fix/controller-admin-ipc`.
검증일: 2026-09-15. Linux, 일반 사용자 권한, Go race detector 사용.

## 구현 계약

- `remove-node`, `token create/list/revoke`는 실행 중 controller의 Unix 소켓만 사용한다.
  OS UID/PID로 관리 주체를 확인하며 TCP API에는 관리 endpoint를 등록하지 않는다.
- controller는 registry 및 PKI 초기화 전에 data directory의 단일 소유권을 확보한다.
  중복 실행은 거부하고, 이전 프로세스의 비정상 종료 후 남은 소켓은 소유권 확보 후 교체한다.
- 노드 삭제는 진행 중 API 요청을 먼저 끝낸 뒤 WireGuard 적용, registry 저장,
  삭제 identity 기록, lease 해제, direct readiness 및 현재 metric label 정리를 수행한다.
  적용/저장 실패는 성공으로 응답하지 않으며 이전 WireGuard 설정 복구를 시도한다.
- 삭제된 identity의 인증서는 protected API 전체에서 차단한다. 새 bootstrap token으로도
  같은 identity를 재등록할 수 없다. 재가입은 새 이름을 사용한다.
- token은 TTL, 단일 사용 여부, 승인 시도 횟수, 마지막 사용 주체/시각, 폐기 시각을 저장한다.
  단일 사용 승인은 registry 변경 전에 기록하므로 이후 실패하거나 응답을 잃어도 소모된다.
  revoke가 성공한 뒤에는 새 bootstrap 승인이 불가능하다. 이미 발급한 인증서는 별도 정책이다.

## 자체 리뷰에서 조치한 결함

| 결함 | 영향 | 조치 및 회귀 검증 |
|---|---|---|
| 관리 CLI의 별도 파일 수정과 controller 메모리 불일치 | 삭제 노드 잔존 및 동시 변경 유실 | controller 소유 IPC, 단일 소유권, 동시 registry/토큰 변경·재시작 검증 |
| 삭제 후 기존 인증서나 bootstrap으로 identity 부활 | 해제 lease 재사용과 기존 권한이 충돌 | registry에 영구 삭제 기록 저장, 인증/등록 경로에서 거부, 실제 TLS 연결로 반복 시도 |
| 평문 모드 direct report가 삭제 기록을 검사하지 않음 | 삭제된 readiness와 metric label 재생성 | 평문 authorizeNode에도 삭제 검사, 100회 direct report/등록 재시도 |
| 관리 서버 Close가 handler 종료까지 기다리지 않음 | 소유권 해제 뒤 이전 handler가 registry 쓰기 가능 | Shutdown으로 승인된 mutation 종료까지 소유권 유지, 저장을 지연시킨 종료 경합 테스트 |
| `token revoke <token> --config ...`의 flags 파싱 중단 | 문서화된 명령이 다른 설정을 사용하거나 실패 | token-first/flags-first 모두 실제 CLI 프로세스로 검증 |
| 비어 있는 토큰 저장소를 초기 설치로 취급 | 전부 폐기한 뒤 재시작하면 새 토큰 발급 | 파일이 없는 최초 초기화만 발급, 전부 폐기 후 강제 종료/재시작 검증 |

## 테스트 범위

| 테스트 | 조건 | 확인 내용 |
|---|---|---|
| `TestAdminRemovalOverUnixAndTLSRevokesIdentityAcrossRestart` | 실제 Unix socket + TLS + bootstrap + mTLS | 삭제 직후 fleet/candidates/direct 상태 및 controller WG 구성에서 제거, 기존 인증서 30회 등록/조회 거부, lease 재사용, 재시작 후에도 거부 |
| `TestAdminVariableMeshConcurrentMutationsAndRestart` | 2 / 16 / 64 / 253개 기존 노드, 모든 노드 사이 양방향 readiness | 신규 N개 등록으로 2N population 구성 후 최대 8개 동시 작업으로 N개 삭제·토큰 생성/폐기 실행, 삭제 ID별 3회 부활 시도 거부, 재시작 후 N개 신규 노드·N개 삭제 기록·N개 폐기 이력 유지 |
| 동일 메쉬 테스트의 최대 규모 | 기존 253개, 교체 중 최대 506개 identity, 기존 readiness 63,756개 방향성 간선 | 삭제 대상의 outgoing/incoming readiness 모두 제거, 신규 등록 유실 및 주소 충돌 없음 |
| `TestBootstrapSingleUseReplayAndRevocationThroughIPC` | 실제 TLS bootstrap 32개 동시 요청 | 동일 단일 사용 토큰 승인 정확히 1회, IPC revoke 후 50회 재사용 거부 |
| `TestSingleUseConcurrentAdmissionAndRestart` | 서로 다른 TokenStore 인스턴스 64개 | 공유 flock 하에서 단일 사용 승인 1회, 재시작 후 사용 주체·횟수 유지 |
| `TestRevokeWaitsForAdmittedUse` | 승인 callback을 지연시킨 뒤 revoke | 승인 완료 전 revoke 성공 금지, 완료 후 재승인 거부 |
| `TestRemoveFaultsLeaveAllStateUnchangedAndRecover` | ENOSPC / EROFS / rename EIO / WG 실행 실패 주입 | 성공 응답 금지, registry/삭제 기록/readiness 유지, 저장 실패 시 이전 WG 구성 복원, 장애 해제 후 삭제 성공 |
| `TestTokenAdmissionAndRevokeFailOnUnwritableDirectory` | 실제 디렉터리 쓰기 권한 제거 | 토큰 저장 실패 시 등록 callback 실행 금지 및 폐기 성공 오보고 금지, 권한 복구 후 승인 가능 |
| `TestAdminCLIProcessesAndCrashRestart` | production CLI entrypoint를 별도 프로세스로 실행 | 중복 controller 실행 거부, CLI 옵션 전달, SIGKILL 이후 소켓 복구, 삭제/폐기 유지, offline 명령 파일 변경 없음 |
| `TestAdminMalformedBodiesDoNotMutateState` | 알 수 없는 필드, 잘린 JSON, 복수 JSON, 제어문자 identity, 1 MiB 초과 입력을 10회 반복 | 400 응답 및 토큰 상태 유지 |
| `TestAdminBoundaryLockAndAudit`, `TestAdminRejectsUnsafeSocketPaths` | TCP 관리 접근, 미인증 handler, 소켓 권한, symlink/공개 디렉터리/일반 파일 경로 | 비인가 경로 거부, 파일 보존, 감사 로그에 actor/target/result 존재 및 토큰 평문 부재 |
| `TestRemovalDrainsAdmittedRequests`, `TestAdminShutdownWaitsForMutation` | 요청/저장 완료를 채널로 지연 | 삭제 후 늦은 쓰기 및 종료 시 소유권 조기 해제 방지 |
| `TestRestartRejectsConflictingRemovedIdentity` | legacy name-only active node와 삭제 ID 충돌 | 마이그레이션 전후 충돌 거부, 실패 시 원본 파일 보존 |

## 재현 명령과 결과

```bash
go test -race ./...
go vet ./...
go build -o /tmp/vpnctl-admin-review ./cmd/vpnctl
git diff --check

go test -race -shuffle=20260915 -count=3 \
  ./internal/controller ./internal/pki ./cmd/vpnctl \
  -run 'Test(AdminVariableMesh|AdminRemovalOverUnix|BootstrapSingleUse|RemovedPlainNode|AdminShutdownWaits|SingleUseConcurrent|RevokeWaits|AdminCLIProcesses)'
```

전체 race 테스트, 정적 검사, CLI 빌드 및 diff 검사를 통과했다.
고정 seed `20260915`로 순서를 섞은 핵심 테스트도 3회 반복 통과했다.
반복 실행 시간은 controller 63.046초, PKI 1.108초, CLI 1.498초였다.

## 검증 한계와 후속 작업

- 이번 테스트의 WireGuard 부분은 실제 설정 생성과 command runner 계약을 검증하고,
  실행 실패를 주입한다. 커널 WireGuard handshake, packet 전달, route 반영은 검증하지 않았다.
  일반 사용자 환경에서 `unshare --user --map-root-user --net true`가
  `uid_map: Operation not permitted`로 실패해 격리된 실제 네트워크 시험을 수행할 수 없었다.
  253개 테스트 노드는 registry/제어 상태 규모이며 253개 실제 네트워크 네임스페이스가 아니다.
- controller의 삭제 성공과 망 전체의 즉시 packet 격리는 다른 계약이다. 원격 agent는
  candidates 갱신 후 direct reconcile에서 peer를 제거한다. controller와 단절된 agent는
  stale peer를 유지할 수 있으며, 이 기간의 해제 lease 재사용까지 포함한 검증이 필요하다.
  #20 / #23 / #24의 stale-state, 경로 reconcile, fault matrix에서 다룬다.
- 이번 identity 단위 차단은 인증서 일련번호별 폐기·자동 갱신·CA rotation을 대체하지 않는다.
  이 기능들은 다음 M1 작업 #12에서 구현한다.
- 저장 실패 주입과 SIGKILL 재시작을 검증했다. 전원 장애 내구성, 실제 디스크 고장,
  WireGuard 적용과 rollback이 함께 실패했을 때의 자동 수렴은 이 결과로 보장하지 않는다.
- legacy token 배열은 mutation 때 version 1 형식으로 이전한다. 운영 업그레이드 전
  전체 data directory를 백업하고, 구버전으로 단순 실행 파일 교체를 하지 않는다.

253개 동시 HTTP 관리 요청의 throughput/SLO를 이 무결성 테스트로 보장하지 않는다. API timeout은 30초이며, 영속 mutation 대기열의 overload admission과 명시적 backpressure는 별도 운영 검증 대상이다.
