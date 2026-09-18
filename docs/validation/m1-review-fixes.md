# M1 전체 리뷰 후속 수정

기준: PR #42 이후 main `a89abea`. [원래 리뷰](../reviews/2026-09-17-m1-review.md)의
신규 결함 #43–#47을 M1/timo-kang에 배정하고 수정했다. 기존 #14와 #20의 재현된
snapshot 경쟁 및 명시적 direct 실패 무시도 함께 수정했다. #14/#20 전체 제품·경로
검증 요구사항을 완료한 것은 아니다.

## 변경과 실패 계약

| 이슈 | 변경 | 실패/재시도 계약 |
| --- | --- | --- |
| #43 | registry schema/version 검증, 초기화 표식, restore에 표식 포함 | 기존 누락/빈/null 상태는 WG 적용 전에 거부. 정상 빈 registry와 legacy migration은 허용 |
| #44 | registry/token/config/PKI의 공통 원자 저장기 및 디렉터리 체인 fsync | 교체 전 실패는 이전 상태 유지. 교체 후 fsync 실패는 새 파일·메모리·WG 유지, 오류 반환 및 다음 변경 전 동기화 재확인 |
| #45 | node serve 수명의 PKI worker | cached VPN 복원 시도 후 시작, 초기 등록 실패·agent 재시도 중 유지, 설정 대상 변경 시 교체, 종료 시 join |
| #46 | heartbeat, health, 후보 조회, STUN, direct 측정의 실행 분리 | direct는 동시 요청 8개, round당 최대 32 peer, probe/report 15초, 이력 업로드는 별도 유한 큐. peer별 2초 probe/3초 총 요청 한도. 큰 fleet은 round-robin |
| #47 | 발급 후 registry 게시, pending→enrolled/online 가입 상태 | single-use 소비 유지. 실패한 신규 발급은 node/lease 없음. 응답 유실은 같은 이름+새 token으로 복구. 미사용 pending은 관리 삭제 |
| #14 부분 | snapshot mutex 및 각 reader/subscriber에 slice 복제 | consumer 변경이 다른 snapshot을 덮어쓰지 않음. 짧은 key의 표시용 slicing도 안전하게 처리 |
| #20 부분 | 실패 보고 시 양방향 과거 성공 제거 | mutual/either 모드 모두 과거 성공으로 계속 ready가 되지 않음 |

WG peer 적용은 한 worker만 수행한다. probe 결과가 WG를 직접 변경하지 않으며,
새 후보 snapshot은 이전 측정을 취소·회수한다. 늦은 측정 결과가 더 최근 WG desired
state를 덮어쓰는 경로를 제거했다. 이미 서버로 전송된 보고의 프로토콜 세대 검증과
NAT/endpoint 변화·실제 WG handshake 기반 승격은 #20/#23의 후속 작업이다.

32 peer보다 큰 fleet에서는 전체 측정 주기가 길어진다. heartbeat/health의 진행은
유지되지만 readiness TTL 및 측정 주기 조율은 M3 검증에 포함해야 한다. 로봇의
VPN은 서버 uplink에 도달하는 수단이며 다중 relay/통신망 전환 완성으로 해석하지 않는다.

## 재현 및 검증

- 캐시 없는 전체 `go test -race -count=1 ./...`, normal/integration vet, CLI build.
- 원자 저장기의 create/chmod/write/short-write/file-fsync/close/rename/directory-fsync
  오류 주입 및 임시 파일 정리. 디렉터리 fsync 실패 후 재시도도 상위 경로를 동기화.
- 실제 strace로 registry/token 교체 뒤 부모 디렉터리 fsync 확인.
- registry 교체 후 오류에서 register/NAT/remove의 파일·메모리·WG 일치와 재시작 검증.
- single-use 소비/revoke의 불확실 커밋 후 재승인 차단; admission callback 미실행.
- 실제 TLS/CLI로 6초 인증서의 초기 등록 실패 중 갱신, 오류 해제 후 같은 identity/IP
  복귀 및 SIGTERM 종료. 동일 설정 50회 재시도 시 PKI worker 중복 없음.
- race 모드 1/3/8/32 silent peer × 빠른/지연 API × 3회: heartbeat age 약 1초,
  검사 기준 2.5초 미만. 1초 health 설정에서 장애 감지 약 3초, 기준 4초 미만.
  종료 후 FD/goroutine 기준치 복귀, 직접 요청 최대 8개. 취소된 보고의 늦은 완료가
  새 WG 적용 상태를 덮어쓰지 않음.
- monitor snapshot publish/read/subscribe 동시 실행 및 reader 데이터 변경 격리.
- mutual/either 각각 30회 성공→실패 반복 후 즉시 readiness 해제.

모든 커널 검증은 `scripts/test-netns.sh`의 `--network none` disposable Docker와
내부 namespace에서 수행한다. 호스트 네트워크/운영 인증서는 사용하지 않는다.

| 실제 커널 시나리오 | 로컬 결과 |
| --- | --- |
| auto direct, 기본 health, silent peer 1/3/8/32 | PASS, 최대 heartbeat age 1.025초 미만, controller 장애 감지 약 6.92초, 자동 복구 |
| registry 삭제/빈/null 후 controller 재시작 | PASS, 복원 요구 오류, 기존 WG peer/AllowedIPs 유지 |
| 초기 register만 WG 명령 오류로 실패, VPN-only PKI 접근 | PASS, 원래 8초 인증서 만료 시점 이후에도 갱신, 실패 해제 후 동일 identity/lease 재개 |
| 기존 1/3/8/32 PKI lifecycle matrix | PASS, 계획 구간 143,184 probes, 실패 0 |
| command timeout/rollback/shutdown 및 정상 direct injection | PASS |

초기 네트워크 fixture는 PKI-off IPC 준비 확인과 metrics URL을 수정했다. 등록 실패
주입도 변경 없는 WG 설정을 건너뛰는 최적화를 고려해 showconf와 syncconf 모두를
실패시키도록 보완했다. 실제 오류가 발생하지 않은 실행은 회귀 검증 성공으로 세지 않았다.

검증 로그는 `/tmp/vpnctl-review-*.log`, 실제 네트워크 결과는
`/tmp/vpnctl-review-netns-full/`에 있다. GitHub CI는 PR의 현재 head에서 다시 검증한다.
실제 전원 차단/저장장치 장애 시험은 수행하지 않았다. fsync 호출·오류 계약 검증과
프로세스 kill/restart 검증을 물리적 전원 장애 실측으로 확대 해석하지 않는다.

#39의 과거 CI HTTPS timeout 287건 원인 전체가 규명된 것은 아니므로 #39와 M1 최종
gate #13은 별도 판정을 유지한다. M2의 통계/freshness, M3의 다중 relay/underlay 전환,
M4 예측/앱 연동 또한 이 수정의 완료 범위에 포함되지 않는다.
