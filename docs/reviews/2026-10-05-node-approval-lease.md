# #157 노드 승인 수명 보호 자체 리뷰

앱 route 활성화 전에 노드에도 독립적인 만료 차단을 추가했다. `prepare --lease`는
닫힌 후보를 만들고 `node relay supervise`가 새 승인 응답으로 임대를 연다. 실제 앱
route 활성화는 여전히 하지 않는다. 운영 계약과 배포 절차는
[node-approval-lease.md](../architecture/node-approval-lease.md)에 있다.

## 발견한 결함과 조치

| 발견 내용 | 조치 및 검증 |
| --- | --- |
| 새 요청 시각으로 같은 응답의 BOOTTIME 한도를 다시 계산하면 시계 역행이 승인 수명을 늘릴 수 있음 | 같은 세대의 최초 증거를 고정하고, 다음 세대도 controller가 ExpiresAt을 늘린 만큼만 증가 허용. 재시작·재전송·BOOTTIME 경과·wall rollback 단위 시험 |
| 응답 완료 시각을 freshness로 쓰면 지연 응답이 만료 경로를 다시 열 수 있음 | RPC 직전의 두 시계 값을 사용. 재시작은 transient freshness를 잃으며, deadline 이후 도착한 성공 응답도 새 요청 전까지 차단. 명시적 거부를 context 오류로 덮어쓰지 않음 |
| 갱신 도중 journal 저장 실패 후 다른 후보가 계속 승인될 가능성 | 각 후보마다 uncertainty를 다시 확인하고, 두 커널 차단 수단을 각각 시도. 모든 준비 명령 및 journal 실패 경계 시험 |
| 8개 후보 감독 루프와 CLI가 경합하면 target reserve가 즉시 busy로 실패 | 동일한 총 1초 안에서 잠금 획득만 재시도. 작업 자체는 반복하지 않음. 최초 실패 `/tmp/vpnctl-node-lease-scale8` 보존, 수정 후 같은 구성 통과 |
| 최대 20초 관측 배치가 독점 잠금으로 10초 임대 갱신을 막을 수 있음 | 후보 사이에서 전체 보호 후보를 갱신. 단일 관측 3초, 유지관리 5초, 배치 20초를 구분. 실제 blackhole에서 8개 BOOTTIME gate가 활성 상태인지 별도 읽기 샘플링 |
| 현재 승인 상한을 넘긴 커널 임대를 readback에서 발견해도 보고만 할 가능성 | 유효하지 않은 임대 readback은 차단을 함께 시도하고 정상 readiness로 표시하지 않음 |

시험 코드에서도 nft fixture 구문과 하위 테스트 cleanup에 의해 다음 단계의
supervisor가 종료되는 문제를 수정했다. 실패 실행은 끝까지 완료했고 결과 디렉터리를
덮어쓰거나 기존 실행을 취소하지 않았다.

## 로컬 검증 근거

Linux `7.0.0-30-generic`, Docker `--network none`, 실행마다 2 CPU / 2 GiB.
netns와 bpffs는 해당 시험 컨테이너에만 생성했다. 아래 경로는 개발 머신의 원본
증거 위치이며 운영 의존성이 아니다. 변경 중 실행은 manifest에 dirty로 기록된다.
최종 커밋 검증은 PR의 production/race CI 및 업로드 artifact로 추적한다.

| 시험 | 결과 / 증거 |
| --- | --- |
| controller colocated/separate × 보호 후보 1/4/8, 두 대상 | production 6구성 통과, `/tmp/vpnctl-node-lease-matrix` |
| SIGSTOP/SIGKILL 뒤 새 TCP 및 사전에 열린 TCP | 두 신호 각각 별도 연결로 확인, 같은 행렬의 `node-lease.json` |
| cache lock, namespace lock, ENOSPC, stdout backpressure, 느린 nft | 5종 통과. 만료 후 캐시만으로 복구 불가, 새 mTLS 응답으로 복구. `/tmp/vpnctl-node-lease-faults-final` |
| controller 단절 중 유지 및 노드 승인 만료 | 노드는 짧은 기존 승인을 보유하고 릴레이는 새 장기 승인을 받은 상태에서 노드만 차단. 같은 디렉터리 `node-approval-expiry.json` |
| 노드 인증서 철회 | 릴레이 승인은 유효한 채 노드 통신 차단. 뒤이은 단절로 거부가 취소되지 않음. `node-revoked.json` |
| 외부 peer/route/tc/nft 변조 | 해당 후보 차단, 타 후보 유지, 외부 객체 보존, 충돌 해소 후 명시적 복구. `/tmp/vpnctl-node-lease-faults-fixed`의 `node-foreign.json` (동 실행의 다른 초기 fixture 실패는 별도 보존) |
| nft 생성, link up, timer 준비/선택 직후 SIGKILL | 4경계 통과, `/tmp/vpnctl-node-lease-crash` |
| 별도 controller, 8후보, 장시간 blackhole 관측 | 35.96초 / 71회 커널 샘플 모두 활성; 잘못된 정상 경로 선택 없음. `/tmp/vpnctl-node-lease-slow-production` |
| 단위/race 및 정적 검증 | relaycache/relayapply/CLI 회귀, 신규 실패 경계 race, `go vet ./...`, `go build ./...` 통과 |

## 판정 범위

현재 구현은 보호된 노드 후보의 승인 수명 관리와 다음 앱 actuator의 기반이다.
기존 무보호 후보를 자동 업그레이드하지 않는다. 미래 actuator는 `LeaseVersion=3`과
검증된 live guard가 없는 후보를 사용하면 안 된다. target quarantine을 만료 cleanup으로
해제해서 main/default 경로를 다시 열어서는 안 된다.

재사용하는 relayguard의 실제 커널 CAS/replay 시험과 clock 주입 단위 시험은 물리적인
robot suspend + wall rollback의 새 배포 판정을 대체하지 않는다. 해당 물리 경계는
전용 VM/다른 머신에서 별도 검증해야 한다. 공유 개발 머신은 suspend/reboot/clock/network
변경을 하지 않았다. 실제 NetworkManager·Netplan·udev 공존 및 앱 route 전환/검증/LKG
rollback은 #22/#23의 후속 완료 기준으로 유지한다. 기존 M2 24시간 성공 기록은 그대로다.
