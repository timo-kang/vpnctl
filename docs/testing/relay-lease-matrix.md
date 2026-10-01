# 릴레이 승인·lease 검증 계약

#127의 시험은 실제 controller, mTLS 등록 identity, 제품 CLI `node relay prepare`,
`relay apply/supervise`, Linux WireGuard/nftables를 연결한다. 별도 Docker 컨테이너 안에
2 relay × 2 underlay 및 애플리케이션 서버를 만든다. 로봇에는 직접 서버에 도달할
underlay/default route가 없다. 시험의 source route·forwarding·SNAT는 명시적 fixture이며
제품의 자동 경로 선택, 승인된 forwarding 정책이나 TCP 세션 이동을 구현한 것은 아니다.

## 재현

```sh
go test -race ./internal/relayapply ./internal/relaycache ./cmd/vpnctl
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
  VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-lease-results \
  scripts/test-netns.sh \
  -test.run='^TestNetns_M3(AuthorityMatrix|LeaseConflicts|LeasePressure|SupervisionScale)$' \
  -test.timeout=12m
```

CI는 동일한 전용 job에서 실행하고 성공/실패 모두 `m3-lease-matrix` artifact를 남긴다.
기존 network job은 이 네 시험만 제외하며 기존 topology/PKI 시험은 유지한다.
M2 24시간 원본, 이전 실행의 컨테이너·namespace·artifact를 재사용하거나 정지하지 않는다.
실제 host 시계 변경·절전·재부팅은 수행하지 않는다.

## 판정 범위

| 시험 | 실제 입력과 완료 조건 | 증거 |
|---|---|---|
| `M3AuthorityMatrix` | withdraw, disabled, peer/endpoint 삭제, key generation 전이, 인증서 revoke, identity remove, 실제 60초 TTL 만료를 네 경로 각각에 적용. 기존 TCP 단절, 새 연결 차단, kernel peer 회수, HTTP 단절 중 재개 금지, 새 승인·명시적 설치 후 새 연결 복구 | `m3-authority-*/report.json`, 경로별 stream JSONL, supervisor JSONL, 공개 kernel inventory |
| `M3LeaseConflicts` | 외부 peer와 승인 회수의 동시 발생, 외부 PSK/route/guard chain, flowtable 출현. 10초 lease보다 오래 기다려 관리 대상 차단·외부 설정 보존·영향 없는 endpoint 통신 지속을 확인 | `conflict.json`, supervisor JSONL, `outcome.json` |
| `M3LeasePressure` | 실제 cache lock, 제품과 동일한 abstract datagram namespace lock, 30초 지연 nft 명령, 가득 찬 4096-byte stdout pipe. 네 경로 기존/새 TCP 차단, peer 잔존, transport outage 중 cached-only 재허가 거절, 새 응답 후 동일 peer 재허가 | `pressure.json`, stream/감독 JSONL, 주입 증거와 공개 kernel snapshot |
| `M3SupervisionScale` | 1/3/8/32 node × 4 path를 1/8 endpoint에 분배. 실제 peer/return-route 수, 빈 endpoint, 반복 supervision, 종료 후 8 endpoint 만료 및 HTTP 실패 중 재개 금지 | `m3-supervision-scale-*/report.json`, supervisor JSONL |
| 동일 namespace 동시 부하 | 32 node/128 peer + 별도 relay cache의 빈 8 endpoint: 총 16 endpoint를 두 supervisor가 처리. refresh/apply/release/잘못된 endpoint 요청 48개를 동시 반복하고 명시적으로 복구 | 규모 report의 성공·busy·거절 수, 메모리, cycle/JSON 크기 |

path/endpoint/key는 이미 bound된 정의를 덮어쓸 수 없다. 경로를 먼저 비활성화하고
삭제한 뒤 새 path ID로 승인한다. identity remove는 이름의 tombstone을 남기므로
replacement identity를 새로 등록하고 별도로 grant한다. 인증서 갱신과 권한 부여는 별개다.

## 시간과 가용성 해석

- 커널의 절대 approval expiry 및 최대 10초 lease와 **시험이 실패를 관측한 시각**은 다르다.
  stream은 기존 TCP socket을 재연결하지 않고 100ms 간격, 500ms timeout으로 검사한다.
  `last_success_at`/`first_failure_at`은 관측 경계이며 packet drop의 정확한 순간이 아니다.
- 감독의 목표 cadence는 1초, 작업 context는 5초다. 규모 보고서는 1초 초과 횟수와 최대
  cycle, JSON bytes, 프로세스 RSS/HWM을 보존한다. 시험의 5.5초 상한은 scheduler/결과
  기록을 포함한 검출 여유이며 제품의 context 예산을 늘리지 않는다.
- cache/namespace lock은 대기열 없이 충돌을 즉시 거절한다. burst에서는 한 종류의 요청이
  모두 거절될 수 있다. 성공률을 숨기지 않으며, 이것을 무중단 가용성 또는 공정한 스케줄링
  보장으로 해석하지 않는다. 운영 호출자는 bounded retry/backoff를 사용한다.
- lease만 만료되고 WG 장치·peer가 유지되었다면 새 검증 응답으로 재허가할 수 있다.
  장치를 회수·재생성하면 handshake 상태가 사라진다. 명시적 양쪽 설치 시험의 복구를
  기존 TCP 세션의 보존이나 relay-only 재시작의 즉각적인 복구 시간으로 해석하지 않는다.
- 실제 peer 수 검증은 모든 fleet 노드의 동시 앱 트래픽 시험이 아니다. 최악 부하/SLO,
  자동 failover, 다른 kernel/nft 버전, 물리 underlay 및 실제 suspend/reboot는 별도 판정이다.

## 반복 거절·재생과 증거 보존

`TestDeploymentRepeatedOutageAndReplayAfterDenial`은 거절을 저장한 뒤 reopen을 반복하며
429/500/503/EOF/timeout 및 과거 generation/다른 controller 응답을 총 84회 주입한다.
새 유효 승인이 오기 전에는 승인 상태가 회복되지 않아야 한다. 기존 cache 시험은
refresh 저장 전후 중단, uncertain marker, high-water와 오래된 상태 복원도 다룬다.
별도 `M3PathTopology`는 SIGSTOP/SIGKILL 및 제한된 tmpfs ENOSPC의 실제 패킷 차단을 다룬다.

실행 manifest의 `suite_commit`, `suite_dirty`, CLI/시험 binary SHA-256, container image,
kernel, CPU/메모리 제한을 결과와 함께 보존한다. dirty 실행은 탐색 증거이며 최종 CI의
정확한 commit/binary 결과와 혼동하지 않는다. `outcome.json`은 실패한 시험에도 공개
kernel 상태를 남긴다. private key·PSK·token·credential cache를 export하지 않는다.

캐시와 controller 원장을 모두 과거로 복원하고 외부의 신뢰 가능한 최신 revision 증거도
잃으면 로컬 high-water만으로 rollback을 발견할 수 없다. 이는 보호되는 모델에 포함하지
않는다. 새 mTLS 응답의 인증은 peer 인증이며 controller 원장 자체의 rollback 방지는 아니다.
원장·백업의 복구 절차와 외부 revision anchor는 별도의 운영 설계가 필요하다.
