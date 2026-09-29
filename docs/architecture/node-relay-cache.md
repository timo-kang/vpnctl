# Node 경로 키와 승인 cache (#105, #21)

`node relay refresh`는 인증된 catalog의 승인 경로마다 WireGuard 키를 생성·보관하고
controller의 key/IP binding을 확인한다. `status`는 controller 접속 없이 그 준비 상태를
읽는다. LTE가 없는 노드도 향후 Wi-Fi/Ethernet과 relay를 통해 서버 uplink에 도달하도록
후보를 준비하는 단계다. 이 명령은 OS interface/route, relay peer, forwarding, NAT를
설치하지 않으며 `usable_cache`는 실제 uplink 성공이나 비밀키 소유 증명을 뜻하지 않는다.

## 실행과 설정

[Catalog 발행](relay-catalog.md)과 node enrollment 이후 실행한다.

```bash
vpnctl node relay refresh --config node.yaml
vpnctl node relay status --config node.yaml
# 운영 환경에서 저장 위치와 짧은 호출 기한을 지정할 수도 있다.
vpnctl node relay refresh --config node.yaml --cache-dir /var/lib/vpnctl-node/relay-cache --timeout 30s
```

위치는 `--cache-dir` → `node.relay_cache_dir` → `<node.pki_dir>/relay-cache` 순서다.
`node.name`과 credential identity가 같아야 한다. 기존 node/server 공개키와 path 키는
분리한다. legacy private key가 설정돼 있으면 공개키를 유도해 쌍의 일치 여부도 검사한다.
`catalog`/`bind`는 cache를 관리하지 않는 저수준 명령으로 남는다. 관리 cache의 path를
다른 키로 수동 bind하면 다음 refresh가 불일치를 거절한다.

refresh는 최대 2분, CAS 충돌 재조회는 최대 256회이며 10~250ms 범위의 지연에 jitter를
넣는다. 더 짧은 `--timeout`과 SIGINT/SIGTERM 취소를 지원한다. 이 기한은 HTTP와 재시도에
적용한다. 운영체제의 멈춘 파일 I/O를 강제로 취소하는 보장은 없다. 실패 시 JSON 보고서를
stdout에 출력하고 0이 아닌 종료값을 반환한다. status는 읽기에 성공하면 만료·차단 상태도
JSON과 종료값 0으로 반환하므로 자동화는 `validity`, `preparation`, `usable_cache`를 검사한다.
손상·권한 오류처럼 cache를 안전하게 열 수 없는 경우는 stderr와 비정상 종료로 보고한다.

현재 node agent의 자동 refresh나 controller의 TTL 자동 연장은 없다. 배포 저장소에서
관리자 승인 갱신과 노드 refresh 주기를 구성해야 한다. 기본 승인 TTL은 1시간이며 binding은
TTL을 연장하지 않는다. 겹친 refresh는 기다리지 않고 busy로 실패하므로 한 실행 주체가
주기를 소유해야 한다. 장애 중 변경된 revoke/disabled/drain은 다음 인증 sync에서 확인된다.
즉시 원격 철회나 기존 OS 경로의 만료 시 처리 정책은 이 cache가 제공하지 않는다.

## 저장과 신뢰 경계

- cache 디렉터리는 실행 UID 소유 0700, 파일은 같은 UID 소유의 단일 hardlink인 일반
  파일 0600이어야 한다. symlink/FIFO/hardlink를 거절한다. 상위 디렉터리는 root 또는
  실행 UID 소유이고 group/other 쓰기를 허용하지 않아야 한다. 예외는 root 소유 sticky
  디렉터리(`/tmp`)다. 그룹 쓰기 가능한 checkout 아래에 개인 키를 두지 않는다.
- `cache.lock`의 비차단 프로세스 lock을 열려 있는 동안 보유한다. lock 파일을 직접
  삭제하지 않는다. 동일 UID/root 자체를 악의적 공격자로부터 격리하는 저장소는 아니다.
- `state.json` 한 파일에 키 원장, 마지막 수락 snapshot, 인증된 최고 generation과 digest,
  갱신 상태를 저장한다. 최대 2MiB다. 임시 파일 fsync → rename → 디렉터리 fsync 뒤에만
  성공을 보고한다. `initialized` 표식이 있는데 state가 없으면 새 키로 초기화하지 않는다.
- private key는 binding POST 전에 내구성 있게 저장한다. 응답을 잃거나 controller commit
  뒤 로컬 저장이 실패해도 같은 키로 GET/재시도한다. 재시작 시 기존 키를 새로 만들지 않는다.
  삭제된 path 키도 원장에 보존하며 최대 1,024개다. 자동 GC·키 교체·키 import는 제공하지 않는다.
- 최초 인증된 controller ID를 고정한다. schema/node/time/key/IP/hash를 검증하고 세대 역행,
  다른 ID, 동일 세대의 다른 typed JSON 내용을 거절한다. 배열 재정렬도 다른 내용이다.
  더 높은 유효 revision이 로컬 키와 불일치해 거절돼도 그 최고 세대는 기억한다.
- 한 번 키를 준비한 path의 정의는 고정한다. controller가 아직 unbound로 아는 path라도
  key 준비 후 endpoint/relay/underlay/target 정의가 바뀌면 새 path ID가 필요하다.
- 권한 거절·부정합은 영속 차단 상태다. 이후 단순 통신 실패가 차단을 해제하지 않는다.
  신뢰할 수 있는 일치 응답을 완전히 수락해야 해제한다. 시계 관측 최고값을 기록해 30초를
  넘는 역행을 감지하며 status도 이 값의 저장을 위해 쓰기 권한이 필요하다.
- 정상 종료되지 않은 refresh는 `in_progress`로 남고 후보 사용을 차단한다. 부분 저장,
  파일/디렉터리 fsync 오류는 `uncertain`이다. reopen/refresh에서 파일 검증과 sync를
  성공한 뒤 다시 준비해야 한다. status만으로 진행 중이던 네트워크 승인을 완료하지 않는다.

## 상태 해석

| 상황 | 보고와 행동 |
| --- | --- |
| 초기 cache 없음 | `validity=missing`, `preparation=empty`, `usable_cache=false` |
| 유효 후보 전부 binding 확인 | `validity=valid`, `preparation=complete`; 활성 후보가 있으면 `usable_cache=true` |
| controller outage | refresh 오류 + `refresh.result=unavailable`; 기존 유효·준비 후보는 계속 조회 가능 |
| 일부 후보만 준비 | `preparation=partial`; 승인된 bound 후보가 있고 차단 사유가 없으면 그 후보만 사용 가능 |
| 만료·시계 역행 | `expired`/`clock_skew`, `usable_cache=false` |
| 인증 거절·revision/키 불일치 | `blocked_reason`과 `preparation=blocked`; 이전 snapshot은 진단용으로 보존 |
| 진행 중 프로세스 종료 | `refresh.result=in_progress`, `partial`, `usable_cache=false`; 다시 refresh |
| 저장 불확실성 | `validity=uncertain`, `usable_cache=false`; 저장소 복구 후 reopen/refresh |
| drain/disabled/삭제 | 해당 후보를 준비 대상에서 제외, 삭제된 키는 retired로 보존 |

`observed_generation`은 거절된 최신 세대를 포함할 수 있어 `catalog.generation`보다 높을
수 있다. 출력에 private key는 포함하지 않는다. `paths`의 bound/IP는 OS 적용 확인이 아니다.

## 백업·복구 절차

모든 cache 사용 프로세스를 중지하고 전체 cache 디렉터리를 비밀정보 백업으로 보관한다.
PKI credential 백업과 path cache는 별개이며 controller PKI backup에는 노드 private key가
없다. 파일을 Git이나 이슈·일반 로그에 올리지 않는다. 복원 시 UID/0700/0600을 유지하고
동일 cache를 두 노드에서 동시에 실행하지 않는다. 중단 시 `.pending-*` 파일이 남을 수
있으며 이것도 개인 키를 포함할 수 있다. 프로세스를 멈춘 뒤에만 미사용 임시 파일을 정리한다.

| 장애 | 복구 절차 |
| --- | --- |
| 응답 유실/일시 통신 오류 | 원본 cache를 유지한 채 refresh 재실행. binding/key/IP가 같음을 status로 확인 |
| ENOSPC/fsync 실패 | 저장소 문제 해결 → reopen → refresh. `uncertain` 상태로 적용 진행 금지 |
| state 일부 삭제·손상·로컬 키 없는 binding | 전체 최신 cache 복원. 없으면 관리자가 이전 path를 disabled/retire하고 새 ID로 승인; 잔존 peer 정리는 배포 절차에서 확인 |
| 오래된 node cache 복원 | 현재 controller와 refresh. 없는 private key의 기존 binding을 자동 인수하지 않음; 완전한 백업이나 새 path 승인 필요 |
| 오래된 controller backup 복원 | 최신 controller 원장 복원. generation 숫자만 올려 우회하지 않음. 최신 node 원장과 배포 peer를 대조해 폐기/승인을 재구성 |
| controller ID 교체 | 자동 재신뢰하지 않음. 이전 경로/peer 폐기와 신규 controller 신뢰·enrollment를 명시적으로 수행하고 별도 새 cache 사용 |
| 인증서 revoke/remove | 자격 갱신 또는 명시적 re-enrollment. 유효한 인증 응답과 key/path 일치가 확인될 때까지 cache 차단 유지 |
| clock_skew | 시계 동기화 후 refresh. 캐시 삭제로 만료를 우회하지 않음 |

새 cache에 이미 존재하는 binding의 비밀키를 추측/재발급할 수 없다. 반대로 전체 cache와
표식을 모두 삭제한 사실을 외부 원장 없이 로컬에서 감지할 수도 없다. cache 삭제는 일반
문제 해결책이 아니며 복구와 새 승인 절차를 먼저 확정한다.

## 검증과 후속 범위

```bash
go test -race ./internal/relaycache ./cmd/vpnctl ./internal/controller
VPNCTL_RELAY_CACHE_SCALE=1 go test -race ./internal/controller \
  -run '^TestRelayCacheVariableScale$' -count=1 -timeout=5m -v
```

단위 시험은 저장 전/rename 후 fsync 실패, 응답 유실, 취소, 반복 CAS 충돌, 권한·링크·손상,
만료·clock 역행·revision 변조를 주입한다. 실제 mTLS 시험은 revoke/remove, 1/3/8/32노드의
동시 최초 binding, 4 relay×2 underlay, cache reopen, controller backup/reload 뒤 같은
키·IP·정확한 binding 수를 검증한다. 실제 CLI 프로세스에서 CA 전환·rollback과 cache 갱신도
함께 확인한다. 후속 #22의 underlay mapping/source pin, #23의 prepare/apply/journal,
#24의 경로 전환 SLO가 남아 있으며 이 준비 기능으로 M2/M3 운영 합격을 선언하지 않는다.
