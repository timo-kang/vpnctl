# Relay의 영속 승인 cache (#114)

`vpnctl relay refresh`는 인증된 배포 view를 검증해 디스크에 저장하고,
`vpnctl relay status`는 controller 접속 없이 그 승인의 유효성을 보고한다.
`approval_valid`는 **저장된 승인 메타데이터의 유효성**이다. relay 비밀키 소유·로컬 키 일치,
WG peer 적용·forwarding·서버 uplink 성공을 뜻하지 않는다. 빈 deployment도 유효한 승인이다.
그 의미는 해당 relay에 배포할 peer가 0개라는 것이며 이전 peer를 계속 쓰라는 뜻이 아니다.

## 명령과 배포 책임

[등록 ACK·인증서 동기화와 관리자 grant](relay-recipient.md)를 먼저 완료한다.

```sh
vpnctl relay sync-credentials --config relay-identity.yaml
vpnctl relay refresh --config relay-identity.yaml --relay-id relay-a --timeout 20s
vpnctl relay status --config relay-identity.yaml --relay-id relay-a
# 배포 저장소에서 별도 영속 볼륨을 사용할 수도 있다.
vpnctl relay refresh --config relay-identity.yaml --relay-id relay-a \
  --cache-dir /var/lib/vpnctl-relay/relay-a
```

기본 경로는 `<node.pki_dir>/relay-deployments/<relay-id>`다. 명시적인 `--cache-dir`가
우선하며 node의 키 cache와 분리한다. principal ID와 relay ID를 파일에 고정하므로 같은
디렉터리를 다른 relay나 신원에 재사용하면 실패한다. 잘못된 relay ID/상대 경로 탈출은
디렉터리를 만들기 전에 거절한다. node cache와도 형식을 혼용할 수 없다.

refresh는 최대 20초의 context와 SIGINT/SIGTERM 취소를 사용하고 HTTP 재시도는 하지 않는다.
파일 I/O 자체가 정지한 경우까지 기한을 보장하지 않는다. status는 네트워크와 인증서 갱신을
수행하지 않으며 `--timeout`을 받지 않는다. refresh 실패도 가능한 경우 진단 JSON을 stdout에
출력한 뒤 비정상 종료한다. status는 만료/차단 상태를 읽으면 종료 0이므로 자동화는
`approval_valid`, `validity`, `blocked_reason`을 검사해야 한다. 파일 손상/권한 오류는 비정상 종료다.

운영 스케줄러가 인증 동기화, 관리자 승인 TTL 갱신, relay refresh를 각각 실행해야 한다.
refresh 자체는 인증서·승인 TTL을 연장하지 않는다. 권한 철회는 push되지 않으므로 다음
인증 응답까지 알 수 없고, 통신 단절 동안에는 마지막 승인의 만료 시각이 유효성 한도다.
설치된 peer를 정해진 시점에 차단하는 daemon/커널 정책은 아직 구현하지 않았다.

## 저장과 재시작 계약

- 실행 UID 소유 0700 디렉터리, 같은 UID의 0600 단일 hardlink 일반 파일만 허용한다.
  symlink/FIFO/쓰기 가능한 비신뢰 상위 경로는 거절한다. root 소유 sticky `/tmp`는 허용한다.
  node cache와 같은 검증된 파일 구현을 사용하며 UID/root 자체를 공격자로 격리하지 않는다.
- `cache.lock`의 비차단 프로세스 lock을 명령 종료까지 유지한다. `state.json`은 최대 2MiB,
  `kind=relay_deployment`, 버전 1이다. 최초 `initialized` 표식 이후 state가 없어지면 새
  cache로 취급하지 않는다. lock/state/표식을 수동 삭제해 복구하지 않는다.
- 임시 파일 fsync → rename → 디렉터리 fsync 후에만 성공을 보고한다. 저장 실패는
  `uncertain`이며 그 인스턴스의 status는 승인을 유효하다고 보고하지 않는다. 저장소 문제를
  해결하고 reopen/refresh하여 검증한다. private key/token/certificate를 cache에 저장하지 않는다.
- controller ID, 최고 수락/관측 generation과 typed JSON SHA256을 고정한다. 역행·controller
  교체·같은 generation 내용 변경(배열 순서 포함)을 거절한다. principal/relay/schema,
  시간/path/binding/hash/정확한 `/32`를 매번 검증한다.
- 같은 controller의 pool 변경, relay key generation 역행, 같은 key generation의 공개키 변경은
  거절한다. 구조적으로 유효한 더 높은 revision은 이 검사를 통과하지 못해도 최고 세대로
  기억한다. 따라서 더 낮은 과거 응답으로 차단을 해제할 수 없다. 정상적으로 승인된 key
  generation 증가는 메타데이터로만 수락하며 로컬 private key 교체는 수행하지 않는다.
- 갱신 전 `in_progress`를 내구성 있게 기록한다. 진행 중 프로세스 종료나 권한 거절 저장
  실패 후에는 네트워크 오류만으로 이전 승인이 복원되지 않는다. 새로운 검증된 응답을
  끝까지 저장해야 차단이 해제된다. 마지막 승인 snapshot은 진단용으로 보존한다.
- 마지막 관측 시각의 최고값을 status/refresh 때 저장한다. 30초 초과 시계 역행은
  `clock_skew`이며, 작은 역행도 이미 관측한 만료를 되돌리지 않는다.

| 상황 | 결과 |
|---|---|
| 최초 승인 없음 | `missing`, `approval_valid=false` |
| 유효 승인 저장 | `valid`, `approval_valid=true`; 빈 peer 목록도 가능 |
| timeout/EOF/일반 5xx/429 | refresh 오류; 이전 승인에 차단 사유가 없고 아직 유효하면 사용 가능 |
| 401/403/인증서 거절 | 영속 `blocked_reason`; 이후 통신 실패로 해제되지 않음 |
| TLS 검증 실패/잘못된 응답/controller 저장 불확실 | 영속 차단 |
| 만료/시계 역행 | `expired`/`clock_skew`, `approval_valid=false` |
| 갱신 도중 강제 종료 | `in_progress`; 새로 수락한 응답 전까지 유효성 false |
| 저장 실패 | `uncertain`; 상태 파일과 디렉터리 검증 후 refresh 필요 |

## 복구와 검증 범위

cache를 사용하는 프로세스를 종료한 뒤 전체 디렉터리를 백업한다. 원래 UID와 0700/0600을
복원하고 controller와 refresh하여 현재 승인을 확인한다. 오래된 cache 전체를 복원하거나
디렉터리 전체를 삭제한 사실은 별도 외부 원장 없이 감지할 수 없다. controller 백업의 세대를
숫자만 올려 우회하지 않으며, controller ID 교체는 기존 승인·peer 회수와 새 신뢰 설정을
포함한 명시적 복구로 처리한다. 여러 relay를 한 cache 디렉터리로 합치지 않는다.

단위/race 검사는 세대·신원 변조, 권한 거절과 통신 실패, 만료/시계 역행, 저장 전후 오류,
실제 프로세스 종료, 동시 갱신, 링크/권한/부분 삭제를 포함한다. 실제 mTLS에서는 CA
prepare/activate/rollback, revoke/remove/grant 철회와 재시작을 검사하며 CLI 프로세스에서도
refresh/status의 JSON·종료값을 확인한다. 규모 시험은 1/3/8/32 node × 4 relay × 2 path에서
relay별 정확한 peer 수, 반복 갱신·재개방과 철회를 검사한다.

[로컬 WG key 검증·peer 적용 journal·복구](relay-peer-apply.md)는 별도 명령으로 구현했다.
`refresh|status`는 메타데이터 명령이며 설치된 peer를 직접 회수하지 않는다. 운영자는
[상시 감독 `relay supervise`](relay-lease.md)를 실행해 승인 갱신과 차단을 유지해야 한다.
새 apply는 감독 중단 시에도 만료되는 커널 lease를 설치한다. 목적지별 forwarding 권한과
서버 반환 방식의 배포 통합, 장비 수준 실패 qualification은 #114/#124에 남아 있다.
