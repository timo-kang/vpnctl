# 관측 지연 원인과 lease 조회 통합 제외 (2026-10-11)

#185의 관측 지연은 아직 해결되지 않았다. 이번 변경은 실제 커널 회귀와
검증 근거를 추가한다. 제품의 조회 방식, 10초 관측 기준, 3초 wave,
승인·BOOTTIME·nft 타이머·준비/활성화 트랜잭션은 유지한다.

## main CI에서 확정한 실패

main `115f4699c6688858ef57e05a950029bd394dbc6c`의
[CI 38135538059](https://github.com/timo-kang/vpnctl/actions/runs/38135538059)는
39개 성공 / 1개 실패다. 실패한
[8경로 CPU 격리 검사](https://github.com/timo-kang/vpnctl/actions/runs/38135538059/job/114458517126)는
전체 VM 1 CPU, 로봇 역할 합산 0.5 CPU, race, 두 앱 조건이다.
정상 경로 위치 3·7은 통과했고 위치 0의 app이 `observation_stale`로 실패했다.

| 실패 당시 보존된 값 | 결과 |
| --- | --- |
| 검사 시각 | 2026-10-11T11:29:41.761075094Z |
| 검사 입력 읽기·해석 | 13.732123ms |
| 마지막 사용 가능한 행의 관측 시각 | 11:29:31.622628208Z |
| 그 행의 작업 완료 시각 | 11:29:34.229800423Z |
| 검사 시점의 관측 나이 | 10.138446886s |
| 다음 행의 관측 시각 | 11:29:39.572054748Z |
| 다음 행의 작업 완료 시각 | 11:29:41.817436451Z |
| 다음 주기의 admission / maintenance | 3.647878528s / 1.056248923s |

다음 작업 완료는 실패 검사보다 56.361357ms 늦다. 다음 관측 자체는 이미
이루어졌지만 그 주기가 아직 끝나지 않았다. 연속 proof 간격은 7.949426540s로
10초보다 짧아도, 앞선 관측에서 다음 행 완료까지는 10.194808243s다.
따라서 사후 정상 행만 보고 원래 실패를 로그 읽기의 오탐으로 바꿀 수 없다.
`finished_at`은 stdout 쓰기 완료/수신 시각이 아니며, admission은 큐 대기와
cache/engine 열기·검증을 포함한다. 이 자료만으로 순수 잠금 대기나 파일 쓰기를
각각 주원인이라고 단정하지 않는다.

원본은 `/tmp/vpnctl-main-115f469-ci-failure/artifact`, scalar 검증 결과는
같은 상위 디렉터리의 `snapshot-verified.json`에 보존했다.

## 고정된 한 번의 명령 비용 계측

제품 코드를 바꾸지 않는 Go overlay로 외부 명령을 고정 종류별 횟수·시간만
계측했다. argv, 명령 출력, 키, 주소를 계측 필드로 추가하지 않았다.
`/tmp/vpnctl-command-profile-vm`은 전체 VM 1 CPU / 로봇 0.5 CPU / race의
8경로 세 위치를 모두 완료했고, 격리와 원래 판정도 별도 검증했다.
계측 source/overlay/사전 계획은 그 안의 `diagnostic-overlay-evidence`에 있다.

완료되고 applied인 행만 집계했다(기준 행 포함; app 15행, app2 20행).
아래 호출 수와 합산 시간은 각 행의 값에 대한 중앙값이다.
app 주기 중앙값은 2.771s, 그 중 admission 0.999s다.
nft 조회 60회 / 합산 0.161s, nft 갱신 16회 / 합산 0.143s,
ip 주소 조회 26회 / 합산 0.038s였다. app2에서도 비슷한 명령 비용 순서였다.
이 수치는 주기 전체 범위이며, 부모 phase와 겹친다. 합쳐서 배타적 소요 시간으로
계산하면 안 된다. BPF syscall과 직접 procfs 읽기는 이 분류에 포함하지 않는다.
로컬 표본은 CI보다 빠르며 계측 부담도 있으므로 성능 향상 증거가 아니다.

## 결합 조회를 제외한 실제 커널 반례

같은 경계에서 lease table과 전역 flowtable을 한 프로세스로 조회하는 안을
시험했다. 캐시 재사용 없이 매번 조회하더라도 nft 자체의 처리 범위가 중요하다.
[공식 nft 문서](https://netfilter.org/projects/nftables/manpage.html)는 복수 명령을
지원하지만, 전역 조회와 특정 테이블 조회의 결합이 각각의 범위를 보존하는지는
실제 바이너리로 확인해야 한다.

NET_ADMIN만 부여한 새 network-none 컨테이너에서 nft **1.0.6**으로 재현했다.
호스트 네트워크 설정은 변경하지 않았다. 모든 실행은 CPU 1, 메모리 256MiB,
swap 0, PID 64, 읽기 전용 rootfs와 종료 제한을 적용했다.

- `-j -n -T -f /dev/stdin` 또는 `-f -`에 텍스트 명령을 전달하면 성공 종료인데
  출력이 비었다. 부재 테이블도 이 방식으로 성공할 수 있어 적용 불가다.
- 고정 명령을 argv로 전달하면 두 개의 JSON 문서가 나왔다.
  두 문서를 모두 해석해도 외부 `inet/ip/ip6` 테이블의 flowtable을 놓쳤다.
- `전역 → 소유 테이블`, `소유 테이블 → 전역` 두 순서 모두 동일했다.
  세 주소군 × 두 순서 **6건 모두 결합 조회 0개 / 개별 전역 조회 1개**였다.
- flowtable 없는 대조군 두 건은 양쪽 모두 0개였다.

따라서 이 최적화는 제품 구현 전에 제외했다. 출력 parser를 바꾸는 것만으로
해결되지 않으며, 조회 실패 시 정상으로 처리하는 fallback도 추가하지 않는다.
이 결과를 모든 nft 버전의 동작으로 일반화하지 않는다. 기존 제품의 독립 전역
조회는 같은 반례를 정상 검출한다.

초기 fixture의 예약어 이름 오류, 컴파일 오류, 출력 형식 확인 실행도 지우지
않았다. 최종 범위 비교는 `/tmp/vpnctl-lease-read-kernel-scope-v2`, 제외한
독립 RED 테스트와 파일은 `/tmp/vpnctl-lease-query-rejected-evidence`에 있다.

## 영구 회귀와 남은 작업

`TestLiveLeaseReadGlobalFlowtables`는 upstream의 누락 현상을 요구하지 않는다.
실제 production `LeaseStatus`/`Lease`가 다음 계약을 지키는지 검사한다.

1. 소유 lease를 만들고, 일반 외부 테이블만 있을 때 정상 조회한다.
2. 외부 `inet/ip/ip6` flowtable이 생기면 조회와 새 승인을 통한 갱신을 거부한다.
3. 삭제하면 다시 정상 조회하고, 재추가하면 다시 거부한다.
4. 모든 조회 후 빈 fixture lease가 저절로 활성화되지 않았는지 확인한다.

기존 `scripts/test-route-query.sh`와 CI의 커널 계약 검사에서 함께 실행한다.
fixture의 Docker·초기 loopback-only namespace·정확한 CAP_NET_ADMIN 검사가
호스트 실행을 거부한다. 주소/키/원시 nft 출력 대신 고정 결과와 버전만 기록한다.

정상 코드의 실제 커널 계약은 통과했다. `LeaseStatus`를 잘못된 결합 조회로
바꾼 overlay는 세 주소군 모두에서 실패했다. 초기 staged 갱신 조회만 합치는
별도 overlay도 세 주소군 모두에서 거부 조건을 위반해 검출됐다. 두 변이 실행은
`/tmp/vpnctl-lease-global-kernel-mutant`와
`/tmp/vpnctl-lease-staged-kernel-mutant`에 보존했다.
이 회귀 보강은 용량 문제 해결이나 M3 완료 판정이 아니다.

다음 원인 분리는 admission의 대기/열기·검증과 관측 wave 안의 명령/비명령
시간을 나누는 것이다. 실제로 비용이 큰 구간만 후보로 삼고, 안전성 검증 후
동일 자원 조건의 고정 A/B에서 전체 관측 나이와 완료 시간을 비교한다.
단순 호출 감소, 로컬 한 번의 성공, 임계값 완화로 #185를 닫지 않는다.
