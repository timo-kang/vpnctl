# M3 target 관측·선택 판단 검증 (#153)

2026-10-04, latest main `c64a006` 위에서 구현한 #153을 검증했다. 제품 동작과 사용법은
[실제 target 관측·선택 판단 계약](../architecture/node-target-selection.md)에 있다.
검증 범위는 승인된 후보의 TCP 도달성 및 `desired_path_id`, `applied=false` 출력이다.
앱 경로 자동 적용·세션 전환·SLO의 합격 기록이 아니다.

## 실제 통신 시험

`scripts/test-m3-target-selection.sh`는 2 CPU / 2 GiB 일회용 Docker 컨테이너에서 실행한다.
controller 동일/별도 namespace, relay 2개, underlay 2개, 별도 TCP target을 사용한다.
기존 fixture의 source route를 제거하고 제품 `prepare --probe-routes`로 후보를 준비했다.
robot namespace의 `rp_filter=2`를 유지했다.

| 프로파일 | 반복 | 결과 |
| --- | --- | --- |
| production | 배치 2종 × 3회 | 6/6 통과 |
| race | 배치 2종 × 2회 | 4/4 통과 |

각 배치에서 baseline, controller offline, underlay UDP blackhole, relay uplink 장애,
모든 target 불가, 대안 복구, 선호 후보 복귀, 외부 peer 보존, manual pin 실패, target route
설치 직후 SIGKILL, source rule 설치 직후 SIGKILL의 11개 단계를 기록한다. 모든 선택 주기에서
route/rule 불변과 일반 unbound 앱 경로가 생기지 않음을 검사했다. 중단된 prepare는
제품 recover로 정확히 회수했다. 운영 호스트의 clock/network/reboot/suspend는 변경하지 않았다.

로컬 artifacts는 `/tmp/vpnctl-target-selection-final-production` 및
`/tmp/vpnctl-target-selection-final-race`다. 재현 시 별도 경로를 사용하며 manifest의 binary SHA,
suite commit/dirty 상태, CPU/memory/race 설정과 함께 확인한다. 후보 정책 단위 검증에는
1/3/8/32 node × 8후보, 100회 반복 flap, 16-sample history 한도, manual/cost 제한,
관측 재사용·세대 역행·승인 만료·시계 역행+suspend, malformed evidence를 포함했다.
이는 32-node 실제 통신 부하 합격을 뜻하지 않는다.

## 발견·조치

1. **독립 probe의 반환 경로 누락:** 장치/source bind만으로는 앱 route가 없는 robot의
   `rp_filter=2` 검사에서 반환 TCP 패킷이 버려졌다. 소유 candidate table의 target route와
   내부 source /32 rule을 opt-in prepare에 추가했다. 시스템 필터를 끄지 않았다.
2. **오래된 관측을 후처리 시각으로 갱신:** kernel 재검사 뒤 시각을 부여하면 실제 probe보다
   늦은 fresh evidence처럼 보일 수 있었다. probe 종료 시각을 유지하고 선택 시 freshness를 검사한다.
3. **local target/다른 gateway 오판 여지:** 전후 source/device route를 대조하고 local/gateway/다른
   interface 경로를 거절한다. unrelated WG counter 증가만으로 TCP 증거를 대신하지 않는다.
4. **시험 판독기의 생략 필드 잔존:** 이전 JSON struct에 덮어 읽으면서 빈 추천이 과거 path로 남았다.
   줄마다 새 객체를 디코딩하도록 수정했다. 제품도 추천 철회를 빈 `desired_path_id`로 명시하며
   이전 소비자 객체에 덮어 읽어도 경로가 지워지는 회귀 검증을 추가했다.
5. **Go network timeout 분류 누락:** `net.Error.Timeout()`도 timeout으로 분류한다. 권한·fd 고갈·취소는
   통신 실패 비율에 넣지 않는다.

초기 실패는 `/tmp/vpnctl-target-selection-initial`, `...-route-check`, `...-owned-routes`에
그대로 보존했다. 실행 중 실험을 취소하거나 같은 run 결과를 덮어쓰지 않았다.

## 남은 통합 gate

PR #154의 최초 CI `37181524329`는 새 target selection production/race를 포함해
17개 job이 통과했으나 M2 production이 `target_restart` 복구 기한 150초를 초과했다.
node-1의 저장 WG 표본에는 node-2가 빠졌고 종료 직전 kernel에는 존재했다. 반복 direct
전환 원인이 원본의 상태 건수만으로 구분되지 않아 #121에 연결하고 병합을 보류했다.
후속 진단은 고정 원인 코드별 건수와 파싱한 시각만 저장한다. 노드별 최근 512개 로그
기록의 코드·시각, 초과 삭제 건수, 파싱/읽기 누락 여부를 명시하며 원문·키·주소·임의
오류는 내보내지 않는다. 이 진단은 기존 stored-WG/freshness/150초 판정에 관여하지 않는다.
별도 main 재현 또는 후속 CI의 성공만으로 최초 실패의 원인을 해결했다고 보지 않는다.

#23에서 실제 앱 route stage/validate/commit/rollback과 selection 세대 fencing을 연결해야 한다.
#22의 장치/address/route 변경·복구, #24의 target 응답 payload·NAT source·기존/새 TCP 세션,
실제 NetworkManager/Netplan/udev 공존과 failover SLO는 별도 검증한다. 관측 CLI의 임시 선택 이력은
재시작 후 초기화되며 route가 적용돼 있다고 표시하지 않는다. 기존 M2 24시간 합격 기록은 유지된다.
