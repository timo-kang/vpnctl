# M2 증거 분석·압력 검증 자체 리뷰

## 검토 중 보완한 결함

- 복구 marker만 있으면 장애 검사를 수행했다고 오인할 수 있었다. controller/underlay의
  실제 오류, application 실패 분류, 삭제 후 registry 감소를 같은 장애 구간에서 요구한다.
- 자원 측정 한 줄만으로 완료 처리할 수 있었다. 시작/끝 coverage와 구간 공백을 검사한다.
- 최종 snapshot 뒤 장애가 다시 발생해도 앞선 snapshot을 재사용할 수 있었다.
  final 이후 정상 중간 표본이나 새 장애를 허용하지 않는다.
- 잘못된 줄에서 중단한 hash를 전체 파일 hash로 오인할 수 있었다. bounded drain과
  hash_scope를 추가하고 입력 제한을 넘으면 실패한다.
- 압력 해제 후의 최종 건수만 맞으면 거부된 쓰기의 부작용을 놓칠 수 있었다.
  압력 중 재조회와 ID 집합·중복 검사를 추가했다.
- 첫 압력 fixture는 갱신 window 전 요청해 정상 정책의 409를 받았다. 실제 window에
  진입하도록 fixture를 구성하고 production SyncCredentials 경로로 갱신·설치·ACK와
  인증서 변경을 검사한다. 제품의 admission/PKI 정책은 변경하지 않았다.

- 결과 분석에서 드러난 #95: 장애 이전 정상 WG 관측과 node 0만으로 복구를 인정했다.
  모든 노드의 장애 해제 이후 WG/uplink 및 현재 peer ID를 공통 150초 안에서 검사하도록
  바꾸고 최종 readiness도 검사한다. 이전 표본/부분 peer/교체 전 ID 회귀를 추가했다.
- worker의 관측 시각은 API 수집 시작 시각이다. 수집 도중 갱신된 cache를 미래 시각
  오류로 오판하지 않도록 실제 측정된 API 시간 범위까지 허용하고, 그 밖의 미래값은 거절한다.

## 검증

- 분석기 정상/실패/불완전 분류, 증거 누락·시간/phase 모순·freshness·latency·counter reset
  회귀 검사. 이전 공개 CI 결과물의 재분석에서도 실행 완료와 M2 보류를 구분했다.
- legacy/tiered 실제 mTLS 혼합 WAL 압력, 503 및 회복, 정확한 입력 원장, API 조회,
  compaction, 제어 API와 인증서 갱신. race 포함 최종 결과는 PR CI에 기록한다.
- 지속형 CI에 실제 종료 코드 보존과 독립 분석 단계를 연결하고, 혼합 압력은 별도 CI job에
  격리했다. 짧은 smoke나 fixture 성공으로 #19를 닫지 않는다.

## 남은 한계

trace는 승인 원장이 아니다. counter 증가량은 관측된 하한이며, 숨은 reset과 bounded
페이지의 누락을 복원하지 않는다. 자원 peak와 latency 분위수는 표본값이다. CA/삭제 인증
replay와 최종 integrity는 runner 내부 검사에 의존한다. 대표 배포 환경에서의 장기 혼합
압력/전체 모집단 대조는 여전히 별도 최종 판정 조건이다.
