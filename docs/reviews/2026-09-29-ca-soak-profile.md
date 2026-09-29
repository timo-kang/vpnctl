# CA 장기 profile 검증 대기 검토 (#97)

## 원인과 수정 범위

`MaintainCredentials`는 성공적인 동기화 뒤 잔여 인증서 수명의 1/6, 최대 60초를
기다린다. 1시간 client certificate/40분 renewal window의 장기 profile에서는 정상적인
worker도 CA prepare 이후의 새로운 trust를 알아차리는 데 거의 60초가 걸릴 수 있다.
기존 soak는 activate/retire를 각 30초만 기다렸다. 이때 ACK 누락으로 activate를
거절하는 controller의 409는 올바른 보호 동작이다.

60초 인증서인 short smoke에서는 worker가 약 10초 이내에 다시 동기화하여 이 불일치가
가려졌다. 제품 polling/ACK/expiry/전환 정책은 유지하고 최대 idle delay를 명시적 상수로
공유한다. production profile의 CA 검증 예산은 60초 idle + 60초 TLS·파일 설치·ACK 여유로
작업당 120초다. short profile은 기존 30초를 유지한다. 이는 CA 유지보수의 시험 예산이며
API 2초, 모든 노드 공통 복구 150초, 경로 failover SLO와 별개다. controller/네트워크가
계속 불가하면 여전히 실패하며 ACK 조건을 생략하지 않는다.

`VPNCTL_SOAK_PROFILE=production`으로 실제 60초 관측 cadence와 1시간 인증서를 짧은
실행에서도 사용할 수 있다. 기본 auto는 24시간 이상이면 production을 선택하며,
24시간 이상의 smoke profile은 거절한다. 요청 profile은 manifest, 선택된 profile과 CA
예산은 trace start에 남긴다. 짧은 production profile은 실제 24시간 통과가 아니다.

## 검증과 자체 리뷰

- 실제 1시간 인증서, mTLS, 자동 maintenance worker 3개를 사용한다. worker 첫 ACK 직후
  prepare하고 30초 뒤 activate가 여전히 거절되는 경계를 재현한다. 자동 동기화 뒤
  activate, 신규 issuer 인증서·ACK, retire, 재전환·rollback·retire를 확인한다.
- ACK는 멱등적이어서 같은 generation/certificate의 재전송은 저장 At을 바꾸지 않는다.
  테스트는 실제 ACK HTTP 처리 완료를 관측해 첫 maintenance를 정렬한다.
- 테스트가 직접 SyncCredentials를 호출해 실제 대기 조건을 우회하지 않는다.
- 빠른 profile/잘못된 입력/24h와 short profile 혼용 회귀와 실제 production profile
  network smoke를 CI에 추가한다. 최종 결과는 연결된 PR에 기록한다.
- 실패한 기존 baseline은 완료 근거에서 제외하고, 검증한 새 불변 실행 파일로 시간을
  새로 잰다. 독립 API 압력 fixture가 장기 실제 생산자의 전체 원장 대조를 대신하지 않는다.
