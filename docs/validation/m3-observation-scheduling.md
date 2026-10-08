# 관측 사전·후속 검사의 입장 순서 (#202)

## 결함과 보존 조건

`26b490f`의 실제 관측 엔진과 기본 selector를 가상 시간으로 실행하면,
8개 후보 중 마지막 두 위치에만 정상 경로가 있을 때 관측을 잃는 반례가 있다.
각 사전 검사는 180ms, 후속 검사는 160ms, 정상 TCP는 900ms,
나머지 TCP는 10ms다. 실패한 TCP에도 원인 귀속을 위한 후속 검사가 필요하다.

- 정상 후보가 p6이면 TCP는 2.96초에 끝나지만 후속 검사를 마치지 못한다.
- 정상 후보가 p7이면 TCP가 2.40초에 시작해 공유 3초 예산을 넘는다.
- 다른 후보의 TCP가 성공해도 후속 ownership 검사에서 거부되는 경우에
  같은 결함이 재현된다. TCP 성공 여부를 입장 우선순위의 근거로 쓰지 않는다.

모든 사전 검사를 먼저 끝내는 장벽도 해법이 아니다. 마지막 사전 검사가
예산 끝까지 막히면 앞에서 완료한 TCP의 후속 검사까지 막기 때문이다.
`TestBlockedLatePrecheckPreservesEarlierVerifiedCandidate`가 이 조건을 검증한다.

## 스케줄 계약

한 wave의 검사 소유자는 계속 하나다. 모든 사전 검사 ticket을 catalog
순서로 먼저 등록한다. 후속 검사가 기다리는 동안에는 사전 검사를 최대 두 번
입장시킨 뒤 후속 검사 하나를 입장시킨다. 후속 검사끼리는 대기열 순서를 따른다.
사전 검사가 모두 끝나면 남은 후속 검사를 계속 처리한다.

2:1은 양쪽 대기열의 진행을 위한 입장 횟수 제한이다. 검사 실행 시간이나
TCP 응답 시간을 예측하지 않는다. 사전 검사 두 번을 이미 입장시킨 뒤
후속 검사가 도착하면 다음 해제 시 그 후속 검사를 입장시킬 수 있다.
TCP 완료를 기다리며 다른 TCP의 시작을 막는 장벽은 없다.

위 유한 작업량에서 p7의 TCP 시작은 1.92초, TCP와 후속 검사의 완료는
2.98초다. 이 가상 시간 결과를 실제 CPU의 지연 상한이나 성능 향상으로
해석하지 않는다. 실제 VM의 자원 범위는 별도로 검증한다.

취소된 ticket은 건너뛴다. 입장을 부여받은 직후 취소된 경우에도 그 ticket의
소유권만 반납하며 다른 검사 소유권을 해제하지 않는다. 모든 worker를 join한 뒤
wave를 반환한다. gate는 승인·관측 결과를 저장하거나 재사용하지 않는다.

다음 기준은 바뀌지 않는다.

- 공유 wave 3초, 기본 연결 정책 1초, selector freshness 10초.
- TCP 전후의 실제 승인, lease, kernel ownership, inventory, underlay generation 검사.
- BOOTTIME/nft 차단, fail-closed mutation의 직렬 소유권, 최종 batch 유효성 검사.
- 두 개의 서로 다른 fresh report를 요구하는 selector와 replay 거부.
- 후보 수, catalog 사전 검사 순서, 모든 TCP worker의 병렬 실행 가능성.

## 회귀와 한계

`internal/relayapply/observation_schedule_repro_test.go`는 실제 엔진과
기본 selector를 사용하며 kernel/transport 경계만 기존 fake로 대체한다.
공유 호스트의 네트워크나 시계를 변경하지 않는다.

- 유일한 정상 경로 8개 위치 × 앞 후보의 TCP 실패/성공 후 ownership 거부.
- 느린 사전/후속 검사 16개 위치 × 유일한 정상 경로 8개 위치(128개 조합).
- 사전 검사/TCP/후속 검사 중 취소와 전체 worker 종료.
- 늦은 사전 검사 정지, 후속 검사 거부, 두 fresh report 확인과 replay 거부.
- 별도 gate 회귀에서 대기 중/입장 부여 후 취소, 취소된 후속 검사 뒤의 진행.

가상 시간에서 연속 wave가 같은 시각에 닿으면 엄격한 replay 규칙에 따라
거부된다. 재현 fixture는 서로 다른 wave 사이에만 1ms를 진행시킨다.
실제 selector의 시간 비교는 변경하지 않으며 같은 report 재사용을 따로 거부한다.

이미 입장한 검사가 공유 deadline까지 막히는 상황에서 모든 후보의 관측을
보장하지 않는다. TCP가 성공했더라도 후속 검사가 끝나지 않으면 건강한 경로로
인정하지 않는다. 검사 비용이 큰 임의의 작업량에 대해 최적 스케줄을 보장하지도 않는다.

```sh
GOMAXPROCS=2 go test -p=2 -race ./internal/relayapply \
  -run 'Test(SlowEarlyPostchecks|LateCandidateStill|BlockedLatePrecheck|ObservationSchedule|ObservationCanceled|TargetPrecheck|TargetFailedFirst|TargetQueued)' \
  -count=1
```

## 실제 자원 조건의 검증

4/8경로, 두 앱, 정상 후보의 처음·중간·끝 위치에서 실제 payload와 steady
관측 간격을 확인한다. 기존 격리 VM wrapper를 사용한다. 호스트의 네트워크,
커널, 전원 상태를 바꾸지 않으며 진행 중인 시험을 중단하거나 덮어쓰지 않는다.

```sh
# 공유 CPU: guest 1 vCPU, outer 1 CPU, robot 합산 0.5 CPU
VPNCTL_VM_CPUS=1 VPNCTL_VM_RACE=1 \
  ./scripts/test-vm.sh --case application-capacity-4 application-capacity-8 \
  --robot-cpus 0.5

# 역할 분리: guest 2 vCPU, outer 2 CPU, robot CPU 0/0.5 CPU,
# controller·relay·측정 CPU 1/1 CPU
VPNCTL_VM_CPUS=2 VPNCTL_VM_RACE=1 \
  ./scripts/test-vm.sh --case application-capacity-4 application-capacity-8 \
  --robot-cpus 0.5 --cpu-layout split
```

수정 전후 비교는 같은 호스트·이미지·quota에서 하며 8경로는 반복 표본도 보존한다.
공유 CPU와 역할 분리 결과를 서로 다른 조건으로 기록한다. 실제 mask, thread
소속, CPU 사용량 증거와 원래 10초 freshness 기준을 유지한다. 실험별 결과와
최종 HEAD CI는 [#202](https://github.com/timo-kang/vpnctl/issues/202)에 기록한다.

이 수정은 기존 원격 CPU8 실패의 유일한 원인을 입증하지 않는다. 최소 배포
CPU, 장기 안정성 및 전체 M3 판정은 [#185](https://github.com/timo-kang/vpnctl/issues/185)의
별도 과제다. 기존 저자원 실패를 성공한 재실행으로 대체하지 않는다.
자원 측정 범위는 [관측 용량 검증](m3-observation-capacity.md)을 따른다.
