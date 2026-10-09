# M3 배포 용량 검증 (#185)

## 현재 판정 범위

CPU quota는 해당 CPU에서 사용할 수 있는 실행 시간의 비율이다. `0.25`
성공을 임의 로봇의 최소 CPU 사양으로 변환하지 않는다. CPU 모델, 빌드의
race 사용 여부, 역할 배치, 경로·앱 수, 시험 구간을 함께 기록한다.
로봇·조종기는 NUC/Intel, Jetson, Raspberry Pi, Qualcomm 등 여러 후보와
기존 머신을 대상으로 한다. 특정 CPU 하나를 선정하거나 모델명으로 지원을
제한하지 않는다. 대표 하드웨어별 실제 시험과 장기 시험이 끝날 때까지
#185와 M3 배포 용량 판정은 열어 둔다.

각 결과에는 실제 CPU·아키텍처·OS/커널·RAM·저장장치, 실행 역할과 경로·앱 수를
고정해 기록한다. 지원 범위는 해당 환경에서 관측 지연·복구 시간·자원 사용
기준을 만족한 구성으로 표시한다. 한 모델의 quota 수치를 다른 모델의 성능으로
환산하거나 미시험 장비를 통과로 표시하지 않는다. RAM·저장장치 부족을
배포 전제로 삼지는 않되 용량 및 I/O 영향의 재현을 위해 정보를 남긴다.

| 시험 | 범위 | 아직 검증하지 않는 부분 |
| --- | --- | --- |
| `application-capacity-4/8` | 두 자동 actuator, 정상 경로 위치 3개, 15초 이상 유지 | 초기 준비, CPU 제한 중 재구축 |
| `application-capacity-rebuild-4/8` | 자동 actuator 1개 + 수동 고정 actuator 1개, 비활성 후보 재구축, 60초 이상 유지 | 초기 준비, 활성 경로 failover, LAN 보존, 장기 부하 |
| `application-capacity-startup-4/8` | 인증 등록·앱용 경로 준비·앱 예약부터 로봇 quota 적용, 두 자동 앱, 정상 경로 위치 3개 | 전원 부팅·키 생성, 재구축, 활성 전환, 장기 부하 |
| `manager-auto/install-4/8` | 실제 NetworkManager·Netplan 공존 및 전환 | 로봇만의 CPU 한도 |

서로 다른 시험의 성공을 합쳐 모든 조건이 동시에 검증됐다고 판정하지 않는다.
재구축 시험의 수동 앱은 독립 통신 보존을 확인한다. 두 앱 모두 자동인
조건의 재구축 용량을 증명하지 않는다.

## CPU 제한 중 재구축

```sh
VPNCTL_VM_CPUS=2 VPNCTL_VM_RACE=1 \
  VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-capacity-rebuild-new-run \
  ./scripts/test-vm.sh \
  --case application-capacity-rebuild-4 application-capacity-rebuild-8 \
  --robot-cpus 0.5 --cpu-layout split
```

각 실행에는 새 빈 결과 디렉터리를 사용한다. 과거 실패나 실행 중인 실험은
덮어쓰거나 중단하지 않는다. 게스트 실행기 변경 시 기존 `VPNCTL_VM_IMAGE`를
재사용하지 말고 새 이미지를 빌드한다.

- 로봇 supervisor·actuator 2개와 명령 자식은 CPU 0의 합산 quota를 사용한다.
  컨트롤러·릴레이 2개·측정기는 CPU 1 / 1 CPU를 사용한다. 초기 enrollment,
  preparation 및 재구축 활성화 설정은 로봇 quota 밖이다.
- 정상 경로는 4경로에서 0/1/3, 8경로에서 0/3/7 위치를 각각 사용한다.
  다른 후보의 첫 번째 앱 TCP는 blackhole 처리한다. 두 번째 앱은 정상
  경로에 고정하고 실제 payload를 계속 확인한다.
- 두 앱이 통신하는 동안 다음 비활성 후보의 endpoint route를 삭제한다.
  재구축은 제한된 로봇 supervisor가 수행한다. 이전과 다른 소유 세대,
  인증된 lease 재활성화와 해당 후보의 실제 TCP 성공을 모두 확인한다.
- 준비된 후보에서 첫 번째 앱의 통신 시작은 45초 이내, 삭제 후 재구축 및
  유지 검증은 120초 이내여야 한다. 최소 60초 동안 두 앱의 실제 통신,
  각각 3회 이상의 적용 주기와 10초 이내 최신 관측 간격을 확인한다.
  복구 전에는 손상 후보를 제외한 모든 lease, 복구 후에는 전체 lease가
  활성 상태여야 한다. 한 번 관측된 통신/lease 실패는 이후 복구로 지우지 않는다.
  완료 기록 사이 간격뿐 아니라 마지막 선택 경로 관측의 현재 나이도 검사한다.
  기록이 중단되면 기존 통신이 계속되더라도 10초 후에는 실패한다.
- supervisor·두 actuator의 표본 FD는 128 이하, RSS는 각 512 MiB 이하여야
  한다. 표본 최대치이며 자식 프로세스 전체 RSS나 누수 부재를 뜻하지 않는다.
- 시작·종료 CPU quota, 사용량, throttling, pressure, 실제 CPU 마스크와
  역할별 모든 관측 스레드 배치를 검증한다. 증거가 누락되거나 시간 기준,
  실제 앱 모드 또는 4/8경로 식별자가 맞지 않으면 통과시키지 않는다.

외부 컨테이너는 network-none, capability 없음, 메모리 2 GiB / 게스트
768 MiB 한도를 유지한다. 호스트 네트워크·커널·시간·전원은 변경하지 않는다.
split도 동일 물리 CPU와 게스트 커널/IRQ를 공유하므로 물리 서버 분리를
완전히 재현하는 것은 아니다. 운영 관측 3초 예산, 승인·철회, nft 및
BOOTTIME 보호 기준은 변경하지 않는다.

## 초기 등록·준비부터 CPU 제한

```sh
VPNCTL_VM_CPUS=2 VPNCTL_VM_RACE=1 \
  VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-capacity-startup-new-run \
  ./scripts/test-vm.sh \
  --case application-capacity-startup-4 application-capacity-startup-8 \
  --robot-cpus 0.5 --cpu-layout split
```

`startup`은 별도의 split 프로필이다. 네트워크 namespace, 사전 공급된
WireGuard 키와 설정 파일은 시험 구성에 해당한다. 이후 실제 node join의
인증 등록과 재등록, catalog refresh/plan, 각 앱용 경로의 최초 prepare,
두 앱 reserve 명령을 처음부터 로봇 cgroup에서 실행한다. 임시 일반 경로를
미리 설치했다가 해제하는 기존 fixture 절차는 사용하지 않는다.

각 단기 명령은 clone3로 로봇 그룹에서 시작한다. 실행 직전 실제 cgroup과
CPU 마스크를 확인한 뒤 exec하며, 자식도 같은 제한을 상속한다. 공개 보고서는
단계명·시간·배치 검증 결과만 담으며 bootstrap token이나 인증서 키는 담지 않는다.
모든 필수 단계의 순서와 성공, 명시적 ownership admission 재시도만 허용한다.

초기 준비 시간은 컨트롤러 시작 직전부터 모든 후보의 실제 TCP 확인 및 두 앱
예약 완료까지 120초 이내다. 중간의 서버 준비와 측정 시간도 포함하므로
로봇 연산 시간이나 전원 부팅 시간으로 해석하지 않는다. 로봇 CPU 누적 사용량은
그 초기 구간부터 측정한다. 컨트롤러·릴레이·측정기는 계속 CPU 1에 둔다.
그 뒤 두 자동 actuator의 실제 통신, 최소 15초/각 3주기 이상 유지와 10초
최신 관측 기준을 동일 quota에서 검사한다. 이 성공으로 재구축이나 실제
NetworkManager·Netplan 공존까지 통과했다고 판정하지 않는다.

## 남은 완료 조건

1. 로봇·조종기 대표 하드웨어군별로 시험 머신과 경로·앱 수를 정하고
   production 빌드로 동일 시험을 반복한다. race 빌드는 별도 회귀 결과로
   기록한다. 현재 x86 샌드박스 성공으로 다른 아키텍처나 장비까지 판정하지 않는다.
2. 초기 준비 제한 프로필의 대표 장비 검증과 두 자동 앱 재구축을 확인한다.
3. 자원 포화 시 진단과 readiness, 차단 및 예산 복구 후 재확인을 검증한다.
4. 실제 관리자 공존, 활성 경로 전환, 독립 LAN 보존을 동일 역할 예산에서
   검증하고 장기 부하를 추가한다. 부족한 표본으로 p95나 no-uplink SLO
   성공을 선언하지 않는다.

기존 전체 VM 0.25 CPU 실패와 이후 역할 분리 시험 결과는 서로 다른
범위의 증거다. 과거 실패는 [관측 용량 기록](m3-observation-capacity.md)에
그대로 보존한다.
