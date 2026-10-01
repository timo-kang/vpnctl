# 릴레이 시계·전원·영속 상태의 VM 경계 검증

추적: [#128](https://github.com/timo-kang/vpnctl/issues/128),
[#135](https://github.com/timo-kang/vpnctl/issues/135),
[#136](https://github.com/timo-kang/vpnctl/issues/136). 이 runner는 M3 플랫폼 경계의
증거를 수집한다. 실행 완료, 개별 조건 충족, M3 최종 승인은 서로 다른 판정이다.

## 공유 호스트를 변경하지 않는 실행 계약

`scripts/test-vm.sh`는 일회용 QEMU/KVM 게스트를 Docker 안에서 실행한다. 일반
컨테이너는 호스트 realtime을 공유하므로 컨테이너에 `SYS_TIME`/`SYS_BOOT`를 주는
방식으로 시계·절전을 시험하지 않는다. Linux time namespace도 realtime을 분리하지
않는다. [Linux time namespaces](https://www.man7.org/linux/man-pages/man7/time_namespaces.7.html).

- 외부 실행 컨테이너: CPU 1개, 메모리 2GiB, swap 0, PID 256개, network none,
  capability 전부 제거, no-new-privileges, 읽기 전용 root, 128MiB 임시 `/tmp`.
  유일한 장치 전달은 `/dev/kvm`이다. 호스트 network, Docker socket, block device를
  전달하지 않는다. 호스트의 clock/power 명령을 호출하지 않는다.
- 게스트: vCPU 1개, RAM 768MiB, 복사본 overlay root disk와 전용 32MiB 영속 state disk.
  power/clock 명령은 게스트 HTTP agent만 실행한다. 매 요청 전에 kernel marker,
  무작위 DMI UUID, 별도 boot ID 및 실행별 bearer token을 검증한다.
- image는 읽기 전용으로 전달하고 실행 디렉터리만 쓰기를 허용한다. disk 생성은
  일반 파일에 `mkfs.ext4 -d`/`qemu-img`를 사용하며 host mount/loop 장치를 쓰지 않는다.
- QMP socket과 게스트 HTTP forwarding은 외부 컨테이너 내부에만 있다. 호스트 포트를
  publish하지 않는다. 임의 shell RPC는 제공하지 않는다.
- 종료 시 이번 실행에서 만든 이름의 컨테이너와 private 디렉터리만 정리한다.
  다른 컨테이너·namespace·실험·M2 24시간 원본에 손대지 않는다. 실패한 실행의
  private 디스크는 원인 조사용으로 보존하고 경로를 출력한다.

필요 조건은 Linux x86-64, 사용자가 접근 가능한 `/dev/kvm`, Docker, cgroup v2,
Go, Python 3, Bash 및 충분한 임시 디스크 공간이다. Go 빌드는 2개 작업으로 제한한다.
이미지 빌드 단계만 Ubuntu 패키지 다운로드가 필요하며 실행 게스트는 인터넷에 연결되지
않는다. KVM이 없으면 호스트 설정을 바꾸거나 다른 방식으로 우회하지 않고 실패한다.
하드웨어 보안 격리나 악성 guest code 실행 서비스로 인증한 runner는 아니다.

## 재현과 다른 배포 저장소의 입력

```sh
# 우선 부팅·격리·플랫폼 정보만 확인한다.
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-vm-boot scripts/test-vm.sh --case boot

# 전체 조합. 알려진 지원 한계/결함도 별도 판정으로 남는다.
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-vm-matrix scripts/test-vm.sh --case matrix

# 선택 사례는 각각 새 VM으로 실행한다.
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-vm-power scripts/test-vm.sh --case suspend reboot reset
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-vm-clock scripts/test-vm.sh --case clock --mode stopped --delta -31
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-vm-delay scripts/test-vm.sh --case delayed-commit --delta -31

# 배포용 Linux 바이너리와 미리 만든 VM 이미지도 사용할 수 있다.
VPNCTL_TEST_BINARY=/absolute/path/vpnctl \
VPNCTL_VM_IMAGE=sha256:IMAGE_ID \
VPNCTL_ARTIFACT_DIR=/absolute/path/new-results \
scripts/test-vm.sh --case lease
```

`VPNCTL_VM_IMAGE`는 이 저장소의 `tests/vm/Dockerfile`로 만든 runner image다.
임의 OS image를 의미하지 않는다. 플랫폼 버전을 바꾸려면 Dockerfile의 게스트
패키지를 변경해 별도로 검증한다. suite 소스, runner image, CLI를 함께 버전 고정한다.
기본 CLI는 checkout에서 빌드하며 외부 binary의 출처와 SHA-256을 따로 기록한다.
실제 구형 CLI 비교에는 lease 도입 전 커밋
`6e2da45c89de2d3ad2e4c930f1037472e6440692`의 git object가 필요하다.
새 journal/marker를 삭제하여 downgrade가 되게 만들지 않는다.

`VPNCTL_KEEP_VM_WORK=1`이면 성공해도 이번 private 디스크를 보존한다. 이 디렉터리에는
시험용 개인키·인증서가 있으므로 공개 artifact로 올리지 않는다. 매번 새로운 결과
디렉터리를 지정한다. 자동 CI는 호스트에서 안전한 Python 단위 검사만 실행한다.
KVM power matrix는 위 명령으로 명시적으로 실행하며 일반 network CI 성공으로
대체하지 않는다. 배포 저장소는 이 입력/결과 계약으로 전용 runner를 호출할 수 있다.

## 실제 검증 범위

게스트 안에 실제 controller와 mTLS identity, 제품 CLI, WireGuard/nftables,
2 relay × 2 underlay를 구성한다. 로봇에서 앱 서버까지 직접 도달하는 route는 없고
네 경로 모두 릴레이를 통과한다. forwarding/SNAT는 명시적인 시험 fixture다.
각 경로에서 새 TCP와 처음 연 뒤 재연결하지 않는 TCP를 별도로 검사한다.
요청별 nonce와 서버가 관측한 source 주소를 검증한다. 제어 HTTP timeout이나 누락된
probe 응답을 dataplane 차단 성공으로 계산하지 않는다.
명시적 재설치가 끝난 뒤의 복구 확인에서는 시험 제어 연결 reset/timeout을 별도
`recovery-control-gap`으로 기록하고, 기존 12초 예산 안에서 새 nonce로 다시 관측한다.
그 응답이 실제 네 경로 모두 통과해야 복구다. 설치 명령을 자동 재실행하지 않으며,
차단 증거 수집이나 잘못된 protocol 응답에는 이 재시도를 적용하지 않는다.

| 사례 | 주입 및 판정 |
| --- | --- |
| lease / clock | 감독 정상 종료 또는 실행 중, wall -2/-31/-600/+2/+600초. 외부 monotonic의 마지막 통과·최초 실패를 기록하고 12초 관측 후 차단/복구를 검사 |
| pause | 감독 SIGSTOP 확인 뒤 QMP stop/cont, RTC host/vm 각각 12초. 감독을 재개하기 전 TCP를 검사 |
| pause-expired | 실제 60초 승인 후 70초 QMP pause. 외부 UTC가 승인 expires_at을 넘었는지 확인 |
| pause-fenced | 감독 종료, 모든 관리 endpoint release와 빈 inventory 확인 후 QMP pause. 재개 직후와 캐시만 사용하는 동안 차단 유지, 시간 확인·새 승인·명시적 설치로 복구 |
| suspend | 게스트의 실제 systemctl suspend/deep(S3). QMP suspended 상태 확인 후 12초 뒤 system_wakeup. frozen supervisor보다 먼저 TCP 검사 |
| reboot / reset | 게스트 systemctl reboot / QMP system_reset. boot ID 변경, 이전 journal의 kernel domain 거절, 같은 이름의 외부 dummy link 보존 |
| expiry / denied | 실제 승인 60초와 게스트 +61초 / grant 철회. 차단 뒤 시계 역행·HTTP 단절·캐시 재시작으로 자동 복구하지 않음 |
| namespace | 소유 fixture process만 종료하고 relay namespace를 교체. 같은 이름의 외부 자원을 채택·삭제하지 않음 |
| enospc | 전용 32MiB 게스트 state filesystem을 실제 block 크기의 동기 쓰기로 채움. 제품 refresh 실패, lease 차단 후 강제 재부팅·domain 거절·새 설치 |
| rename / fsync / fsync-dir | 실제 refresh syscall에 EIO 주입. rename은 strace, fsync는 게스트의 소유 child를 추적하는 ptrace 주입기를 사용. 실패 확인 후 차단·강제 재부팅·새 설치 |
| downgrade / legacy-upgrade | 구형 실행 파일로 새 journal 거절/무변경 확인. 별도 새 디렉터리에 구형 peer 설치 후 새 supervisor가 회수하고 명시적 재설치. 이후 재부팅 |
| delayed-commit | 실제 승인 갱신이 nft batch를 준비한 직후 supervisor를 SIGSTOP. child nft 실행을 12초 보류하고 시계 정상/-31초 조건에서 실제 commit. supervisor 재개 전에 네 경로 TCP를 검사 |

ENOSPC filesystem에는 controller 및 node/relay cache도 있으므로 **전체 fixture 저장소
부족** 시험이다. 특정 cache 하나만 실패한 결과로 해석하지 않는다. syscall 오류는
대상 relay refresh에만 주입한다. rename의 `(INJECTED)` 또는 fsync의 대상 fd와
실제 반환 errno 증거가 없으면 실패한다.
게스트의 이 전용 filesystem만 ext4 내부 `reserved_clusters`를 0으로 설정한다.
그렇지 않으면 큰 filler가 ENOSPC를 반환해도 작은 cache 저장은 예약 공간에 성공할 수
있다. [Linux ext4 예약 공간](https://cdn.kernel.org/doc/html/latest/admin-guide/ext4.html).
파일 fsync는 실제 `.pending-*` 파일, 디렉터리 fsync는 rename 이후 CommitError를
확인한다. 단순 cache open 시의 fsync 오류를 이 두 결과에 포함하지 않는다.
Go의 OS thread 이동 때문에 strace의 호출 순번만으로 fsync 대상을 지정하지 않는다.
게스트 전용 ptrace 주입기는 자신이 fork한 refresh 프로세스와 그 thread만 추적하고,
실제 fd 경로와 rename 성공을 확인하여 한 번의 fsync에 EIO를 반환한다. 주입기 종료
시 tracee도 종료되는 EXITKILL을 사용하며 기존 PID에 attach하지 않는다.
[Linux ptrace 계약](https://man7.org/linux/man-pages/man2/ptrace.2.html).
syscall error + reboot는 모든 디스크 펌웨어의 torn-write/power-loss 보장과 다르다.

재부팅 후 복구는 이전 원장을 그대로 둔 채 새 identity/controller/cache를 명시적으로
구성하는 fresh bootstrap이다. 동일 controller로 무중단 재접속하는 시험이 아니다.
실험마다 새 VM을 만들며 이전 실패 원본을 다음 성공으로 덮어쓰지 않는다.

## 시간 판정과 artifact

외부 observer의 monotonic은 guest clock 변경과 guest pause의 영향을 받지 않는다.
각 probe에 외부 시작/종료 시각을 기록하고 guest realtime/monotonic/boottime,
실제 nft cutoff/element expiry, 감독 JSONL을 같이 남긴다. 10초 lease 검출 기준에는
1초 관측 여유가 있다. 마지막 응답 시각은 커널 hook의 정확한 통과 시각이 아니며
이 수치를 11초짜리 제품 lease 또는 현장 최악 지연 보장으로 해석하지 않는다.
새 TCP만 복구 판정에 사용하며 기존 TCP 세션 이동/보존을 보장하지 않는다.

- `run-*.txt`: suite commit/dirty, CLI·구형 CLI·시험 binary digest, runner image ID,
  host boot ID, 자원 제한, kernel/root disk digest.
- `runner.json`: 실제 QEMU 버전, cgroup CPU/memory/swap, capability, image manifest.
- `host-isolation.json`: 실행 전후 host boot와 wall/monotonic/boottime 차이.
  host NTP 보정도 이 차이에 포함될 수 있으며, 테스트가 시계를 변경했다는 뜻은 아니다.
- `verdicts.json`: 전체 요약. 각 사례의 `verdict.json`은 원인·복구·부분 증거를 보존한다.
- `observer.jsonl`: QMP 상태/이벤트, monotonic probe, 공개 kernel inventory, 진단.
- `console.log`/`qemu.log`: 실행 진단. console의 실행별 bearer token은 종료 시 가린다.
  private disk, config/credential cache, WireGuard private key/PSK는 export하지 않는다.

`completed=true`는 실험 절차가 끝났다는 뜻이고 `qualified=true`만 해당 조건을
충족했다는 뜻이다. `unsupported_reason`은 재현된 플랫폼 한계,
`defect_reason`은 재현된 제품 경계 결함, `error`는 시험/구현 실패다.
exit 1은 미완료 사례, exit 2는 완료했으나 결함이 관측된 사례다. exit 0이어도
unsupported 사례가 있으면 플랫폼 전체 합격이 아니다. 소비자는 반드시
`verdicts.json`의 개별 qualification과 배포 profile을 비교한다.
dirty 실행은 탐색 증거이며 최종 commit의 결과로 주장하지 않는다.

## 운영 배포의 전원·시간 계약

QMP stop은 S3가 아니다. 현재 QEMU 조합에서는 `rtc clock=host`여도 QMP pause 동안
Linux의 모든 clock이 멈췄다. RTC device가 진행하는 것과 Linux realtime이 재개 전에
동기화되는 것은 다르다. 12초 및 실제 승인 기한을 넘는 pause 뒤에도 기존·새 TCP가
통과했다. 게스트 내부의 두 timer만으로 외부 경과 시간을 알아낼 수 없다.
[QEMU RTC 설정](https://www.qemu.org/docs/master/system/qemu-manpage.html),
[QMP power/state 명령](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html).

다른 배포 저장소의 VM 관리자는 아래 순서를 책임져야 한다.

1. 새 apply/자동 재시작을 막고 모든 해당 relay supervisor를 종료한다. SIGSTOP만
   하는 것은 fence가 아니다. in-flight child 종료까지 확인한다.
2. 같은 UID/cache/netns에서 각 관리 endpoint에 `relay release --endpoint-id ID`를
   실행한다. 모든 성공과 관리 peer/route/guard 해제, 대상 트래픽 차단을 확인한다.
   실패하거나 확인할 수 없으면 pause를 중단한다. 외부 dataplane fence도 가능하지만
   resume 이후에도 유지되고 실제 drop을 확인할 수 있어야 한다.
3. 이 **차단 확인 후에만** VM pause/snapshot 유지보수 또는 강제 clock 작업을 수행한다.
   게스트의 자동 resume hook으로 나중에 차단하는 것은 첫 패킷 유출을 막지 못한다.
4. 재개 후 차단을 유지한 채 신뢰할 수 있는 시간과 controller 원장을 확인한다.
   새 mTLS 승인, key generation, 실제 kernel ownership 확인을 거쳐 명시적 설치한다.
   이전 캐시만으로 자동 재개하지 않는다.
5. boot/netns가 바뀌면 이전 전체 cache를 보존·격리하고 새 소유 상태로 설치한다.
   journal/initialized marker만 지우지 않는다. 별도의 nft/WG restore 서비스가
   이전 gate를 자동 복원하도록 배포하지 않는다.

관리자 계약을 우회하는 무통보 VM freeze/live snapshot restore는 지원하지 않는다.
별도로 -31초 clock step과 12초 지연 nft commit을 겹치면 이미 만료한 경로가 다시
열리는 결함도 재현했다(#136). 상대 timeout은 commit 시점부터 시작하고, 정지된
부모의 context timeout은 child의 늦은 commit을 취소하지 못한다. 따라서 앞뒤의
userspace freshness 검사 또는 재개 후 cleanup을 hard realtime 차단 보장으로
사용하지 않는다. 이 조합도 사전 fence 없이 배포 조건을 충족했다고 판단할 수 없다.
cache와 controller 원장을 모두 과거로 되돌리고 외부 revision 증거도 잃는 rollback은
로컬 high-water만으로 검출할 수 없다. 외부 fence/revision anchor가 필요하다.
VM의 S3 성공은 물리 장비, 다른 kernel/QEMU, hibernate, 이동된 snapshot의 성공을
뜻하지 않는다. 실제 배포 플랫폼은 같은 suite로 다시 판정해야 한다.

현재 탐색 검증 환경은 Ubuntu 24.04, Linux 6.8.0-146-generic, nftables 1.0.9,
systemd 255, QEMU 8.2 계열이다. 정확한 package/image 값은 실행 manifest에 남긴다.
최종 증거와 미해결 조건은 #128/#135/#136에 연결하며 #124/#114/M3 gate를 자동으로 닫지 않는다.
