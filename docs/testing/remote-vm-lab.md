# 전용 서버의 격리 VM 준비와 전원 시험

`scripts/lab/runner.py`는 호스트에 Go/QEMU를 설치하거나 KVM 권한을 변경하지
않고 기존 `tests/vm` 시험을 준비한다. SSH 접속, 서버 주소와 인증 키는 배포
저장소나 운영자가 관리한다. 이 문서와 스크립트는 고정된 소스 commit에서 함께
가져다 사용할 수 있다. 기존 CI runner와 제품 판정 기준은 변경하지 않는다.

## 호스트와 권한

Linux x86-64, Python 3.9 이상, Git, rootful Docker의 로컬 Unix socket,
cgroup v2, `/dev/kvm`, 최소 24GiB의 여유 공간이 필요하다. Docker 사용 권한은
신뢰하는 운영자에게만 제공한다. 이 스크립트는 Docker socket을 컨테이너에
전달하지 않는다.

호스트 계정의 `/dev/kvm` 읽기·쓰기 권한은 요구하지 않는다. Docker가 실행
컨테이너에 장치와 그 장치의 GID만 전달하고, QEMU는 호스트 사용자 UID/GID로
실행한다. 호스트 그룹·ACL·sudo 설정은 그대로 둔다. 장치나 KVM 기능을 사용할
수 없으면 시험 실패이며, TCG나 호스트 권한 변경으로 자동 우회하지 않는다.

실행 컨테이너는 1 CPU quota, 지정 CPU affinity, RAM 2GiB, swap 0, PID 256,
network none, capability 없음, no-new-privileges, 읽기 전용 root를 사용한다.
쓰기 경로는 실행별 private work/results와 128MiB `/tmp`뿐이다. 전달 장치는
KVM 하나이며, 호스트 network/PID namespace·블록 장치·포트 공개는 사용하지 않는다.
게스트의 전원 명령은 기존 marker/UUID/boot ID/token 검증을 거친다.
실제 네트워크 인터페이스 목록은
[Python `socket.if_nameindex`](https://docs.python.org/3.12/library/socket.html#socket.if_nameindex)로
조회하며 `lo` 하나만 허용한다. `/sys/class/net`에는
[`bonding_masters` 관리 파일](https://docs.kernel.org/networking/bonding.html#configuring-bonding-manually-via-sysfs)도
있을 수 있어 디렉터리 항목 수를 인터페이스 수로 취급하지 않는다. marker 누락,
조회 실패, 외부 인터페이스는 모두 거부한다.

CPU affinity는 CPU 독점 예약이 아니다. 같은 CPU나 SMT sibling에서 다른 작업이
실행될 수 있다. 기존 서비스가 있는 서버의 결과를 전용 하드웨어 성능 보장이나
배포 SLO로 해석하지 않는다. 최초 단계는 환경 부팅·격리·게스트 전원 시험이다.

## 준비

linked worktree 대신 `.git` 디렉터리를 가진 독립 clone을 사용한다. Go 1.25가
linked worktree에서 바깥 저장소의 commit을 기록할 수 있어 실제 CLI의
`vcs.revision`과 `vcs.modified=false`도 검사한다. source checkout은 깨끗해야 한다.
시험 root는 checkout 밖의 새 경로여야 하며 source/manifest/log는 private으로
보관한다. 실패한 준비 경로는 덮어쓰거나 자동 재사용하지 않는다.

```sh
# 운영자가 사용할 소스와 두 개 이상의 CPU를 명시적으로 선택한다.
git clone <repository> vpnctl-lab-source
cd vpnctl-lab-source
git checkout --detach <reviewed-commit>
lab_cpus=2,3
lab_root=/absolute/private/path/new-lab

# 도구 이미지는 여기서 한 번 준비하고 이후 immutable image ID로 사용한다.
docker pull golang:1.25.0-bookworm
DOCKER_BUILDKIT=0 docker build \
  --cpu-period=100000 --cpu-quota=200000 --cpuset-cpus="$lab_cpus" \
  --memory=2g --memory-swap=2g \
  --iidfile /absolute/private/path/runner-image-id \
  -f tests/vm/Dockerfile tests/vm

python3 scripts/lab/runner.py prepare --root "$lab_root" --cpuset "$lab_cpus" \
  --builder-image golang:1.25.0-bookworm \
  --runner-image "$(cat /absolute/private/path/runner-image-id)"
```

runner image는 같은 소스의 `tests/vm/Dockerfile`로 만든 이미지여야 한다.
이미지 ID·suite commit·CLI build info·실제 binary hash·guest kernel/disk hash를
기록한다. Ubuntu 패키지 버전과 builder image tag는 나중에 바뀔 수 있으므로
다른 날의 재빌드가 동일하다고 주장하지 않는다. 이미 준비한 image ID와 private
root를 보존해 같은 환경에서 후속 실행한다.

컴파일 전에 capability 없는 비루트 컨테이너가 runner의 Python 파일을 읽을 수
있는지 검사한다. Dockerfile은 private checkout의 umask가 런타임에 전파되지 않도록
이 파일들을 0644로 지정한다.

컴파일은 네트워크가 있는 별도 컨테이너에서 2 CPU·4GiB로 제한한다. 소스는
읽기 전용, 모듈/빌드 캐시와 출력은 private lab root만 쓴다. 현재 CLI와 integration
binary, 기존 VM 계약의 세 역사적 CLI를 빌드한다. 필요한 과거 commit object도
clone에 있어야 한다. Go의 자동 toolchain 교체는 허용하지 않는다.

이미지 조립은 기존 `make_image.py`를 1 CPU·2GiB, network none, capability 없음으로
실행한다. root disk는 일반 파일이며 host mount/loop device를 사용하지 않는다.
private parent 아래 바이너리 input은 capability 없는 UID 0 작성자가 읽을 수
있도록 0755, image 출력 디렉터리는 쓸 수 있도록 0777로 둔다. 다른 사용자에게 parent 디렉터리를 공개하지 않는다.

## 실행과 판정

```sh
# 먼저 부팅과 격리 조건 확인. 다음 명령은 별도의 새 실행 디렉터리를 만든다.
python3 scripts/lab/runner.py run --root "$lab_root" --case boot
python3 scripts/lab/runner.py run --root "$lab_root" --case reboot reset
# S3 지원 여부는 별도로 판정한다. QMP pause를 S3 성공으로 대체하지 않는다.
python3 scripts/lab/runner.py run --root "$lab_root" --case suspend
```

실행기는 각 호출에 무작위 이름의 컨테이너·디렉터리를 만들며 원래 exit code를
보존한다. 준비 단계의 개별 명령 상한은 30분, 실행 호출 상한은 20분이다. watchdog
종료는 시험 실패다. 정상 실패에 대한 자동 재시도는 없다. 컨테이너 정리는 이번
실행의 이름과 ownership label이 일치할 때만 한다. 다른 컨테이너나 Docker image를
prune하지 않는다.

`runs/<id>/results/verdicts.json`의 각 `completed`, `qualified`, 오류·지원 한계를
읽어야 한다. `exit.json`은 원래 실행 결과를, `host-before.json`/`host-after.json`은
호스트 boot ID와 기존 컨테이너의 시작 시각·재시작 횟수를 보존한다. 기존 서비스가
변했다면 다른 운영 작업 여부까지 조사하기 전에는 격리 합격으로 처리하지 않는다.
이 확인은 기존 서비스의 모든 요청이 무중단이었다는 성능 보장은 아니다.

원본 report/log와 private guest disk는 공개 업로드하지 않는다. 각 실행의 결과와
개인키가 있는 private disk를 구분하고, 보존·암호화·폐기는 배포 저장소가 책임진다.
`root/runs/<id>`만 선택하여 관리하고, 실패 기록을 이후 성공으로 덮어쓰지 않는다.
호스트 reboot·절전·시계 조정은 이 runner의 기능이 아니다.

기존 시나리오와 시간/전원 판정의 의미는
[relay VM 경계 계약](relay-vm-boundaries.md)을 따른다. 이 초기 실행기는
boot/reboot/reset/suspend만 허용하며, 성능 진단이나 앱 회복 실험은 해당 소스와
고정 protocol을 별도로 준비한다. 다른 서버에서의 성공으로 기존 PR의 실패를
소급 통과시키지 않는다.
