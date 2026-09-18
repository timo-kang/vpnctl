# 네트워크 sandbox 실행 계약 v1

실행기는 현재 vpnctl과 같은 저장소에서 버전 관리한다. 향후 독립 운영 시에도
아래 입력·출력과 권한 경계를 유지한다. topology/장애 시나리오는 `*_test.go`,
프로세스/namespace 수명 관리는 `network_helpers_test.go`, 실행 환경은 `Dockerfile`,
호스트 진입점은 `../../scripts/test-netns.sh`에 둔다. 배포 설정은
[별도 계약](../../docs/deployment/relay-network.md)에 둔다.

## 호출

Linux, Docker daemon 접근, 이 checkout의 Go 버전, kernel WireGuard가 필요하다.
runner는 `NET_ADMIN`/`SYS_ADMIN`을 가진 일회용 `--network none` 컨테이너 안에서 실행된다.
운영 호스트 네트워크에 직접 실행하는 도구가 아니다. 커널을 공유하므로 적대적 코드의
격리 실행을 위한 보안 sandbox도 아니다.

```sh
# 제품과 시험 코드를 같은 checkout에서 빌드한다.
VPNCTL_RACE=0 VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-results ./scripts/test-netns.sh

# 다른 배포 저장소에서 빌드한 제품을 이 suite로 검증한다.
VPNCTL_TEST_BINARY=/absolute/path/to/vpnctl \
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_NETNS_SIZES=1,3,8,32 \
VPNCTL_ARTIFACT_DIR=/tmp/deployment-vpnctl-results \
/path/to/pinned-vpnctl/scripts/test-netns.sh

# 새 품질 API의 실제 WG/CLI/HTTP/metrics 검증만 실행한다.
./scripts/test-netns.sh -test.run '^TestNetns_MonitorQuality$'
```

외부 바이너리는 실행 파일이어야 하며 Docker 이미지와 호환되는 Linux architecture/ABI로
빌드해야 한다. suite와 제품의 CLI/API가 호환되는 버전을 같이 고정한다. 임의 구버전과의
호환성을 보장하지 않는다. Go test 실행기는 여전히 이 checkout에서 빌드하므로 지금은
독립 배포 패키지가 아니라 **외부 제품 빌드를 받을 수 있는 시험 실행 계약**이다.

| 입력 | 의미 |
| --- | --- |
| `VPNCTL_TEST_BINARY` | 생략하면 checkout에서 제품 빌드. 지정 시 복사해 읽기 전용 mount. 상대 경로는 호출한 디렉터리 기준 |
| `VPNCTL_RACE` | `1` 기본, `0` 배포 빌드. 외부 바이너리의 계측 여부를 바꾸지 않고 suite에만 적용 |
| `VPNCTL_TEST_CPUS` | Docker CPU 제한. 생략 시 제한 없음 |
| `VPNCTL_NETNS_SIZES` | fleet 시나리오의 노드 수. 기본 `1,3,8,32`, 각 값 1~64 |
| `VPNCTL_ARTIFACT_DIR` | 결과 경로. 생략 시 임시 디렉터리. Docker bind mount 제약 때문에 쉼표가 없는 경로 사용 |
| 나머지 인자 | Go test 실행기 인자. `-test.run`, `-test.timeout` 등 |

## 결과와 책임

프로세스의 0 exit가 선택한 시험 통과를 의미한다. 준비/빌드/시험 실패도 0으로 바꾸지 않는다.
`run-*.txt`에는 계약 버전, suite commit/수정 여부, 실제 제품·시험 바이너리 SHA256,
Docker image ID, host kernel, race/CPU/규모/선택 인자를 기록한다. 외부 실행 서비스가
이 파일과 JSON/JSONL/log/Prometheus 결과를 함께 보관한다. 컨테이너는 빌드 시 기록한
image ID로 실행하므로 동시 실행이 공유 tag를 교체해도 다른 이미지가 선택되지 않는다.

새 시나리오는 controller API, 앱 데이터 경로, 의도된 실패, 복구 성공을 따로 판정한다.
비밀키/token/config 전체를 결과 artifact에 넣지 않는다. 기본 gateway, 전체 firewall,
conntrack 초기화 등 파괴적인 시험 동작은 해당 컨테이너의 namespace 안에 한정한다.
CI에 특정 대시보드·원격 서비스 업로드를 결합하지 않는다.

별도 프로젝트로 옮길 시점은 다른 제품의 공통 소비자가 생기거나, 독립적으로 유지하는
장시간 lab/VM/실장비/다중 호스트 운영이 필요할 때다. 그때 runner와 topology를 묶어
버전된 image/package로 배포하고 외부 바이너리 또는 image 입력을 추가한다. 현재의
공통 helper를 범용 SDK나 topology DSL로 확대하는 작업은 선행하지 않는다.

상세 topology와 범위는 [network-sandbox.md](../../docs/validation/network-sandbox.md)를 참고한다.

`TestNetns_UplinkDiagnosis` adds the product's staged uplink CLI to the same
external-binary contract: two underlays, a real kernel WG relay, a target-only
server, mark-based outer route selection and three rounds of staged outages and
recovery. The PKI mesh matrix also runs automatic uplink collection on each node
and saves `node-*-automatic-uplink.json` artifacts. No modem hardware or host
network mutation is required; missing optional collectors remain unknown.
