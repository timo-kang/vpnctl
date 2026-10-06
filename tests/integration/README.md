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

`TestNetns_M3PathTopology`는 두 relay × 두 underlay에서 제품 CLI의 node 후보와 relay peer·
반환 route를 설치하고 TCP echo/source, 충돌 보존, 철회 차단과 SIGKILL 복구를 검증한다.
승인 발행·forwarding/NAT·앱 route 선택은 fixture다. 결과는 `m3-prepare-*/report.json`에 남긴다.
`TestNetns_M3RelayDeploymentScale`는 1/3/8/32 node 승인 × 4 path의 정확한 peer·route 수를
실제 커널과 반복 CLI 실행으로 검사하고 `m3-relay-scale-*/nodes-*.json`에 기록한다.
이는 32대 동시 통신이나 자동 전환 SLO 검증을 의미하지 않는다.

## M3 CI 실행 예산

승인·충돌·압력 검증과 supervisor 규모 검증은 독립된 컨테이너/시험 프로세스로 실행한다.
이전에는 앞선 세 그룹에 524.71초를 사용한 뒤, 마지막 32 node × 8 endpoint 검증이
전체 12분 timer에 중단됐다(#150). 아래 제한은 전체 시험 묶음의 실행 예산이다.
개별 준비·명령·승인 만료·kernel lease 판정 시간과 2 CPU/2 GiB 조건은 유지한다.

| CI 작업 / artifact | 선택한 시험 | Go 전체 제한 | CI job 제한 |
| --- | --- | --- | --- |
| `m3-lease-matrix` | `M3AuthorityMatrix`, `M3LeaseConflicts`, `M3LeasePressure` | 12분 | 15분 |
| `m3-supervision-population` | `M3SupervisionScale`의 1/3/8/32 node × 1/8 endpoint 전부 | 8분 | 12분 |
| `m3-supervision-kernel-delay` | `M3SupervisionScale/nodes_32_endpoints_8`, 각 ip/wg/nft 명령에 5ms 지연 | 4분 | 12분 |

8분 규모 예산은 기존 실행에서 작은 일곱 규모만 약 162초를 사용한 점과 마지막 규모의
동시 작업·장애/재승인 단계를 고려해 별도로 부여한다. 지연 profile의 4분 예산은 기존과
같다. 두 profile은 `fail-fast: false`인 별도 matrix job이므로 한쪽 실패로 다른 쪽을
취소하거나 건너뛰지 않는다. 기존 kernel job에서는 위 네 top-level test를 계속 제외해
중복 실행하지 않는다. 각 실행의 manifest·공개 보고서는 구분된 artifact에 남긴다.

판정 시 runner exit 0과 함께 population의 `(nodes, endpoints, command_delay_ms)`가
`{1,3,8,32} × {1,8} × {0}`인 **8개** 완료 보고서, kernel-delay의 `(32,8,5)` **1개**
완료 보고서를 확인한다. 보고서 누락·`completed=false`·timeout·skip은 검증 완료가 아니다.
호스트에서 시험 바이너리를 직접 실행하지 않고 같은 runner로 재현한다.

```sh
VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-population \
./scripts/test-netns.sh -test.run='^TestNetns_M3SupervisionScale$' \
  -m3-scale-command-delay-ms=0 -test.timeout=8m

VPNCTL_RACE=0 VPNCTL_TEST_CPUS=2 VPNCTL_TEST_MEMORY=2g \
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m3-kernel-delay \
./scripts/test-netns.sh -test.run='^TestNetns_M3SupervisionScale$/^nodes_32_endpoints_8$' \
  -m3-scale-command-delay-ms=5 -test.timeout=4m
```

## Controller 배치 검증

`./scripts/test-m3-control-isolation.sh`는 실제 controller를 relay0과 같은 namespace에
두는 배치와 별도 namespace에 두는 배치를 모두 시험한다. 두 relay의 독립 mTLS 신원,
controller 단절 중 유효 승인 유지, supervisor 사망·offline 재시작, 실제 승인 만료와
새 승인 복구를 별도 uplink TCP로 검사한다. [구성과 판정](../../docs/validation/m3-control-isolation.md)에
fixture 경로 선택과 제품 자동전환의 경계, 재사용 입력·결과를 명시한다.

## Application target routing

`scripts/test-m3-target-application.sh` runs the #159 application contract in
disposable network-none containers: colocated/separate controllers, 1/4/8
prepared candidates, unbound payload/NAT evidence, quarantine of existing TCP,
automatic failover, process death and node-only approval expiry/revocation.
The fixture provisions rp_filter only inside its owned robot namespace using
a temporary private proc mount. No host sysctl, network, clock or power changes.
See [deployment prerequisites](../../docs/deployment/node-application-routing.md).

Application CI runs production and race at 2 CPU / 2 GiB with identical safety
deadlines and assertions. `scripts/test-m3-observation-capacity.sh` focuses on
1/4/8 prepared candidates and two actuators with one healthy path among seven
2s timeouts, in first/middle/last catalog positions. Set `VPNCTL_RACE=0|1` and
`VPNCTL_TEST_CPUS=1|2|4` for capacity profiles; use a new `VPNCTL_ARTIFACT_DIR`
for each run. The full application suite also runs these cases. See
[capacity evidence and limits](../../docs/validation/m3-observation-capacity.md).

Direct retry loss uses a persistent namespace worker (`retry-packets.jsonl`),
with monotonic sample times, a 100ms nonce timeout and 50ms spacing. The original
5s maximum observed gap, minimum 12s fault exposure, final recovery reply before
fault removal, and 15s offline reactivation bounds remain. CI also runs a
negative control which stops a real responder after the baseline and must reject
a gap exceeding 5s. The original 32-node coarse-measurement failure is retained
in #166; it is not retrospectively classified as a passing run.

The quarantine fallback fixture proves the same target/default-route payload
before reservation and after explicit release. Its two owned veth neighbours
are permanent, and route/packet/neighbour evidence is retained on failure.
The post-release check is still one TCP probe with a 1s deadline. This fixture
checks target protection; physical ARP/roaming convergence remains a separate
test. Neither fixture changes the shared host's network or Wi-Fi settings.

Image preparation limits each APT phase to 180s (plus a 5s kill grace), with
30s HTTP/HTTPS inactivity timeouts and two retries. APT update errors fail setup
instead of proceeding with partial package lists. The wrapper preserves
`setup-*.log` and source identity even if preparation fails before the normal
run manifest exists; `pipefail` propagates the Docker failure. These are setup
bounds only and never relax the network tests' deadlines or success criteria.

### Underlay 이벤트 세대 (#169)

`TestNetns_UnderlayEvents`는 실제 link/address/route의 삭제·복원, rename, 동일 ifindex
재사용, 공유 nexthop 변경, 미설정 장치 제외 및 2048개 이벤트 범람 후 새 snapshot을
검증한다. `TestNetns_M3TargetApplicationUnderlayEvents`는 분리 controller·두 underlay·
두 relay·두 독립 actuator에서 변경 전 성공을 재사용하지 않는 2회 확인과 실제 payload
복구, 다른 앱의 통신 유지를 검사한다. 둘 다 application production/race CI에 포함한다.
실제 Wi-Fi BSSID roaming, LTE/SIM 등록, NM/Netplan/udev daemon 호환성 인증은 아니다.
`application-underlay-events.json`, `underlay-events.json` 및 원본 JSONL을 보존한다.
