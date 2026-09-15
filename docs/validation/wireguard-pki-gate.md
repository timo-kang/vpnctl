# M1: 실제 WireGuard uplink와 인증서 수명주기 검증

## 실행 환경과 재현

`./scripts/test-netns.sh`는 현재 checkout에서 race detector를 포함한 CLI와 테스트
바이너리를 만들고, 별도 Docker 컨테이너에서 실행한다. Linux kernel WireGuard,
Docker 사용 권한, Go 1.25 이상이 필요하다.

```bash
# direct peer injection 및 1/3/8/32노드 PKI·장애 검증
make test-netns

# 특정 규모 또는 반복 실행
VPNCTL_NETNS_SIZES=1,8,32 \
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-network-results \
./scripts/test-netns.sh -test.run TestNetns_PKILifecycleUplink -test.count=3
```

컨테이너는 `--network none`이며 내부에 bridge, controller 네임스페이스와 노드별
네임스페이스를 만든다. `NET_ADMIN`은 WireGuard/veth/route/손실 주입에,
`SYS_ADMIN`과 AppArmor 예외는 컨테이너 안의 `ip netns` mount/setns에 사용한다.
호스트 네트워크, Docker socket, 호스트 시스템 디렉터리는 mount하지 않는다.
빌드한 바이너리만 읽기 전용으로 mount하고, 지정한 측정 결과 디렉터리에만 기록한다.
검증 컨테이너와 임시 빌드는 종료 시 제거한다. 결과 디렉터리는 보존한다.

명시적으로 통합 검증을 요청했는데 권한이나 도구가 없으면 실패한다. `SKIP`을 성공으로
보고하지 않는다. 일반 `go test ./...`에서는 이 커널 검증을 실행하지 않는다.
GitHub Actions의 `M1 reliability`는 일반 race/vet/build와 커널 검증을 각각 실행한다.
커널 CI는 `VPNCTL_RACE=0`으로 실제 배포 빌드를 사용한다. 기본값은 `VPNCTL_RACE=1`이며
로컬 전체 규모 반복에는 race 계측을 포함한다. race의 CPU 비용 때문에 작은 CI runner에서
32개 client의 TLS 처리량이 떨어지는 문제를 배포 성능과 구분한다. 트래픽·개별 요청 기한과
실패 판정은 두 빌드에서 동일하다. `VPNCTL_TEST_CPUS=2`로 컨테이너 CPU를 제한할 수 있다.

## 네트워크와 절차

- controller의 underlay는 `192.0.2.1`, WireGuard 주소는 `10.77.0.1`이다.
  노드마다 독립적인 커널 `wg0`와 실제 `vpnctl node serve` 프로세스를 사용한다.
- 가입·최초 설정 동기화 때만 provisioning 주소로 controller를 호출한다. 이후
  controller URL을 `https://10.77.0.1:8443`으로 바꾸고 VPN 주소로만 관리한다.
- 애플리케이션 echo 서버는 controller 네임스페이스의 **VPN 주소에만** bind한다.
  노드에 기본 경로와 인터넷 연결은 없다. `ip route get` 및 WireGuard의 handshake,
  transfer counter로 애플리케이션 트래픽이 실제 터널을 통과했는지 확인한다.
- 노드마다 policy routing을 번갈아 켜고 끈다. 재시작 후에도 주소·공개키·peer·
  AllowedIPs·IPv4 경로·rule이 유지되는지 확인한다.
- client 인증서는 30초, server 인증서는 10초이며 renewal window는 각각 20초/7초다.
  자동 갱신을 파일과 관리 API에서 확인한 뒤 CA prepare → activate → retire를 수행한다.
  다음 CA도 실제 발급·ack까지 진행한 뒤 rollback → retire를 수행한다.
- 유효했던 이전 node 자격증명을 별도로 보존하고 새 자격증명으로 재가입한다.
  이전 인증서를 폐기한 다음 조회 50회·갱신 50회가 모두 **HTTP 403**인지 확인한다.
  정상 node/애플리케이션은 계속 통신한다. CA prepare와 rollback의 잘못된 반복도
  각각 20회 거부되는지 검사한다.
- controller 강제 종료/재시작, 한 노드의 underlay 100% 손실 2초, node 종료와
  `wg0` 삭제 후 재시작을 실행한다. controller PKI 상태와 node identity/IP도 재검사한다.

## 계측과 판정

각 노드에서 독립적으로 다음 요청을 실행한다.

| 측정 | 주기 | 실패 기준 |
|---|---|---|
| UDP echo | 정상·장애 중 20ms 송신 주기, 수신은 별도 처리 | 500ms 내 올바른 sequence 응답 없음 또는 socket 오류 |
| 지속 TCP echo | 50ms | 500ms 내 올바른 응답 없음, socket 오류 및 재연결 횟수 |
| mTLS fleet API | 100ms, 매번 새 TLS handshake | 1초 내 성공 응답 없음 |

Go ticker가 스케줄링 때문에 생략한 tick은 송신 패킷 수에 포함하지 않는다. UDP는
응답 대기와 송신을 분리해 손실 시 500ms timeout 때문에 송신률이 낮아지는 계측 오류를
방지한다. 손실률의 분모는 실제 송신 시도 수다. 기록은 송신 시각순으로 정렬해 분석한다.

`*.jsonl`은 개별 측정, `summary.json`은 node/phase/protocol별 송신·실패·TCP 재연결·
최장 실패 구간과 성공 표본 간격, `kernel.json`은 PKI 전환 전후 공개 커널 상태다.
최장 실패 구간에는 실패 판단을 위한 timeout이 포함되어 실제 단절 시간의 보수적인
관측값이다. 20ms보다 짧은 단절이나 모든 패킷의 전달을 보장하는 측정은 아니다.
개인키·token·authority/credentials 파일은 artifact에 포함하지 않는다.
실패 로그의 최초 bootstrap token은 가린다.

정상 갱신·인증서 폐기/재가입·CA 교체·롤백 및 복구 완료 구간에서는 모든 노드의
UDP/TCP/HTTPS 실패 0건, TCP 재연결 0회를 요구한다. 각 구간/프로토콜에 최소 3개
표본이 있어야 하며, probe 프로세스의 정상 종료와 미결 측정 배출도 확인한다.
100% 손실 주입에서 실제 UDP 실패가 없으면 계측 자체가 실패한 것으로 판정한다.
controller/API 복원과 손실 해제 후 API 복원은 5초, `wg0`가 사라진 node의 복원은
8초 안에 확인해야 한다. 이 값들은 가속 검증용 기준이며 현장 SLA를 대신하지 않는다.

## 발견한 결함과 수정

1. **VPN으로만 controller에 도달하는 node의 재시작 불가**: `node serve`가 API
   동기화를 먼저 요구해, 삭제된 터널을 복원할 기회가 없었다. kernel 실험에서
   8초 동안 `network is unreachable`로 재현했다. 완전한 로컬 WireGuard 설정이
   있으면 먼저 경로를 복원하도록 변경했다. 최초 가입은 provisioning 경로가 필요하다.
2. **개별 HTTP timeout에서 supervisor 종료**: 요청의 `DeadlineExceeded`를
   프로세스 취소로 처리했다. owning context가 취소됐을 때만 종료하고 네트워크
   오류는 재시도한다. 실제 API timeout을 발생시키는 별도 CLI 회귀 테스트로 검증한다.
3. **통합 테스트의 실행 경로·인터페이스 이름·프로세스 회수 문제**: package 작업
   디렉터리에서 잘못된 build 경로를 사용했고 PID가 길면 인터페이스 이름이 Linux
   제한을 넘었다. 현재 checkout의 바이너리를 주입하고 짧은 이름과 명시적 Wait를 쓴다.
4. **IPv4 uplink 판정에 IPv6 DAD의 정상 변화를 포함**: 초기 IPv6 주소 검증 완료 후
   추가되는 로컬 경로를 PKI의 경로 변경으로 오판했다. 시험 대상인 IPv4 경로를 명시해
   비교한다. IPv6 데이터 경로 검증으로 해석하면 안 된다.

5. **변경 없는 WireGuard 설정의 반복 적용**: 32노드 실험에서 드문 UDP 손실과
   API 지연이 관측되어 heartbeat 경로를 점검했다. `wg syncconf`는 기존 peer를
   유지해도 AllowedIPs 변경 요청을 보낼 수 있고, 커널은 교체 flag에 따라 기존
   prefix를 제거하고 다시 넣는다. 동일 설정까지 반복 적용할 필요가 없다.
   매번 `wg showconf`로 실제 장치를 읽고, 개인키·포트·peer·prefix·명시 endpoint 등
   제어하는 값이 모두 같을 때만 적용을 생략한다. 설정하지 않은 NAT endpoint는
   학습된 값을 보존한다. 파싱/조회 실패나 차이가 있으면 기존 적용/rollback 경로를
   사용한다. 성공 결과만 캐시하지 않으므로 외부 drift와 삭제 장치 복구를 숨기지 않는다.
   [WireGuard tools 구현](https://git.zx2c4.com/wireguard-tools/tree/src/setconf.c),
   [Linux WireGuard 구현](https://github.com/torvalds/linux/blob/master/drivers/net/wireguard/netlink.c).

6. **시험용 UDP 소켓과 agent 수신 포트 경합**: API 응답만 보고 agent가 준비됐다고
   판단하면, 시험 클라이언트의 임시 UDP 포트가 51900을 먼저 차지할 수 있었다.
   `ss`로 agent 수신 소켓이 바인딩된 뒤 프로브를 시작하도록 준비 판정을 강화했다.
7. **CI의 계측 부하와 전체 반복 제한**: 작은 runner에서 race 계측을 적용한 32노드
   TLS 요청이 지연됐다. 커널 CI에는 배포 빌드를 사용하고 별도 전체 race 작업을 유지한다.
   같은 요청 기준의 2 CPU 배포 빌드 시험은 95,714건 실패 0건으로 통과했다.
   폐기 인증서 50회 반복의 전체 시간 제한도 개별 1초 제한을 고려해 60초로 조정했다.

## 범위의 한계

단일 controller/relay 경유 uplink에 대한 소프트웨어·커널 통합 검증이다. LTE 모뎀이나
직접 서버 연결이 없는 로봇도 사용할 수 있는 VPN 경로의 기본 생명주기를 검사한다.
실제 로봇 이동, 무선 링크 품질, NAT 조합, 다중 relay 선택·전환, 다른 네트워크로의
handoff는 M3에서 별도 검증해야 한다. VPN peer까지의 underlay 연결 자체는 필요하다.
네트워크 단절이 인증서 잔여 수명을 넘는 상황의 무인 재가입은 보장하지 않는다.
갱신 응답 저장 후 유실 및 CSR 복구는 기존 [PKI 통합 검증](pki-lifecycle.md)에서 다룬다.
