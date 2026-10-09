# TCP 관측의 실시간 경로 조회 비용 (#185)

## 변경 범위와 계약

후보 TCP 관측 전후의 `ip route get` 프로세스 두 개를 현재 네트워크
네임스페이스의 RTNETLINK 조회로 대체한다. 각 조회는 새 소켓으로 현재
장치 이름과 설치 시 기록한 ifindex를 확인하고, 출발 IPv4·목적 IPv4·출력
인터페이스를 지정한다. 요청 형식은
[iproute2 v6.8.0의 iproute_get](https://github.com/iproute2/iproute2/blob/v6.8.0/ip/iproute.c)을 따른다.
새 라이브러리나 커널 기능 요구사항을 추가하지 않는다.

단일 커널 응답의 송신자·수신자·sequence·메시지 종류를 확인한다.
응답은 16 KiB 이하이며 중복·잘린 속성, 누락된 출발지/목적지/인터페이스,
gateway, multipath, 비유니캐스트 경로를 거부한다. 조회는 기존 3초 명령
상한과 더 짧은 부모 deadline을 따른다. 취소는 poll 가능한 소켓을 닫고
callback 종료를 기다린다. 조회 결과나 이름/인덱스는 캐시하지 않는다.

승인·인벤토리·설치된 kernel 소유권·리스의 TCP 전후 검증, WireGuard
카운터 증가, 적용 시 재검증, 3초 관측 wave, 10초 freshness 및 10초 kernel
lease는 유지한다. native 조회 시간은 기존 probe phase에 포함되고,
외부 프로세스 개수 진단에는 포함되지 않는다.

주의: Linux의 `oif` 지정 route-get은 명시적 경로가 없어도 직접 연결된
형태의 결과를 만들 수 있다. 격리 시험에서 기존 iproute2와 native 모두
이 동작을 보였다. 따라서 이 조회만으로 설치된 정책 table이 정상이라고
판정하지 않는다. 기존 `kernel.Check`/`conflicts`의 별도 table·rule 검사가
계속 필요하다. 초기 시험의 삭제/blackhole 거부 가정은 잘못된 fixture
기대값이었으며, 통과 결과로 덮어쓰지 않고 별도 보존했다.

## 재현

```sh
VPNCTL_ARTIFACT_DIR=/tmp/route-query-new-run ./scripts/test-route-query.sh
```

스크립트는 race 테스트 바이너리를 빌드해 새 `--network none` 컨테이너에서
실행한다. 1 CPU, 256 MiB, swap 없음, PID 64개, read-only rootfs,
NET_ADMIN 단독 권한을 사용한다. 시험은 env·Docker·root·loopback만 있는
초기 namespace·실제 capability를 확인한 뒤 자신의 dummy·rule·table만
생성하고 제거한다. 호스트 네트워크·커널·시간·전원 설정은 변경하지 않는다.
같은 계약을 CI의 `M3 live route query kernel contract`에서도 실행한다.

계약 시험은 정상→gateway 거부→복구, 잘못된 source/name/index,
local 경로, 같은 이름의 장치 재생성, 취소와 blocked read 종료·FD 회수를
확인한다. 순수 시험은 malformed/oversized/중복/다중 응답과 TCP 이전·이후
각 조회 실패를 확인한다. 이름 비교를 제거한 변이는 테스트가 검출했다.

## 비용 측정과 한계

동일 fixture, Ryzen 9800X3D, race, 1 CPU/256 MiB 컨테이너에서 1,000회씩
3개 표본을 비교했다. 실행 시간은 실제 커널 조회와 프로세스 실행을 포함한다.

| 구현 | 회당 시간 범위 | 시간 중앙값 | Go 할당량 | 할당 횟수 |
| --- | --- | --- | --- | --- |
| 기존 iproute2 | 530.9–547.3 µs | 536.0 µs | 약 72.2 KB | 129 |
| native | 44.6–69.3 µs | 64.4 µs | 약 135.4 KB | 63 |

단일 조회는 약 8.3배 빨랐다. native는 두 netlink 수신 버퍼 때문에
부모 Go 프로세스의 할당량이 늘었다. 위 Go 할당량은 기존 ip 자식 프로세스의
메모리를 포함하지 않으며 전체 시스템 메모리 비교가 아니다. VM 전체의 관측
간격·대기 시간·lease·실제 payload를 별도로 검증해야 한다. 이 결과만으로
원격 CPU8의 10초 초과 실패나 배포 최소 CPU, #185 또는 M3를 해결했다고
판정하지 않는다.

원본 로컬 기록:

- `/tmp/vpnctl-route-query-benchmark.log`: 세 표본 전체.
- `/tmp/vpnctl-route-query-contract-policy.log`: 초기 기대값 오류 보존.
- `/tmp/vpnctl-route-query-contract-socket.log`: 실제 커널 계약·취소 검증.
- `/tmp/vpnctl-route-query-mutation.log`: 이름 검증 제거 변이 검출.
- `/tmp/vpnctl-route-query-baseline-verified.json`: main의 8경로 기준 시험.

진행 중인 전체 VM 비교와 최종 CI의 판정은 #185에 후속 기록한다.
