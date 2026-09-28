# M2 최종 판정과 복합 실행 (#19 / #91)

M2는 단일 controller/relay 구성을 포함한 관측 제품의 판정이다. 로봇이 자체 LTE 없이
VPN/relay를 경유해야 서버 uplink에 도달하는 경우도 포함한다. 실제 다중 relay 및
LTE/Wi-Fi/Ethernet 전환 제어는 M3 #21/#22/#24다. WG handshake/counter 증가를
특정 경로나 application 도달 성공으로 대신 사용하지 않는다.

## 현재 증거와 남은 판정

| #19 기준 | 현재 근거 | 최종 판정에 남은 것 |
| --- | --- | --- |
| 동일 표본의 품질·freshness 의미 | quality 계약, percentile/jitter 및 WG 공통 출력 검사 | 복합 trace의 표본 시각·source·window를 맞춰 API/CLI/HTML/metric 대조; local과 중앙의 서로 다른 수집 주기를 같은 순간으로 비교하지 않기 |
| underlay/controller/relay/overlay/server 장애 구분 | 실제 namespace의 uplink diagnosis와 단일 relay fault matrix | 장기 실행 중 반복 장애의 탐지·복구 및 unknown 오판 여부 |
| 24시간 history/event 재구성 | raw/rollup, 이벤트·회수 이력, 재시작/멱등성/retention 개별 검사 | 동일 실행에서 인정된 생산량과 보존·회수·expiry·drop을 대조하는 최종 분석; 페이지 제한·누락도 기록 |
| unknown/stale을 정상값으로 표시하지 않기 | 공통 품질·WG·저장 상태 단위/통합 검사 | collector 중단·재시작·DB 압력에서 출력과 경보 대조 |
| schema/단위/window 문서 | `quality-api`, `probe-percentiles`, `probe-jitter`, `wireguard-observations`, `storage-health` | 최종 배포 profile의 cadence·규모·예산을 고정 |
| 장애와 수집 실패의 dashboard/alert 구분 | fleet status, alerts, Prometheus 및 cached 저장 상태 | 실제 alert 평가와 복구 기록, exporter 자체 부재 확인 |
| 지원 backend의 E2E | 관리/기존 Linux kernel WG, 1/3/8/32 node suite | 선택한 실제 배포 저장장치·CPU·노드 수에서 장기 결과 확인 |

#70은 관측 생산자 통합, #71은 규모/관계/제어 기능 보호, #74는 영속 집계/조회/부하,
#17은 이벤트·운영 제품을 담당한다. 해당 결과를 검토한 뒤 #19를 닫는다. 짧은 CI,
20M 시간 압축 용량 결과 또는 아래 실행기의 `completed=true`만으로 자동 종료하지 않는다.

## 지속형 실행기

```sh
# 빠른 실행기 검증. 실제 24시간 합격이 아니다.
VPNCTL_SOAK_DURATION=12m VPNCTL_SOAK_NODES=3 \
VPNCTL_SOAK_PHASE_INTERVAL=30s \
VPNCTL_ARTIFACT_DIR=/tmp/vpnctl-m2-smoke ./scripts/test-m2-soak.sh

# 기본 장기 profile. 경로는 원하는 실제 저장장치의 기존 디렉터리를 지정한다.
VPNCTL_SOAK_DURATION=24h VPNCTL_SOAK_NODES=8 \
VPNCTL_SOAK_PHASE_INTERVAL=1h \
VPNCTL_TEST_WORK_ROOT=/path/on/controller-disk \
VPNCTL_ARTIFACT_DIR=/path/to/public-results ./scripts/test-m2-soak.sh
```

노드 수는 3..32, duration은 1m..168h, phase 간격은 20초 이상이다. 모든 phase를
끝내지 못하면 실패한다. 기본 CPU 2개, memory/swap 합계 2GiB를 Docker로 제한한다.
24시간 이상은 direct/monitor/WG가 60초 cadence, 짧은 smoke의 direct/monitor는 2초,
uplink는 최소 30초, WG 중앙 제출은 항상 분당 상한이다. 짧은 profile은 생산 환경의
sampling/용량 합격 근거가 아니다. 메모리 제한은 성능 보장이 아니며 OOM은 실패다.

실제 controller, node serve, kernel WireGuard, monitor, 별도 application server를
동시에 유지한다. 초기 모든 node의 direct+monitor 관측, WG peer 집합, uplink와 저장
상태가 준비된 뒤 경과시간을 잰다. 다음 phase를 반복한다.

1. controller 강제 재시작: API 실패를 반드시 관측한 뒤 상태 수집과 실제 생산자 회복.
2. 한 node의 underlay packet loss 100%: 실제 실패 및 해제 후 회복.
3. application endpoint 중단: controller는 살아 있고 `server_endpoint` 실패가 보여야 함.
4. monitor graceful restart: 중단 전 delivery counter 기록, 새 세션의 재수집.
5. node 삭제·교체: 제거된 인증서의 fleet/renew 요청 각 50회 거절; tombstone ID를
   재사용하지 않고 새 ID/새 WG key로 교체한 뒤 peer와 생산자가 다시 수렴.
6. CA prepare/activate/retire.
7. CA prepare/activate/rollback/retire.

각 API 관측은 2초 timeout이고, 정상 구간 heartbeat age는 30초를 넘지 않아야 한다.
장애 해제 시각 이후 새 WG/uplink 표본과 현재 peer ID를 모든 노드에서 요구한다.
전체 노드가 공유하는 복구 예산은 최대 150초다. 노드마다 예산을 추가하지 않는다. 여기에는 원래 분당 수집 주기를 기다리는
시간이 포함되며 application failover SLO와 같지 않다. 최종 controller 종료 뒤 DB
무결성을 검사한다. 프로세스·namespace 정리는 기존 sandbox runner를 사용한다.

배포 리포지토리는 이 checkout의 runner를 실행하거나 `VPNCTL_TEST_BINARY`로 별도
Linux 실행 파일을 지정할 수 있다. suite commit/dirty 상태, 실행 파일과 test binary
SHA256, image ID, CPU/memory, cadence 관련 profile, 커널과 host 저장 filesystem을
manifest에 남긴다. 빌드 입력은 read-only mount이며 host network/socket은 mount하지 않는다.
private 생성 파일은 지정 storage root 아래 새 `mktemp` 디렉터리에서만 사용하고 삭제한다.

## 결과와 불완전한 실행

- `trace.jsonl`: 관측 시각, phase, heartbeat, API latency, source별 현재 품질 창 표본 수,
  monitor delivery, WG 최신 시각/peer 수, uplink 결과, 제한된 최근 이벤트와 alert,
  certificate fingerprint/만료, 중앙 저장 snapshot. 개인키·토큰·설정 파일은 포함하지 않는다.
- `resources.jsonl`: container/cgroup CPU·메모리·I/O와 사용 불가 신호. 해당 리소스만으로
  실제 deployment disk의 p99나 모든 host 부하를 설명하지 않는다.
- `verdict.json`: 요청/실제 경과시간, 완료 여부, 실행한 phase 건수, `wall_clock_24h`와
  `m2_gate=pending_review`. 파일 부재, nonzero 실행 종료, `completed=false`, phase 누락은
  실패/불완전이다. 정상 종료 메시지 한 줄만으로 통과를 판단하지 않는다.

이 trace의 live 표본 수는 window 값이며 누적 승인량이 아니다. 이벤트와 WG 조회도
page limit이 있고 `events_truncated`를 보존한다. delivery counter는 process restart 시
초기화되므로 phase 전후 별도 세션으로 합산해야 한다. 전체 24시간 timeline/population의
최종 검토에는 query pagination 및 원본/집계/회수/drop 분석을 함께 붙여야 한다.

## 분석과 병행 압력 검증

[#94 실행 결과 분석·압력 fixture](m2-evidence.md)는 현재 실행의 종료 후 검토와 별도
혼합 WAL 압력 검증을 자동화한다. CI는 runner 실제 종료 코드를 보존하고 오프라인 분석기로
trace/verdict/resource/manifest를 대조한다. 독립 mTLS fixture는 승인 ID 원장과 보존 건수,
압력 중 heartbeat/인증서 갱신 등의 지연을 검증한다. 이 두 결과가 성공해도 기존 baseline에
장기 압력이 있었다거나 kernel 생산량 전체를 대조했다는 의미는 아니다.

## 별도로 충족해야 하는 최종 부하 조건

현재 runner의 기본 workload만으로 shared DB/WAL 한도나 WG 128MiB 압력에 반드시
도달하지 않는다. 기존 quota·pinned WAL·경로 24세대·20M 전환 검사는 재현 가능한 별도
근거지만, **장기 복합 부하 중** 저장 압력·반복 등록/삭제·PKI/heartbeat 지연의 최종
판정에는 같은 실행에 압력 profile 및 baseline 대비 자원/지연 분석을 결합해야 한다.
24시간 동안은 raw→rollup의 6시간 경계를 실제로 넘는다. 7일 expiry는 별도 경계 fixture
또는 더 긴 실행의 증거가 필요하다. 가속 시간을 실제 7일 운영으로 표기하지 않는다.

현재 개발 호스트는 NVMe/ext4다. 운영 profile의 저장장치·filesystem, CPU, 최대 노드 수,
관측 관계와 cadence를 확인한 뒤 대표성 및 허용 예산을 확정한다. 이 정보가 없으면
개발 호스트 결과로 기록하고 현장 운영 합격을 자동 선언하지 않는다.
