# 개별 probe RTT jitter 계약

관련 이슈: #87. p50/p95/p99 계약은 [probe-percentiles.md](probe-percentiles.md).

## 모집단과 순서

`jitter_ms`는 같은 reported stream과 조회 bucket 안에서 인접한 성공 probe RTT의 절대 차이 합계를 유효 쌍 수로 나눈 값이다. stream은 node/peer/path/relay/uplink/source 전체를 사용한다. 단방향 지연 jitter, 실제 relay 경로 검증, 로봇 동작 제어 신호가 아니다. 로봇이 VPN을 통해 서버 uplink에 도달하는지의 판정은 별도 probe/전환 검증에 있다.

- RTT는 기존과 동일한 정수 microsecond로 집계하고 API/CLI/HTML에는 millisecond를 사용한다.
- 실패/unknown은 앞뒤 쌍을 끊는다. 성공한 RTT 0과 변화량 0은 실제 값이다. 유효 쌍이 없으면 값은 null, 쌍 수는 0이다.
- 저장 timestamp는 보고된 시각을 microsecond로 정규화한다. timestamp와 stable ID로 정렬하고 raw ID로 재전송을 중복 제거한다. ID나 수신 시각으로 관측 시각을 바꾸지 않는다.
- 같은 timestamp의 서로 다른 표본은 순서를 알 수 없으므로 그룹 전체가 앞뒤 쌍을 끊는다. ID 순서에 따라 결과가 바뀌지 않는다. 이 그룹이 압축 배치 두 개에 걸쳐 있으면 이미 계산한 경계 쌍도 취소한다.
- bucket 경계를 연결하지 않는다. 넓은 bucket 안에 포함되는 여러 시간별 aggregate는 합계/쌍 수/경계를 병합하며 시간별 평균끼리 평균하지 않는다.
- live는 기존 기본 60초 창 `(observed_at-60s, observed_at]`를 사용한다. 기존 unknown 처리처럼 창을 비우고, 시계 역행도 미래 표본을 버린다. stale이면 수치는 보존하되 기존 stale/quality 상태로 현재 판단에서 구별한다. raw/history bucket은 unknown 이전 표본도 보유하므로 live와 모집단이 항상 같지는 않다.
- 여기서 인접함은 **보존된 관측끼리의 인접함**이다. stable ID는 전송 시퀀스가 아니므로 전송 중 빠진 표본을 복원하거나 탐지하지 못한다. 시간 간격만으로 누락/장애를 만들지 않는다. monitor delivery/drop 상태와 history reclamation coverage를 함께 확인한다. 재시작 전후도 같은 stream의 보존된 관측으로 취급하며, 프로세스 epoch를 추정하지 않는다.

## 출력과 계산 가능한 범위

| 필드 | 의미 |
| --- | --- |
| `jitter_ms` | 유효 쌍의 평균 RTT 변화량(ms), 쌍 없음/순서 유실은 null |
| `jitter_pair_count` | 유효 쌍 수, 순서 유실은 null |
| `jitter_known_samples` | 순서 요약이 보존된 관측 수, 실패/unknown 포함 |
| `jitter_status` | `complete` 또는 `unavailable_order` |

`complete`는 반환된 모집단의 순서 정보가 있다는 뜻이다. 손실 없는 전송이나 회수되지 않은 전체 과거 이력을 보증하지 않는다. 회수된 경로는 기존 `coverage.partial`, 삭제 표본 수와 영향을 받은 시간 범위로 표시한다. 남은 경로의 jitter를 회수된 경로에 연결하지 않는다.

구형 aggregate가 조금이라도 포함된 bucket은 전체 jitter와 쌍 수를 null로 한다. 새 관측만의 평균을 전체 구간의 값처럼 제시하지 않는다. `jitter_known_samples`는 그 중 순서 정보가 있는 관측 수를 표시한다. 구형 archived live snapshot도 값/쌍 수 null과 `unavailable_order`로 읽는다. 좁은 구간을 다시 조회하면 새 데이터만의 jitter를 볼 수 있다.

monitor HTTP, fleet status/history API, fleet CLI, monitor watch/TUI, controller HTML에서 같은 필드를 사용한다. Prometheus는 `vpnctl_quality_jitter_seconds`(ms/1000), `vpnctl_quality_jitter_pair_count`, `vpnctl_quality_jitter_known_samples`, `vpnctl_quality_jitter_order_available` gauge를 제공한다. 값 없음은 NaN이다. 기존 freshness gauge와 같이 사용한다. legacy CSV batch stats의 jitter는 이 개별 probe 계약과 다른 모집단이다.

## 저장 활성화와 복구

raw/live jitter는 새 binary에서 바로 계산한다. **압축 이력의 순서 보존은 별도 offline 활성화가 필요하다.** 기존 v6/v7 DB를 여는 것만으로 저장 형식을 바꾸지 않는다. 활성화 전 압축한 구간에는 나중에도 순서를 복원할 수 없다.

```sh
# 컨트롤러를 중지하고 기존 배포의 config/data volume을 사용한다.
vpnctl controller history enable-jitter --config controller.yaml --out pre-jitter-backup.db
vpnctl controller history inspect --config controller.yaml
```

먼저 tiering이 활성화되어 있어야 한다. 명령은 컨트롤러 ownership lock을 확보하고, 덮어쓰지 않는 검증된 백업을 만든 뒤 v6→v8 또는 v7→v9로 전환한다. v8은 경로 회수 비활성, v9는 활성이다. v8 이후 경로 회수를 활성화하면 v9로 전환한다. 취소/실패 시 새 상태를 게시하지 않는다. 기존 aggregate를 재작성하지 않으며 v1과 v2를 함께 읽는다.

v2는 기존 정확한 RTT 분포에 정렬된 경계 그룹, 변화량 합계, 쌍 수, 경계 쌍 요약을 추가한다. 인코딩은 결정적 varint와 CRC를 사용한다. CRC는 손상 검출이며 인증이 아니다. Decode는 길이/표본 수/RTT/쌍 수/경계 불변조건과 canonical varint를 검사한다. 저장 검증은 schema와 시간별 구간의 경계도 검사한다. 기존 1 MiB payload, 256 MiB rollup, 768 MiB 사용 페이지, 1 GiB DB 한도를 유지한다.

구형 binary는 v8/v9를 거절한다. downgrade가 필요하면 컨트롤러를 중지하고 현재 데이터 디렉터리를 따로 보존한 뒤, DB가 없는 복구 디렉터리에 **활성화 전 백업**을 restore한다. user_version만 낮추지 않는다. 백업 이후 관측은 과거 binary에서 복원되지 않는다. 새 binary의 backup/restore는 부분 압축과 v1/v2 혼합을 보존한다.

## 검증

- 손계산 성공/실패/unknown/zero, 창 하한, 시계 역행, stale, clone 격리.
- 독립 oracle와 100개 무작위 시퀀스의 모든 분할, 좌/우 결합 병합 및 동일 timestamp.
- 역순 도착/중복/재시작, 512행 압축 경계의 timestamp 그룹, rollback 후 재개, 매 commit 재조회, backup/restore.
- v1/v2 혼합, 순서 유실 표시, 이관 취소/ownership/백업 덮어쓰기 거절, 미래 schema와 불가능한 summary 거절, decoder fuzz.
- schema 5/6/7/8/9 × 1/3/8/32 실제 direct/monitor 생산자 mTLS matrix.
- 20M raw→압축 저장 시험과 24세대 경로 회수 시험은 새 v2 summary로 진행한다. 일반 race/crash는 runner disk, 가속 저장 용량 시험은 기존 2 GiB 제한 tmpfs를 사용한다. 이는 운영 disk SLA나 장기 무손실 soak 판정과 구분한다.
