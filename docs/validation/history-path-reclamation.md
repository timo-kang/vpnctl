# 경로 교체와 과거 이력 회수 계약

#77의 schema v7 정책이다. [시간 집계 저장소](history-tiered-storage.md)의 v6 위에서
**현재 관측을 우선하도록 별도로 활성화**한다. 7일 이력을 모두 보존하는 계약이 아니다.
경로 수 한도에 도달하면 안전한 과거 경로의 집계를 지우고 새 경로를 받아들인다.
삭제된 표본 수와 영향 시간은 API에 반드시 표시한다. 기존 v5/v6 DB는 자동 전환하지 않는다.

## 활성화와 복원

controller를 중지한 상태에서 다음 명령을 실행한다. 다른 배포 저장소에서도 같은 바이너리와
config/data volume을 사용하면 된다. 명령은 controller 소유권 잠금을 획득하고 검사된 백업을
먼저 생성한다. 기존 백업을 덮어쓰지 않는다.

```sh
vpnctl controller history inspect --config controller.yaml
# schema v5인 경우에만 먼저 수행
vpnctl controller history enable-tiering --config controller.yaml --out pre-tiering.db
# schema v6에서 명시적으로 활성화
vpnctl controller history enable-reclamation --config controller.yaml --out pre-reclamation.db
vpnctl controller history inspect --config controller.yaml
```

schema 7 및 `tiering.reclamation_enabled=true`를 확인하고 controller를 시작한다.
활성화 실패는 v6를 유지한다. 백업 생성 뒤 실패한 경우에는 해당 백업을 보존하고 재시도 때
새 파일명을 사용한다. 활성화 후 이미 삭제된 이력은 비활성화만으로 복원할 수 없다.
되돌리려면 controller를 중지하고 현재 DB/WAL/SHM을 함께 보관한 다음, 별도의 복구 data_dir에
활성화 전 백업을 복원한다. 백업 이후 받은 관측은 그 백업에 없다는 점을 고려해야 한다.

```sh
vpnctl controller history restore --config recovery-controller.yaml --file pre-reclamation.db
```

구버전 바이너리로 schema 7을 열거나 `user_version`을 낮추지 않는다. 복구 후 검사 결과의
schema 6을 확인하고 서비스 data_dir을 전환한다. 이 작업은 실제 운영 환경에 자동 적용되지 않는다.

## 회수 대상과 한도

- 새 stream 승인 시에만 작동한다. 기존 stream의 일반 제출·동일 ID 재시도는 회수를 유발하지 않는다.
- 노드 256개 / 전체 8,192개 한도에 도달하면, raw가 하나도 없고 마지막 관측이 durable seal
  이하인 과거 stream을 고른다. 최근 약 6시간의 raw와 해당 ID 멱등성을 보호한다.
- 같은 업로드 배치에 포함된 모든 경로를 보호한다. 뒤에서 갱신될 경로를 앞선 새 경로가
  회수하지 않으므로 관측 배열의 순서로 기존 이력이 사라지지 않는다.
- 노드 한도는 그 노드의 과거 경로로만 해소한다. 전체 한도도 제출 노드의 과거 경로를
  우선하고, 이후 다른 노드의 오래된 경로를 선택한다. 동률은 stream ID로 결정한다.
- 배치당 회수 집계는 최대 1,024행/4MiB이며 후보 탐색은 제한된 목록을 사용한다.
  손실 기록은 node/source/hour별로 합쳐 최대 65,536행, 7일 보존 경계에 따라 만료한다.
- 전체 배치를 처리할 안전한 후보나 회수 예산이 없으면 HTTP 503 `history_quota`로
  **배치 전체를 롤백**한다. `reclamation_work`는 배치를 나눠 제출해 완화할 수 있다.
  `reclamation_rows`는 보존 만료/공간 정책을 점검한다. 무제한 즉시 재시도하지 않는다.
- 최근 raw 경로 자체가 한도를 채우면 계속 quota가 발생한다. 이 정책은 무제한 경로/노드 수,
  짧은 시간 안의 악의적 label 생성, 모든 source에 대한 별도 공정성까지 보장하지 않는다.
- DB 사용 페이지 768MiB, 물리 DB 1GiB, 기존 WAL·HTTP 예산을 유지한다. raw뿐 아니라
  최종 live snapshot/손실 기록의 페이지까지 검사한다. 동일 ID 재전송은 새 raw를 만들지 않을 때
  공간 압력에서도 멱등 성공을 유지한다.

삭제, 손실 기록, 집계 count/bytes, 새 raw/stream/live snapshot은 같은 transaction이다.
취소·내용 충돌·쓰기 실패·commit 전 종료는 모두 롤백한다. commit 뒤 응답 유실은 같은 ID로
재전송할 수 있다. 회수한 경로의 과거 raw 재전송은 durable seal 규칙으로 명시적으로 거절한다.

## API v4, 페이지와 손실 표시

활성 DB는 `/fleet/history` schema 4를 반환한다. 업데이트된 client는 v2/v3/v4를 지원하고,
v4의 `tiering.coverage`가 없거나 모순되면 오류를 낸다. 이전 client는 지원하지 않는 schema를
거절한다. 저장소의 구형 `Query` 인터페이스도 회수 손실이 있는 결과를 완전한 이력처럼 반환하지 않는다.

```json
{
  "partial": true,
  "discarded_samples": 42,
  "first_affected": "2026-09-26T00:00:00Z",
  "last_affected": "2026-09-26T03:00:00Z",
  "resolution_seconds": 3600
}
```

`coverage`는 실제 `start/end`와 node/source 필터에 맞는 **전체 조회 범위**의 손실이다.
모든 페이지에 반복되므로 페이지별로 더하지 않는다. `first_affected/last_affected`는 손실이
있는 시간 bucket들의 바깥 경계다. 그 사이 모든 시각에 손실이 있었다는 뜻은 아니다.
회수된 경로별 RTT/품질을 다른 경로와 섞지 않고, 삭제 population만 node/source/hour로 기록한다.
unknown도 삭제 표본 수에 포함하지만 성공/실패로 바꾸지 않는다.

`partial=false`는 이 범위에 회수 기록이 없다는 뜻이다. 생산자가 실행됐거나 수집에 빈틈이
없었다는 보장이 아니다. 소스 미연결/오프라인/업로드 거절은 별도 관측 상태와 계수로 판단한다.

회수마다 epoch를 증가시키고 stream ID는 재사용하지 않는다. 페이지 사이에 어느 노드에서든
회수가 발생하면 기존 cursor는 HTTP 400으로 거절하며 처음부터 조회해야 한다. 전체 페이지의
snapshot을 보장하지 않으므로 지속적인 회수 중에는 조회를 끝내기 어려울 수 있다.
자동 무한 재조회 대신 운영 측에서 수집 부하/경로 생성 속도를 확인한다.

CLI 텍스트는 `PARTIAL HISTORY`와 삭제 표본 수를 표시하고 JSON은 coverage를 그대로 노출한다.
HTML 상태 화면은 회수 정책의 활성 여부를 표시한다. HTML의 현재 품질 목록은 기간별 손실
조회 화면이 아니므로 정확한 손실 범위는 history API/CLI를 사용한다.
`inspect`/API storage의 `reclaimed_streams`, `reclaimed_samples`는 DB의 누적 회수 수이고,
`reclamation_rows`는 아직 남은 손실 기록 행 수다. 만료 후에도 누적 수는 유지한다.
검사 시 `누적 삭제 표본 = 남은 손실 표본 + 만료된 손실 표본`을 확인한다.

## 검증 방법과 한계

```sh
go test -race ./...
go vet ./...
go build ./cmd/vpnctl
VPNCTL_HISTORY_CHURN_SCALE=1 go test ./internal/history -run '^TestPathChurnVariableMesh$' -count=1 -timeout 5m -v
VPNCTL_HISTORY_SPACE_SCALE=1 go test ./internal/history -run '^TestTieredLiveSnapshotSpaceBudget$' -count=1 -v
```

- 1/3/8/32개 노드, 두 source, 24개 uplink 세대/3개 relay label, unknown/실패/성공을 실제
  Ingest/Maintain/QueryPage로 처리한다. 원본 관측의 독립 oracle과 남은 모든 bucket을 대조하며
  `보존 표본 + 보고된 삭제 표본 = 승인된 원본`을 검사한다. 1노드는 peer가 없는 경계 사례다.
- 일반 race suite의 32노드는 5세대로도 stream 한도를 넘겨 회수를 검사한다. 24세대 전체는
  별도 CI capacity 단계에서 실행한다. 시간 압축 시험이며 실제 7일 동안 실행한 soak가 아니다.
- 트랜잭션 중 취소/쓰기 실패, commit 전후 실제 프로세스 종료와 WAL reopen, backup/restore,
  손실 metadata 손상, 반복 label 생성, 자체 quota/전체 quota, 배치 작업 상한을 검사한다.
- 실제 mTLS 업로드의 commit 후 응답을 끊고 새 client로 재시도한다. 동시에 heartbeat,
  candidates, WireGuard config, status, 인증서 동기화를 호출하고 폐기된 인증서의 접근을 거절한다.
  이 시험은 실제 커널 WireGuard 전환이나 회수 부하 중 CA 교체 완료의 증거가 아니다.

실제 monitor 생산자 연결(#70), 등록/삭제·생산자·PKI·경로 변경·조회가 결합된 장시간 부하
(#71/#74), M3의 물리 다중 릴레이 전환 검증은 별도로 남는다. 이 기능은 관측 이력의 저장 정책이며
로봇 동작이나 VPN 경로 선택 정책을 변경하지 않는다.
