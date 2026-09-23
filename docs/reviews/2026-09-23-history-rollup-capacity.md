# 기존 전송 경로 재검증과 full mesh 집계 후보 리뷰

기준 main: `84fe0fd0a47c671ff93efafa0939d2f98d9b3f95` (PR #73).

## 기존 변경 재검증

- 큐 overflow·cancel·재시도·본문 보존·정확한 손실 계수: race 10회 반복 통과.
- quota/일시적 오류 혼합, mTLS 생산자·삭제/폐기, 1/3/8/32 peer 제어 starvation:
  race 2회 반복 통과. 이 검증에서 기존 수정의 새 운영 결함은 확인하지 못했다.
- 알려진 16/256 stream 및 7일 raw 예산 불일치는 #71에 남아 있다. 이전 전송 수정으로
  full mesh의 모든 관계가 production에 저장되는 것은 아니다.

## 이번 구현과 검증

`ProbeAggregate`는 기존 raw와 같은 RTT microsecond 정밀도의 빈도 분포를 인코딩한다.
시도/unknown/성공, 평균과 nearest-rank p95를 유지한다. SQLite raw query와 skewed population,
순서 변경, 분할/병합 및 중복 제출 후의 결과를 직접 대조했다. 저장 계층이 중복 제거한
자료를 집계해야 한다는 경계를 분명히 했다.

- malformed·손상·truncation·비정규 varint·분모·크기/개수 한도·Add/Merge의 원자성 검증.
- decoder fuzz 30초, checksum 이후의 구조 해석도 포함하여 838,342회 통과.
- 전체 `go test -race ./...`, `go vet ./...`, 바이너리 build 및 diff check 통과.
- 후보 SQLite에는 1/3/8/32노드 hub/full mesh, 2 source, 4개 uplink label 세대를 사용한다.
  full 시험은 cadence 60초/7일이고, routine matrix는 15분/8시간이다.
- raw ID는 실제 128-bit 난수이고 도착 시각을 섞는다. failure/unknown reason 64 bytes,
  0~60초 범위의 microsecond RTT, 같은 DB에 uplink 322,560 snapshot/4 targets를 포함한다.

로컬 full mesh 실험의 수정 후 결과:

| 항목 | 결과 |
| --- | --- |
| 방향성 관계 / source | 992 / 2 |
| 보존 stream (uplink 4세대) | 7,936 |
| 표현한 관측 | 19,998,720 |
| 최근 6시간 raw | 714,240행 |
| 시간 집계 | 321,408행 |
| DB 본체 | 562,343,936 bytes (768 MiB 목표 내) |
| probe fixture WAL peak | 6,497,272 bytes (64 MiB 내) |
| reporter별 24h 조회+JSON 최대 | 38.8ms |
| reporter별 7d 조회+JSON 최대 | 120.6ms |
| reporter별 7d JSON 최대 | 12,248,320 bytes |
| 32개 reporter의 7d 조회를 순차 실행 | 약 3.72초 |

모든 reporter의 관계/source/경로별 성공·실패·unknown population을 검증했다. 프로세스 내
원본 aggregate를 조회 결과에 재사용하지 않고 DB connection을 다시 열어 읽었다.

## 발견 후 수정한 검증 결함

1. 기존 uplink seed가 `streams`의 행 수를 노드 수로 취급했다. 다중 stream에서 중복된
   snapshot/series가 생성돼 충돌했다. 노드 집합을 한 번 materialize하여 정확성과 fixture
   비용을 함께 수정했다. 이전 32-stream fixture의 데이터 의미는 유지한다.
2. 후보 fixture의 한 시간 단일 transaction이 76,310,672-byte WAL을 만들었다. 작은
   transaction으로 나누고 각 commit 직후 peak를 측정하도록 수정한 뒤 full 시험을 통과했다.
3. 최초 fuzz는 대부분 checksum에서 끝나 구조 검증 근거가 약했다. checksum을 다시 맞춘
   변형도 입력하여 varint·개수·분포 검사까지 도달시켰다.
4. 형식의 표본 상한을 raw row quota와 같은 상수에 묶으면 향후 quota 축소 시 과거 인코딩을
   거절할 수 있다. 별도의 `MaxAggregateSamples` 형식 한도로 분리했다.

## 판정과 한계

집계 형식과 독립적인 용량 실험을 도입할 근거는 확보했다. 최종 변경의 CI에서 기존
production 규모 시험, 새 full mesh candidate/fuzz, kernel WireGuard/PKI를 모두 확인한다.

production schema/API/retention/stream quota는 그대로다. 이 실험은 오래된 구간을 집계로
직접 생성하므로 실제 raw→aggregate 이관, concurrent reader의 WAL, late retry의 멱등성,
partial query 경계, authentication, 모든 label 길이와 모든 category의 최대 quota를 검증한
것은 아니다. 원본 ID/timestamp/reason/시계열 순서는 분포로 복구할 수 없다.

[후속 #74](https://github.com/timo-kang/vpnctl/issues/74)에 durable seal·원자적 compaction·
조회량/경계·live 상태 보존·migration·backup/restore·운영 신호 및 완료 기준을 등록했다.
상세 계약과 재현 명령은 [계층 보존 후보](../validation/history-tiered-retention.md)에 있다.
#71과 M2 gate를 완료 처리하지 않는다.
