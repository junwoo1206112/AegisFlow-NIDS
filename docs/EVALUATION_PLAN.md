# Evaluation plan

이 문서는 AegisFlow Network Monitoring의 CICIDS2017 기반 평가 계획을 정리한다. 핵심 원칙은 “평가 가능성은 제공하되, 데이터 누수가 있는 성능 수치를 과장하지 않는다”이다.

## 1. 평가 목표

AegisFlow의 평가는 다음 질문에 답하는 것을 목표로 한다.

- 정상 flow와 이상 flow를 이진 분류 관점에서 얼마나 구분하는가?
- 이상 이벤트를 놓치는 비율은 어느 정도인가?
- 정상 트래픽을 이벤트로 오탐하는 비율은 어느 정도인가?
- 현장 모니터링 관점에서 false positives per hour가 감당 가능한가?
- 단일 flow 처리 지연이 실시간 대시보드에 적합한가?

## 2. 사용할 데이터

1차 대상은 CICIDS2017 MachineLearningCSV 파일이다. 이 파일은 CICFlowMeter가 생성한 flow feature와 라벨을 포함한다.

저장소에는 원본 데이터셋을 포함하지 않는다.

- 데이터 크기가 큼
- 배포 조건과 재현성 관리가 필요함
- Git 저장소를 가볍게 유지해야 함

사용자는 `data/raw/` 아래에 CSV를 직접 배치한 뒤 평가 스크립트를 실행한다.

```powershell
.\.venv\Scripts\python.exe scripts/evaluate_cicids.py --csv "data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" --limit 50000
```

## 3. 현재 평가 스크립트

[scripts/evaluate_cicids.py](../scripts/evaluate_cicids.py)는 CICIDS2017 CSV의 주요 컬럼을 `NetworkFlow` 입력으로 변환한 뒤, 현재 탐지기의 `is_alert` 결과를 라벨과 비교한다.

현재 매핑하는 컬럼은 다음과 같다.

| CICIDS2017 컬럼 | AegisFlow 필드 |
|---|---|
| Destination Port | `dst_port` |
| Flow Duration | `duration_ms` |
| Total Fwd Packets | `packets` |
| Total Length of Fwd Packets | `bytes_total` |
| SYN Flag Count | `tcp_syn_count` |
| Label | `BENIGN` 여부 |

운영 문맥 피처인 `failed_logins`, `connections_last_minute`, `unique_ports_last_minute`는 현재 중립값으로 채운다. 따라서 이 스크립트는 “완전한 최종 성능 평가”가 아니라 “라벨 CSV 기반 간이 평가”다.

## 4. 산출 지표

스크립트는 다음 값을 출력한다.

- TP: 이상 이벤트를 탐지
- TN: 정상을 정상으로 유지
- FP: 정상을 경보로 오탐
- FN: 이상 이벤트를 놓침
- Precision
- Recall
- F1
- False positive rate

운영 관점에서는 추가로 다음 지표가 필요하다.

- False positives per hour
- p50/p95/p99 detection latency
- flows per second 처리량
- 공격 유형별 recall
- severity별 triage 정확도

## 5. 데이터 누수 방지

최종 성능을 주장하려면 임의 행 분할을 피해야 한다. 같은 날짜, 같은 호스트, 같은 공격 캠페인의 패턴이 train/test에 동시에 섞이면 성능이 과대평가될 수 있다.

권장 분할 방식은 다음과 같다.

1. 날짜 단위 holdout
2. 호스트 또는 서브넷 단위 holdout
3. 공격 유형 단위 holdout
4. 학습에는 BENIGN baseline만 사용하고, threshold는 validation 구간에서 고정
5. test 구간은 마지막에 한 번만 사용

## 6. 개선 계획

다음 단계에서 평가 품질을 높일 수 있다.

- CICIDS2017 전체 날짜별 CSV를 읽는 batch evaluator 추가
- 공격 유형별 confusion matrix 출력
- 평가 결과를 JSON/Markdown으로 저장
- `connections_last_minute`, `unique_ports_last_minute`를 CSV row가 아니라 시간창 단위로 재계산
- 정상 baseline 학습 데이터와 평가 데이터를 날짜 기준으로 분리
- latency benchmark 추가

## 7. 면접용 결론

> 현재 프로젝트는 성능 수치를 과장하기보다, 평가 가능한 구조와 데이터 누수 방지 원칙을 명확히 둔 네트워크 이상징후 모니터링 포트폴리오입니다. 실제 성능 주장은 CICIDS2017 날짜/호스트 단위 holdout과 FP/hour 측정 이후에 하는 것이 맞습니다.
