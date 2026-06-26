# Architecture and threat model

## 데이터 흐름

```text
Simulator / POST /api/detect
            │
            ▼
  Pydantic boundary validation
            │
            ▼
  Feature extraction ──► Signature rules
            │                    │
            └────► Isolation Forest
                         │
                         ▼
             Combined risk + evidence
                    │         │
                    ▼         ▼
                SQLite     WebSocket
                    │         │
                    └──► SOC dashboard
```

`detector.py`가 유일한 탐지 결정 소스다. `storage.py`는 결정 결과를 변경하지 않고 보존·집계하며, UI도 서버가 계산한 결과를 재해석하지 않는다.

## 위험 점수 의미

규칙 경보는 `1 - (1-rule) × (1-anomaly×0.35)`로 완만하게 보정하고, 규칙 없는 이상은 `anomaly×0.75`를 사용한다. 독립 확률이라는 가정을 충족하지 않으므로 이 값은 **보정된 공격 확률이 아니라 triage 우선순위 점수**다. 운영 데이터에서 calibration하기 전 확률로 표시해서는 안 된다.

## 신뢰 경계

- 모든 외부 flow 필드는 타입, 범위, IP 형식 검증을 통과해야 한다.
- SQLite 문장은 값 바인딩을 사용한다. 동적 severity 값은 Enum을 거친다.
- 대시보드는 API에서 온 IP, 공격명, 설명을 HTML escape한다.
- 브라우저에는 원시 payload나 자격 증명을 저장하지 않는다.
- WebSocket 큐는 100개로 제한되며 느린 소비자가 탐지를 막지 않는다.

## 배포 전 필요한 작업

로컬 데모 경계를 넘어 배포하려면 OIDC/RBAC, TLS, CORS allowlist, reverse proxy rate limiting, 감사 로그, 비밀 관리, DB 마이그레이션, 외부 메시지 브로커, 관측성, 개인정보 보존 정책을 추가해야 한다.

## 실데이터 평가 프로토콜

1. 동일 수집기와 집계 창으로 train/test feature를 생성한다.
2. 랜덤 행 분할 대신 날짜 또는 호스트 단위 holdout을 사용한다.
3. 클래스별 precision, recall, F1과 confusion matrix를 기록한다.
4. 정상 시간당 오탐 수(FP/hour), flow 처리량, p50/p95 탐지 지연을 측정한다.
5. 임계값은 test가 아닌 validation 구간에서 고정한다.
6. 모델·feature schema·데이터 기간을 함께 버전 관리한다.
