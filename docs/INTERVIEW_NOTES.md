# Interview notes

이 문서는 AegisFlow NIDS를 면접에서 설명할 때의 핵심 방어 포인트를 정리한다. 목적은 프로젝트를 과장하지 않고, 보안 시스템 설계 의도와 한계를 정확히 말하는 것이다.

## 1. 왜 NIDS인가?

마린웍스 지원 포트폴리오의 핵심 키워드는 네트워크 보안, 침입탐지, 보안 진단, AI 기반 이상징후 분석이다. NIDS는 이 네 가지를 한 프로젝트 안에서 자연스럽게 보여줄 수 있다.

이 프로젝트는 단순히 머신러닝 모델 하나를 만드는 데서 끝나지 않고, 다음 흐름을 구현한다.

```text
flow 입력 → 검증 → 탐지 → 근거 생성 → 저장 → 실시간 대시보드 → 조사 상태 관리
```

즉, 보안 이벤트가 실제 운영 화면까지 도달하는 end-to-end 구조를 보여준다.

## 2. 왜 패킷 캡처가 아니라 flow 기반인가?

원시 패킷 캡처 기반 IDS는 권한, 운영체제 네트워크 스택, 드라이버, 고성능 패킷 처리 같은 범위가 커진다. 포트폴리오 목적에서는 핵심 보안 분석 로직과 운영 흐름을 보여주는 것이 더 중요하다.

그래서 이 프로젝트는 Zeek, CICFlowMeter, NetFlow 같은 수집기가 만든 flow 데이터를 입력으로 받는 구조를 택했다. 이 선택은 다음 장점이 있다.

- 로컬 환경에서 관리자 권한 없이 안전하게 실행 가능
- CICIDS2017 같은 공개 flow 데이터셋과 연결 가능
- 포트, 프로토콜, 패킷 수, 바이트 수, 연결 수 같은 보안 분석 피처를 직접 다룰 수 있음
- 대시보드와 API 중심의 시스템 설계를 명확히 보여줄 수 있음

면접에서는 이렇게 말하는 것이 안전하다.

> 이 프로젝트는 패킷 캡처 엔진이 아니라 flow 기반 NIDS 분석 프로토타입입니다. 실제 운영에서는 Zeek, CICFlowMeter, NetFlow 같은 수집기와 연결하는 구조로 확장할 수 있습니다.

## 3. 왜 규칙 + Isolation Forest인가?

보안 탐지에서 모든 것을 머신러닝으로 처리하면 설명 가능성이 떨어진다. 반대로 규칙만 쓰면 알려지지 않은 이상 흐름을 놓칠 수 있다.

그래서 AegisFlow는 두 신호를 결합한다.

| 탐지 방식 | 역할 |
|---|---|
| Signature rules | Port Scan, Brute Force, DoS, Exfiltration, C2처럼 설명 가능한 공격 패턴 탐지 |
| Isolation Forest | 정상 baseline과 다른 흐름 형태를 anomaly score로 탐지 |

면접에서는 “정확도를 높이기 위한 복잡한 모델”보다 “보안 운영자가 이해할 수 있는 판단 근거”를 우선했다고 설명하는 것이 좋다.

## 4. risk score는 공격 확률인가?

아니다. 이 프로젝트의 risk score는 보정된 공격 확률이 아니라 SOC triage 우선순위 점수다.

현재 점수는 다음 신호를 결합한다.

- 가장 강한 규칙 점수
- Isolation Forest anomaly score
- 경보 여부
- severity threshold

따라서 면접에서는 다음처럼 말해야 한다.

> risk score는 공격일 확률이라기보다 분석가가 어떤 이벤트를 먼저 봐야 하는지 정렬하기 위한 우선순위 점수입니다. 확률로 주장하려면 별도 calibration과 검증 데이터가 필요합니다.

## 5. 왜 정확도 수치를 강하게 주장하지 않는가?

침입탐지 데이터셋은 누수 문제가 쉽게 생긴다. 특히 CICIDS2017 같은 flow CSV를 임의 행 단위로 나누면 같은 날짜, 같은 호스트, 같은 공격 캠페인의 패턴이 train/test에 동시에 들어갈 수 있다.

그래서 현재 README와 평가 문서는 다음 원칙을 둔다.

- synthetic demo 결과를 실제 성능으로 주장하지 않는다.
- CICIDS2017 평가는 간이 스크립트로 제공하되, 최종 주장은 날짜/호스트 단위 holdout 이후에만 한다.
- precision, recall, F1뿐 아니라 false positives per hour를 함께 본다.

## 6. 운영 환경으로 확장하려면?

현재 프로젝트는 포트폴리오 프로토타입이다. 운영 IDS/SOC 환경으로 확장하려면 다음이 필요하다.

- 인증과 권한 관리: OIDC, RBAC
- 통신 보안: TLS, CORS allowlist
- API 보호: reverse proxy, rate limiting
- 감사 가능성: audit log, event immutability
- 데이터 관리: DB migration, retention policy, 개인정보 최소화
- 이벤트 파이프라인: Kafka, Redis Streams, RabbitMQ 같은 메시지 브로커
- 관측성: metrics, tracing, structured logging
- 실데이터 평가: 날짜/호스트 단위 holdout, FP/hour, p95 latency

## 7. 한 문장 요약

> AegisFlow NIDS는 실제 패킷 차단 제품이 아니라, 네트워크 flow를 기반으로 설명 가능한 규칙 탐지와 이상탐지를 결합하고 SOC 대시보드까지 구현한 보안 포트폴리오 프로토타입입니다.
