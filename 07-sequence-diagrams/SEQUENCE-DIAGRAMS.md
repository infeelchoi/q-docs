# Q-SIGN 시퀀스 다이어그램

> Post-Quantum Cryptography 기반 SSO 인증 시스템의 주요 플로우

## 📑 시퀀스 다이어그램 카탈로그

### 인증 플로우
- **[AUTH-FLOW.md](AUTH-FLOW.md)** - 상세 인증 플로우 (7개 다이어그램)
  - OIDC 인증 플로우 (Authorization Code with PKCE)
  - SSO (Single Sign-On) 플로우
  - MFA (Multi-Factor Authentication) 플로우
  - Refresh Token 플로우
  - Logout 플로우
  - Token Introspection 플로우
  - Client Credentials Flow (M2M)

### 토큰 관리
- **[TOKEN-LIFECYCLE.md](TOKEN-LIFECYCLE.md)** - 토큰 라이프사이클 (7개 다이어그램)
  - Access Token 생성 플로우
  - Refresh Token 플로우
  - Token Revocation (토큰 폐기)
  - Token Validation (검증)
  - Token Expiration & Auto-Renewal
  - Hybrid Token Generation (RSA + PQC)
  - Session Management & Token Binding

### 키 관리
- **[KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)** - PQC 키 관리 (8개 다이어그램)
  - PQC 키 생성 플로우 (Luna HSM)
  - PQC 서명 생성 플로우
  - PQC 서명 검증 플로우
  - 키 회전 (Key Rotation)
  - Vault 초기화 및 Unseal
  - Transit Engine 설정
  - HSM 슬롯 관리
  - 비밀 키 관리 (KV Secret Engine)

### 배포 관리
- **[DEPLOYMENT-FLOW.md](DEPLOYMENT-FLOW.md)** - GitOps 배포 플로우 (8개 다이어그램)
  - 전체 CI/CD 파이프라인
  - ArgoCD Application 생성
  - Auto-Sync 동기화
  - Self-Heal (자동 복구)
  - Rollback (이전 버전 복원)
  - Blue-Green 배포
  - Canary 배포
  - Multi-Environment 배포

---

## 💡 빠른 시작 다이어그램

이 문서에는 QSIGN 시스템의 핵심 플로우를 이해하기 위한 기본 시퀀스 다이어그램이 포함되어 있습니다. 더 상세한 플로우는 위 카탈로그의 전용 문서를 참조하세요.

## 1. 사용자 인증 플로우 (PQC SSO)

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Angular App
    participant APISIX as APISIX Gateway
    participant KC as Keycloak PQC
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM

    User->>App: 1. 로그인 요청
    App->>APISIX: 2. /realms/myrealm/protocol/openid-connect/auth
    APISIX->>KC: 3. Forward 인증 요청
    KC->>User: 4. 로그인 페이지 표시
    User->>KC: 5. 사용자명/비밀번호 제출
    KC->>KC: 6. 사용자 인증 검증
    KC->>Vault: 7. PQC 키 요청 (Transit Engine)
    Vault->>HSM: 8. DILITHIUM3 키 조회
    HSM-->>Vault: 9. PQC 키 반환
    Vault-->>KC: 10. PQC 서명 키 제공
    KC->>KC: 11. PQC 토큰 생성 (DILITHIUM3 서명)
    KC-->>APISIX: 12. Authorization Code 반환
    APISIX-->>App: 13. Authorization Code 전달
    App->>APISIX: 14. 토큰 교환 요청 (code)
    APISIX->>KC: 15. /token endpoint
    KC->>KC: 16. DILITHIUM3 Access Token 생성
    KC-->>APISIX: 17. PQC Access Token + ID Token
    APISIX-->>App: 18. 토큰 전달
    App->>User: 19. 로그인 완료
```

## 2. PQC 토큰 발급 및 검증 플로우

```mermaid
sequenceDiagram
    autonumber
    participant KC as Keycloak PQC
    participant Provider as PQC Provider
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant App as Client App

    KC->>Provider: 1. 토큰 생성 요청
    Provider->>Vault: 2. GET /v1/pqc-keys/sign/dilithium-key
    Vault->>HSM: 3. PKCS#11 dilithium-sign
    Note over HSM: Luna HSM에서<br/>DILITHIUM3 서명 수행
    HSM-->>Vault: 4. PQC 서명 데이터
    Vault-->>Provider: 5. 서명된 데이터
    Provider->>Provider: 6. JWT 토큰 조립<br/>(Header + Payload + Signature)
    Provider-->>KC: 7. PQC JWT Token
    KC-->>App: 8. Access Token 발급

    Note over App,KC: === 토큰 검증 단계 ===

    App->>KC: 9. /realms/myrealm/protocol/openid-connect/userinfo
    KC->>Provider: 10. 토큰 서명 검증 요청
    Provider->>Vault: 11. GET /v1/pqc-keys/verify/dilithium-key
    Vault->>HSM: 12. PKCS#11 dilithium-verify
    HSM-->>Vault: 13. 검증 결과 (true/false)
    Vault-->>Provider: 14. 검증 완료
    Provider-->>KC: 15. 토큰 유효성 확인
    KC-->>App: 16. 사용자 정보 반환
```

## 3. Q-KMS Vault 초기화 및 Unseal 플로우

```mermaid
sequenceDiagram
    autonumber
    participant ArgoCD as ArgoCD
    participant K8s as Kubernetes
    participant Init as Init Container
    participant Vault as Vault Pod
    participant HSM as Luna HSM Device

    ArgoCD->>K8s: 1. Vault Deployment Apply
    K8s->>Init: 2. Init Container 실행
    Init->>Init: 3. Unseal 키 로드 (ConfigMap)
    Init->>Vault: 4. vault operator unseal (key1)
    Init->>Vault: 5. vault operator unseal (key2)
    Init->>Vault: 6. vault operator unseal (key3)
    Note over Vault: Unseal 완료<br/>(3/5 키 사용)
    Vault->>Vault: 7. Vault 서비스 시작
    Vault->>HSM: 8. Luna HSM 연결 (/dev/k7pf0)
    HSM-->>Vault: 9. HSM 연결 확인
    Vault->>Vault: 10. pqc-keys/ Secret Engine 활성화
    Vault->>Vault: 11. Transit Engine 활성화
    Vault-->>K8s: 12. Readiness Probe 성공
    K8s-->>ArgoCD: 13. Vault Healthy 상태 보고
```

## 4. API Gateway를 통한 보호된 리소스 접근

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Angular App
    participant APISIX as APISIX Gateway
    participant KC as Keycloak PQC
    participant API as Backend API
    participant Vault as Q-KMS Vault

    User->>App: 1. API 요청 (with Access Token)
    App->>APISIX: 2. GET /api/resource<br/>Authorization: Bearer {PQC_TOKEN}
    APISIX->>APISIX: 3. JWT 토큰 추출
    APISIX->>KC: 4. JWKS 엔드포인트 호출<br/>/realms/myrealm/protocol/openid-connect/certs
    KC-->>APISIX: 5. PQC 공개키 (DILITHIUM3)
    APISIX->>APISIX: 6. PQC 서명 검증

    alt 토큰 유효
        APISIX->>API: 7. Forward 요청 (with user context)
        API->>Vault: 8. 데이터 암호화/복호화 요청 (필요시)
        Vault-->>API: 9. 암호화된 데이터
        API-->>APISIX: 10. API 응답
        APISIX-->>App: 11. 응답 전달
        App-->>User: 12. 데이터 표시
    else 토큰 무효
        APISIX-->>App: 7. 401 Unauthorized
        App-->>User: 8. 로그인 리다이렉트
    end
```

## 5. Hybrid 서명 플로우 (RSA + DILITHIUM3)

```mermaid
sequenceDiagram
    autonumber
    participant KC as Keycloak PQC
    participant Hybrid as Hybrid Provider
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM

    KC->>Hybrid: 1. Hybrid 토큰 생성 요청

    par Classical 서명 (RSA)
        Hybrid->>Vault: 2a. RSA 서명 요청
        Vault->>HSM: 3a. RSA-2048 Sign
        HSM-->>Vault: 4a. RSA 서명
        Vault-->>Hybrid: 5a. RSA 서명 데이터
    and PQC 서명 (DILITHIUM3)
        Hybrid->>Vault: 2b. DILITHIUM3 서명 요청
        Vault->>HSM: 3b. DILITHIUM3 Sign
        HSM-->>Vault: 4b. PQC 서명
        Vault-->>Hybrid: 5b. PQC 서명 데이터
    end

    Hybrid->>Hybrid: 6. Hybrid JWT 조립<br/>{<br/>  header: {alg: "hybrid-rsa-dilithium3"},<br/>  payload: {...},<br/>  signature: "RSA_SIG|DILITHIUM3_SIG"<br/>}
    Hybrid-->>KC: 7. Hybrid PQC Token

    Note over KC,HSM: 양자 내성 + 하위 호환성 보장
```

## 6. ArgoCD GitOps 배포 플로우

```mermaid
sequenceDiagram
    autonumber
    participant Dev as 개발자
    participant GitLab as GitLab Repo
    participant ArgoCD as ArgoCD
    participant K8s as Kubernetes
    participant App as Application

    Dev->>GitLab: 1. Git Push (Helm Chart 변경)
    GitLab-->>ArgoCD: 2. Webhook / Auto-detect
    ArgoCD->>GitLab: 3. Git Pull (main branch)
    ArgoCD->>ArgoCD: 4. Diff 분석 (Desired vs Current)

    alt Auto-Sync Enabled
        ArgoCD->>K8s: 5. Apply Manifest (자동)
    else Manual Sync
        ArgoCD->>Dev: 5. Out-of-Sync 알림
        Dev->>ArgoCD: 6. Sync 버튼 클릭
        ArgoCD->>K8s: 7. Apply Manifest
    end

    K8s->>App: 8. Rolling Update 실행
    App-->>K8s: 9. Readiness Probe 성공
    K8s-->>ArgoCD: 10. Healthy 상태 보고
    ArgoCD-->>Dev: 11. Sync 완료 알림
```

## 7. 모니터링 및 로깅 플로우

```mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant SW as SkyWalking Agent
    participant OAP as SkyWalking OAP
    participant ES as Elasticsearch
    participant Prom as Prometheus
    participant Grafana as Grafana
    participant User as 운영자

    App->>SW: 1. Trace Data (APM)
    SW->>OAP: 2. gRPC/HTTP Send
    OAP->>ES: 3. Store Traces

    App->>Prom: 4. Metrics Export (/metrics)
    Prom->>Prom: 5. Scrape & Store

    User->>Grafana: 6. 대시보드 접속
    Grafana->>Prom: 7. PromQL Query
    Grafana->>ES: 8. Logs Query (via SkyWalking)
    Prom-->>Grafana: 9. Metrics Data
    ES-->>Grafana: 10. Trace/Log Data
    Grafana-->>User: 11. 통합 대시보드 표시

    Note over User,Grafana: Prometheus: 메트릭<br/>SkyWalking: APM/Trace<br/>Elasticsearch: 로그 저장
```

## 📊 다이어그램 범례

### 주요 컴포넌트
- **Keycloak PQC**: PQC SSO 인증 서버 (Namespace: pqc-sso)
- **Q-KMS Vault**: Vault + Luna HSM (Namespace: q-kms)
- **APISIX Gateway**: API Gateway (Namespace: qsign-prod)
- **Luna HSM**: 하드웨어 보안 모듈 (/dev/k7pf0)

### 프로토콜
- **PKCS#11**: HSM 통신 프로토콜
- **OIDC**: OpenID Connect (OAuth 2.0 기반)
- **gRPC**: SkyWalking 통신
- **HTTP/REST**: API 통신

### 엔드포인트
- **Keycloak**: http://192.168.0.11:30699
- **Q-KMS Vault**: http://192.168.0.11:30820
- **APISIX Gateway**: http://192.168.0.11:32236
- **Grafana**: http://192.168.0.11:30030

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
