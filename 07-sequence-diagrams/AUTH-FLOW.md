# 인증 플로우 시퀀스 다이어그램

## 🔐 전체 인증 아키텍처

```mermaid
graph TB
    subgraph "Client Layer"
        A[Web App]
        B[Mobile App]
        C[CLI Tool]
    end

    subgraph "Gateway Layer"
        D[APISIX Gateway]
    end

    subgraph "Authentication Layer"
        E[Keycloak PQC]
        F[PostgreSQL]
    end

    subgraph "Key Management Layer"
        G[Q-KMS Vault]
        H[Luna HSM]
    end

    A --> D
    B --> D
    C --> D
    D --> E
    E --> F
    E --> G
    G --> H
```

## 1. OIDC 인증 플로우 (Authorization Code Flow with PKCE)

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Client App
    participant APISIX as Q-Gateway
    participant KC as Q-Sign (Keycloak)
    participant DB as PostgreSQL
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM

    Note over User,HSM: 1단계: 인증 요청
    User->>App: 1. 로그인 버튼 클릭
    App->>App: 2. PKCE Code Verifier 생성
    App->>App: 3. Code Challenge 계산<br/>(SHA256(verifier))
    App->>APISIX: 4. GET /auth?response_type=code<br/>&client_id=xxx<br/>&code_challenge=xxx<br/>&code_challenge_method=S256
    APISIX->>KC: 5. Forward 인증 요청
    KC->>User: 6. 로그인 페이지 리다이렉트

    Note over User,HSM: 2단계: 사용자 인증
    User->>KC: 7. POST /auth<br/>username & password
    KC->>DB: 8. SELECT user FROM users<br/>WHERE username=?
    DB-->>KC: 9. User 정보 반환
    KC->>KC: 10. 비밀번호 검증<br/>(bcrypt compare)

    Note over User,HSM: 3단계: Authorization Code 발급
    KC->>KC: 11. Authorization Code 생성
    KC->>DB: 12. INSERT INTO auth_sessions
    DB-->>KC: 13. Session 저장 완료
    KC-->>APISIX: 14. Redirect with code=xxx
    APISIX-->>App: 15. Redirect to callback

    Note over User,HSM: 4단계: 토큰 교환
    App->>APISIX: 16. POST /token<br/>grant_type=authorization_code<br/>code=xxx<br/>code_verifier=xxx
    APISIX->>KC: 17. Forward token request
    KC->>KC: 18. Code Challenge 검증<br/>SHA256(verifier) == challenge?
    KC->>DB: 19. SELECT session
    DB-->>KC: 20. Session 정보

    Note over User,HSM: 5단계: PQC 토큰 생성
    KC->>Vault: 21. POST /v1/pqc-keys/sign<br/>payload={user_id, exp, ...}
    Vault->>HSM: 22. PKCS#11 Sign<br/>Algorithm: DILITHIUM3
    HSM->>HSM: 23. Hardware Signing
    HSM-->>Vault: 24. PQC Signature
    Vault-->>KC: 25. Signed Data
    KC->>KC: 26. JWT Assembly<br/>header.payload.signature

    Note over User,HSM: 6단계: 토큰 반환
    KC-->>APISIX: 27. access_token, refresh_token,<br/>id_token, expires_in
    APISIX-->>App: 28. Token Response
    App->>App: 29. Store tokens (localStorage)
    App->>User: 30. 로그인 완료
```

## 2. SSO (Single Sign-On) 플로우

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App1 as Application 1
    participant App2 as Application 2
    participant KC as Q-Sign (Keycloak)
    participant Session as SSO Session

    Note over User,Session: 사용자가 App1에 이미 로그인된 상태
    User->>App1: 1. 로그인
    App1->>KC: 2. 인증 요청
    KC->>KC: 3. 사용자 인증
    KC->>Session: 4. SSO Session 생성<br/>(Cookie: KEYCLOAK_SESSION)
    KC-->>App1: 5. Access Token 반환
    App1-->>User: 6. 로그인 완료

    Note over User,Session: 사용자가 App2 접속 (SSO)
    User->>App2: 7. 로그인 시도
    App2->>KC: 8. 인증 요청
    KC->>Session: 9. SSO Session 확인
    Session-->>KC: 10. Valid Session 존재
    KC->>KC: 11. 자동 로그인<br/>(prompt=none)
    KC-->>App2: 12. Access Token 즉시 발급
    App2-->>User: 13. 자동 로그인 완료<br/>(비밀번호 입력 불필요)
```

## 3. MFA (Multi-Factor Authentication) 플로우

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Client App
    participant KC as Q-Sign
    participant TOTP as TOTP Provider
    participant SMS as SMS Gateway

    User->>App: 1. 로그인 (ID/PW)
    App->>KC: 2. 인증 요청
    KC->>KC: 3. 1차 인증 (비밀번호)
    KC->>KC: 4. MFA Required 확인

    alt TOTP 방식
        KC-->>User: 5a. TOTP 코드 입력 요청
        User->>App: 6a. TOTP 코드 입력
        App->>KC: 7a. TOTP 검증 요청
        KC->>TOTP: 8a. Verify TOTP
        TOTP-->>KC: 9a. Valid
    else SMS 방식
        KC->>SMS: 5b. SMS 발송
        SMS-->>User: 6b. 인증번호 수신
        User->>App: 7b. 인증번호 입력
        App->>KC: 8b. SMS 코드 검증
        KC->>KC: 9b. Valid
    end

    KC->>KC: 10. 2차 인증 완료
    KC-->>App: 11. Access Token 발급
    App-->>User: 12. 로그인 완료
```

## 4. Refresh Token 플로우

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Client App
    participant API as Backend API
    participant APISIX as Q-Gateway
    participant KC as Q-Sign

    User->>App: 1. API 호출
    App->>API: 2. GET /api/data<br/>Authorization: Bearer {access_token}
    API-->>App: 3. 401 Unauthorized<br/>(Token Expired)

    Note over App,KC: Access Token 갱신
    App->>App: 4. Refresh Token 확인
    App->>APISIX: 5. POST /token<br/>grant_type=refresh_token<br/>refresh_token=xxx
    APISIX->>KC: 6. Forward refresh request
    KC->>KC: 7. Refresh Token 검증
    KC->>KC: 8. 새 Access Token 생성
    KC-->>APISIX: 9. New access_token
    APISIX-->>App: 10. Token Response

    Note over App,KC: 재시도
    App->>App: 11. Update stored token
    App->>API: 12. GET /api/data<br/>Authorization: Bearer {new_token}
    API-->>App: 13. 200 OK + Data
    App-->>User: 14. 데이터 표시
```

## 5. Logout 플로우

```mermaid
sequenceDiagram
    autonumber
    actor User as 사용자
    participant App as Client App
    participant KC as Q-Sign
    participant Session as SSO Session
    participant DB as PostgreSQL

    User->>App: 1. 로그아웃 클릭
    App->>App: 2. ID Token 준비
    App->>KC: 3. GET /logout<br/>?id_token_hint={id_token}<br/>&post_logout_redirect_uri={uri}

    KC->>Session: 4. SSO Session 조회
    Session-->>KC: 5. Session 정보
    KC->>DB: 6. DELETE FROM sessions<br/>WHERE session_id=?
    DB-->>KC: 7. Session 삭제 완료
    KC->>Session: 8. Cookie 삭제
    KC->>KC: 9. Refresh Token 폐기

    KC-->>App: 10. Redirect to post_logout_uri
    App->>App: 11. localStorage.clear()
    App-->>User: 12. 로그아웃 완료<br/>(로그인 페이지로 이동)
```

## 6. Token Introspection (토큰 검증)

```mermaid
sequenceDiagram
    autonumber
    participant API as Backend API
    participant APISIX as Q-Gateway
    participant KC as Q-Sign
    participant Vault as Q-KMS
    participant HSM as Luna HSM

    API->>APISIX: 1. Validate Token Request
    APISIX->>KC: 2. POST /introspect<br/>token={access_token}
    KC->>KC: 3. JWT Decode<br/>(header.payload.signature)

    Note over KC,HSM: PQC 서명 검증
    KC->>Vault: 4. POST /v1/pqc-keys/verify
    Vault->>HSM: 5. PKCS#11 Verify<br/>Algorithm: DILITHIUM3
    HSM->>HSM: 6. Hardware Verification
    HSM-->>Vault: 7. Verification Result
    Vault-->>KC: 8. Valid/Invalid

    KC->>KC: 9. Expiration Check<br/>(exp > now?)
    KC->>KC: 10. Scope Validation
    KC-->>APISIX: 11. {active: true, sub: user_id,<br/>scope: "openid email"}
    APISIX-->>API: 12. Token Valid
```

## 7. Client Credentials Flow (Machine-to-Machine)

```mermaid
sequenceDiagram
    autonumber
    participant Service1 as Service A
    participant APISIX as Q-Gateway
    participant KC as Q-Sign
    participant Service2 as Service B

    Note over Service1,Service2: M2M 인증 (서비스 간 통신)
    Service1->>APISIX: 1. POST /token<br/>grant_type=client_credentials<br/>client_id=service-a<br/>client_secret=xxx
    APISIX->>KC: 2. Forward request
    KC->>KC: 3. Client Credentials 검증
    KC->>KC: 4. Service Token 생성<br/>(no user context)
    KC-->>APISIX: 5. access_token (service scope)
    APISIX-->>Service1: 6. Token Response

    Service1->>APISIX: 7. GET /service-b/api<br/>Authorization: Bearer {token}
    APISIX->>APISIX: 8. JWT Validation
    APISIX->>Service2: 9. Forward request
    Service2-->>APISIX: 10. API Response
    APISIX-->>Service1: 11. Response
```

## 📊 인증 상태 다이어그램

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated
    Unauthenticated --> Authenticating: Login Request
    Authenticating --> Authenticated: Success
    Authenticating --> Unauthenticated: Failed
    Authenticated --> TokenExpired: Access Token Expires
    TokenExpired --> Authenticated: Refresh Token Success
    TokenExpired --> Unauthenticated: Refresh Failed
    Authenticated --> Unauthenticated: Logout
```

## 🔑 토큰 타입

### Access Token
- **용도**: API 접근 권한
- **유효기간**: 5분 ~ 30분
- **형식**: PQC JWT (DILITHIUM3 서명)

### Refresh Token
- **용도**: Access Token 갱신
- **유효기간**: 30일
- **형식**: Opaque Token (UUID)

### ID Token
- **용도**: 사용자 정보 전달
- **유효기간**: Access Token과 동일
- **형식**: Standard JWT (RS256 or PQC)

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Protocol**: OIDC/OAuth 2.0 + PQC
