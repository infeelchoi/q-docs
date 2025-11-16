# 토큰 라이프사이클 시퀀스 다이어그램

## 1. Access Token 생성 플로우

```mermaid
sequenceDiagram
    autonumber
    participant KC as Q-Sign (Keycloak)
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant DB as PostgreSQL

    Note over KC,DB: 토큰 발급 요청 수신
    KC->>KC: 1. 사용자 인증 완료
    KC->>KC: 2. 토큰 페이로드 생성<br/>{sub, iat, exp, scope}

    Note over KC,HSM: PQC 서명 생성
    KC->>Vault: 3. POST /v1/pqc-keys/sign<br/>payload={user_id, exp, roles}
    Vault->>Vault: 4. Serialize payload
    Vault->>HSM: 5. PKCS#11 C_Sign<br/>Algorithm: CKM_DILITHIUM3
    HSM->>HSM: 6. Hardware Signing<br/>(FIPS 140-2 Level 3)
    HSM-->>Vault: 7. PQC Signature (binary)
    Vault->>Vault: 8. Base64 encode signature
    Vault-->>KC: 9. Signed Data

    Note over KC,DB: JWT 조합
    KC->>KC: 10. Create JWT Header<br/>{alg: "DILITHIUM3", typ: "JWT"}
    KC->>KC: 11. Base64URL encode parts
    KC->>KC: 12. Concatenate:<br/>header.payload.signature

    Note over KC,DB: 세션 저장
    KC->>DB: 13. INSERT INTO user_sessions<br/>(token_id, user_id, exp)
    DB-->>KC: 14. Session saved

    KC-->>KC: 15. Return JWT Token
```

## 2. Refresh Token 플로우

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client App
    participant KC as Q-Sign
    participant DB as PostgreSQL
    participant Vault as Q-KMS
    participant HSM as Luna HSM

    Note over Client,HSM: Refresh Token 요청
    Client->>KC: 1. POST /token<br/>grant_type=refresh_token<br/>refresh_token=xxx

    Note over KC,DB: Refresh Token 검증
    KC->>KC: 2. Decode refresh token
    KC->>DB: 3. SELECT FROM refresh_tokens<br/>WHERE token_id=?
    DB-->>KC: 4. Token info {user_id, exp, scope}

    KC->>KC: 5. Validate expiration<br/>(exp > now?)

    alt Token expired
        KC-->>Client: 6a. 401 Unauthorized<br/>{error: "token_expired"}
    else Token valid
        Note over KC,HSM: 새 Access Token 생성
        KC->>KC: 7. Create new token payload
        KC->>Vault: 8. Request PQC signature
        Vault->>HSM: 9. Sign with DILITHIUM3
        HSM-->>Vault: 10. PQC Signature
        Vault-->>KC: 11. Signed data
        KC->>KC: 12. Generate new access_token

        Note over KC,DB: Refresh Token Rotation
        KC->>KC: 13. Generate new refresh_token
        KC->>DB: 14. UPDATE refresh_tokens<br/>SET token=new, used_at=now
        DB-->>KC: 15. Updated

        Note over KC,Client: 토큰 반환
        KC-->>Client: 16. {<br/>  access_token: "xxx",<br/>  refresh_token: "yyy",<br/>  expires_in: 1800<br/>}
    end
```

## 3. Token Revocation (토큰 폐기)

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin User
    participant KC as Q-Sign Admin API
    participant DB as PostgreSQL
    participant Cache as Session Cache

    Note over Admin,Cache: 토큰 폐기 요청
    Admin->>KC: 1. POST /admin/realms/myrealm<br/>/users/{id}/logout
    KC->>KC: 2. Validate admin permissions

    Note over KC,Cache: 세션 무효화
    KC->>DB: 3. SELECT FROM user_sessions<br/>WHERE user_id=?
    DB-->>KC: 4. Active sessions list

    KC->>Cache: 5. Delete session cache<br/>for all sessions
    Cache-->>KC: 6. Cache cleared

    KC->>DB: 7. UPDATE user_sessions<br/>SET revoked=true, revoked_at=now
    DB-->>KC: 8. Sessions revoked

    Note over KC,Cache: Refresh Token 폐기
    KC->>DB: 9. DELETE FROM refresh_tokens<br/>WHERE user_id=?
    DB-->>KC: 10. Refresh tokens deleted

    KC->>DB: 11. INSERT INTO token_blacklist<br/>(jti, exp, revoked_at)
    DB-->>KC: 12. Blacklist updated

    KC-->>Admin: 13. {<br/>  status: "success",<br/>  sessions_revoked: 3<br/>}
```

## 4. Token Validation (검증)

```mermaid
sequenceDiagram
    autonumber
    participant API as Backend API
    participant APISIX as Q-Gateway
    participant KC as Q-Sign
    participant Vault as Q-KMS
    participant HSM as Luna HSM
    participant Cache as Token Cache

    Note over API,Cache: API 요청 수신
    API->>APISIX: 1. GET /api/resource<br/>Authorization: Bearer {token}

    Note over APISIX,Cache: 캐시 확인
    APISIX->>Cache: 2. Check token cache
    Cache-->>APISIX: 3. Cache miss

    Note over APISIX,HSM: 토큰 검증
    APISIX->>KC: 4. POST /protocol/openid-connect<br/>/token/introspect
    KC->>KC: 5. Decode JWT<br/>(header, payload, signature)

    Note over KC,HSM: PQC 서명 검증
    KC->>Vault: 6. POST /v1/pqc-keys/verify<br/>{data, signature}
    Vault->>HSM: 7. PKCS#11 C_Verify<br/>Algorithm: CKM_DILITHIUM3
    HSM->>HSM: 8. Hardware Verification
    HSM-->>Vault: 9. Valid/Invalid
    Vault-->>KC: 10. Verification result

    alt Invalid signature
        KC-->>APISIX: 11a. {active: false}
        APISIX-->>API: 12a. 401 Unauthorized
    else Valid signature
        Note over KC,Cache: 추가 검증
        KC->>KC: 13. Check expiration (exp)
        KC->>KC: 14. Check issuer (iss)
        KC->>KC: 15. Check audience (aud)

        KC-->>APISIX: 16. {<br/>  active: true,<br/>  sub: "user123",<br/>  scope: "openid email"<br/>}

        Note over APISIX,Cache: 캐시 저장
        APISIX->>Cache: 17. Cache token validation<br/>(TTL: 5 min)
        Cache-->>APISIX: 18. Cached

        APISIX->>API: 19. Forward request<br/>(with user context)
        API-->>APISIX: 20. API Response
        APISIX-->>API: 21. Response
    end
```

## 5. Token Expiration & Auto-Renewal

```mermaid
sequenceDiagram
    autonumber
    participant App as Client App
    participant Timer as Token Timer
    participant API as Backend API
    participant KC as Q-Sign

    Note over App,KC: 정상 API 호출
    App->>API: 1. GET /api/data<br/>Authorization: Bearer {token}
    API-->>App: 2. 200 OK + Data

    Note over App,KC: 시간 경과 (토큰 만료 임박)
    Timer->>App: 3. Token expiring soon<br/>(exp - 60s)

    Note over App,KC: 사전 갱신 (Proactive Refresh)
    App->>KC: 4. POST /token<br/>grant_type=refresh_token
    KC->>KC: 5. Validate refresh token
    KC->>KC: 6. Generate new access token
    KC-->>App: 7. New access_token
    App->>App: 8. Update stored token

    Note over App,KC: 갱신된 토큰으로 API 호출
    App->>API: 9. GET /api/data<br/>Authorization: Bearer {new_token}
    API-->>App: 10. 200 OK + Data

    Note over App,KC: 토큰 완전 만료 시나리오
    Timer->>Timer: 11. Token expired (exp < now)
    App->>API: 12. GET /api/data<br/>Authorization: Bearer {expired_token}
    API-->>App: 13. 401 Unauthorized

    App->>KC: 14. POST /token<br/>grant_type=refresh_token

    alt Refresh token valid
        KC-->>App: 15a. New tokens
        App->>App: 16a. Retry original request
    else Refresh token expired
        KC-->>App: 15b. 401 Unauthorized
        App->>App: 16b. Redirect to login
    end
```

## 6. Hybrid Token Generation (RSA + PQC)

```mermaid
sequenceDiagram
    autonumber
    participant KC as Q-Sign (Keycloak)
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM

    Note over KC,HSM: 하이브리드 토큰 생성 요청
    KC->>KC: 1. Token payload 생성

    Note over KC,HSM: RSA 서명 생성 (Classical)
    KC->>KC: 2. Load RSA private key<br/>(2048-bit)
    KC->>KC: 3. SHA256withRSA signature
    KC->>KC: 4. Base64URL encode<br/>rs256_signature

    Note over KC,HSM: PQC 서명 생성 (Quantum-Safe)
    KC->>Vault: 5. POST /v1/pqc-keys/sign<br/>payload={...}
    Vault->>HSM: 6. PKCS#11 C_Sign<br/>CKM_DILITHIUM3
    HSM-->>Vault: 7. PQC signature
    Vault-->>KC: 8. dilithium3_signature

    Note over KC,HSM: 하이브리드 JWT 조합
    KC->>KC: 9. Create hybrid header:<br/>{<br/>  alg: "RS256+DILITHIUM3",<br/>  typ: "JWT",<br/>  kid: "hybrid-key-1"<br/>}

    KC->>KC: 10. Combine signatures:<br/>{<br/>  rs256: "...",<br/>  dilithium3: "..."<br/>}

    KC->>KC: 11. Encode final JWT:<br/>header.payload.{rs256+pqc}

    KC-->>KC: 12. Return Hybrid JWT Token
```

## 7. Session Management & Token Binding

```mermaid
sequenceDiagram
    autonumber
    participant User as User Browser
    participant App as Client App
    participant KC as Q-Sign
    participant DB as PostgreSQL

    Note over User,DB: 로그인 후 세션 생성
    User->>App: 1. Login successful
    App->>KC: 2. Authorization code exchange
    KC->>KC: 3. Generate session ID
    KC->>KC: 4. Generate access & refresh tokens

    Note over KC,DB: 토큰-세션 바인딩
    KC->>DB: 5. INSERT INTO sessions<br/>(session_id, user_id,<br/> access_token_jti, refresh_token_jti)
    DB-->>KC: 6. Session created

    KC->>KC: 7. Set session cookie<br/>KEYCLOAK_SESSION={session_id}
    KC-->>App: 8. Tokens + Set-Cookie
    App->>User: 9. Store tokens + cookie

    Note over User,DB: 다른 브라우저에서 로그인
    User->>App: 10. Login from different browser
    App->>KC: 11. Authentication request
    KC->>DB: 12. Check existing sessions
    DB-->>KC: 13. User has 1 active session

    alt Concurrent sessions allowed
        KC->>DB: 14a. Create new session
        KC-->>App: 15a. New tokens
    else Single session only
        KC->>DB: 14b. Revoke old session
        KC->>DB: 15b. Create new session
        KC-->>App: 16b. New tokens<br/>(old session invalidated)
    end

    Note over User,DB: 세션 만료
    KC->>KC: 17. Session timeout check<br/>(idle: 30min, max: 10h)
    KC->>DB: 18. UPDATE sessions<br/>SET expired=true
    DB-->>KC: 19. Session expired
```

## 📊 토큰 타임라인

```mermaid
gantt
    title Token Lifecycle Timeline
    dateFormat mm:ss
    axisFormat %M:%S

    section Access Token
    Valid                :00:00, 05:00
    Expiring Soon        :04:00, 01:00
    Expired              :05:00, 25:00

    section Refresh Token
    Valid                :00:00, 30:00

    section Session
    Active               :00:00, 10:00
    Idle Timeout         :10:00, 20:00
```

## 🔑 토큰 구조

### Access Token (PQC JWT)
```json
{
  "header": {
    "alg": "DILITHIUM3",
    "typ": "JWT",
    "kid": "pqc-key-1"
  },
  "payload": {
    "sub": "user-uuid-123",
    "iat": 1700000000,
    "exp": 1700001800,
    "iss": "http://192.168.0.11:30181/realms/myrealm",
    "aud": "account",
    "scope": "openid email profile",
    "azp": "app-client",
    "session_state": "session-uuid-456"
  },
  "signature": "dilithium3_signature_base64url"
}
```

### Refresh Token (Opaque)
```json
{
  "id": "refresh-uuid-789",
  "user_id": "user-uuid-123",
  "client_id": "app-client",
  "iat": 1700000000,
  "exp": 1702592000,
  "scope": "openid email profile offline_access"
}
```

## ⏱️ 토큰 타임 설정

| Token Type | Default Lifetime | Configurable |
|------------|------------------|--------------|
| Access Token | 5분 - 30분 | ✅ |
| Refresh Token | 30일 | ✅ |
| ID Token | Access Token과 동일 | ✅ |
| Session (SSO) | 10시간 | ✅ |
| Idle Timeout | 30분 | ✅ |

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Token Algorithm**: DILITHIUM3 (PQC)
