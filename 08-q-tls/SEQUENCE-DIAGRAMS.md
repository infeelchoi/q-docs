# Q-TLS Sequence Diagrams

Q-TLS (Quantum-resistant Transport Security Layer) 프로토콜의 주요 시퀀스 다이어그램 모음입니다.

## 목차

1. [전체 Q-TLS Hybrid 핸드셰이크](#1-전체-q-tls-hybrid-핸드셰이크)
2. [키 교환 상세 흐름 (KYBER1024 KEM)](#2-키-교환-상세-흐름-kyber1024-kem)
3. [인증서 검증 흐름](#3-인증서-검증-흐름)
4. [Session Resumption (Session ID)](#4-session-resumption-session-id)
5. [Session Ticket 발급 및 재사용](#5-session-ticket-발급-및-재사용)
6. [Mutual TLS 인증 흐름](#6-mutual-tls-인증-흐름)
7. [에러 처리 시나리오](#7-에러-처리-시나리오)
8. [0-RTT 데이터 전송 흐름](#8-0-rtt-데이터-전송-흐름)
9. [OCSP Stapling](#9-ocsp-stapling)
10. [세션 종료 및 재협상](#10-세션-종료-및-재협상)

---

## 1. 전체 Q-TLS Hybrid 핸드셰이크

Q-TLS Hybrid 모드의 전체 핸드셰이크 프로세스 (30+ steps)

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM
    participant OCSP as OCSP Responder

    Note over C,S: Phase 1: Initial Handshake

    C->>S: 1. ClientHello<br/>[TLS 1.3, PQC Extensions,<br/>Cipher Suites,<br/>Supported Groups: X25519, Kyber1024,<br/>Signature Algorithms: ECDSA, Dilithium3]

    Note over S: 2. Verify TLS version<br/>3. Select Cipher Suite:<br/>TLS_HYBRID_ECDHE_KYBER1024_RSA_DILITHIUM3_WITH_AES_256_GCM_SHA384

    S->>C: 4. ServerHello<br/>[Selected Cipher Suite,<br/>Session ID,<br/>Server Random]

    Note over C,S: Phase 2: Key Exchange (Hybrid)

    S->>C: 5. EncryptedExtensions<br/>[ALPN: h2, Server Name]

    S->>HSM: 6. Request Kyber1024 Public Key
    HSM-->>S: 7. Kyber1024 Public Key

    S->>C: 8. KeyShare Extension<br/>[ECDHE P-384 Public Key,<br/>Kyber1024 Public Key]

    Note over C,S: Phase 3: Server Authentication

    S->>C: 9. CertificateRequest (Optional)<br/>[Acceptable CAs,<br/>Signature Algorithms]

    S->>C: 10. Certificate Chain<br/>[Server Cert (Hybrid),<br/>Intermediate CA,<br/>Root CA]

    S->>OCSP: 11. OCSP Stapling Request
    OCSP-->>S: 12. OCSP Response (Good)

    S->>C: 13. CertificateStatus<br/>[OCSP Response]

    Note over S: 14. Sign transcript with Dilithium3

    S->>HSM: 15. Request Dilithium3 Signature
    HSM-->>S: 16. Dilithium3 Signature

    S->>C: 17. CertificateVerify<br/>[Dilithium3 Signature + ECDSA Signature]

    Note over S: 18. Derive Master Secret:<br/>HKDF(ECDHE_Secret || Kyber1024_Secret)

    S->>C: 19. Finished<br/>[HMAC of all handshake messages]

    Note over C,S: Phase 4: Client Authentication

    Note over C: 20. Verify Server Certificate Chain<br/>21. Verify OCSP Status<br/>22. Verify Dilithium3 Signature<br/>23. Verify ECDSA Signature

    Note over C: 24. Generate ECDHE Key Pair<br/>25. Encapsulate Kyber1024

    C->>S: 26. Certificate Chain (if requested)<br/>[Client Cert (Hybrid)]

    C->>S: 27. CertificateVerify<br/>[Client Dilithium3 + ECDSA Signature]

    C->>S: 28. KeyShare Extension<br/>[ECDHE Public Key,<br/>Kyber1024 Ciphertext]

    Note over C: 29. Derive Master Secret:<br/>HKDF(ECDHE_Secret || Kyber1024_Secret)

    C->>S: 30. Finished<br/>[HMAC of all handshake messages]

    Note over C,S: Phase 5: Application Data

    S-->>C: 31. NewSessionTicket<br/>[Session Ticket Encryption Key]

    Note over C,S: 32. Handshake Complete<br/>Symmetric Encryption Active

    C->>S: 33. Application Data (Encrypted)<br/>[AES-256-GCM]
    S->>C: 34. Application Data (Encrypted)<br/>[AES-256-GCM]
```

### 핸드셰이크 메시지 크기

| 메시지 | 전통 TLS 1.3 | Q-TLS Hybrid | 증가율 |
|--------|-------------|--------------|--------|
| ClientHello | ~200 bytes | ~400 bytes | 2x |
| ServerHello | ~150 bytes | ~300 bytes | 2x |
| Certificate | ~2 KB | ~8 KB | 4x |
| CertificateVerify | ~256 bytes | ~3 KB | 12x |
| KeyShare (Kyber1024) | 32 bytes | 1,568 bytes | 49x |
| **Total Handshake** | **~3 KB** | **~15 KB** | **5x** |

---

## 2. 키 교환 상세 흐름 (KYBER1024 KEM)

KYBER1024 Key Encapsulation Mechanism과 ECDHE의 하이브리드 키 교환

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    Note over C,S: ECDHE P-384 Key Exchange

    Note over S: 1. Generate ECDHE Key Pair<br/>Private: d_s (384 bits)<br/>Public: Q_s = d_s * G

    S->>C: 2. ECDHE Public Key (Q_s)<br/>[48 bytes]

    Note over C: 3. Generate ECDHE Key Pair<br/>Private: d_c (384 bits)<br/>Public: Q_c = d_c * G

    Note over C: 4. Compute ECDHE Shared Secret<br/>S_ecdhe = d_c * Q_s<br/>[48 bytes]

    C->>S: 5. ECDHE Public Key (Q_c)<br/>[48 bytes]

    Note over S: 6. Compute ECDHE Shared Secret<br/>S_ecdhe = d_s * Q_c<br/>[48 bytes]

    Note over C,S: KYBER1024 KEM

    S->>HSM: 7. Generate Kyber1024 Key Pair

    Note over HSM: 8. Kyber1024.KeyGen()<br/>Private Key: sk (3,168 bytes)<br/>Public Key: pk (1,568 bytes)

    HSM-->>S: 9. Kyber1024 Public Key (pk)<br/>[1,568 bytes]

    S->>C: 10. Kyber1024 Public Key (pk)<br/>[1,568 bytes]

    Note over C: 11. Kyber1024.Encapsulate(pk)<br/>→ (ct, ss)<br/>Ciphertext: 1,568 bytes<br/>Shared Secret: 32 bytes

    C->>S: 12. Kyber1024 Ciphertext (ct)<br/>[1,568 bytes]

    S->>HSM: 13. Request Kyber1024 Decapsulation<br/>[Ciphertext]

    Note over HSM: 14. Kyber1024.Decapsulate(sk, ct)<br/>→ ss<br/>Shared Secret: 32 bytes

    HSM-->>S: 15. Kyber1024 Shared Secret (ss)<br/>[32 bytes]

    Note over C,S: Hybrid Secret Derivation

    Note over C: 16. Combine Secrets (Client)<br/>combined = S_ecdhe || ss_kyber<br/>[48 + 32 = 80 bytes]

    Note over S: 17. Combine Secrets (Server)<br/>combined = S_ecdhe || ss_kyber<br/>[48 + 32 = 80 bytes]

    Note over C: 18. Derive Master Secret (Client)<br/>MS = HKDF-Expand(<br/>  HKDF-Extract(combined),<br/>  "master secret",<br/>  handshake_hash<br/>)<br/>[32 bytes]

    Note over S: 19. Derive Master Secret (Server)<br/>MS = HKDF-Expand(<br/>  HKDF-Extract(combined),<br/>  "master secret",<br/>  handshake_hash<br/>)<br/>[32 bytes]

    Note over C,S: Session Key Derivation

    Note over C: 20. Derive Session Keys (Client)<br/>client_write_key = HKDF(MS, "c ap traffic")<br/>server_write_key = HKDF(MS, "s ap traffic")<br/>client_write_iv = HKDF(MS, "c ap iv")<br/>server_write_iv = HKDF(MS, "s ap iv")

    Note over S: 21. Derive Session Keys (Server)<br/>[Same derivation as client]

    Note over C,S: 22. Keys Established<br/>AES-256-GCM Ready
```

### 키 교환 성능 비교

| 알고리즘 | 키 생성 | Encaps/DH | Decaps/DH | 공개키 크기 | 암호문 크기 |
|---------|---------|-----------|-----------|------------|------------|
| ECDHE P-384 | 0.5ms | 0.5ms | 0.5ms | 48 bytes | 48 bytes |
| Kyber1024 | 0.08ms | 0.12ms | 0.10ms | 1,568 bytes | 1,568 bytes |
| **Hybrid** | **0.58ms** | **0.62ms** | **0.60ms** | **1,616 bytes** | **1,616 bytes** |

---

## 3. 인증서 검증 흐름

X.509v3 하이브리드 인증서 체인 검증 및 OCSP 확인

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant OCSP as OCSP Responder
    participant CRL as CRL Distribution Point

    S->>C: 1. Certificate Chain<br/>[Server Cert, Intermediate CA, Root CA]

    Note over C: Certificate Chain Validation

    Note over C: 2. Extract Server Certificate<br/>Subject: CN=api.qsign.local<br/>Issuer: CN=Q-Sign Intermediate CA<br/>Valid From: 2025-01-01<br/>Valid To: 2026-01-01

    Note over C: 3. Verify Certificate Not Expired<br/>Current Time: 2025-11-16<br/>Status: Valid ✓

    Note over C: 4. Extract Public Keys<br/>RSA-4096 Public Key<br/>Dilithium3 Public Key (OID: 1.3.6.1.4.1.2.267.7.6.5)

    Note over C: 5. Verify Subject Alternative Names<br/>DNS: api.qsign.local<br/>DNS: *.qsign.local<br/>IP: 192.168.1.100

    Note over C: 6. Extract Intermediate CA Cert<br/>Subject: CN=Q-Sign Intermediate CA<br/>Issuer: CN=Q-Sign Root CA

    Note over C: 7. Verify Intermediate CA Signature<br/>Verify RSA-4096 Signature ✓<br/>Verify Dilithium3 Signature ✓

    Note over C: 8. Extract Root CA Cert<br/>Subject: CN=Q-Sign Root CA<br/>Issuer: CN=Q-Sign Root CA (Self-Signed)

    Note over C: 9. Verify Root CA in Trust Store<br/>SHA-256 Fingerprint Match ✓<br/>Root CA Trusted ✓

    Note over C: 10. Verify Root CA Self-Signature<br/>RSA-4096 Signature ✓<br/>Dilithium3 Signature ✓

    Note over C: OCSP Validation

    S->>C: 11. CertificateStatus (OCSP Stapling)<br/>[OCSP Response]

    Note over C: 12. Extract OCSP Response<br/>Response Status: Successful<br/>Cert Status: Good<br/>This Update: 2025-11-16 10:00:00<br/>Next Update: 2025-11-17 10:00:00

    Note over C: 13. Verify OCSP Response Signature<br/>Responder: CN=Q-Sign OCSP Responder<br/>Signature Algorithm: Dilithium3<br/>Signature Verification: ✓

    Note over C: 14. Verify OCSP Freshness<br/>Current Time: 2025-11-16 15:30:00<br/>Within Validity Period ✓

    alt OCSP Stapling Not Available
        C->>OCSP: 15. OCSP Request<br/>[Server Cert Serial Number]

        Note over OCSP: 16. Check Certificate Status<br/>Query HSM/Database

        OCSP-->>C: 17. OCSP Response<br/>[Status: Good]

        Note over C: 18. Verify OCSP Response<br/>(Same as steps 12-14)
    end

    Note over C: CRL Validation (Fallback)

    alt OCSP Not Available
        Note over C: 19. Extract CRL Distribution Point<br/>URI: http://crl.qsign.local/ca.crl

        C->>CRL: 20. Download CRL

        CRL-->>C: 21. CRL File<br/>[Revoked Certificates List]

        Note over C: 22. Verify CRL Signature<br/>Issuer: CN=Q-Sign Intermediate CA<br/>Signature: Dilithium3 ✓

        Note over C: 23. Check Server Cert Serial<br/>Serial: 0x1A2B3C4D5E6F<br/>Not in Revoked List ✓
    end

    Note over C: Extended Validation

    Note over C: 24. Verify Key Usage Extension<br/>Digital Signature ✓<br/>Key Encipherment ✓<br/>Key Agreement ✓

    Note over C: 25. Verify Extended Key Usage<br/>Server Authentication (1.3.6.1.5.5.7.3.1) ✓<br/>Client Authentication (1.3.6.1.5.5.7.3.2) ✓

    Note over C: 26. Verify Subject Key Identifier<br/>SKI: 4A:5B:6C:7D:8E:9F... ✓

    Note over C: 27. Verify Authority Key Identifier<br/>AKI matches Issuer SKI ✓

    Note over C: 28. Verify Basic Constraints<br/>CA: FALSE ✓<br/>Path Length: N/A

    Note over C: 29. All Validations Passed ✓<br/>Certificate Chain Valid
```

### 인증서 검증 체크리스트

| 검증 항목 | 설명 | 실패 시 동작 |
|----------|------|------------|
| Expiration | 유효기간 확인 | Alert: certificate_expired |
| Signature | RSA + Dilithium3 서명 검증 | Alert: bad_certificate |
| Chain | 루트 CA까지 체인 검증 | Alert: unknown_ca |
| OCSP/CRL | 폐기 상태 확인 | Alert: certificate_revoked |
| Hostname | SAN/CN 매칭 | Alert: bad_certificate |
| Key Usage | 용도 확장 필드 확인 | Alert: unsupported_certificate |

---

## 4. Session Resumption (Session ID)

Session ID 기반 세션 재개 메커니즘

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant Cache as Session Cache

    Note over C,S: Initial Full Handshake

    C->>S: 1. ClientHello<br/>[Session ID: empty]

    S->>S: 2. Generate Session ID<br/>[32 bytes random]

    S->>Cache: 3. Store Session State<br/>[Session ID: 0x1A2B...,<br/>Master Secret,<br/>Cipher Suite,<br/>Client Cert (if any)]

    S->>C: 4. ServerHello<br/>[Session ID: 0x1A2B...]

    Note over C,S: ... Full Handshake ...

    Note over C: 5. Store Session ID<br/>[0x1A2B..., Master Secret]

    C->>S: Application Data
    S->>C: Application Data

    Note over C,S: Connection Closed

    Note over C,S: Session Resumption (New Connection)

    C->>S: 6. ClientHello<br/>[Session ID: 0x1A2B...,<br/>Cipher Suites (same as before)]

    S->>Cache: 7. Lookup Session ID<br/>[0x1A2B...]

    Cache-->>S: 8. Session State Found<br/>[Master Secret, Cipher Suite]

    Note over S: 9. Verify Session Valid<br/>- Not Expired (< 24 hours)<br/>- Cipher Suite Supported<br/>- Security Parameters Match

    alt Session Valid
        S->>C: 10. ServerHello<br/>[Same Session ID: 0x1A2B...,<br/>Cipher Suite]

        Note over C,S: 11. NO Certificate Exchange<br/>NO KeyExchange<br/>NO CertificateVerify

        Note over C: 12. Derive New Keys from Master Secret<br/>client_write_key = HKDF(MS, nonce_c, nonce_s)<br/>server_write_key = HKDF(MS, nonce_s, nonce_c)

        Note over S: 13. Derive New Keys from Master Secret<br/>(Same derivation)

        S->>C: 14. ChangeCipherSpec
        S->>C: 15. Finished<br/>[HMAC with new keys]

        C->>S: 16. ChangeCipherSpec
        C->>S: 17. Finished<br/>[HMAC with new keys]

        Note over C,S: 18. Session Resumed<br/>Handshake Time: ~10ms (vs ~80ms full)

        C->>S: Application Data (Encrypted)
        S->>C: Application Data (Encrypted)

    else Session Invalid/Not Found
        S->>C: 19. ServerHello<br/>[New Session ID: 0x9F8E...]

        Note over C,S: 20. Full Handshake Required
    end
```

### Session Resumption 성능 비교

| 메트릭 | Full Handshake | Session Resumption | 개선율 |
|--------|----------------|--------------------|--------|
| Round Trips | 2-RTT | 1-RTT | 50% |
| Handshake Time | ~80ms | ~10ms | 87.5% |
| CPU Usage | 100% | 5% | 95% |
| Network Bandwidth | ~15 KB | ~500 bytes | 97% |
| HSM Operations | 4 ops | 0 ops | 100% |

---

## 5. Session Ticket 발급 및 재사용

RFC 5077 Session Ticket 메커니즘

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    Note over C,S: Initial Full Handshake

    C->>S: 1. ClientHello<br/>[Extension: SessionTicket (empty)]

    S->>C: 2. ServerHello<br/>[Extension: SessionTicket Supported]

    Note over C,S: ... Full Handshake ...

    C->>S: Finished
    S->>C: Finished

    Note over S: Ticket Generation

    Note over S: 3. Create Session State<br/>state = {<br/>  protocol_version: TLS 1.3,<br/>  cipher_suite: TLS_HYBRID_...,<br/>  master_secret: MS,<br/>  client_identity: CN=...,<br/>  timestamp: 2025-11-16 15:00:00<br/>}

    S->>HSM: 4. Encrypt Session State<br/>[AES-256-GCM, Ticket Encryption Key]

    Note over HSM: 5. Ticket Encryption Key (TEK)<br/>Rotated every 24 hours<br/>Stored in HSM

    HSM-->>S: 6. Encrypted Ticket<br/>[Ciphertext + Auth Tag]

    Note over S: 7. Create Session Ticket<br/>ticket = {<br/>  encrypted_state: [...],<br/>  lifetime: 86400 (24 hours),<br/>  ticket_age_add: random_value<br/>}

    S->>C: 8. NewSessionTicket<br/>[Ticket Data: ~1 KB]

    Note over C: 9. Store Session Ticket<br/>[Server: api.qsign.local,<br/>Ticket, Expiration]

    C->>S: Application Data
    S->>C: Application Data

    Note over C,S: Connection Closed

    Note over C,S: Ticket Resumption (New Connection)

    C->>S: 10. ClientHello<br/>[Extension: SessionTicket (Ticket Data),<br/>Cipher Suites]

    Note over S: 11. Extract Session Ticket

    S->>HSM: 12. Decrypt Session Ticket<br/>[TEK from 24h ago or current]

    alt Decryption Successful
        HSM-->>S: 13. Decrypted Session State<br/>[Master Secret, Cipher Suite, etc.]

        Note over S: 14. Validate Ticket<br/>- Timestamp < 24 hours ✓<br/>- Cipher Suite Supported ✓<br/>- Protocol Version Match ✓

        S->>C: 15. ServerHello<br/>[Extension: SessionTicket (empty = resuming)]

        Note over C,S: 16. Abbreviated Handshake<br/>(No Certificate Exchange)

        Note over C: 17. Derive New Keys<br/>from Master Secret

        Note over S: 18. Derive New Keys<br/>from Master Secret

        S->>C: 19. Finished
        C->>S: 20. Finished

        Note over S: 21. Issue New Ticket<br/>(Optional, for future resumption)

        S->>C: 22. NewSessionTicket<br/>[New Ticket]

        Note over C,S: 23. Session Resumed via Ticket<br/>Handshake Time: ~15ms

    else Decryption Failed / Ticket Expired
        Note over S: 24. Ticket Invalid<br/>TEK Rotated / Expired

        S->>C: 25. ServerHello<br/>[No SessionTicket Extension]

        Note over C,S: 26. Full Handshake Required
    end
```

### Session Ticket vs Session ID

| 특성 | Session ID | Session Ticket |
|------|-----------|----------------|
| 서버 상태 | Stateful (캐시 필요) | Stateless (암호화된 상태) |
| 확장성 | 제한적 (메모리) | 높음 (무제한) |
| 로드 밸런싱 | Sticky Session 필요 | 불필요 (모든 서버 지원) |
| 티켓 크기 | 32 bytes | ~1 KB |
| 보안 | 서버 메모리 | HSM 암호화 |
| 권장 용도 | 단일 서버 | 분산 환경 |

---

## 6. Mutual TLS 인증 흐름

클라이언트 인증서 기반 상호 인증 (mTLS)

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant C_HSM as Client HSM
    participant S_HSM as Server HSM
    participant OCSP as OCSP Responder

    Note over C,S: Server Authentication (Same as before)

    C->>S: 1. ClientHello<br/>[Cipher Suites, Extensions]

    S->>C: 2. ServerHello

    S->>C: 3. Server Certificate Chain<br/>[Server Cert, Intermediate CA, Root CA]

    S->>C: 4. CertificateRequest<br/>[Acceptable CAs:<br/>  - CN=Q-Sign Enterprise CA<br/>  - CN=Q-Sign Device CA,<br/>Signature Algorithms:<br/>  - Dilithium3<br/>  - ECDSA-P384]

    S->>S_HSM: 5. Sign handshake transcript
    S_HSM-->>S: Dilithium3 Signature

    S->>C: 6. CertificateVerify<br/>[Server Signature]

    S->>C: 7. Finished

    Note over C: Server Certificate Validation

    Note over C: 8. Verify Server Certificate Chain ✓<br/>9. Verify OCSP Status ✓<br/>10. Verify Dilithium3 + ECDSA ✓

    Note over C,S: Client Authentication

    Note over C: 11. Select Client Certificate<br/>Subject: CN=device-001.qsign.local<br/>Issuer: CN=Q-Sign Device CA<br/>Serial: 0xABCD1234

    C->>S: 12. Client Certificate Chain<br/>[Client Cert,<br/>Q-Sign Device CA,<br/>Q-Sign Root CA]

    Note over S: Client Certificate Validation

    S->>OCSP: 13. OCSP Request<br/>[Client Cert Serial: 0xABCD1234]

    OCSP-->>S: 14. OCSP Response<br/>[Status: Good]

    Note over S: 15. Verify Client Certificate<br/>- Issued by Trusted CA ✓<br/>- Not Expired ✓<br/>- OCSP Status: Good ✓<br/>- Extended Key Usage:<br/>  Client Authentication ✓

    Note over S: 16. Extract Client Identity<br/>Subject DN: CN=device-001.qsign.local<br/>OU: IoT Devices<br/>O: Q-Sign Enterprise

    Note over C: 17. Compute handshake hash

    C->>C_HSM: 18. Sign with Dilithium3<br/>[Handshake Transcript Hash]

    Note over C_HSM: 19. Client Private Key (Dilithium3)<br/>Stored in HSM / TPM

    C_HSM-->>C: 20. Dilithium3 Signature<br/>[~2.5 KB]

    C->>S: 21. CertificateVerify<br/>[Dilithium3 Signature + ECDSA Signature]

    Note over S: 22. Verify Client Signature<br/>Verify against Client Public Key

    alt Signature Valid
        Note over S: 23. Signature Verification ✓<br/>Client Authenticated

        C->>S: 24. Finished<br/>[HMAC of handshake]

        Note over S: 25. Verify Finished Message ✓

        S->>C: 26. NewSessionTicket<br/>[Include Client Identity]

        Note over C,S: 27. Mutual Authentication Complete<br/>Both Parties Authenticated

        Note over S: 28. Bind Client Identity to Session<br/>Session Attributes:<br/>  - client_dn: CN=device-001...<br/>  - client_cert_serial: 0xABCD1234<br/>  - auth_time: 2025-11-16 15:30:00

        C->>S: 29. Application Data<br/>[User: device-001.qsign.local]

        Note over S: 30. Authorization Check<br/>ACL: device-001 → API access ✓

        S->>C: 31. Application Data<br/>[200 OK]

    else Signature Invalid
        Note over S: 32. Signature Verification Failed ✗

        S->>C: 33. Alert: decrypt_error<br/>[Client Authentication Failed]

        Note over S: 34. Close Connection
    end
```

### mTLS 사용 사례

| 시나리오 | 클라이언트 인증 | 인증서 발급 | 용도 |
|---------|---------------|-----------|------|
| IoT 디바이스 | 필수 | Device CA | 디바이스 인증 |
| 서비스 간 통신 | 필수 | Service CA | 마이크로서비스 |
| 관리자 접근 | 필수 | User CA | 관리 콘솔 |
| 공개 API | 선택적 | - | 일반 사용자 |

---

## 7. 에러 처리 시나리오

Q-TLS Alert 프로토콜 및 에러 복구

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: Scenario 1: Unsupported Cipher Suite

    C->>S: 1. ClientHello<br/>[Cipher Suites: TLS_AES_128_GCM_SHA256]

    Note over S: 2. Check Supported Cipher Suites<br/>Required: TLS_HYBRID_ECDHE_KYBER1024_...<br/>Client Offers: TLS_AES_128_GCM_SHA256<br/>Match: None ✗

    S->>C: 3. Alert: handshake_failure<br/>[Alert Level: Fatal,<br/>Alert Description: No shared cipher suite]

    Note over S: 4. Close Connection

    Note over C: 5. Log Error<br/>Retry with Fallback Cipher Suite

    C->>S: 6. ClientHello (Retry)<br/>[Cipher Suites: TLS_HYBRID_..., TLS_AES_256_GCM_SHA384]

    S->>C: 7. ServerHello<br/>[Selected: TLS_HYBRID_...]

    Note over C,S: Scenario 2: Certificate Verification Failure

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: 8. Certificate Chain<br/>[Server Cert (Expired)]

    Note over C: 9. Verify Certificate<br/>Valid To: 2025-10-01<br/>Current: 2025-11-16<br/>Status: Expired ✗

    C->>S: 10. Alert: certificate_expired<br/>[Alert Level: Fatal]

    Note over C: 11. Close Connection<br/>Log: Server certificate expired

    Note over C,S: Scenario 3: OCSP Revocation

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: 12. Certificate + OCSP Stapling<br/>[OCSP Status: Revoked]

    Note over C: 13. Verify OCSP Response<br/>Certificate Status: Revoked<br/>Revocation Date: 2025-11-15<br/>Reason: Key Compromise

    C->>S: 14. Alert: certificate_revoked<br/>[Alert Level: Fatal]

    Note over C: 15. Close Connection<br/>Block Server in Local Cache

    Note over C,S: Scenario 4: Signature Verification Failure

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: Certificate
    S->>C: 16. CertificateVerify<br/>[Dilithium3 Signature (Invalid)]

    Note over C: 17. Verify Signature<br/>Dilithium3.Verify(pk, transcript, sig)<br/>Result: Invalid ✗

    C->>S: 18. Alert: decrypt_error<br/>[Alert Level: Fatal,<br/>Description: Signature verification failed]

    Note over C: 19. Close Connection<br/>Potential MITM Attack Detected

    Note over C,S: Scenario 5: Protocol Version Mismatch

    C->>S: 20. ClientHello<br/>[Supported Versions: TLS 1.2, TLS 1.1]

    Note over S: 21. Check Protocol Version<br/>Required: TLS 1.3 or higher<br/>Client Max: TLS 1.2<br/>Compatible: No ✗

    S->>C: 22. Alert: protocol_version<br/>[Alert Level: Fatal]

    Note over S: 23. Close Connection

    Note over C,S: Scenario 6: Decrypt Error (Bad Finished)

    C->>S: ClientHello
    S->>C: ServerHello
    Note over C,S: ... Handshake ...
    S->>C: Finished
    C->>S: 24. Finished<br/>[HMAC: Invalid]

    Note over S: 25. Verify Finished HMAC<br/>HMAC(master_secret, handshake_hash)<br/>Verification: Failed ✗

    S->>C: 26. Alert: decrypt_error<br/>[Alert Level: Fatal]

    Note over S: 27. Close Connection<br/>Possible Key Derivation Mismatch

    Note over C,S: Scenario 7: Insufficient Security

    C->>S: 28. ClientHello<br/>[Key Share: ECDHE P-256 only,<br/>No Kyber1024]

    Note over S: 29. Security Policy Check<br/>Required: Hybrid PQC (ECDHE + Kyber1024)<br/>Client Offers: ECDHE P-256 only<br/>Policy: Insufficient ✗

    S->>C: 30. Alert: insufficient_security<br/>[Alert Level: Fatal,<br/>Description: PQC required]

    Note over S: 31. Close Connection

    Note over C,S: Scenario 8: Internal Error (HSM Failure)

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: Certificate

    Note over S: 32. Request HSM Signature<br/>Operation: Dilithium3.Sign

    Note over S: 33. HSM Error<br/>Error: CKR_DEVICE_ERROR<br/>HSM Connection Lost

    S->>C: 34. Alert: internal_error<br/>[Alert Level: Fatal]

    Note over S: 35. Close Connection<br/>Reconnect to Backup HSM
```

### Alert 프로토콜 코드

| Alert Code | 이름 | Level | 설명 | 복구 가능 |
|-----------|------|-------|------|----------|
| 0 | close_notify | Warning | 정상 종료 | N/A |
| 10 | unexpected_message | Fatal | 잘못된 메시지 순서 | No |
| 20 | bad_record_mac | Fatal | MAC 검증 실패 | No |
| 40 | handshake_failure | Fatal | 핸드셰이크 실패 | Yes (Retry) |
| 42 | bad_certificate | Fatal | 인증서 형식 오류 | No |
| 43 | unsupported_certificate | Fatal | 지원되지 않는 인증서 | No |
| 44 | certificate_revoked | Fatal | 인증서 폐기됨 | No |
| 45 | certificate_expired | Fatal | 인증서 만료 | No |
| 46 | certificate_unknown | Fatal | 인증서 검증 실패 | No |
| 47 | illegal_parameter | Fatal | 잘못된 파라미터 | No |
| 48 | unknown_ca | Fatal | 알 수 없는 CA | No |
| 51 | decrypt_error | Fatal | 복호화 실패 | No |
| 70 | protocol_version | Fatal | 프로토콜 버전 불일치 | Yes (Fallback) |
| 71 | insufficient_security | Fatal | 보안 수준 부족 | Yes (Upgrade) |
| 80 | internal_error | Fatal | 내부 오류 | Yes (Retry) |
| 90 | user_canceled | Warning | 사용자 취소 | Yes |

---

## 8. 0-RTT 데이터 전송 흐름

Early Data (0-RTT) 전송 메커니즘

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant Cache as Session Cache

    Note over C,S: Initial Connection (Full Handshake)

    C->>S: 1. ClientHello
    S->>C: 2. ServerHello
    Note over C,S: ... Full Handshake ...
    S->>C: 3. Finished

    S->>C: 4. NewSessionTicket<br/>[Ticket,<br/>max_early_data_size: 16384,<br/>early_data indication]

    Note over C: 5. Store Session Ticket<br/>+ Early Data Key

    C->>S: 6. Application Data
    S->>C: 7. Application Data

    Note over C,S: Connection Closed

    Note over C,S: 0-RTT Resumption (New Connection)

    Note over C: 8. Prepare Early Data<br/>Request: GET /api/user/profile<br/>Headers: Authorization: Bearer ...

    Note over C: 9. Derive Early Traffic Secret<br/>early_secret = HKDF-Extract(PSK, 0)<br/>early_traffic_key = HKDF-Expand(<br/>  early_secret,<br/>  "c e traffic",<br/>  ClientHello_hash<br/>)

    C->>S: 10. ClientHello<br/>[Extension: early_data,<br/>Extension: pre_shared_key (Ticket),<br/>Extension: psk_key_exchange_modes]

    Note over C,S: ⚡ 0-RTT: Send data before handshake complete

    C->>S: 11. Early Data (Encrypted with early_traffic_key)<br/>[GET /api/user/profile<br/>Authorization: Bearer xyz...]

    C->>S: 12. EndOfEarlyData

    Note over S: 13. Verify Session Ticket

    S->>Cache: 14. Check Ticket + Anti-Replay

    alt Ticket Valid + No Replay
        Cache-->>S: 15. Ticket Valid<br/>Anti-Replay: OK

        Note over S: 16. Derive Early Traffic Secret<br/>(Same as Client)

        Note over S: 17. Decrypt Early Data<br/>Result: GET /api/user/profile

        Note over S: 18. Process Early Data<br/>Check: Idempotent? Safe Method?<br/>GET Request: Safe ✓

        Note over S: 19. Execute Request<br/>Query User Profile

        S->>C: 20. ServerHello<br/>[Extension: pre_shared_key,<br/>Extension: early_data (accepted)]

        Note over C,S: 21. Continue Handshake<br/>(Abbreviated, no Certificate)

        S->>C: 22. EncryptedExtensions
        S->>C: 23. Finished

        C->>S: 24. Finished

        Note over S: 25. Derive Application Traffic Keys

        S->>C: 26. Application Data (Response to Early Data)<br/>[200 OK,<br/>{"user": "john", "email": "..."}]

        Note over C,S: 27. Total RTT: 0-RTT ⚡<br/>Early Data Accepted

        S->>Cache: 28. Mark Ticket as Used<br/>[Anti-Replay Window: 10 seconds]

    else Ticket Replay Detected
        Cache-->>S: 29. Replay Detected ✗<br/>Ticket Already Used

        Note over S: 30. Reject Early Data

        S->>C: 31. ServerHello<br/>[Extension: early_data (rejected)]

        Note over C: 32. Early Data Rejected<br/>Fallback to 1-RTT

        Note over S: 33. Ignore Early Data<br/>Do NOT process request

        Note over C,S: 34. Continue Handshake

        C->>S: 35. Application Data (Re-send)<br/>[GET /api/user/profile]

        S->>C: 36. Application Data<br/>[200 OK]

        Note over C,S: 37. Total RTT: 1-RTT<br/>(Fallback)
    end
```

### 0-RTT 보안 고려사항

| 항목 | 위험 | 완화 방법 |
|------|------|----------|
| Replay Attack | 중복 요청 실행 | Anti-replay cache (10초 윈도우) |
| Forward Secrecy | Early data는 PFS 없음 | 민감한 데이터 금지 |
| 안전한 메서드만 허용 | POST/PUT 위험 | GET/HEAD만 허용 또는 멱등성 보장 |
| 데이터 크기 제한 | DoS 공격 | max_early_data_size: 16 KB |

### 0-RTT 허용 조건

```yaml
Early Data 허용 조건:
  메서드:
    - GET (Safe method)
    - HEAD
    - OPTIONS

  금지 메서드:
    - POST (State-changing)
    - PUT
    - DELETE
    - PATCH

  최대 크기:
    - 16 KB (max_early_data_size)

  Anti-Replay:
    - 윈도우: 10초
    - 저장소: Redis / In-Memory Cache
    - Ticket Hash: SHA-256

  권장 사용:
    - Static content
    - Idempotent APIs
    - Public data queries
```

---

## 9. OCSP Stapling

OCSP Stapling을 통한 인증서 상태 확인 최적화

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant OCSP as OCSP Responder
    participant Cache as OCSP Cache

    Note over S: Server Startup / Certificate Load

    Note over S: 1. Load Server Certificate<br/>Serial: 0x1A2B3C4D<br/>OCSP Responder: http://ocsp.qsign.local

    S->>OCSP: 2. OCSP Request (at startup)<br/>[Certificate Serial: 0x1A2B3C4D,<br/>Issuer: Q-Sign Intermediate CA]

    Note over OCSP: 3. Query Certificate Status<br/>Database / HSM

    OCSP-->>S: 4. OCSP Response<br/>[Response:<br/>  Status: Good,<br/>  This Update: 2025-11-16 10:00:00,<br/>  Next Update: 2025-11-17 10:00:00,<br/>  Signature: Dilithium3]

    S->>Cache: 5. Cache OCSP Response<br/>[TTL: Until Next Update]

    Note over C,S: TLS Handshake with OCSP Stapling

    C->>S: 6. ClientHello<br/>[Extension: status_request (OCSP)]

    Note over S: 7. Check Extension<br/>Client requests OCSP: Yes

    S->>Cache: 8. Lookup Cached OCSP Response

    alt OCSP Response Cached & Fresh
        Cache-->>S: 9. OCSP Response (Cached)<br/>[Status: Good, Age: 2 hours]

        S->>C: 10. ServerHello<br/>[Extension: status_request]

        S->>C: 11. Certificate Chain<br/>[Server Cert, Intermediate CA, Root CA]

        S->>C: 12. CertificateStatus<br/>[OCSP Response (Stapled)]

        Note over C: 13. Verify OCSP Response<br/>- Signature: Dilithium3 ✓<br/>- Status: Good ✓<br/>- Freshness: Within validity ✓<br/>- Responder: Trusted ✓

        Note over C: 14. Certificate Status: Valid ✓<br/>No need to contact OCSP Responder

    else OCSP Response Expired / Not Cached
        Cache-->>S: 15. OCSP Response Expired or Not Found

        S->>OCSP: 16. Fresh OCSP Request<br/>[Certificate Serial: 0x1A2B3C4D]

        alt OCSP Responder Available
            OCSP-->>S: 17. OCSP Response<br/>[Status: Good]

            S->>Cache: 18. Update Cache<br/>[New OCSP Response]

            S->>C: 19. CertificateStatus<br/>[Fresh OCSP Response]

            Note over C: 20. Verify OCSP Response ✓

        else OCSP Responder Unavailable
            Note over S: 21. OCSP Request Timeout<br/>Fallback Strategy

            alt Soft-Fail Mode
                Note over S: 22. Soft-Fail: Continue without OCSP<br/>(Use cached CRL if available)

                S->>C: 23. Certificate (No OCSP Stapling)

                Note over C: 24. Client-side OCSP Check<br/>or CRL Validation

            else Hard-Fail Mode
                Note over S: 25. Hard-Fail: Reject Handshake

                S->>C: 26. Alert: internal_error<br/>[OCSP verification required but unavailable]

                Note over S: 27. Close Connection
            end
        end
    end

    Note over C,S: Handshake Continues

    S->>C: CertificateVerify
    S->>C: Finished
    C->>S: Finished

    Note over C,S: Application Data

    Note over S: OCSP Response Refresh (Background)

    loop Every 1 hour
        Note over S: 28. Check OCSP Cache Expiration

        alt OCSP Response Expiring Soon (< 2 hours)
            S->>OCSP: 29. Refresh OCSP Request

            OCSP-->>S: 30. Updated OCSP Response

            S->>Cache: 31. Update Cache<br/>[New Response]

            Note over S: 32. OCSP Response Refreshed
        end
    end
```

### OCSP Stapling 장점

| 측면 | 기존 OCSP | OCSP Stapling | 개선 |
|------|----------|---------------|------|
| 클라이언트 지연 | ~100ms | 0ms | 100% |
| 프라이버시 | 낮음 (OCSP에 접속 노출) | 높음 (서버만 접속) | ✓ |
| OCSP 서버 부하 | 높음 | 낮음 (캐싱) | 90% 감소 |
| 네트워크 요청 | 클라이언트 → OCSP | 서버 → OCSP (백그라운드) | ✓ |
| 실패 처리 | Soft-fail (취약) | 서버에서 재시도 | ✓ |

### OCSP Stapling 설정

```yaml
# Server Configuration
ocsp_stapling:
  enabled: true

  # OCSP Responder URL (from certificate)
  responder_url: http://ocsp.qsign.local

  # Cache settings
  cache:
    backend: redis  # or memory
    ttl: auto  # Use NextUpdate from OCSP response
    refresh_before_expiry: 2h

  # Timeout settings
  timeout:
    connect: 5s
    read: 10s

  # Failure handling
  on_failure: soft-fail  # or hard-fail

  # Background refresh
  background_refresh:
    enabled: true
    interval: 1h
```

---

## 10. 세션 종료 및 재협상

정상 종료, 재협상, 강제 종료 시나리오

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: Scenario 1: Normal Session Termination

    Note over C,S: Active Session
    C->>S: Application Data
    S->>C: Application Data

    Note over C: 1. Application Closing<br/>Initiate Graceful Shutdown

    C->>S: 2. Alert: close_notify<br/>[Alert Level: Warning]

    Note over C: 3. Close Write Direction<br/>No more data to send

    S->>C: 4. Application Data (Final)<br/>[Last response]

    Note over S: 5. Acknowledge Close<br/>Finish sending data

    S->>C: 6. Alert: close_notify<br/>[Alert Level: Warning]

    Note over S: 7. Close Write Direction

    Note over C: 8. Receive close_notify<br/>Close Read Direction

    Note over C,S: 9. TCP FIN Handshake

    C->>S: TCP FIN
    S->>C: TCP ACK
    S->>C: TCP FIN
    C->>S: TCP ACK

    Note over C,S: 10. Connection Closed<br/>Session Ended Gracefully

    Note over C,S: Scenario 2: Renegotiation (Key Update)

    Note over C,S: Active Session (Long-lived)

    Note over S: 11. Check Data Volume<br/>Encrypted Data: > 100 GB<br/>Trigger Key Update

    S->>C: 12. KeyUpdate Request<br/>[update_requested: update_requested]

    Note over S: 13. Derive New Application Keys<br/>application_traffic_secret_N+1 = <br/>HKDF-Expand-Label(<br/>  application_traffic_secret_N,<br/>  "traffic upd", "", 32<br/>)

    Note over S: 14. Switch to New Keys<br/>All subsequent messages use new keys

    Note over C: 15. Receive KeyUpdate Request

    Note over C: 16. Derive New Application Keys<br/>(Same derivation as server)

    C->>S: 17. KeyUpdate Response<br/>[update_requested: update_not_requested]

    Note over C: 18. Switch to New Keys

    Note over C,S: 19. Key Update Complete<br/>Continue Application Data

    C->>S: 20. Application Data (New Keys)
    S->>C: 21. Application Data (New Keys)

    Note over C,S: Scenario 3: Post-Handshake Authentication

    Note over C,S: Active Session (Client Not Authenticated)

    Note over S: 22. Require Client Authentication<br/>for Sensitive Operation

    S->>C: 23. CertificateRequest<br/>[Acceptable CAs,<br/>Signature Algorithms]

    Note over C: 24. User Consent<br/>Select Client Certificate

    C->>S: 25. Certificate Chain<br/>[Client Cert]

    C->>S: 26. CertificateVerify<br/>[Dilithium3 + ECDSA Signature]

    C->>S: 27. Finished<br/>[Post-Handshake Auth]

    Note over S: 28. Verify Client Certificate & Signature

    alt Client Authenticated
        Note over S: 29. Client Authentication Success ✓<br/>Upgrade Session Privileges

        S->>C: 30. Finished<br/>[Acknowledgment]

        Note over C,S: 31. Continue with Elevated Privileges

        C->>S: 32. Application Data (Authorized)<br/>[Sensitive Operation]

        S->>C: 33. Application Data<br/>[200 OK]

    else Client Authentication Failed
        Note over S: 34. Client Authentication Failed ✗

        S->>C: 35. Alert: bad_certificate<br/>[Alert Level: Fatal]

        Note over S: 36. Close Connection
    end

    Note over C,S: Scenario 4: Abrupt Connection Close

    Note over C,S: Active Session

    Note over C: 37. Unexpected Error<br/>(Application Crash)

    Note over C: 38. TCP Connection Closed<br/>Without close_notify

    Note over S: 39. Detect Connection Reset<br/>TCP RST or Timeout

    Note over S: 40. Session Cleanup<br/>- Remove from Session Cache<br/>- Free Resources<br/>- Log: Unexpected Close

    Note over S: 41. Security Check<br/>Potential Attack?<br/>Log for Analysis
```

### 세션 종료 비교

| 종료 방식 | close_notify 전송 | TCP FIN | 세션 재개 가능 | 사용 사례 |
|----------|------------------|---------|--------------|----------|
| Normal Close | Yes (양방향) | Yes | Yes | 정상 종료 |
| Half Close | Yes (단방향) | No | Yes | 데이터 수신 대기 |
| Abrupt Close | No | RST | No | 애플리케이션 크래시 |
| Alert Close | Yes (Fatal Alert) | Yes | No | 프로토콜 오류 |

### 재협상 트리거 조건

```yaml
키 업데이트 트리거:
  데이터 볼륨:
    threshold: 100 GB
    action: KeyUpdate Request

  시간 기반:
    threshold: 24 hours
    action: KeyUpdate Request

  세션 업그레이드:
    condition: 민감한 작업 요청
    action: Post-Handshake Authentication

  보안 정책 변경:
    condition: Cipher Suite 변경 필요
    action: Full Renegotiation (New Handshake)
```

---

## 성능 메트릭 요약

### 핸드셰이크 성능 비교

| 시나리오 | RTT | 핸드셰이크 시간 | 네트워크 데이터 | HSM 작업 |
|---------|-----|----------------|----------------|----------|
| Full Handshake | 2-RTT | 80ms | ~15 KB | 4 ops |
| Session ID Resumption | 1-RTT | 10ms | ~500 bytes | 0 ops |
| Session Ticket Resumption | 1-RTT | 15ms | ~1.5 KB | 1 op (decrypt) |
| 0-RTT Early Data | 0-RTT | 5ms | ~2 KB | 1 op (PSK) |

### 보안 레벨 비교

| 프로토콜 | 양자 내성 | Forward Secrecy | 인증 강도 | 권장 용도 |
|---------|----------|-----------------|-----------|----------|
| TLS 1.3 (RSA) | No | No | 중간 | 레거시 호환 |
| TLS 1.3 (ECDHE) | No | Yes | 중간 | 일반 웹 |
| Q-TLS Hybrid | Yes | Yes | 높음 | 엔터프라이즈 |
| Q-TLS PQC Only | Yes | Yes | 최고 | 정부/금융 |

---

## 관련 문서

- [Q-TLS-OVERVIEW.md](./Q-TLS-OVERVIEW.md) - Q-TLS 개요
- [Q-TLS-ARCHITECTURE.md](./Q-TLS-ARCHITECTURE.md) - 아키텍처 설계
- [HANDSHAKE-PROTOCOL.md](./HANDSHAKE-PROTOCOL.md) - 핸드셰이크 프로토콜 상세
- [CIPHER-SUITES.md](./CIPHER-SUITES.md) - 암호화 스위트
- [CERTIFICATE-MANAGEMENT.md](./CERTIFICATE-MANAGEMENT.md) - 인증서 관리
- [IMPLEMENTATION-GUIDE.md](./IMPLEMENTATION-GUIDE.md) - 구현 가이드
- [TESTING-VALIDATION.md](./TESTING-VALIDATION.md) - 테스트 및 검증

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Document Status**: Complete
