# Q-SSL Sequence Diagrams

Q-SSL 핸드셰이크, 세션 재개, 에러 처리 등의 상세 시퀀스 다이어그램 모음입니다.

## 목차

- [1. Full Handshake (TLS 1.2)](#1-full-handshake-tls-12)
- [2. Full Handshake (TLS 1.3)](#2-full-handshake-tls-13)
- [3. Abbreviated Handshake (Session Resumption)](#3-abbreviated-handshake-session-resumption)
- [4. Session Ticket](#4-session-ticket)
- [5. Mutual TLS (mTLS)](#5-mutual-tls-mtls)
- [6. 에러 시나리오](#6-에러-시나리오)
- [7. 키 교환 상세](#7-키-교환-상세)

---

## 1. Full Handshake (TLS 1.2)

### 1.1 전체 흐름 (Hybrid PQC)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    rect rgb(230, 240, 255)
        Note over C,HSM: Phase 1: Hello (협상)
        C->>S: ClientHello
        Note right of C: • TLS 1.2<br/>• Random (32B)<br/>• Cipher suites<br/>• Extensions (PQC)

        S->>C: ServerHello
        Note left of S: • Selected cipher<br/>• Random (32B)<br/>• Session ID
    end

    rect rgb(255, 240, 230)
        Note over C,HSM: Phase 2: Server Auth & Key Exchange

        S->>HSM: Load certificate
        HSM-->>S: Hybrid cert
        S->>C: Certificate
        Note left of S: • Server cert<br/>• Intermediate certs<br/>• (RSA + Dilithium3)

        S->>HSM: Generate ECDHE + Kyber keys
        HSM-->>S: Public keys
        S->>HSM: Sign params (ECDSA + Dilithium3)
        HSM-->>S: Hybrid signature

        S->>C: ServerKeyExchange
        Note left of S: • ECDHE P-384 pubkey (65B)<br/>• Kyber1024 pubkey (1568B)<br/>• Hybrid signature (~3400B)

        alt Mutual TLS
            S->>C: CertificateRequest
            Note left of S: • Client cert types<br/>• Accepted CAs
        end

        S->>C: ServerHelloDone
    end

    rect rgb(230, 255, 240)
        Note over C,HSM: Phase 3: Client Key Exchange

        alt Mutual TLS
            C->>C: Load client cert
            C->>S: Certificate
            Note right of C: • Client cert<br/>• (RSA/ECDSA + Dilithium3)
        end

        C->>C: Generate ECDHE keypair
        C->>C: ECDH compute (server pubkey)
        Note right of C: ECDHE shared secret (48B)

        C->>C: Kyber1024 Encapsulation
        Note right of C: • Kyber shared secret (32B)<br/>• Kyber ciphertext (1568B)

        C->>S: ClientKeyExchange
        Note right of C: • ECDHE pubkey (65B)<br/>• Kyber ciphertext (1568B)

        S->>HSM: ECDH compute
        HSM-->>S: ECDHE shared secret (48B)
        S->>HSM: Kyber Decapsulation
        HSM-->>S: Kyber shared secret (32B)

        alt Mutual TLS
            C->>C: Sign handshake hash
            C->>S: CertificateVerify
            Note right of C: Hybrid signature
        end

        C->>C: Hybrid Pre-Master Secret
        Note right of C: PMS = Hash(ECDHE || Kyber)

        C->>C: Master Secret Derivation
        Note right of C: MS = PRF(PMS, "master secret",<br/>ClientRandom + ServerRandom)

        C->>C: Session Keys Derivation
        Note right of C: Keys = PRF(MS, "key expansion",<br/>ServerRandom + ClientRandom)

        C->>S: ChangeCipherSpec
        C->>S: Finished (encrypted)
        Note right of C: verify_data = PRF(MS,<br/>"client finished", Hash(msgs))
    end

    rect rgb(255, 255, 230)
        Note over C,HSM: Phase 4: Server Finish

        S->>S: Hybrid Pre-Master Secret
        S->>S: Master Secret Derivation
        S->>S: Session Keys Derivation

        S->>S: Verify Client Finished
        S->>C: ChangeCipherSpec
        S->>C: Finished (encrypted)
        Note left of S: verify_data = PRF(MS,<br/>"server finished", Hash(msgs))

        C->>C: Verify Server Finished
    end

    rect rgb(240, 255, 240)
        Note over C,S: ✅ Handshake Complete (~90ms)
        C<<->>S: Application Data (encrypted)
    end
```

### 1.2 메시지 타이밍 분석

```yaml
TLS 1.2 Full Handshake 타이밍 (Hybrid PQC):

  RTT 1 (Client → Server → Client):
    - ClientHello: 0ms
    - ServerHello: +5ms (네트워크)
    - Certificate: +5ms
    - ServerKeyExchange: +5ms (ECDHE + Kyber + Sign)
    - ServerHelloDone: +5ms
    총: ~20ms

  Client Processing:
    - ECDH compute: +2ms
    - Kyber Encapsulation: +0.5ms
    - Key derivation: +1ms
    총: ~3.5ms

  RTT 2 (Client → Server):
    - ClientKeyExchange: +5ms (네트워크)
    - ChangeCipherSpec + Finished: +5ms
    총: ~10ms

  Server Processing:
    - ECDH compute: +2ms (HSM)
    - Kyber Decapsulation: +1ms (HSM)
    - Key derivation: +1ms
    - Verify Finished: +0.5ms
    총: ~4.5ms

  RTT 3 (Server → Client):
    - ChangeCipherSpec + Finished: +5ms
    총: ~5ms

  전체 핸드셰이크: ~43ms (네트워크) + ~50ms (PQC 연산) = ~93ms
```

---

## 2. Full Handshake (TLS 1.3)

### 2.1 TLS 1.3 Handshake (1-RTT)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    rect rgb(230, 240, 255)
        Note over C,HSM: Phase 1: Hello + Key Share (1-RTT)

        C->>C: Generate ECDHE + Kyber keys
        C->>S: ClientHello
        Note right of C: • TLS 1.3<br/>• Random<br/>• Cipher suites<br/>• Extensions:<br/>  - key_share (ECDHE + Kyber)<br/>  - supported_groups<br/>  - signature_algorithms

        S->>S: Process ClientHello
        S->>HSM: Generate ECDHE + Kyber keys
        HSM-->>S: Server key shares

        S->>S: ECDH + Kyber Decapsulation
        Note left of S: Early secret, Handshake secret

        S->>C: ServerHello
        Note left of S: • Selected cipher<br/>• key_share (ECDHE + Kyber)

        S->>C: {EncryptedExtensions}
        Note left of S: Encrypted with Handshake keys

        S->>HSM: Load certificate
        HSM-->>S: Hybrid cert
        S->>C: {Certificate}
        Note left of S: Server cert (RSA/ECDSA + Dilithium3)

        S->>HSM: Sign transcript (ECDSA + Dilithium3)
        HSM-->>S: Hybrid signature
        S->>C: {CertificateVerify}
        Note left of S: Signature over handshake transcript

        S->>C: {Finished}
        Note left of S: HMAC over transcript

        Note over S: 서버는 이제 Application Data 전송 가능
    end

    rect rgb(230, 255, 240)
        Note over C,HSM: Phase 2: Client Finish

        C->>C: ECDH + Kyber Encapsulation
        C->>C: Derive secrets
        C->>C: Verify server Finished

        alt Mutual TLS
            C->>S: {Certificate}
            Note right of C: Client cert

            C->>S: {CertificateVerify}
            Note right of C: Signature
        end

        C->>S: {Finished}
        Note right of C: HMAC over transcript

        Note over C: 클라이언트는 이제 Application Data 전송 가능
    end

    rect rgb(240, 255, 240)
        Note over C,S: ✅ Handshake Complete (~70ms, 1-RTT)
        C<<->>S: Application Data (encrypted)
    end
```

### 2.2 TLS 1.3 vs TLS 1.2 비교

```mermaid
graph TB
    subgraph TLS12["TLS 1.2 Handshake"]
        direction TB
        T12_R1[RTT 1: ClientHello → ServerHelloDone]
        T12_C[Client Process]
        T12_R2[RTT 2: ClientKeyExchange → Finished]
        T12_S[Server Process]
        T12_R3[RTT 3: ChangeCipherSpec + Finished]
        T12_R1 --> T12_C --> T12_R2 --> T12_S --> T12_R3
    end

    subgraph TLS13["TLS 1.3 Handshake"]
        direction TB
        T13_R1[RTT 1: ClientHello + KeyShare]
        T13_S[Server Process + Response]
        T13_C[Client Finish]
        T13_R1 --> T13_S --> T13_C
    end

    TLS12 -.->|2-RTT, ~93ms| TLS13
    TLS13 -.->|1-RTT, ~70ms| TLS12

    style TLS12 fill:#ffccbc
    style TLS13 fill:#c8e6c9
```

---

## 3. Abbreviated Handshake (Session Resumption)

### 3.1 Session ID 기반 재개

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: 이전 연결에서 Session ID 캐시됨

    rect rgb(230, 240, 255)
        Note over C,S: Fast Resume (1-RTT)

        C->>S: ClientHello
        Note right of C: • session_id = 0x1234... (cached)<br/>• cipher_suites

        S->>S: Lookup Session Cache
        Note left of S: session_id = 0x1234...

        alt Session Found & Valid
            S->>S: Load cached Master Secret
            S->>C: ServerHello
            Note left of S: • session_id = 0x1234... (same)<br/>• cipher_suite (same)

            Note over C,S: Skip Certificate, KeyExchange
            Note over C,S: Reuse cached Master Secret

            C->>C: Derive Session Keys<br/>(new randoms)
            C->>S: ChangeCipherSpec
            C->>S: Finished (encrypted)

            S->>S: Derive Session Keys
            S->>S: Verify Client Finished
            S->>C: ChangeCipherSpec
            S->>C: Finished (encrypted)

            C->>C: Verify Server Finished

            Note over C,S: ✅ Session Resumed (~15ms)

        else Session Not Found
            S->>C: ServerHello (new session_id)
            Note over C,S: → Full Handshake
        end
    end

    C<<->>S: Application Data
```

### 3.2 Session Cache 관리

```mermaid
graph TB
    subgraph SERVER["Server Session Cache"]
        direction TB

        RECEIVE[Receive ClientHello<br/>with session_id]
        LOOKUP{Session<br/>Cache Lookup}
        FOUND[Session Found]
        NOTFOUND[Session Not Found]
        VALID{Timeout<br/>Check}
        RESUME[Resume Session]
        FULL[Full Handshake]
        STORE[Store New Session]

        RECEIVE --> LOOKUP
        LOOKUP -->|Hit| FOUND
        LOOKUP -->|Miss| NOTFOUND

        FOUND --> VALID
        VALID -->|Valid| RESUME
        VALID -->|Expired| FULL

        NOTFOUND --> FULL
        FULL --> STORE
    end

    style RESUME fill:#c8e6c9
    style FULL fill:#ffccbc
```

---

## 4. Session Ticket

### 4.1 Session Ticket 발급

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: Full Handshake 완료 후

    rect rgb(230, 240, 255)
        Note over C,S: Ticket 발급

        S->>S: Create Session Ticket
        Note left of S: • Master Secret<br/>• Cipher Suite<br/>• Timestamp<br/>• Encrypt with Ticket Key

        S->>C: NewSessionTicket
        Note left of S: • Encrypted ticket (opaque)<br/>• Lifetime hint (3600s)

        C->>C: Store Session Ticket
        Note right of C: 클라이언트 측 저장<br/>(서버 메모리 불필요)
    end

    C<<->>S: Application Data

    Note over C,S: === 시간 경과 (재연결) ===

    rect rgb(230, 255, 240)
        Note over C,S: Ticket 기반 재개

        C->>S: ClientHello
        Note right of C: • session_id = empty<br/>• session_ticket extension<br/>  (encrypted ticket)

        S->>S: Decrypt Session Ticket
        S->>S: Verify Ticket
        Note left of S: • Timestamp check<br/>• Integrity check

        alt Ticket Valid
            S->>S: Extract Master Secret
            S->>C: ServerHello
            Note left of S: • session_id = empty<br/>• session_ticket extension (empty)

            Note over C,S: Reuse Master Secret from Ticket

            C->>C: Derive Session Keys
            C->>S: ChangeCipherSpec + Finished

            S->>S: Derive Session Keys
            S->>C: ChangeCipherSpec + Finished

            Note over C,S: ✅ Resumed with Ticket (~15ms)

        else Ticket Invalid/Expired
            S->>C: ServerHello (no ticket ext)
            Note over C,S: → Full Handshake
        end
    end

    C<<->>S: Application Data
```

### 4.2 Session Ticket vs Session Cache

```yaml
Session Resumption 방식 비교:

  Session Cache (Session ID):
    저장 위치: 서버 메모리
    확장성: 제한적 (서버당 캐시 크기)
    로드밸런싱: 어려움 (세션 affinity 필요)
    장점:
      - 구현 간단
      - 빠른 lookup
    단점:
      - 서버 메모리 사용
      - 클러스터 환경에서 복잡

  Session Ticket (RFC 5077):
    저장 위치: 클라이언트 (encrypted)
    확장성: 무제한 (stateless 서버)
    로드밸런싱: 쉬움 (모든 서버가 ticket 복호화 가능)
    장점:
      - 서버 메모리 절약
      - 클러스터 친화적
      - 수평 확장 용이
    단점:
      - Ticket 암호화/복호화 오버헤드
      - Ticket key 관리 필요
      - Forward secrecy 약화 (ticket key 노출 시)

  QSIGN 권장: Session Ticket (확장성 우선)
```

---

## 5. Mutual TLS (mTLS)

### 5.1 mTLS 전체 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    rect rgb(230, 240, 255)
        Note over C,HSM: Phase 1: Hello
        C->>S: ClientHello
        S->>C: ServerHello
    end

    rect rgb(255, 240, 230)
        Note over C,HSM: Phase 2: Server Auth

        S->>C: Certificate (Server)
        Note left of S: Server hybrid cert

        S->>C: ServerKeyExchange
        Note left of S: ECDHE + Kyber + Signature

        S->>C: CertificateRequest
        Note left of S: • cert_types: [rsa_sign, ecdsa_sign, dilithium3]<br/>• supported_signature_algorithms<br/>• certificate_authorities (trusted CAs)

        S->>C: ServerHelloDone
    end

    rect rgb(230, 255, 240)
        Note over C,HSM: Phase 3: Client Auth + Key Exchange

        C->>C: Load client certificate
        C->>S: Certificate (Client)
        Note right of C: Client hybrid cert<br/>(ECDSA + Dilithium3)

        C->>S: ClientKeyExchange
        Note right of C: ECDHE + Kyber

        C->>C: Sign handshake transcript
        Note right of C: Hash(all handshake msgs)

        C->>S: CertificateVerify
        Note right of C: Hybrid signature:<br/>• ECDSA P-384 signature<br/>• Dilithium3 signature

        S->>S: Verify client certificate chain
        S->>S: Verify CertificateVerify signature
        Note left of S: • Verify ECDSA signature<br/>• Verify Dilithium3 signature<br/>• Both must succeed (AND)

        C->>S: ChangeCipherSpec
        C->>S: Finished
    end

    rect rgb(255, 255, 230)
        Note over C,HSM: Phase 4: Server Finish

        S->>C: ChangeCipherSpec
        S->>C: Finished
    end

    rect rgb(240, 255, 240)
        Note over C,S: ✅ Mutual Auth Complete
        C<<->>S: Application Data
        Note over C,S: 양방향 인증 완료
    end
```

### 5.2 CertificateRequest 메시지

```yaml
CertificateRequest Message:

  구조:
    - certificate_types (1+ bytes):
        1: rsa_sign
        64: ecdsa_sign
        128: dilithium3 (experimental)

    - supported_signature_algorithms (TLS 1.2+):
        - ecdsa_secp384r1_sha384 (0x0503)
        - rsa_pss_rsae_sha384 (0x0804)
        - dilithium3 (0x0800)

    - certificate_authorities (0+ bytes):
        - DN (Distinguished Name) 리스트
        - 예: "CN=QSIGN Root CA, O=QSIGN, C=KR"

  클라이언트 동작:
    1. 요청된 cert_types 확인
    2. 신뢰할 수 있는 CA 확인
    3. 적합한 클라이언트 인증서 선택
    4. 인증서 전송
    5. CertificateVerify로 소유 증명
```

### 5.3 CertificateVerify 검증

```python
# CertificateVerify 검증 (Hybrid)

def verify_certificate_verify(
    handshake_messages,
    certificate_verify_msg,
    client_public_keys
):
    """
    CertificateVerify 메시지 검증 (Hybrid)

    Args:
        handshake_messages: ClientHello ~ ClientKeyExchange (Finished 제외)
        certificate_verify_msg: CertificateVerify 메시지
        client_public_keys: {
            'ecdsa': client_ecdsa_public_key,
            'dilithium': client_dilithium_public_key
        }

    Returns:
        True if both signatures valid
    """
    import hashlib
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes

    # 1. Handshake transcript hash
    transcript_hash = hashlib.sha384(handshake_messages).digest()

    # 2. Parse CertificateVerify
    #    signature_algorithm (2 bytes) + signature_length (2 bytes) + signature
    sig_algorithm = int.from_bytes(certificate_verify_msg[0:2], 'big')
    sig_length = int.from_bytes(certificate_verify_msg[2:4], 'big')
    signature_data = certificate_verify_msg[4:4+sig_length]

    # 3. Hybrid signature parsing
    #    ECDSA signature (96 bytes for P-384) + Dilithium3 signature (~3293 bytes)
    ecdsa_sig = signature_data[:96]
    dilithium_sig = signature_data[96:]

    # 4. Verify ECDSA signature
    try:
        client_public_keys['ecdsa'].verify(
            ecdsa_sig,
            transcript_hash,
            ec.ECDSA(hashes.SHA384())
        )
        ecdsa_valid = True
    except:
        ecdsa_valid = False

    # 5. Verify Dilithium3 signature
    try:
        # import oqs
        # verifier = oqs.Signature("Dilithium3", client_public_keys['dilithium'])
        # dilithium_valid = verifier.verify(transcript_hash, dilithium_sig, ...)
        dilithium_valid = True  # pseudo-code
    except:
        dilithium_valid = False

    # 6. Both signatures must be valid (AND condition)
    return ecdsa_valid and dilithium_valid

# 사용 예시
# is_valid = verify_certificate_verify(handshake_msgs, cert_verify, client_keys)
# if not is_valid:
#     send_alert(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR)
#     close_connection()
```

---

## 6. 에러 시나리오

### 6.1 인증서 검증 실패

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: Certificate

    C->>C: Verify Certificate Chain

    alt Certificate Expired
        C->>C: Check notAfter field
        C->>S: Alert: certificate_expired (45)
        C->>C: Close Connection
        Note over C,S: ❌ Handshake Failed

    else Certificate Revoked
        C->>C: Check CRL/OCSP
        C->>S: Alert: certificate_revoked (44)
        C->>C: Close Connection
        Note over C,S: ❌ Handshake Failed

    else Unknown CA
        C->>C: CA not in trust store
        C->>S: Alert: unknown_ca (48)
        C->>C: Close Connection
        Note over C,S: ❌ Handshake Failed

    else Invalid Signature
        C->>C: Verify cert signature
        C->>S: Alert: bad_certificate (42)
        C->>C: Close Connection
        Note over C,S: ❌ Handshake Failed

    else Certificate Valid
        C->>S: Continue Handshake
        Note over C,S: ✅ Proceed
    end
```

### 6.2 Cipher Suite 협상 실패

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>S: ClientHello
    Note right of C: cipher_suites = [0x1301, 0x1302, 0xC02C]

    S->>S: Check supported ciphers
    Note left of S: server_ciphers = [0xC030, 0xC028]

    S->>S: Find common cipher
    Note left of S: Intersection = {} (empty)

    S->>C: Alert: handshake_failure (40)
    Note left of S: No common cipher suite

    S->>S: Close Connection
    C->>C: Log Error
    Note over C,S: ❌ Handshake Failed

    opt Client Retry
        C->>C: Expand cipher list (fallback)
        C->>S: ClientHello (retry)
        Note right of C: cipher_suites += [0xC030]
    end
```

### 6.3 Finished 검증 실패

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    Note over C,S: Handshake messages exchanged

    C->>C: Compute verify_data
    Note right of C: PRF(master_secret,<br/>"client finished",<br/>Hash(handshake_msgs))

    C->>S: ChangeCipherSpec
    C->>S: Finished (encrypted)
    Note right of C: verify_data (12 bytes)

    S->>S: Decrypt Finished message
    S->>S: Compute expected verify_data

    alt verify_data Mismatch
        S->>S: Constant-time compare
        Note left of S: received != expected

        S->>C: Alert: decrypt_error (51)
        Note left of S: Finished verification failed

        S->>S: Close Connection
        C->>C: Log Error
        Note over C,S: ❌ Handshake Failed

        opt Analysis
            Note over C,S: Possible causes:<br/>• Key derivation error<br/>• Message tampering<br/>• Implementation bug<br/>• MITM attack
        end

    else verify_data Match
        S->>C: ChangeCipherSpec
        S->>C: Finished
        Note over C,S: ✅ Handshake Success
    end
```

---

## 7. 키 교환 상세

### 7.1 Hybrid 키 교환 세부 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    rect rgb(255, 240, 230)
        Note over C,HSM: Classical ECDHE

        S->>HSM: Generate ECDHE P-384 keypair
        HSM-->>S: (ecdhe_priv_s, ecdhe_pub_s)

        S->>C: ServerKeyExchange
        Note left of S: ecdhe_pub_s (65 bytes)

        C->>C: Generate ECDHE P-384 keypair
        Note right of C: (ecdhe_priv_c, ecdhe_pub_c)

        C->>C: ECDH(ecdhe_priv_c, ecdhe_pub_s)
        Note right of C: ecdhe_shared_secret (48 bytes)

        C->>S: ClientKeyExchange
        Note right of C: ecdhe_pub_c (65 bytes)

        S->>HSM: ECDH(ecdhe_priv_s, ecdhe_pub_c)
        HSM-->>S: ecdhe_shared_secret (48 bytes)

        Note over C,S: ✅ ECDHE shared secret 일치
    end

    rect rgb(230, 255, 240)
        Note over C,HSM: PQC Kyber1024

        S->>HSM: Kyber1024.Keygen()
        HSM-->>S: (kyber_sk, kyber_pk)
        Note left of HSM: sk: 3168 bytes<br/>pk: 1568 bytes

        S->>C: ServerKeyExchange
        Note left of S: kyber_pk (1568 bytes)

        C->>C: Kyber1024.Encaps(kyber_pk)
        Note right of C: → (ciphertext, shared_secret)

        Note right of C: ciphertext: 1568 bytes<br/>shared_secret: 32 bytes

        C->>S: ClientKeyExchange
        Note right of C: kyber_ciphertext (1568 bytes)

        S->>HSM: Kyber1024.Decaps(kyber_sk, ciphertext)
        HSM-->>S: kyber_shared_secret (32 bytes)

        Note over C,S: ✅ Kyber shared secret 일치
    end

    rect rgb(255, 255, 230)
        Note over C,HSM: Hybrid Combination

        C->>C: Combine Secrets
        Note right of C: combined = ecdhe_shared (48B) ||<br/>kyber_shared (32B)

        C->>C: Hash to PMS
        Note right of C: pms = SHA384(combined)[:48]

        S->>S: Combine Secrets
        Note left of S: combined = ecdhe_shared (48B) ||<br/>kyber_shared (32B)

        S->>S: Hash to PMS
        Note left of S: pms = SHA384(combined)[:48]

        Note over C,S: ✅ Pre-Master Secret 일치 (48 bytes)
    end

    rect rgb(240, 255, 255)
        Note over C,S: Master Secret & Session Keys

        C->>C: Master Secret
        Note right of C: ms = PRF(pms, "master secret",<br/>client_random + server_random)

        C->>C: Session Keys
        Note right of C: keys = PRF(ms, "key expansion",<br/>server_random + client_random)

        S->>S: Master Secret
        S->>S: Session Keys

        Note over C,S: ✅ Session Keys 일치
        Note over C,S: • client_write_enc_key (32B)<br/>• server_write_enc_key (32B)<br/>• client_write_iv (4B)<br/>• server_write_iv (4B)
    end
```

### 7.2 키 유도 트리

```mermaid
graph TB
    subgraph INPUTS["Inputs"]
        CR[Client Random<br/>32 bytes]
        SR[Server Random<br/>32 bytes]
        ECDHE[ECDHE Secret<br/>48 bytes]
        KYBER[Kyber Secret<br/>32 bytes]
    end

    subgraph DERIVATION["Key Derivation"]
        COMBINE["Combine<br/>ECDHE + Kyber"]
        PMS[Pre-Master Secret<br/>SHA384 → 48 bytes]
        MS[Master Secret<br/>PRF-SHA384 → 48 bytes]
        KB[Key Block<br/>PRF-SHA384 → variable]
    end

    subgraph OUTPUTS["Session Keys"]
        CWK[Client Write Enc Key<br/>32 bytes AES-256]
        SWK[Server Write Enc Key<br/>32 bytes AES-256]
        CWIV[Client Write IV<br/>4 bytes]
        SWIV[Server Write IV<br/>4 bytes]
    end

    ECDHE --> COMBINE
    KYBER --> COMBINE
    COMBINE --> PMS

    PMS --> MS
    CR --> MS
    SR --> MS

    MS --> KB
    SR --> KB
    CR --> KB

    KB --> CWK
    KB --> SWK
    KB --> CWIV
    KB --> SWIV

    style INPUTS fill:#e3f2fd
    style DERIVATION fill:#fff9c4
    style OUTPUTS fill:#c8e6c9
```

### 7.3 보안 속성

```yaml
Hybrid 키 교환 보안 속성:

  1. Perfect Forward Secrecy (PFS):
     - ECDHE: 세션별 임시 키 생성
     - Kyber: KEM 세션별 독립적 캡슐화
     - 개인키 노출되어도 과거 세션 안전

  2. Quantum Resistance:
     - ECDHE: 양자 컴퓨터에 취약 (Shor's algorithm)
     - Kyber1024: 양자 안전 (256-bit security)
     - Hybrid: min(ECDHE, Kyber) = Quantum-safe

  3. Security Level:
     - Classical: min(ECDHE P-384, Kyber1024) = 192-bit
     - Quantum: Kyber1024 = 256-bit equivalent
     - 전체: 256-bit quantum-resistant

  4. Attack Resistance:
     - MITM: 서명으로 방지
     - Replay: Nonce (random) 사용
     - Downgrade: TLS version in Finished verify_data
     - Key Compromise: PFS로 과거 세션 보호

  5. Hybrid 보안 원칙:
     - 둘 중 하나만 안전해도 전체 안전
     - Classical 깨져도 Kyber로 보호
     - Kyber 깨져도 Classical로 보호 (현재)
```

---

## 요약

### Q-SSL Sequence 핵심

1. **Full Handshake**: TLS 1.2 (2-RTT, ~90ms), TLS 1.3 (1-RTT, ~70ms)
2. **Session Resumption**: Session ID 또는 Session Ticket (~15ms)
3. **mTLS**: 양방향 인증, CertificateVerify로 소유 증명
4. **Hybrid 키 교환**: ECDHE + Kyber → Quantum-safe PMS
5. **에러 처리**: Certificate, Cipher, Finished 검증 실패 시나리오

### 성능 최적화

- Session resumption으로 핸드셰이크 시간 80% 감소
- TLS 1.3으로 1-RTT 달성
- Session ticket으로 서버 확장성 향상

### 다음 단계

- [IMPLEMENTATION-GUIDE.md](./IMPLEMENTATION-GUIDE.md) - Q-SSL 구현 가이드
- [TESTING-VALIDATION.md](./TESTING-VALIDATION.md) - 테스트 및 검증
- [INTEGRATION.md](./INTEGRATION.md) - 시스템 통합

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Security Level**: FIPS 140-2 Level 3
