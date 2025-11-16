# TLS-PQC Hybrid 핸드셰이크 프로토콜

## 📘 개요

Q-TSL의 핵심인 TLS-PQC Hybrid 핸드셰이크 프로토콜에 대한 상세 문서입니다. TLS 1.3을 기반으로 KYBER1024 키 교환 및 DILITHIUM3 서명을 통합한 양자 내성 핸드셰이크를 설명합니다.

## 🔐 TLS 1.3 핸드셰이크 기본

### 표준 TLS 1.3 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: 1-RTT Handshake

    C->>S: ClientHello
    Note right of C: + key_share (x25519)<br/>+ supported_versions<br/>+ signature_algorithms

    S->>C: ServerHello
    Note left of S: + key_share (x25519)<br/>+ selected cipher suite

    S->>C: EncryptedExtensions
    S->>C: Certificate
    S->>C: CertificateVerify
    S->>C: Finished

    Note over C,S: [Encrypted with handshake keys]

    C->>C: Verify Certificate
    C->>C: Derive Keys

    C->>S: Finished

    Note over C,S: [Application Data]

    C->>S: HTTP Request (encrypted)
    S->>C: HTTP Response (encrypted)
```

### TLS 1.3 메시지 구조

```yaml
TLS 1.3 Messages:

  ClientHello:
    - Protocol Version: TLS 1.3 (0x0304)
    - Random: 32 bytes
    - Session ID: legacy (compatibility)
    - Cipher Suites: list of supported suites
    - Extensions:
        - supported_versions
        - supported_groups
        - key_share
        - signature_algorithms
        - server_name (SNI)

  ServerHello:
    - Protocol Version: TLS 1.3
    - Random: 32 bytes
    - Cipher Suite: selected suite
    - Extensions:
        - supported_versions
        - key_share

  Certificate:
    - Certificate List
    - Certificate Extensions

  CertificateVerify:
    - Signature Algorithm
    - Signature (over handshake hash)

  Finished:
    - HMAC of handshake transcript
```

## 🚀 Q-TSL Hybrid 핸드셰이크 확장

### Hybrid 핸드셰이크 개요

```yaml
Q-TSL Enhancements:

  Key Exchange:
    Classical: ECDHE P-384
    PQC: KYBER1024
    Combined: KDF(ECDHE_secret || KYBER_secret)

  Authentication:
    Classical: RSA-4096 or ECDSA-P384
    PQC: DILITHIUM3
    Policy: Verify both signatures

  Cipher Suite:
    Key Exchange: Hybrid ECDHE-KYBER1024
    Authentication: Hybrid RSA-DILITHIUM3
    Encryption: AES-256-GCM
    Hash: SHA-384

  Extensions:
    - pqc_supported_groups (new)
    - pqc_signature_algorithms (new)
    - hybrid_mode (new)
```

### 전체 Hybrid 핸드셰이크

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Q-Gateway Server

    Note over C,S: Q-TSL Hybrid Handshake

    C->>S: ClientHello (Extended)
    Note right of C: + supported_groups:<br/>  - kyber1024<br/>  - p384<br/>+ signature_algorithms:<br/>  - dilithium3<br/>  - rsa_pss_rsae_sha384<br/>+ pqc_hybrid_mode: true

    S->>S: Select Algorithms
    Note left of S: Key Exchange: kyber1024 + p384<br/>Signature: dilithium3 + rsa

    S->>C: ServerHello (Hybrid)
    Note left of S: + key_share:<br/>  - p384 public key<br/>  - kyber1024 public key

    S->>C: EncryptedExtensions
    Note left of S: + hybrid_mode: enabled

    S->>C: Certificate (Hybrid)
    Note left of S: + PQC Certificate Chain<br/>+ Classical Certificate Chain

    S->>C: CertificateVerify (Dual Signature)
    Note left of S: + DILITHIUM3 Signature<br/>+ RSA-PSS Signature

    S->>C: Finished
    Note left of S: HMAC(transcript)

    C->>C: Verify Both Signatures
    C->>C: Derive Hybrid Shared Secret
    C->>C: Compute Session Keys

    C->>S: Certificate (if mutual TLS)
    C->>S: CertificateVerify (Dual Signature)
    C->>S: Finished

    Note over C,S: Secure Channel Established

    C->>S: Application Data
    S->>C: Application Data
```

## 📨 ClientHello 메시지

### ClientHello 구조

```yaml
ClientHello (Q-TSL Extended):

  legacy_version: 0x0303 (TLS 1.2 for compatibility)
  random: [32 bytes]
  legacy_session_id: [0-32 bytes]

  cipher_suites:
    # Hybrid Cipher Suites (Preferred)
    - TLS_HYBRID_ECDHE_KYBER1024_RSA_DILITHIUM3_WITH_AES_256_GCM_SHA384 (0xTBD1)
    - TLS_HYBRID_ECDHE_KYBER1024_ECDSA_DILITHIUM3_WITH_AES_256_GCM_SHA384 (0xTBD2)

    # Pure PQC Cipher Suites
    - TLS_KYBER1024_DILITHIUM3_WITH_AES_256_GCM_SHA384 (0xTBD3)

    # Fallback Classical Suites
    - TLS_AES_256_GCM_SHA384 (0x1302)
    - TLS_CHACHA20_POLY1305_SHA256 (0x1303)

  extensions:
    # TLS 1.3 Standard Extensions
    - supported_versions: [0x0304]
    - server_name: "q-gateway.qsign.local"

    # Supported Groups (Classical + PQC)
    - supported_groups:
        # PQC KEMs
        - kyber1024 (0x0512)
        - kyber768 (0x0511)

        # Classical ECDHE
        - x25519 (0x001D)
        - secp384r1 (0x0018)

    # Key Share (Hybrid)
    - key_share:
        client_shares:
          # PQC Key Share
          - group: kyber1024
            key_exchange: [1568 bytes - KYBER1024 public key]

          # Classical Key Share
          - group: secp384r1
            key_exchange: [97 bytes - P-384 public key]

    # Signature Algorithms (Classical + PQC)
    - signature_algorithms:
        # PQC Signatures
        - dilithium3 (0x0B01)
        - dilithium5 (0x0B02)

        # Classical Signatures
        - rsa_pss_rsae_sha384 (0x0805)
        - ecdsa_secp384r1_sha384 (0x0503)

    # PQC Hybrid Mode Extension (Custom)
    - pqc_hybrid_mode:
        enabled: true
        validation_policy: "require_both"
        fallback_allowed: false
```

### ClientHello 생성 예제

```python
def create_client_hello():
    """
    Q-TSL ClientHello 메시지 생성
    """
    client_hello = TLSClientHello()

    # 기본 필드
    client_hello.legacy_version = 0x0303  # TLS 1.2
    client_hello.random = os.urandom(32)
    client_hello.legacy_session_id = b''

    # Cipher Suites (Hybrid 우선)
    client_hello.cipher_suites = [
        CipherSuite.TLS_HYBRID_ECDHE_KYBER1024_RSA_DILITHIUM3_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_KYBER1024_DILITHIUM3_WITH_AES_256_GCM_SHA384,
        CipherSuite.TLS_AES_256_GCM_SHA384,  # Fallback
    ]

    # Extensions
    extensions = []

    # 1. Supported Versions
    extensions.append(SupportedVersionsExtension(
        versions=[0x0304]  # TLS 1.3
    ))

    # 2. Server Name Indication
    extensions.append(ServerNameExtension(
        server_name="q-gateway.qsign.local"
    ))

    # 3. Supported Groups (PQC + Classical)
    extensions.append(SupportedGroupsExtension(
        named_group_list=[
            NamedGroup.kyber1024,
            NamedGroup.kyber768,
            NamedGroup.x25519,
            NamedGroup.secp384r1,
        ]
    ))

    # 4. Key Share (Hybrid)
    # KYBER1024 키 생성
    kyber_keypair = kyber1024_keygen()
    # ECDHE P-384 키 생성
    ecdhe_keypair = ecdh_p384_keygen()

    extensions.append(KeyShareExtension(
        client_shares=[
            KeyShareEntry(
                group=NamedGroup.kyber1024,
                key_exchange=kyber_keypair.public_key
            ),
            KeyShareEntry(
                group=NamedGroup.secp384r1,
                key_exchange=ecdhe_keypair.public_key
            ),
        ]
    ))

    # 5. Signature Algorithms (PQC + Classical)
    extensions.append(SignatureAlgorithmsExtension(
        supported_signature_algorithms=[
            SignatureScheme.dilithium3,
            SignatureScheme.dilithium5,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.ecdsa_secp384r1_sha384,
        ]
    ))

    # 6. PQC Hybrid Mode (Custom Extension)
    extensions.append(PQCHybridModeExtension(
        enabled=True,
        validation_policy="require_both",
        fallback_allowed=False
    ))

    client_hello.extensions = extensions

    return client_hello
```

### ClientHello 다이어그램

```mermaid
graph TB
    subgraph "ClientHello Components"
        subgraph "Basic Fields"
            VER[Version: 0x0303]
            RND[Random: 32 bytes]
            SID[Session ID: legacy]
        end

        subgraph "Cipher Suites"
            CS1[Hybrid ECDHE-KYBER1024<br/>RSA-DILITHIUM3]
            CS2[Pure KYBER1024<br/>DILITHIUM3]
            CS3[Fallback: AES-256-GCM]
        end

        subgraph "Extensions"
            EXT1[supported_versions<br/>TLS 1.3]
            EXT2[server_name<br/>SNI]
            EXT3[supported_groups<br/>kyber1024, p384]
            EXT4[key_share<br/>PQC + Classical]
            EXT5[signature_algorithms<br/>dilithium3, rsa_pss]
            EXT6[pqc_hybrid_mode<br/>enabled]
        end
    end

    VER --> CS1
    RND --> CS1
    SID --> CS1

    CS1 --> EXT1
    CS2 --> EXT2
    CS3 --> EXT3

    EXT1 --> EXT4
    EXT2 --> EXT5
    EXT3 --> EXT6

    style CS1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style EXT4 fill:#bbdefb,stroke:#1565c0,stroke-width:2px
    style EXT6 fill:#fff9c4,stroke:#f57f17,stroke-width:2px
```

## 📩 ServerHello 및 알고리즘 협상

### ServerHello 구조

```yaml
ServerHello (Q-TSL):

  legacy_version: 0x0303
  random: [32 bytes]
  legacy_session_id_echo: [client session id]

  cipher_suite:
    # Selected Hybrid Suite
    - TLS_HYBRID_ECDHE_KYBER1024_RSA_DILITHIUM3_WITH_AES_256_GCM_SHA384

  extensions:
    # Supported Versions
    - supported_versions: 0x0304

    # Key Share (Server's public keys)
    - key_share:
        server_share:
          # KYBER1024 Server Public Key
          - group: kyber1024
            key_exchange: [1568 bytes]

          # ECDHE P-384 Server Public Key
          - group: secp384r1
            key_exchange: [97 bytes]

    # Hybrid Mode Confirmation
    - pqc_hybrid_mode:
        enabled: true
        selected_pqc_kem: kyber1024
        selected_classical_kem: secp384r1
        selected_pqc_sig: dilithium3
        selected_classical_sig: rsa_pss_rsae_sha384
```

### 알고리즘 협상 로직

```python
def negotiate_algorithms(client_hello, server_config):
    """
    서버의 알고리즘 협상 로직
    """

    # 1. Cipher Suite 선택
    selected_cipher = None
    for suite in client_hello.cipher_suites:
        if suite in server_config.supported_cipher_suites:
            selected_cipher = suite
            break

    if not selected_cipher:
        raise TLSAlert(AlertDescription.handshake_failure)

    # 2. Key Exchange Algorithm 선택
    pqc_kem = None
    classical_kem = None

    for group in client_hello.supported_groups:
        if group in [NamedGroup.kyber1024, NamedGroup.kyber768]:
            if not pqc_kem:
                pqc_kem = group
        elif group in [NamedGroup.secp384r1, NamedGroup.x25519]:
            if not classical_kem:
                classical_kem = group

    if server_config.hybrid_mode_required:
        if not (pqc_kem and classical_kem):
            raise TLSAlert(AlertDescription.insufficient_security)

    # 3. Signature Algorithm 선택
    pqc_sig = None
    classical_sig = None

    for sig in client_hello.signature_algorithms:
        if sig in [SignatureScheme.dilithium3, SignatureScheme.dilithium5]:
            if not pqc_sig:
                pqc_sig = sig
        elif sig in [SignatureScheme.rsa_pss_rsae_sha384, SignatureScheme.ecdsa_secp384r1_sha384]:
            if not classical_sig:
                classical_sig = sig

    if server_config.hybrid_mode_required:
        if not (pqc_sig and classical_sig):
            raise TLSAlert(AlertDescription.insufficient_security)

    return {
        'cipher_suite': selected_cipher,
        'pqc_kem': pqc_kem,
        'classical_kem': classical_kem,
        'pqc_sig': pqc_sig,
        'classical_sig': classical_sig,
    }
```

### 협상 다이어그램

```mermaid
graph TB
    START[Receive ClientHello]

    subgraph "Cipher Suite Negotiation"
        CS_CHECK{Supported<br/>Cipher Suite?}
        CS_SELECT[Select Hybrid Suite]
        CS_FAIL[Alert: handshake_failure]
    end

    subgraph "KEM Negotiation"
        KEM_CHECK{PQC + Classical<br/>KEMs Available?}
        KEM_SELECT[Select: KYBER1024 + P-384]
        KEM_FALLBACK[Fallback to Classical Only]
    end

    subgraph "Signature Negotiation"
        SIG_CHECK{PQC + Classical<br/>Signatures Available?}
        SIG_SELECT[Select: DILITHIUM3 + RSA]
        SIG_FAIL[Alert: insufficient_security]
    end

    COMPLETE[Generate ServerHello]

    START --> CS_CHECK
    CS_CHECK -->|Yes| CS_SELECT
    CS_CHECK -->|No| CS_FAIL

    CS_SELECT --> KEM_CHECK
    KEM_CHECK -->|Yes| KEM_SELECT
    KEM_CHECK -->|No| KEM_FALLBACK

    KEM_SELECT --> SIG_CHECK
    KEM_FALLBACK --> SIG_CHECK

    SIG_CHECK -->|Yes| SIG_SELECT
    SIG_CHECK -->|No| SIG_FAIL

    SIG_SELECT --> COMPLETE

    style CS_SELECT fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style KEM_SELECT fill:#bbdefb,stroke:#1565c0,stroke-width:2px
    style SIG_SELECT fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style CS_FAIL fill:#ffccbc,stroke:#d84315,stroke-width:2px
    style SIG_FAIL fill:#ffccbc,stroke:#d84315,stroke-width:2px
```

## 🔑 키 교환 (KYBER1024 KEM + ECDHE)

### Hybrid 키 교환 프로세스

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: Hybrid Key Exchange

    rect rgb(200, 230, 201)
        Note over C: PQC Key Exchange (KYBER1024)
        C->>C: kyber_pk, kyber_sk = Kyber1024.Keygen()
        C->>S: ClientHello + kyber_pk
        S->>S: kyber_ct, kyber_ss = Kyber1024.Encaps(kyber_pk)
        S->>C: ServerHello + kyber_ct
        C->>C: kyber_ss' = Kyber1024.Decaps(kyber_ct, kyber_sk)
        Note over C,S: kyber_ss == kyber_ss' (32 bytes)
    end

    rect rgb(255, 249, 196)
        Note over C: Classical Key Exchange (ECDHE P-384)
        C->>C: ecdh_pk, ecdh_sk = ECDH_P384.Keygen()
        C->>S: ClientHello + ecdh_pk
        S->>S: ecdh_pk', ecdh_sk' = ECDH_P384.Keygen()
        S->>C: ServerHello + ecdh_pk'
        C->>C: ecdh_ss = ECDH(ecdh_sk, ecdh_pk')
        S->>S: ecdh_ss' = ECDH(ecdh_sk', ecdh_pk)
        Note over C,S: ecdh_ss == ecdh_ss' (48 bytes)
    end

    rect rgb(187, 222, 251)
        Note over C,S: Combine Shared Secrets
        C->>C: combined_ss = kyber_ss || ecdh_ss
        S->>S: combined_ss = kyber_ss || ecdh_ss
        C->>C: master_secret = HKDF-Extract(combined_ss)
        S->>S: master_secret = HKDF-Extract(combined_ss)
        Note over C,S: Identical master_secret (48 bytes)
    end
```

### 키 파생 함수 (KDF)

```python
def derive_hybrid_shared_secret(kyber_ss, ecdh_ss, handshake_context):
    """
    Hybrid 공유 비밀 파생
    """

    # 1. Shared Secret 결합
    combined_ss = kyber_ss + ecdh_ss  # 32 + 48 = 80 bytes

    # 2. HKDF-Extract (Early Secret)
    early_secret = HKDF_Extract(
        salt=b'\x00' * 32,
        ikm=b'\x00' * 32
    )

    # 3. Derive Handshake Secret
    handshake_secret = HKDF_Expand_Label(
        secret=Derive_Secret(early_secret, "derived", ""),
        label="handshake",
        context=combined_ss,
        length=48
    )

    # 4. Derive Handshake Keys
    client_handshake_traffic_secret = HKDF_Expand_Label(
        secret=handshake_secret,
        label="c hs traffic",
        context=handshake_context,
        length=48
    )

    server_handshake_traffic_secret = HKDF_Expand_Label(
        secret=handshake_secret,
        label="s hs traffic",
        context=handshake_context,
        length=48
    )

    # 5. Derive Master Secret
    master_secret = HKDF_Expand_Label(
        secret=Derive_Secret(handshake_secret, "derived", ""),
        label="master",
        context=handshake_context,
        length=48
    )

    # 6. Derive Application Keys
    client_application_traffic_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="c ap traffic",
        context=handshake_context,
        length=48
    )

    server_application_traffic_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="s ap traffic",
        context=handshake_context,
        length=48
    )

    return {
        'handshake_secret': handshake_secret,
        'master_secret': master_secret,
        'client_handshake_key': derive_key(client_handshake_traffic_secret),
        'server_handshake_key': derive_key(server_handshake_traffic_secret),
        'client_application_key': derive_key(client_application_traffic_secret),
        'server_application_key': derive_key(server_application_traffic_secret),
    }
```

### 키 파생 다이어그램

```mermaid
graph TB
    subgraph "Hybrid Key Derivation"
        KYBER[KYBER1024 Shared Secret<br/>32 bytes]
        ECDH[ECDHE P-384 Shared Secret<br/>48 bytes]

        COMBINE[Combined Secret<br/>80 bytes]

        HKDF[HKDF-Extract<br/>Early Secret]

        HS_SEC[Handshake Secret<br/>48 bytes]

        subgraph "Handshake Keys"
            C_HS[Client Handshake Traffic Secret]
            S_HS[Server Handshake Traffic Secret]
        end

        MS_SEC[Master Secret<br/>48 bytes]

        subgraph "Application Keys"
            C_AP[Client Application Traffic Secret]
            S_AP[Server Application Traffic Secret]
        end
    end

    KYBER --> COMBINE
    ECDH --> COMBINE

    COMBINE --> HKDF
    HKDF --> HS_SEC

    HS_SEC --> C_HS
    HS_SEC --> S_HS

    HS_SEC --> MS_SEC

    MS_SEC --> C_AP
    MS_SEC --> S_AP

    style COMBINE fill:#fff9c4,stroke:#f57f17,stroke-width:3px
    style HS_SEC fill:#bbdefb,stroke:#1565c0,stroke-width:2px
    style MS_SEC fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

## ✍️ 서버 인증 (DILITHIUM3 + RSA/ECDSA 서명)

### Dual Signature 검증

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant HSM as Luna HSM

    Note over S: Server Authentication

    S->>C: Certificate (Hybrid Chain)
    Note left of S: + PQC Certificate (DILITHIUM3)<br/>+ Classical Certificate (RSA-4096)

    S->>S: Compute Handshake Hash
    Note left of S: hash = SHA384(handshake_messages)

    rect rgb(200, 230, 201)
        Note over S,HSM: PQC Signature (DILITHIUM3)
        S->>HSM: Sign Request (hash)
        HSM->>HSM: dilithium3_sign(sk, hash)
        HSM-->>S: DILITHIUM3 Signature (3293 bytes)
    end

    rect rgb(255, 249, 196)
        Note over S,HSM: Classical Signature (RSA-PSS)
        S->>HSM: Sign Request (hash)
        HSM->>HSM: rsa_pss_sign(sk, hash)
        HSM-->>S: RSA-PSS Signature (512 bytes)
    end

    S->>C: CertificateVerify
    Note left of S: + DILITHIUM3 Signature<br/>+ RSA-PSS Signature

    C->>C: Verify PQC Certificate Chain
    C->>C: Verify Classical Certificate Chain

    C->>C: dilithium3_verify(pk, hash, sig1)
    C->>C: rsa_pss_verify(pk, hash, sig2)

    alt Both Signatures Valid
        C->>C: Authentication Success
    else Any Signature Invalid
        C->>S: Alert: decrypt_error
    end
```

### CertificateVerify 메시지

```yaml
CertificateVerify (Hybrid):

  # PQC Signature
  pqc_signature:
    algorithm: dilithium3
    signature: [3293 bytes]

  # Classical Signature
  classical_signature:
    algorithm: rsa_pss_rsae_sha384
    signature: [512 bytes]

  # Signature Context
  context: "TLS 1.3, server CertificateVerify"

  # Signed Data
  signed_data:
    - context_string: "TLS 1.3, server CertificateVerify"
    - separator: 0x00
    - handshake_hash: SHA384(all handshake messages)
```

### 서명 검증 코드

```python
def verify_server_authentication(certificate_verify, handshake_messages, cert_chain):
    """
    서버 인증 검증 (Dual Signature)
    """

    # 1. Handshake Hash 계산
    handshake_hash = hashlib.sha384(handshake_messages).digest()

    # 2. Signed Data 구성
    context_string = b"TLS 1.3, server CertificateVerify"
    signed_data = context_string + b'\x00' + handshake_hash

    # 3. PQC 인증서 체인 검증
    pqc_cert = cert_chain['pqc']
    if not verify_certificate_chain(pqc_cert):
        raise TLSAlert(AlertDescription.bad_certificate)

    # 4. Classical 인증서 체인 검증
    classical_cert = cert_chain['classical']
    if not verify_certificate_chain(classical_cert):
        raise TLSAlert(AlertDescription.bad_certificate)

    # 5. DILITHIUM3 서명 검증
    pqc_public_key = extract_public_key(pqc_cert)
    pqc_signature = certificate_verify['pqc_signature']

    pqc_valid = dilithium3_verify(
        public_key=pqc_public_key,
        message=signed_data,
        signature=pqc_signature
    )

    # 6. RSA-PSS 서명 검증
    classical_public_key = extract_public_key(classical_cert)
    classical_signature = certificate_verify['classical_signature']

    classical_valid = rsa_pss_verify(
        public_key=classical_public_key,
        message=signed_data,
        signature=classical_signature,
        hash_algorithm='sha384'
    )

    # 7. Hybrid 정책 검증
    if not (pqc_valid and classical_valid):
        raise TLSAlert(AlertDescription.decrypt_error)

    return True
```

## 👤 클라이언트 인증 (Mutual TLS)

### Mutual TLS 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Q-Gateway Server

    Note over C,S: Mutual TLS (mTLS) Handshake

    C->>S: ClientHello
    S->>C: ServerHello
    S->>C: EncryptedExtensions
    S->>C: CertificateRequest
    Note left of S: + certificate_authorities<br/>+ signature_algorithms

    S->>C: Certificate (Server)
    S->>C: CertificateVerify (Server)
    S->>C: Finished

    C->>C: Verify Server Certificate
    C->>C: Verify Server Signatures

    C->>S: Certificate (Client)
    Note right of C: + PQC Client Certificate<br/>+ Classical Client Certificate

    C->>C: Compute Handshake Hash
    C->>C: Sign with DILITHIUM3
    C->>C: Sign with RSA/ECDSA

    C->>S: CertificateVerify (Client)
    Note right of C: + DILITHIUM3 Signature<br/>+ RSA-PSS Signature

    C->>S: Finished

    S->>S: Verify Client Certificate
    S->>S: Verify Client Signatures

    Note over C,S: Mutual Authentication Complete
```

### CertificateRequest 메시지

```yaml
CertificateRequest:

  certificate_request_context: [opaque]

  extensions:
    # Signature Algorithms
    - signature_algorithms:
        - dilithium3
        - rsa_pss_rsae_sha384
        - ecdsa_secp384r1_sha384

    # Signature Algorithms Cert
    - signature_algorithms_cert:
        - dilithium3
        - rsa_pss_rsae_sha384

    # Certificate Authorities
    - certificate_authorities:
        - "CN=QSIGN Client CA, O=Q-Sign"
        - "CN=QSIGN Root CA, O=Q-Sign"

    # PQC Hybrid Mode
    - pqc_hybrid_mode:
        require_pqc: true
        require_classical: true
```

## ✅ Finished 메시지 및 세션 키 파생

### Finished 메시지

```yaml
Finished Message:

  verify_data:
    # HMAC of all handshake messages
    HMAC-SHA384(
      finished_key,
      Transcript-Hash(all handshake messages)
    )

  finished_key:
    # Client Finished Key
    HKDF-Expand-Label(
      client_handshake_traffic_secret,
      "finished",
      "",
      32
    )

    # Server Finished Key
    HKDF-Expand-Label(
      server_handshake_traffic_secret,
      "finished",
      "",
      32
    )
```

### Finished 검증 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: Exchange Finished Messages

    S->>S: Compute Server Finished
    Note left of S: verify_data = HMAC(<br/>  finished_key,<br/>  transcript_hash<br/>)

    S->>C: Finished (Server)

    C->>C: Verify Server Finished
    C->>C: Compute Expected HMAC
    C->>C: Compare with Received

    alt Server Finished Valid
        C->>C: Server Authenticated
    else Invalid
        C->>S: Alert: decrypt_error
    end

    C->>C: Compute Client Finished
    C->>S: Finished (Client)

    S->>S: Verify Client Finished
    S->>S: Compute Expected HMAC
    S->>S: Compare with Received

    alt Client Finished Valid
        S->>S: Client Authenticated
        Note over C,S: Handshake Complete
    else Invalid
        S->>C: Alert: decrypt_error
    end
```

### 세션 키 파생

```python
def derive_session_keys(master_secret, handshake_context):
    """
    애플리케이션 세션 키 파생
    """

    # 1. Application Traffic Secrets
    client_app_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="c ap traffic",
        context=handshake_context,
        length=48
    )

    server_app_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="s ap traffic",
        context=handshake_context,
        length=48
    )

    # 2. Derive AES-256-GCM Keys
    client_write_key = HKDF_Expand_Label(
        secret=client_app_secret,
        label="key",
        context=b"",
        length=32  # AES-256
    )

    server_write_key = HKDF_Expand_Label(
        secret=server_app_secret,
        label="key",
        context=b"",
        length=32
    )

    # 3. Derive IVs
    client_write_iv = HKDF_Expand_Label(
        secret=client_app_secret,
        label="iv",
        context=b"",
        length=12  # GCM nonce
    )

    server_write_iv = HKDF_Expand_Label(
        secret=server_app_secret,
        label="iv",
        context=b"",
        length=12
    )

    # 4. Exporter Master Secret (for Key Export)
    exporter_master_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="exp master",
        context=handshake_context,
        length=48
    )

    # 5. Resumption Master Secret (for Session Resumption)
    resumption_master_secret = HKDF_Expand_Label(
        secret=master_secret,
        label="res master",
        context=handshake_context,
        length=48
    )

    return {
        'client_write_key': client_write_key,
        'server_write_key': server_write_key,
        'client_write_iv': client_write_iv,
        'server_write_iv': server_write_iv,
        'exporter_master_secret': exporter_master_secret,
        'resumption_master_secret': resumption_master_secret,
    }
```

## 🔄 Session Resumption

### Session ID 기반 재개

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server
    participant Cache as Session Cache

    Note over C,S: Initial Full Handshake

    C->>S: ClientHello (session_id = empty)
    S->>C: ServerHello (session_id = new_id)
    Note over C,S: [Full Handshake]
    S->>C: NewSessionTicket
    S->>Cache: Store Session (session_id, secrets)
    C->>C: Store Session ID

    Note over C,S: Session Resumption

    C->>S: ClientHello (session_id = existing_id)
    S->>Cache: Lookup Session
    Cache-->>S: Session Found

    alt Session Valid
        S->>C: ServerHello (session_id = existing_id)
        Note over C,S: [Abbreviated Handshake]
        S->>C: Finished
        C->>S: Finished
        Note over C,S: Resume Application Data
    else Session Invalid/Expired
        S->>C: ServerHello (session_id = new_id)
        Note over C,S: [Full Handshake Required]
    end
```

### Session Ticket 기반 재개

```yaml
NewSessionTicket:

  ticket_lifetime: 86400  # 24 hours
  ticket_age_add: [random 32-bit value]
  ticket_nonce: [random value]

  ticket: [encrypted session state]
    # Encrypted with ticket_encryption_key
    encrypted_data:
      - protocol_version: TLS 1.3
      - cipher_suite: TLS_HYBRID_ECDHE_KYBER1024_RSA_DILITHIUM3_WITH_AES_256_GCM_SHA384
      - resumption_master_secret: [48 bytes]
      - client_identity: [cert fingerprint]
      - issue_time: [timestamp]
      - pqc_algorithms: [kyber1024, dilithium3]

  extensions:
    - early_data: max_early_data_size = 16384
```

### Session Resumption 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: Session Ticket Resumption

    C->>C: Load Session Ticket
    C->>S: ClientHello
    Note right of C: + pre_shared_key extension<br/>+ psk_key_exchange_modes<br/>+ early_data (optional)

    S->>S: Decrypt Ticket
    S->>S: Verify Ticket Validity

    alt Ticket Valid
        S->>C: ServerHello
        Note left of S: + pre_shared_key extension<br/>+ selected_identity = 0

        S->>C: EncryptedExtensions
        Note left of S: + early_data: accepted

        S->>C: Finished

        C->>C: Derive PSK-based Keys
        C->>S: Finished

        Note over C,S: Session Resumed (1-RTT)

    else Ticket Invalid
        S->>C: ServerHello (no pre_shared_key)
        Note over C,S: Full Handshake Required
    end
```

## 🚀 0-RTT 데이터 전송

### 0-RTT 개요

```yaml
0-RTT (Zero Round-Trip Time):

  Benefits:
    - Faster connection establishment
    - Reduced latency for repeated connections
    - Improved user experience

  Security Considerations:
    - No forward secrecy for 0-RTT data
    - Replay attack vulnerability
    - Anti-replay mechanisms required

  Use Cases:
    - HTTP GET requests
    - Idempotent operations only
    - Read-only API calls

  Restrictions:
    - No state-changing operations
    - Limited to max_early_data_size
    - Server can reject early data
```

### 0-RTT 흐름

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant S as Server

    Note over C,S: 0-RTT Data Transmission

    C->>C: Load Session Ticket
    C->>C: Derive Early Traffic Secret

    C->>S: ClientHello
    Note right of C: + early_data indication<br/>+ pre_shared_key<br/>+ key_share (for 1-RTT)

    C->>S: [0-RTT Application Data]
    Note right of C: Encrypted with early_traffic_secret<br/>Example: HTTP GET /api/data

    S->>S: Decrypt Ticket
    S->>S: Check Replay Cache

    alt Early Data Accepted
        S->>S: Process 0-RTT Data
        S->>C: ServerHello
        Note left of S: + pre_shared_key<br/>+ selected_identity

        S->>C: EncryptedExtensions
        Note left of S: + early_data: accepted

        S->>C: [1-RTT Application Response]
        Note left of S: Response to 0-RTT request

        S->>C: Finished

        C->>S: Finished

        Note over C,S: Total: 0-RTT for request

    else Early Data Rejected
        S->>C: ServerHello
        S->>C: EncryptedExtensions
        Note left of S: + early_data: rejected

        S->>C: Finished

        C->>S: [Resend as 1-RTT Data]
        Note right of C: Client must resend rejected data

        Note over C,S: Fallback to 1-RTT
    end
```

### Anti-Replay 메커니즘

```python
class AntiReplayCache:
    """
    0-RTT Replay Attack 방지
    """

    def __init__(self, window_size=10):
        self.cache = {}
        self.window_size = window_size  # seconds

    def check_and_store(self, ticket_hash, timestamp):
        """
        티켓 해시를 확인하고 저장
        """
        current_time = time.time()

        # 1. 시간 윈도우 확인
        if abs(current_time - timestamp) > self.window_size:
            return False, "Timestamp out of window"

        # 2. Replay 확인
        if ticket_hash in self.cache:
            cached_time = self.cache[ticket_hash]
            if current_time - cached_time < self.window_size:
                return False, "Replay detected"

        # 3. 캐시에 저장
        self.cache[ticket_hash] = current_time

        # 4. 오래된 항목 정리
        self._cleanup_old_entries(current_time)

        return True, "Accepted"

    def _cleanup_old_entries(self, current_time):
        """
        만료된 캐시 항목 제거
        """
        expired = [
            key for key, timestamp in self.cache.items()
            if current_time - timestamp > self.window_size
        ]
        for key in expired:
            del self.cache[key]
```

### 0-RTT 보안 다이어그램

```mermaid
graph TB
    subgraph "0-RTT Security Analysis"
        subgraph "Threats"
            T1[Replay Attack<br/>Duplicate Requests]
            T2[No Forward Secrecy<br/>for Early Data]
            T3[State Manipulation<br/>via Replay]
        end

        subgraph "Mitigations"
            M1[Anti-Replay Cache<br/>Time Window: 10s]
            M2[Limit to Idempotent Ops<br/>GET, HEAD only]
            M3[Server-side Deduplication<br/>Request ID tracking]
            M4[Strict Validation<br/>Early data acceptance]
        end

        subgraph "Best Practices"
            BP1[Disable for Sensitive Ops]
            BP2[Monitor Replay Attempts]
            BP3[Short Ticket Lifetime]
            BP4[Regular Key Rotation]
        end
    end

    T1 --> M1
    T1 --> M3
    T2 --> M2
    T3 --> M2
    T3 --> M4

    M1 --> BP2
    M2 --> BP1
    M4 --> BP3
    M4 --> BP4

    style T1 fill:#ffccbc,stroke:#d84315,stroke-width:2px
    style T2 fill:#ffccbc,stroke:#d84315,stroke-width:2px
    style M1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style M2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style BP1 fill:#bbdefb,stroke:#1565c0,stroke-width:2px
```

## 🔗 참고 자료

```yaml
Standards:
  TLS 1.3:
    - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
    - RFC 8448: Example Handshake Traces for TLS 1.3

  PQC Extensions:
    - IETF Draft: Hybrid Key Exchange in TLS 1.3
    - NIST FIPS 203: ML-KEM (KYBER)
    - NIST FIPS 204: ML-DSA (DILITHIUM)

  Session Resumption:
    - RFC 5077: TLS Session Resumption without Server-Side State
    - RFC 8446 Section 4.6: Session Tickets

  0-RTT:
    - RFC 8446 Section 2.3: 0-RTT Data
    - RFC 8446 Appendix E.5: Replay Attacks on 0-RTT

Implementation:
  - OpenSSL with OQS Provider
  - BoringSSL with PQC Support
  - liboqs: Open Quantum Safe Library
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Protocol**: TLS 1.3 with PQC Extensions
**Security Level**: NIST Level 3-5
