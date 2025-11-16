# PQC 아키텍처

## 📘 개요

QSIGN 프로젝트는 Post-Quantum Cryptography (PQC) 알고리즘을 기반으로 양자 컴퓨터의 위협으로부터 안전한 인증 및 키 관리 시스템을 구축합니다.

## 🔐 PQC 알고리즘 스택

### NIST 표준화 알고리즘

```mermaid
graph TB
    subgraph "NIST PQC Standards"
        subgraph "디지털 서명"
            D1[DILITHIUM3<br/>FIPS 204 ML-DSA]
            D2[SPHINCS+<br/>FIPS 205 SLH-DSA]
        end

        subgraph "키 교환/암호화"
            K1[KYBER1024<br/>FIPS 203 ML-KEM]
        end
    end

    subgraph "Hybrid Mode"
        H1[RSA 2048/4096]
        H2[ECDSA P-256/P-384]
        H3[AES-256-GCM]
    end

    D1 -->|Primary| JWT[JWT Signing]
    D2 -->|Backup| JWT
    K1 --> TLS[TLS Encryption]

    H1 -.->|Fallback| JWT
    H2 -.->|Fallback| JWT
    H3 -.->|Symmetric| TLS

    style D1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style K1 fill:#bbdefb,stroke:#1565c0,stroke-width:3px
    style D2 fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style H1 fill:#ffccbc,stroke:#d84315,stroke-width:1px,stroke-dasharray: 5 5
    style H2 fill:#ffccbc,stroke:#d84315,stroke-width:1px,stroke-dasharray: 5 5
```

### 알고리즘 세부 사양

#### 1. DILITHIUM3 (ML-DSA)

**NIST FIPS 204 - Module-Lattice-Based Digital Signature Algorithm**

```yaml
알고리즘: DILITHIUM3
표준: NIST FIPS 204 (2024)
보안 수준: NIST Level 3 (AES-192 equivalent)
서명 크기: ~3,293 bytes
공개키 크기: ~1,952 bytes
비밀키 크기: ~4,000 bytes
서명 생성 속도: ~1,000 signs/sec
검증 속도: ~2,000 verifies/sec

사용처:
  - JWT 토큰 서명
  - API 요청 서명
  - 인증서 서명
  - 트랜잭션 무결성 검증
```

**보안 특성:**
- Lattice-based 암호화 (격자 기반)
- 양자 컴퓨터에 대한 내성
- Shor's 알고리즘에 안전
- Grover's 알고리즘에 대한 보안 여유

#### 2. KYBER1024 (ML-KEM)

**NIST FIPS 203 - Module-Lattice-Based Key Encapsulation Mechanism**

```yaml
알고리즘: KYBER1024
표준: NIST FIPS 203 (2024)
보안 수준: NIST Level 5 (AES-256 equivalent)
공개키 크기: ~1,568 bytes
비밀키 크기: ~3,168 bytes
암호문 크기: ~1,568 bytes
공유 비밀 크기: 32 bytes
키 생성 속도: ~10,000 keypairs/sec
캡슐화 속도: ~8,000 ops/sec
역캡슐화 속도: ~8,000 ops/sec

사용처:
  - TLS 1.3 핸드셰이크
  - 세션 키 교환
  - 대칭키 암호화
  - 채널 암호화
```

#### 3. SPHINCS+ (SLH-DSA)

**NIST FIPS 205 - Stateless Hash-Based Signature Algorithm**

```yaml
알고리즘: SPHINCS+-SHA2-256f
표준: NIST FIPS 205 (2024)
보안 수준: NIST Level 3
서명 크기: ~49,856 bytes
공개키 크기: 64 bytes
비밀키 크기: 128 bytes
서명 생성 속도: ~10 signs/sec
검증 속도: ~200 verifies/sec

사용처:
  - 백업 서명 시스템
  - 장기 보관 서명
  - 코드 서명
  - 펌웨어 서명
```

## 🏗️ PQC 통합 아키텍처

### 전체 PQC 스택

```mermaid
graph TB
    subgraph "Application Layer"
        APP1[Web Application]
        APP2[Mobile App]
        APP3[Backend Services]
    end

    subgraph "Authentication Layer - Q-Sign™"
        subgraph "Keycloak PQC"
            KC_AUTH[인증 모듈]
            KC_TOKEN[PQC Token Service]
            KC_SIG[Signature Provider]
        end
    end

    subgraph "Crypto Layer - Q-KMS™"
        subgraph "Vault Transit Engine"
            V_DILITHIUM[DILITHIUM3<br/>Signing Key]
            V_KYBER[KYBER1024<br/>Encryption Key]
            V_SPHINCS[SPHINCS+<br/>Backup Key]
        end

        subgraph "Luna HSM"
            HSM_DILITHIUM[DILITHIUM3<br/>Hardware Key]
            HSM_KYBER[KYBER1024<br/>Hardware Key]
            HSM_QRNG[Quantum RNG]
        end
    end

    subgraph "Gateway Layer - Q-Gateway™"
        GW_TLS[TLS-PQC Hybrid]
        GW_JWT[JWT Verification]
    end

    APP1 & APP2 & APP3 --> GW_TLS
    GW_TLS --> GW_JWT
    GW_JWT --> KC_AUTH

    KC_AUTH --> KC_TOKEN
    KC_TOKEN --> KC_SIG

    KC_SIG --> V_DILITHIUM
    KC_SIG --> V_KYBER

    V_DILITHIUM --> HSM_DILITHIUM
    V_KYBER --> HSM_KYBER

    HSM_QRNG -.->|엔트로피| HSM_DILITHIUM
    HSM_QRNG -.->|엔트로피| HSM_KYBER

    V_SPHINCS -.->|백업| KC_SIG

    style V_DILITHIUM fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style V_KYBER fill:#bbdefb,stroke:#1565c0,stroke-width:3px
    style V_SPHINCS fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style HSM_QRNG fill:#ffccbc,stroke:#d84315,stroke-width:3px
```

### Hybrid Mode 전략

QSIGN은 점진적 전환을 위해 **Hybrid Mode**를 지원합니다:

```mermaid
graph LR
    subgraph "Classic Mode (Legacy)"
        C1[RSA-2048]
        C2[ECDSA-P256]
        C3[AES-128-GCM]
    end

    subgraph "Hybrid Mode (Transition)"
        H1[RSA + DILITHIUM3]
        H2[ECDSA + DILITHIUM3]
        H3[AES + KYBER1024]
    end

    subgraph "Pure PQC Mode (Future)"
        P1[DILITHIUM3]
        P2[SPHINCS+]
        P3[KYBER1024]
    end

    C1 --> H1
    C2 --> H2
    C3 --> H3

    H1 --> P1
    H2 --> P2
    H3 --> P3

    style C1 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style C2 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style H1 fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style H2 fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style P1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style P2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
```

## 🔑 PQC 키 생명주기

### 키 생성 흐름

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant QRNG as Quantum RNG
    participant KC as Keycloak

    Admin->>Vault: 1. Request Key Generation
    Vault->>HSM: 2. Initialize PKCS#11 Session
    HSM->>QRNG: 3. Get Quantum Entropy
    QRNG-->>HSM: 4. Random Bytes (256-bit)

    alt DILITHIUM3 Key
        HSM->>HSM: 5a. Generate DILITHIUM3 Keypair
        HSM-->>Vault: 6a. Public Key + Key Handle
    else KYBER1024 Key
        HSM->>HSM: 5b. Generate KYBER1024 Keypair
        HSM-->>Vault: 6b. Public Key + Key Handle
    end

    Vault->>Vault: 7. Store in Transit Engine
    Vault-->>Admin: 8. Key ID + Metadata

    Admin->>KC: 9. Configure Key in Keycloak
    KC->>Vault: 10. Verify Key Access
    Vault-->>KC: 11. Key Verified ✅
```

### 키 순환 정책

```yaml
키 순환 정책:

  DILITHIUM3 서명 키:
    순환 주기: 90일
    만료 경고: 30일 전
    자동 순환: Enabled
    백업 키 개수: 3

  KYBER1024 암호화 키:
    순환 주기: 180일
    만료 경고: 60일 전
    자동 순환: Enabled
    이전 키 보관: 1년

  SPHINCS+ 백업 키:
    순환 주기: 365일
    만료 경고: 90일 전
    자동 순환: Disabled
    수동 승인: Required

  HSM 마스터 키:
    순환: Never (Hardware Protected)
    백업: Secure Offline Storage
    다중 서명: 3/5 Quorum
```

## 🔐 PQC JWT 토큰 구조

### JWT 헤더

```json
{
  "alg": "DILITHIUM3",
  "typ": "JWT",
  "kid": "pqc-key-2025-001",
  "pqc": true,
  "hybrid": {
    "enabled": true,
    "fallback": "RS256"
  },
  "x5t#S256": "..."
}
```

### JWT 페이로드

```json
{
  "iss": "https://q-sign.local:30181/realms/qsign",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["q-app", "q-gateway"],
  "exp": 1732145723,
  "iat": 1732142123,
  "auth_time": 1732142120,
  "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",

  "pqc_metadata": {
    "algorithm": "DILITHIUM3",
    "security_level": 3,
    "key_id": "pqc-key-2025-001",
    "hsm_backed": true
  },

  "realm_access": {
    "roles": ["user", "admin"]
  },

  "scope": "openid profile email"
}
```

### JWT 서명

```
DILITHIUM3_Sign(
  base64url(header) + "." + base64url(payload),
  private_key_from_hsm
)

서명 크기: ~3,293 bytes (Base64 encoded: ~4,391 chars)
검증 시간: < 5ms
```

### Hybrid JWT (PQC + RSA)

```json
{
  "signatures": [
    {
      "algorithm": "DILITHIUM3",
      "signature": "...",
      "key_id": "pqc-key-2025-001"
    },
    {
      "algorithm": "RS256",
      "signature": "...",
      "key_id": "rsa-key-legacy-001"
    }
  ],
  "validation": {
    "require_pqc": true,
    "allow_classic": false,
    "min_valid_signatures": 1
  }
}
```

## 🌐 TLS-PQC Hybrid

### TLS 1.3 with Post-Quantum KEM

```mermaid
sequenceDiagram
    participant Client
    participant GW as Q-Gateway (APISIX)
    participant Server

    Client->>GW: ClientHello<br/>(supported groups: kyber1024, x25519)

    GW->>GW: Select Key Exchange:<br/>kyber1024 (preferred)<br/>or x25519 (fallback)

    GW->>Client: ServerHello<br/>(selected group: kyber1024)

    Client->>Client: Generate KYBER1024 keypair
    Client->>GW: ClientKeyExchange<br/>(KYBER public key)

    GW->>GW: Encapsulate with KYBER1024
    GW->>Client: ServerKeyExchange<br/>(ciphertext + shared secret)

    Client->>Client: Decapsulate

    Note over Client,GW: Derive session keys from<br/>KYBER shared secret

    Client->>GW: Finished (encrypted)
    GW->>Client: Finished (encrypted)

    Note over Client,GW: Secure PQC-protected channel
```

### 지원 Cipher Suites

```yaml
TLS 1.3 PQC Cipher Suites:

  # Pure PQC
  - TLS_KYBER1024_WITH_AES_256_GCM_SHA384
  - TLS_KYBER768_WITH_AES_256_GCM_SHA384

  # Hybrid (PQC + Classical)
  - TLS_KYBER1024_X25519_WITH_AES_256_GCM_SHA384
  - TLS_KYBER768_P256_WITH_AES_256_GCM_SHA384

  # Fallback (Classical only)
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

## 🔬 PQC 성능 최적화

### 벤치마크 결과

| 작업 | DILITHIUM3 | RSA-2048 | 개선율 |
|------|------------|----------|--------|
| 키 생성 | 0.5ms | 50ms | **100x faster** |
| 서명 생성 | 1.2ms | 2.5ms | 2x faster |
| 서명 검증 | 0.8ms | 0.1ms | 8x slower |
| 서명 크기 | 3,293 bytes | 256 bytes | 13x larger |

| 작업 | KYBER1024 | RSA-2048 | 개선율 |
|------|-----------|----------|--------|
| 키 생성 | 0.1ms | 50ms | **500x faster** |
| 암호화 | 0.15ms | 2.0ms | 13x faster |
| 복호화 | 0.18ms | 5.0ms | 28x faster |
| 암호문 크기 | 1,568 bytes | 256 bytes | 6x larger |

### 최적화 전략

```yaml
성능 최적화:

  1. HSM 세션 풀링:
    - Connection Pool Size: 10
    - Max Sessions: 50
    - Session Timeout: 30m

  2. 키 캐싱:
    - Public Key Cache: 1h
    - Key Metadata Cache: 24h
    - TTL: Configurable

  3. 서명 검증 캐싱:
    - Verified Signatures: 5m
    - Max Cache Size: 10,000 entries
    - LRU Eviction

  4. 병렬 처리:
    - Goroutines for signing: 100
    - Batch verification: Enabled
    - Async operations: Supported

  5. 하드웨어 가속:
    - AVX2 instructions
    - AES-NI
    - HSM offloading
```

## 🛡️ PQC 보안 고려사항

### 위협 모델

```mermaid
graph TB
    subgraph "Quantum Threats"
        Q1[Shor's Algorithm<br/>공개키 암호 파괴]
        Q2[Grover's Algorithm<br/>대칭키 약화]
        Q3[양자 컴퓨터<br/>Timeline: 2030-2040]
    end

    subgraph "Classical Threats"
        C1[Side-channel Attacks]
        C2[Implementation Bugs]
        C3[Key Extraction]
    end

    subgraph "Mitigations"
        M1[PQC Algorithms<br/>NIST approved]
        M2[HSM Protection<br/>Hardware isolation]
        M3[Constant-time Ops<br/>Timing attack prevention]
        M4[Formal Verification<br/>Code audits]
    end

    Q1 -->|해결| M1
    Q2 -->|해결| M1
    Q3 -->|대비| M1

    C1 -->|방어| M2
    C1 -->|방어| M3
    C2 -->|검증| M4
    C3 -->|차단| M2

    style Q1 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style Q2 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style M1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style M2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
```

### 보안 권장사항

```yaml
PQC 보안 Best Practices:

1. 키 보호:
   ✅ HSM에 모든 PQC 개인키 저장
   ✅ QRNG로 키 생성
   ✅ 키 백업 암호화 (AES-256-GCM)
   ✅ 다중 서명 요구 (Critical Operations)
   ❌ 메모리에 평문 키 저장 금지
   ❌ 로그에 키 정보 출력 금지

2. 알고리즘 사용:
   ✅ NIST 승인 파라미터만 사용
   ✅ Hybrid 모드로 점진적 전환
   ✅ 서명 검증 실패 시 거부
   ❌ 약화된 파라미터 사용 금지
   ❌ Deprecated 알고리즘 사용 금지

3. 구현 보안:
   ✅ Constant-time 연산
   ✅ 메모리 초기화 (zeroization)
   ✅ 예외 처리 강화
   ✅ 입력 검증
   ❌ 타이밍 정보 노출 금지
   ❌ 에러 메시지에 민감 정보 포함 금지

4. 운영 보안:
   ✅ 정기적 키 순환
   ✅ 감사 로그 기록
   ✅ 침입 탐지
   ✅ 암호화 통신
   ❌ 프로덕션에서 디버그 모드 금지
   ❌ 약한 인증 메커니즘 사용 금지
```

## 📊 PQC 마이그레이션 로드맵

```mermaid
gantt
    title PQC 마이그레이션 타임라인
    dateFormat YYYY-MM-DD
    section Phase 1: 준비
    PQC 알고리즘 연구           :done, 2024-01-01, 60d
    HSM 통합 개발                :done, 2024-02-01, 90d
    테스트 환경 구축             :done, 2024-03-15, 45d

    section Phase 2: Hybrid 모드
    Hybrid JWT 구현              :done, 2024-05-01, 60d
    TLS-PQC Hybrid               :done, 2024-06-01, 60d
    베타 테스트                  :active, 2024-07-15, 90d

    section Phase 3: 전환
    프로덕션 배포 (20%)          :2024-10-01, 30d
    프로덕션 배포 (50%)          :2024-11-01, 30d
    프로덕션 배포 (100%)         :2024-12-01, 30d

    section Phase 4: Pure PQC
    Classic 알고리즘 Deprecate   :2025-03-01, 90d
    Pure PQC 모드 전환           :2025-06-01, 90d
    레거시 지원 종료             :2025-12-01, 30d
```

## 🔍 참고 자료

### NIST 표준 문서

- **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
  - https://csrc.nist.gov/pubs/fips/203/final

- **FIPS 204**: Module-Lattice-Based Digital Signature Standard
  - https://csrc.nist.gov/pubs/fips/204/final

- **FIPS 205**: Stateless Hash-Based Digital Signature Standard
  - https://csrc.nist.gov/pubs/fips/205/final

### 구현 라이브러리

```yaml
PQC 라이브러리:

  liboqs (Open Quantum Safe):
    버전: 0.10.0+
    언어: C/C++
    알고리즘: DILITHIUM, KYBER, SPHINCS+
    GitHub: https://github.com/open-quantum-safe/liboqs

  boringssl-pqc:
    버전: Custom Build
    알고리즘: KYBER for TLS
    GitHub: https://github.com/google/boringssl

  go-pqc:
    버전: 1.0+
    언어: Go
    용도: Keycloak Provider

  Luna HSM SDK:
    버전: 10.4+
    PKCS#11: PQC Support
    알고리즘: DILITHIUM, KYBER
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**PQC Standards**: NIST FIPS 203/204/205 (2024)
**Security Level**: NIST Level 3-5
