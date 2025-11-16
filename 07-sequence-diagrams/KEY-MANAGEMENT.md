# 키 관리 시퀀스 다이어그램

## 1. PQC 키 생성 플로우 (Luna HSM)

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin CLI
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM (/dev/k7pf0)
    participant Storage as Vault Storage

    Note over Admin,Storage: PQC 키 쌍 생성 요청
    Admin->>Vault: 1. POST /v1/pqc-keys/keys/my-key<br/>{type: "dilithium3"}

    Note over Vault,Storage: Transit Engine 처리
    Vault->>Vault: 2. Validate request
    Vault->>Vault: 3. Check permissions

    Note over Vault,HSM: HSM 키 생성
    Vault->>HSM: 4. PKCS#11 C_GenerateKeyPair<br/>mechanism: CKM_DILITHIUM3
    HSM->>HSM: 5. Generate DILITHIUM3 keypair<br/>(FIPS 140-2 Level 3)
    HSM->>HSM: 6. Store private key securely<br/>(never leaves HSM)
    HSM-->>Vault: 7. Key handle + Public key

    Note over Vault,Storage: 메타데이터 저장
    Vault->>Storage: 8. Store key metadata<br/>{<br/>  name: "my-key",<br/>  type: "dilithium3",<br/>  hsm_handle: "0x1234",<br/>  created_at: "2025-11-16"<br/>}
    Storage-->>Vault: 9. Metadata saved

    Vault-->>Admin: 10. {<br/>  name: "my-key",<br/>  type: "dilithium3",<br/>  public_key: "base64...",<br/>  version: 1<br/>}
```

## 2. PQC 서명 생성 플로우

```mermaid
sequenceDiagram
    autonumber
    participant KC as Q-Sign (Keycloak)
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant QRNG as QRNG (Quantum RNG)

    Note over KC,QRNG: 서명 요청
    KC->>Vault: 1. POST /v1/pqc-keys/sign/my-key<br/>{<br/>  input: "base64_data",<br/>  algorithm: "dilithium3"<br/>}

    Note over Vault,QRNG: 데이터 준비
    Vault->>Vault: 2. Validate key exists
    Vault->>Vault: 3. Base64 decode input
    Vault->>Vault: 4. Hash data (SHA-256)

    Note over Vault,HSM: HSM 서명 작업
    Vault->>HSM: 5. PKCS#11 C_SignInit<br/>mechanism: CKM_DILITHIUM3<br/>key_handle: 0x1234

    HSM->>QRNG: 6. Request random nonce<br/>(if needed)
    QRNG-->>HSM: 7. Quantum random bytes

    HSM->>HSM: 8. DILITHIUM3 Sign operation<br/>(Hardware acceleration)
    HSM-->>Vault: 9. Signature bytes (3293 bytes)

    Note over Vault,KC: 서명 반환
    Vault->>Vault: 10. Base64 encode signature
    Vault-->>KC: 11. {<br/>  signature: "base64_signature",<br/>  key_version: 1,<br/>  algorithm: "dilithium3"<br/>}
```

## 3. PQC 서명 검증 플로우

```mermaid
sequenceDiagram
    autonumber
    participant API as Backend API
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant Cache as Signature Cache

    Note over API,Cache: 서명 검증 요청
    API->>Vault: 1. POST /v1/pqc-keys/verify/my-key<br/>{<br/>  input: "base64_data",<br/>  signature: "base64_sig"<br/>}

    Note over Vault,Cache: 캐시 확인
    Vault->>Cache: 2. Check signature cache<br/>(sig_hash)
    Cache-->>Vault: 3. Cache miss

    Note over Vault,HSM: 데이터 준비
    Vault->>Vault: 4. Base64 decode input & sig
    Vault->>Vault: 5. Hash data (SHA-256)
    Vault->>Vault: 6. Load public key

    Note over Vault,HSM: HSM 검증
    Vault->>HSM: 7. PKCS#11 C_VerifyInit<br/>mechanism: CKM_DILITHIUM3<br/>public_key: ...
    Vault->>HSM: 8. C_Verify(data, signature)
    HSM->>HSM: 9. DILITHIUM3 Verify<br/>(Hardware operation)

    alt Signature valid
        HSM-->>Vault: 10a. CKR_OK (Valid)
        Vault->>Cache: 11a. Cache result (5 min)
        Vault-->>API: 12a. {valid: true}
    else Signature invalid
        HSM-->>Vault: 10b. CKR_SIGNATURE_INVALID
        Vault-->>API: 11b. {valid: false}
    end
```

## 4. 키 회전 (Key Rotation) 플로우

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant Apps as Applications

    Note over Admin,Apps: 새 키 버전 생성
    Admin->>Vault: 1. POST /v1/pqc-keys/keys/my-key/rotate

    Vault->>Vault: 2. Increment version (v2)
    Vault->>HSM: 3. Generate new DILITHIUM3 keypair
    HSM->>HSM: 4. Create new key (v2)
    HSM-->>Vault: 5. New key handle + public key

    Vault->>Vault: 6. Update key metadata<br/>{<br/>  latest_version: 2,<br/>  min_version: 1<br/>}
    Vault-->>Admin: 7. {<br/>  name: "my-key",<br/>  version: 2,<br/>  public_key: "..."<br/>}

    Note over Admin,Apps: 새 키로 서명
    Apps->>Vault: 8. POST /v1/pqc-keys/sign/my-key
    Vault->>HSM: 9. Sign with v2 (latest)
    HSM-->>Vault: 10. Signature (v2)
    Vault-->>Apps: 11. Signature with key_version=2

    Note over Admin,Apps: 이전 키로 검증 (호환성)
    Apps->>Vault: 12. POST /v1/pqc-keys/verify/my-key<br/>(old signature, v1)
    Vault->>HSM: 13. Verify with v1 public key
    HSM-->>Vault: 14. Valid
    Vault-->>Apps: 15. {valid: true, key_version: 1}

    Note over Admin,Apps: 구 버전 폐기
    Admin->>Vault: 16. POST /v1/pqc-keys/keys/my-key/config<br/>{min_version: 2}
    Vault->>Vault: 17. Mark v1 as deprecated
    Vault->>HSM: 18. Optional: Delete v1 from HSM
    Vault-->>Admin: 19. {min_version: 2, latest_version: 2}
```

## 5. Vault 초기화 및 Unseal

```mermaid
sequenceDiagram
    autonumber
    participant Init as Init Script
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM
    participant Admin as Admin (Human)

    Note over Init,Admin: Vault 초기화 (최초 1회)
    Init->>Vault: 1. POST /v1/sys/init<br/>{<br/>  secret_shares: 5,<br/>  secret_threshold: 3<br/>}

    Vault->>HSM: 2. Generate master key<br/>(stored in HSM)
    HSM->>HSM: 3. Create AES-256 master key
    HSM-->>Vault: 4. Key handle

    Vault->>Vault: 5. Split master key (Shamir)<br/>5 shares, 3 threshold
    Vault-->>Init: 6. {<br/>  unseal_keys: ["key1", "key2", ...],<br/>  root_token: "hvs.xxx"<br/>}

    Init->>Admin: 7. 🔐 SAVE THESE KEYS SECURELY!

    Note over Init,Admin: Vault Sealed 상태
    Vault->>Vault: 8. Vault is now SEALED

    Note over Init,Admin: Unseal 작업 (재시작 후)
    Init->>Vault: 9. POST /v1/sys/unseal<br/>{key: "unseal_key_1"}
    Vault-->>Init: 10. {sealed: true, progress: 1/3}

    Init->>Vault: 11. POST /v1/sys/unseal<br/>{key: "unseal_key_2"}
    Vault-->>Init: 12. {sealed: true, progress: 2/3}

    Init->>Vault: 13. POST /v1/sys/unseal<br/>{key: "unseal_key_3"}
    Vault->>HSM: 14. Retrieve master key from HSM
    HSM-->>Vault: 15. Master key
    Vault->>Vault: 16. Decrypt storage encryption key
    Vault-->>Init: 17. {sealed: false, progress: 3/3}

    Note over Init,Admin: Vault Unsealed (Ready)
    Vault->>Vault: 18. ✅ Vault is now UNSEALED
```

## 6. Transit Engine 설정

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin
    participant Vault as Q-KMS Vault
    participant HSM as Luna HSM

    Note over Admin,HSM: Transit Engine 활성화
    Admin->>Vault: 1. POST /v1/sys/mounts/pqc-keys<br/>{<br/>  type: "transit",<br/>  description: "PQC keys"<br/>}
    Vault->>Vault: 2. Mount transit engine at pqc-keys/
    Vault-->>Admin: 3. {mounted: true}

    Note over Admin,HSM: DILITHIUM3 키 생성
    Admin->>Vault: 4. POST /v1/pqc-keys/keys/keycloak-sign<br/>{<br/>  type: "dilithium3",<br/>  exportable: false<br/>}
    Vault->>HSM: 5. C_GenerateKeyPair(CKM_DILITHIUM3)
    HSM-->>Vault: 6. Key handle + public key
    Vault-->>Admin: 7. {name: "keycloak-sign"}

    Note over Admin,HSM: KYBER1024 키 생성 (암호화)
    Admin->>Vault: 8. POST /v1/pqc-keys/keys/data-encrypt<br/>{<br/>  type: "kyber1024",<br/>  exportable: false<br/>}
    Vault->>HSM: 9. C_GenerateKeyPair(CKM_KYBER1024)
    HSM-->>Vault: 10. Key handle + public key
    Vault-->>Admin: 11. {name: "data-encrypt"}

    Note over Admin,HSM: 키 정책 설정
    Admin->>Vault: 12. POST /v1/sys/policies/acl/pqc-user<br/>{<br/>  path: "pqc-keys/sign/*": {<br/>    capabilities: ["update"]<br/>  }<br/>}
    Vault-->>Admin: 13. Policy created
```

## 7. HSM 슬롯 관리

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin CLI
    participant Vault as Vault Plugin
    participant PKCS11 as PKCS#11 Library
    participant HSM as Luna HSM Device

    Note over Admin,HSM: HSM 슬롯 조회
    Admin->>PKCS11: 1. C_GetSlotList(TRUE)
    PKCS11->>HSM: 2. USB/PCIe communication
    HSM-->>PKCS11: 3. Available slots [0, 1, 2]
    PKCS11-->>Admin: 4. Slot list

    Note over Admin,HSM: 슬롯 정보 확인
    Admin->>PKCS11: 5. C_GetSlotInfo(slot=0)
    PKCS11->>HSM: 6. Query slot 0
    HSM-->>PKCS11: 7. {<br/>  description: "Luna K7",<br/>  manufacturer: "Thales",<br/>  flags: CKF_TOKEN_PRESENT<br/>}
    PKCS11-->>Admin: 8. Slot info

    Note over Admin,HSM: 토큰 정보 확인
    Admin->>PKCS11: 9. C_GetTokenInfo(slot=0)
    PKCS11->>HSM: 10. Query token
    HSM-->>PKCS11: 11. {<br/>  label: "vault-token",<br/>  model: "K7",<br/>  serial: "1234567"<br/>}
    PKCS11-->>Admin: 12. Token info

    Note over Admin,HSM: 세션 열기
    Admin->>PKCS11: 13. C_OpenSession(slot=0,<br/>  flags=CKF_SERIAL_SESSION |<br/>  CKF_RW_SESSION)
    PKCS11->>HSM: 14. Open session
    HSM-->>PKCS11: 15. Session handle: 0x5678
    PKCS11-->>Admin: 16. Session opened

    Note over Admin,HSM: 로그인
    Admin->>PKCS11: 17. C_Login(session,<br/>  CKU_USER, "userpin")
    PKCS11->>HSM: 18. Authenticate
    HSM->>HSM: 19. Verify PIN
    HSM-->>PKCS11: 20. CKR_OK
    PKCS11-->>Admin: 21. Logged in

    Note over Admin,HSM: 키 작업 수행
    Vault->>PKCS11: 22. C_Sign(session, data)
    PKCS11->>HSM: 23. Sign operation
    HSM-->>PKCS11: 24. Signature
    PKCS11-->>Vault: 25. Signature

    Note over Admin,HSM: 세션 종료
    Admin->>PKCS11: 26. C_Logout(session)
    Admin->>PKCS11: 27. C_CloseSession(session)
    PKCS11->>HSM: 28. Close session
    HSM-->>PKCS11: 29. CKR_OK
```

## 8. 비밀 키 관리 (KV Secret Engine)

```mermaid
sequenceDiagram
    autonumber
    participant App as Application
    participant Vault as Q-KMS Vault
    participant Storage as Vault Storage
    participant HSM as Luna HSM

    Note over App,HSM: Secret 저장
    App->>Vault: 1. POST /v1/secret/data/database/creds<br/>{<br/>  data: {<br/>    username: "dbuser",<br/>    password: "secret123"<br/>  }<br/>}

    Vault->>Vault: 2. Increment version
    Vault->>HSM: 3. Encrypt with HSM master key
    HSM-->>Vault: 4. Encrypted data
    Vault->>Storage: 5. Store encrypted secret<br/>(version 1)
    Storage-->>Vault: 6. Saved
    Vault-->>App: 7. {<br/>  version: 1,<br/>  created_time: "2025-11-16"<br/>}

    Note over App,HSM: Secret 읽기
    App->>Vault: 8. GET /v1/secret/data/database/creds
    Vault->>Storage: 9. Retrieve encrypted secret
    Storage-->>Vault: 10. Encrypted data (v1)
    Vault->>HSM: 11. Decrypt with HSM master key
    HSM-->>Vault: 12. Plaintext data
    Vault-->>App: 13. {<br/>  data: {<br/>    username: "dbuser",<br/>    password: "secret123"<br/>  },<br/>  metadata: {version: 1}<br/>}

    Note over App,HSM: Secret 업데이트
    App->>Vault: 14. POST /v1/secret/data/database/creds<br/>{data: {password: "new_secret"}
    Vault->>HSM: 15. Encrypt new version
    HSM-->>Vault: 16. Encrypted data
    Vault->>Storage: 17. Store v2 (keep v1)
    Vault-->>App: 18. {version: 2}

    Note over App,HSM: Secret 버전 조회
    App->>Vault: 19. GET /v1/secret/data/database/creds<br/>?version=1
    Vault->>Storage: 20. Retrieve v1
    Vault->>HSM: 21. Decrypt v1
    Vault-->>App: 22. Old secret data (v1)
```

## 🔐 HSM 키 타입

| Algorithm | Key Size | Use Case | NIST Standard |
|-----------|----------|----------|---------------|
| DILITHIUM3 | Public: 1952B<br/>Private: 4000B<br/>Signature: 3293B | Digital Signature | FIPS 204 |
| KYBER1024 | Public: 1568B<br/>Private: 3168B<br/>Ciphertext: 1568B | Key Encapsulation | FIPS 203 |
| SPHINCS+ | Varies | Stateless Signature | FIPS 205 |

## 🏗️ Vault Storage Layout

```
/vault/data/
├── logical/
│   ├── pqc-keys/          # Transit Engine
│   │   ├── policy/
│   │   │   ├── keycloak-sign
│   │   │   └── data-encrypt
│   │   └── archive/       # Old key versions
│   └── secret/            # KV v2 Engine
│       └── database/
│           └── creds      # Encrypted secrets
└── sys/
    ├── policy/            # ACL Policies
    └── mounts/            # Engine mounts
```

## ⚙️ PKCS#11 메커니즘

```c
// DILITHIUM3 서명
CK_MECHANISM mechanism = {
    .mechanism = CKM_DILITHIUM3,
    .pParameter = NULL,
    .ulParameterLen = 0
};

// KYBER1024 암호화
CK_MECHANISM mechanism = {
    .mechanism = CKM_KYBER1024,
    .pParameter = NULL,
    .ulParameterLen = 0
};
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**HSM**: Luna K7 (FIPS 140-2 Level 3)
