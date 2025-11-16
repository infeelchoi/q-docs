# OQS 시퀀스 다이어그램

Open Quantum Safe (OQS) 주요 프로세스의 시퀀스 다이어그램 모음입니다.

## 목차

- [1. OQS 초기화 및 설정](#1-oqs-초기화-및-설정)
- [2. KYBER 키 교환](#2-kyber-키-교환)
- [3. DILITHIUM 서명/검증](#3-dilithium-서명검증)
- [4. Vault OQS Transit Engine 흐름](#4-vault-oqs-transit-engine-흐름)
- [5. Keycloak PQC 인증 흐름](#5-keycloak-pqc-인증-흐름)
- [6. APISIX TLS-PQC 핸드셰이크](#6-apisix-tls-pqc-핸드셰이크)
- [7. 인증서 발급 (OQS CA)](#7-인증서-발급-oqs-ca)
- [8. 키 순환 (Key Rotation)](#8-키-순환-key-rotation)
- [9. 에러 처리 시나리오](#9-에러-처리-시나리오)
- [10. 전체 시스템 통합 흐름](#10-전체-시스템-통합-흐름)

---

## 1. OQS 초기화 및 설정

### 1.1 시스템 부팅 시 OQS 초기화

```mermaid
sequenceDiagram
    participant System
    participant Init as Init Script
    participant LibOQS as liboqs
    participant Provider as oqs-provider
    participant OpenSSL

    Note over System,OpenSSL: 시스템 부팅 및 OQS 초기화

    System->>Init: 부팅 시작
    Init->>Init: /etc/profile.d/openssl-oqs.sh 로드

    Init->>Init: OPENSSL_CONF 설정<br/>/etc/ssl/openssl-oqs.cnf
    Init->>Init: OPENSSL_MODULES 설정<br/>/usr/local/lib64/ossl-modules

    Init->>OpenSSL: OpenSSL 초기화
    OpenSSL->>OpenSSL: openssl.cnf 파싱

    OpenSSL->>Provider: Provider 로드 요청<br/>(oqsprovider)
    Provider->>Provider: oqsprovider.so 로드
    Provider->>LibOQS: liboqs.so 의존성 확인

    LibOQS->>LibOQS: OQS_init()
    LibOQS->>LibOQS: 알고리즘 등록<br/>- KYBER<br/>- DILITHIUM<br/>- FALCON

    LibOQS-->>Provider: 초기화 완료
    Provider->>Provider: OSSL_provider_init() 실행

    Provider->>Provider: 알고리즘 테이블 생성<br/>- KEM algorithms<br/>- Signature algorithms

    Provider-->>OpenSSL: Provider 등록 완료

    OpenSSL->>OpenSSL: 기본 Provider 로드<br/>(default, legacy)

    OpenSSL-->>Init: 초기화 완료

    Init->>Init: 검증 테스트
    Init->>OpenSSL: openssl list -providers
    OpenSSL-->>Init: Provider 목록 반환<br/>- default<br/>- oqsprovider

    Init->>OpenSSL: 알고리즘 목록 조회
    OpenSSL->>Provider: 지원 알고리즘 요청
    Provider-->>OpenSSL: DILITHIUM, FALCON, KYBER 등
    OpenSSL-->>Init: 알고리즘 목록

    Init-->>System: OQS 초기화 성공

    Note over System,OpenSSL: 시스템 준비 완료
```

### 1.2 애플리케이션 OQS 설정

```mermaid
sequenceDiagram
    participant App as Application
    participant Config as Configuration
    participant OpenSSL
    participant Provider as oqs-provider
    participant LibOQS

    Note over App,LibOQS: 애플리케이션 시작 및 OQS 설정

    App->>App: 애플리케이션 시작

    App->>Config: 설정 파일 로드<br/>(app.conf)
    Config-->>App: PQC 설정<br/>- algorithm: dilithium3<br/>- kem: kyber768

    App->>OpenSSL: SSL_CTX_new()
    OpenSSL-->>App: SSL Context 생성

    App->>OpenSSL: SSL_CTX_load_verify_locations()<br/>(CA 인증서)
    OpenSSL->>OpenSSL: CA 인증서 로드 및 검증
    OpenSSL-->>App: 성공

    App->>OpenSSL: SSL_CTX_use_certificate_file()<br/>(PQC 인증서)
    OpenSSL->>Provider: 인증서 파싱 요청
    Provider->>LibOQS: 서명 알고리즘 확인<br/>(DILITHIUM3)
    LibOQS-->>Provider: 알고리즘 정보
    Provider-->>OpenSSL: 인증서 정보
    OpenSSL-->>App: 성공

    App->>OpenSSL: SSL_CTX_use_PrivateKey_file()<br/>(개인키)
    OpenSSL->>Provider: 개인키 파싱
    Provider->>LibOQS: 키 형식 확인
    LibOQS-->>Provider: DILITHIUM3 개인키
    Provider-->>OpenSSL: 키 정보
    OpenSSL-->>App: 성공

    App->>OpenSSL: SSL_CTX_set1_groups_list()<br/>("kyber768:X25519")
    OpenSSL->>Provider: 그룹 설정
    Provider->>LibOQS: KYBER768 지원 확인
    LibOQS-->>Provider: 지원됨
    Provider-->>OpenSSL: 설정 완료
    OpenSSL-->>App: 성공

    App->>OpenSSL: SSL_CTX_set_min_proto_version()<br/>(TLS1_3_VERSION)
    OpenSSL-->>App: 성공

    App->>App: 준비 완료

    Note over App,LibOQS: 애플리케이션이 PQC를 사용할 준비됨
```

---

## 2. KYBER 키 교환

### 2.1 KYBER768 KEM 프로세스

```mermaid
sequenceDiagram
    participant Alice
    participant LibOQS_A as liboqs (Alice)
    participant LibOQS_B as liboqs (Bob)
    participant Bob

    Note over Alice,Bob: KYBER768 키 교환 메커니즘

    Alice->>LibOQS_A: OQS_KEM_new("Kyber768")
    LibOQS_A-->>Alice: kem 객체

    Note over Alice,LibOQS_A: Bob의 키 생성

    Bob->>LibOQS_B: OQS_KEM_new("Kyber768")
    LibOQS_B-->>Bob: kem 객체

    Bob->>LibOQS_B: OQS_KEM_keypair(public_key, secret_key)
    LibOQS_B->>LibOQS_B: 무작위 시드 생성
    LibOQS_B->>LibOQS_B: KYBER768.KeyGen()<br/>- pk: 1184 bytes<br/>- sk: 2400 bytes
    LibOQS_B-->>Bob: 키 쌍 생성 완료

    Bob->>Alice: public_key 전송 (1184 bytes)

    Note over Alice,Bob: Alice의 캡슐화

    Alice->>LibOQS_A: OQS_KEM_encaps(ciphertext, shared_secret, public_key)
    LibOQS_A->>LibOQS_A: 무작위 메시지 m 생성
    LibOQS_A->>LibOQS_A: KYBER768.Encaps(pk, m)<br/>- ct: 1088 bytes<br/>- ss: 32 bytes
    LibOQS_A-->>Alice: ciphertext, shared_secret

    Alice->>Bob: ciphertext 전송 (1088 bytes)

    Note over Alice,Bob: Bob의 역캡슐화

    Bob->>LibOQS_B: OQS_KEM_decaps(shared_secret, ciphertext, secret_key)
    LibOQS_B->>LibOQS_B: KYBER768.Decaps(sk, ct)
    LibOQS_B->>LibOQS_B: 복구된 메시지 m
    LibOQS_B->>LibOQS_B: 공유 비밀 재생성<br/>ss = KDF(m)
    LibOQS_B-->>Bob: shared_secret (32 bytes)

    Note over Alice,Bob: 양측 모두 동일한 shared_secret 보유

    Alice->>Alice: shared_secret_A = 0x1234...
    Bob->>Bob: shared_secret_B = 0x1234...

    Note over Alice,Bob: 검증: shared_secret_A == shared_secret_B

    Alice->>LibOQS_A: OQS_KEM_free(kem)
    Bob->>LibOQS_B: OQS_KEM_free(kem)

    Note over Alice,Bob: 키 교환 완료<br/>이제 shared_secret으로 대칭 키 암호화 가능
```

### 2.2 하이브리드 KEM (X25519 + KYBER768)

```mermaid
sequenceDiagram
    participant Client
    participant Classical as X25519
    participant PQC as KYBER768
    participant Server

    Note over Client,Server: 하이브리드 키 교환

    par 고전 키 교환
        Client->>Classical: X25519 키 쌍 생성
        Classical-->>Client: x25519_private, x25519_public (32 bytes)

        Server->>Classical: X25519 키 쌍 생성
        Classical-->>Server: x25519_private, x25519_public (32 bytes)

        Client->>Server: x25519_public (Client)
        Server->>Client: x25519_public (Server)

        Client->>Classical: ECDH(x25519_private_C, x25519_public_S)
        Classical-->>Client: shared_secret_classical (32 bytes)

        Server->>Classical: ECDH(x25519_private_S, x25519_public_C)
        Classical-->>Server: shared_secret_classical (32 bytes)
    and PQC 키 교환
        Server->>PQC: KYBER768.KeyGen()
        PQC-->>Server: kyber_pk (1184 bytes), kyber_sk (2400 bytes)

        Server->>Client: kyber_pk

        Client->>PQC: KYBER768.Encaps(kyber_pk)
        PQC-->>Client: ciphertext (1088 bytes), shared_secret_pqc (32 bytes)

        Client->>Server: ciphertext

        Server->>PQC: KYBER768.Decaps(kyber_sk, ciphertext)
        PQC-->>Server: shared_secret_pqc (32 bytes)
    end

    Note over Client,Server: 공유 비밀 결합

    Client->>Client: combined_secret = KDF(<br/>  shared_secret_classical ||<br/>  shared_secret_pqc<br/>)
    Server->>Server: combined_secret = KDF(<br/>  shared_secret_classical ||<br/>  shared_secret_pqc<br/>)

    Note over Client,Server: 최종 세션 키 생성

    Client->>Client: session_key = HKDF(combined_secret, ...)
    Server->>Server: session_key = HKDF(combined_secret, ...)

    Note over Client,Server: 하이브리드 키 교환 완료<br/>고전 + PQC 이중 보호
```

---

## 3. DILITHIUM 서명/검증

### 3.1 DILITHIUM3 서명 생성 및 검증

```mermaid
sequenceDiagram
    participant Signer
    participant LibOQS_S as liboqs (Signer)
    participant Verifier
    participant LibOQS_V as liboqs (Verifier)

    Note over Signer,LibOQS_V: DILITHIUM3 디지털 서명

    Signer->>LibOQS_S: OQS_SIG_new("Dilithium3")
    LibOQS_S-->>Signer: sig 객체

    Note over Signer,LibOQS_S: 키 생성

    Signer->>LibOQS_S: OQS_SIG_keypair(public_key, secret_key)
    LibOQS_S->>LibOQS_S: 무작위 시드 ξ 생성
    LibOQS_S->>LibOQS_S: DILITHIUM3.KeyGen(ξ)<br/>- pk: 1952 bytes<br/>- sk: 4000 bytes
    LibOQS_S-->>Signer: 키 쌍 생성 완료

    Signer->>Verifier: public_key 배포 (1952 bytes)

    Note over Signer,LibOQS_S: 메시지 서명

    Signer->>Signer: 서명할 메시지 M 준비

    Signer->>LibOQS_S: OQS_SIG_sign(signature, signature_len,<br/>  message, message_len, secret_key)

    LibOQS_S->>LibOQS_S: 무작위 값 y 생성
    LibOQS_S->>LibOQS_S: w = Ay (mod q)
    LibOQS_S->>LibOQS_S: c = H(M || w)  # 해시
    LibOQS_S->>LibOQS_S: z = y + c·s  # s는 비밀키
    LibOQS_S->>LibOQS_S: 서명 σ = (c, z)<br/>크기: 3293 bytes

    LibOQS_S-->>Signer: signature (3293 bytes)

    Signer->>Verifier: (message, signature) 전송

    Note over Verifier,LibOQS_V: 서명 검증

    Verifier->>LibOQS_V: OQS_SIG_new("Dilithium3")
    LibOQS_V-->>Verifier: sig 객체

    Verifier->>LibOQS_V: OQS_SIG_verify(message, message_len,<br/>  signature, signature_len, public_key)

    LibOQS_V->>LibOQS_V: 서명 파싱: (c, z)
    LibOQS_V->>LibOQS_V: w' = Az - c·t  # t는 공개키
    LibOQS_V->>LibOQS_V: c' = H(M || w')
    LibOQS_V->>LibOQS_V: c == c' 확인

    alt 서명 유효
        LibOQS_V-->>Verifier: OQS_SUCCESS (검증 성공)
        Verifier->>Verifier: 메시지 신뢰
    else 서명 무효
        LibOQS_V-->>Verifier: OQS_ERROR (검증 실패)
        Verifier->>Verifier: 메시지 거부
    end

    Signer->>LibOQS_S: OQS_SIG_free(sig)
    Verifier->>LibOQS_V: OQS_SIG_free(sig)

    Note over Signer,LibOQS_V: 서명/검증 완료
```

### 3.2 OpenSSL을 통한 DILITHIUM 서명

```mermaid
sequenceDiagram
    participant App
    participant OpenSSL
    participant Provider as oqs-provider
    participant LibOQS

    Note over App,LibOQS: OpenSSL EVP API를 통한 DILITHIUM 서명

    App->>OpenSSL: EVP_PKEY_CTX_new_from_name(<br/>  NULL, "dilithium3", "provider=oqsprovider")
    OpenSSL->>Provider: 알고리즘 "dilithium3" 조회
    Provider->>Provider: oqs_signature_algorithms 테이블 검색
    Provider-->>OpenSSL: dilithium3_signature_functions
    OpenSSL-->>App: ctx (EVP_PKEY_CTX)

    Note over App,OpenSSL: 키 생성

    App->>OpenSSL: EVP_PKEY_keygen_init(ctx)
    OpenSSL->>Provider: keygen_init 호출
    Provider-->>OpenSSL: 초기화 완료
    OpenSSL-->>App: 성공

    App->>OpenSSL: EVP_PKEY_keygen(ctx, &pkey)
    OpenSSL->>Provider: keygen 호출
    Provider->>LibOQS: OQS_SIG_new("Dilithium3")
    LibOQS-->>Provider: sig 객체
    Provider->>LibOQS: OQS_SIG_keypair(pk, sk)
    LibOQS->>LibOQS: DILITHIUM3 키 생성
    LibOQS-->>Provider: public_key, secret_key
    Provider->>Provider: EVP_PKEY 객체에 키 저장
    Provider-->>OpenSSL: pkey
    OpenSSL-->>App: 성공

    Note over App,OpenSSL: 서명 생성

    App->>OpenSSL: EVP_MD_CTX_new()
    OpenSSL-->>App: md_ctx

    App->>OpenSSL: EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey)
    OpenSSL->>Provider: sign_init 호출
    Provider->>Provider: 서명 컨텍스트 초기화
    Provider-->>OpenSSL: 성공
    OpenSSL-->>App: 성공

    App->>OpenSSL: EVP_DigestSign(md_ctx, NULL, &sig_len,<br/>  message, message_len)
    OpenSSL->>Provider: 서명 크기 조회
    Provider->>LibOQS: length_signature 조회
    LibOQS-->>Provider: 3293 bytes
    Provider-->>OpenSSL: sig_len = 3293
    OpenSSL-->>App: sig_len = 3293

    App->>App: signature = malloc(sig_len)

    App->>OpenSSL: EVP_DigestSign(md_ctx, signature, &sig_len,<br/>  message, message_len)
    OpenSSL->>Provider: sign 호출
    Provider->>LibOQS: OQS_SIG_sign(sig, &actual_len,<br/>  message, message_len, secret_key)
    LibOQS->>LibOQS: DILITHIUM3.Sign() 실행
    LibOQS-->>Provider: signature
    Provider-->>OpenSSL: signature
    OpenSSL-->>App: 성공

    Note over App,OpenSSL: 서명 검증

    App->>OpenSSL: EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey)
    OpenSSL->>Provider: verify_init 호출
    Provider-->>OpenSSL: 성공
    OpenSSL-->>App: 성공

    App->>OpenSSL: EVP_DigestVerify(md_ctx, signature, sig_len,<br/>  message, message_len)
    OpenSSL->>Provider: verify 호출
    Provider->>LibOQS: OQS_SIG_verify(message, message_len,<br/>  signature, sig_len, public_key)
    LibOQS->>LibOQS: DILITHIUM3.Verify() 실행

    alt 검증 성공
        LibOQS-->>Provider: OQS_SUCCESS
        Provider-->>OpenSSL: 1 (성공)
        OpenSSL-->>App: 1 (성공)
        App->>App: 서명 유효
    else 검증 실패
        LibOQS-->>Provider: OQS_ERROR
        Provider-->>OpenSSL: 0 (실패)
        OpenSSL-->>App: 0 (실패)
        App->>App: 서명 무효
    end

    App->>OpenSSL: EVP_MD_CTX_free(md_ctx)
    App->>OpenSSL: EVP_PKEY_free(pkey)
    App->>OpenSSL: EVP_PKEY_CTX_free(ctx)

    Note over App,LibOQS: 서명/검증 완료
```

---

## 4. Vault OQS Transit Engine 흐름

### 4.1 Transit Engine 암호화/복호화

```mermaid
sequenceDiagram
    participant Client
    participant Vault as Vault API
    participant Transit as Transit Engine<br/>(OQS Plugin)
    participant Storage
    participant LibOQS

    Note over Client,LibOQS: Vault OQS Transit Engine 데이터 암호화

    Client->>Vault: POST /v1/oqs-transit/keys/my-key<br/>{"type": "kyber768"}
    Vault->>Transit: 키 생성 요청

    Transit->>LibOQS: OQS_KEM_new("Kyber768")
    LibOQS-->>Transit: kem 객체

    Transit->>LibOQS: OQS_KEM_keypair(pk, sk)
    LibOQS->>LibOQS: KYBER768.KeyGen()
    LibOQS-->>Transit: public_key, secret_key

    Transit->>Storage: 키 저장 요청
    Storage->>Storage: Encrypt secret_key (master key)
    Storage-->>Transit: 저장 완료

    Transit-->>Vault: 키 생성 완료<br/>{"name": "my-key", "version": 1}
    Vault-->>Client: 200 OK

    Note over Client,LibOQS: 데이터 암호화

    Client->>Vault: POST /v1/oqs-transit/encrypt/my-key<br/>{"plaintext": "base64(data)"}
    Vault->>Transit: 암호화 요청

    Transit->>Storage: 키 조회
    Storage->>Storage: Decrypt secret_key
    Storage-->>Transit: public_key, secret_key

    Transit->>LibOQS: OQS_KEM_encaps(ct, ss, public_key)
    LibOQS->>LibOQS: KYBER768.Encaps()<br/>무작위 메시지 m 생성
    LibOQS-->>Transit: ciphertext (1088 bytes)<br/>shared_secret (32 bytes)

    Transit->>Transit: AES-256-GCM 초기화<br/>key = shared_secret

    Transit->>Transit: encrypted_data = AES_GCM_encrypt(<br/>  plaintext, shared_secret, nonce)

    Transit->>Transit: result = {<br/>  "ciphertext": base64(ct),<br/>  "encrypted_data": base64(encrypted_data),<br/>  "nonce": base64(nonce),<br/>  "version": 1<br/>}

    Transit-->>Vault: 암호화 완료
    Vault-->>Client: 200 OK<br/>{"ciphertext": "vault:v1:..."}

    Note over Client,LibOQS: 데이터 복호화

    Client->>Vault: POST /v1/oqs-transit/decrypt/my-key<br/>{"ciphertext": "vault:v1:..."}
    Vault->>Transit: 복호화 요청

    Transit->>Transit: ciphertext 파싱<br/>(ct, encrypted_data, nonce)

    Transit->>Storage: 키 조회
    Storage-->>Transit: secret_key

    Transit->>LibOQS: OQS_KEM_decaps(ss, ct, secret_key)
    LibOQS->>LibOQS: KYBER768.Decaps()
    LibOQS-->>Transit: shared_secret (32 bytes)

    Transit->>Transit: plaintext = AES_GCM_decrypt(<br/>  encrypted_data, shared_secret, nonce)

    alt 복호화 성공
        Transit-->>Vault: {"plaintext": "base64(data)"}
        Vault-->>Client: 200 OK
    else 복호화 실패
        Transit-->>Vault: Error: 복호화 실패
        Vault-->>Client: 400 Bad Request
    end

    Note over Client,LibOQS: 암호화/복호화 완료
```

### 4.2 Vault PKI Engine 인증서 발급

```mermaid
sequenceDiagram
    participant Client
    participant Vault
    participant PKI as PKI Engine<br/>(OQS Plugin)
    participant Storage
    participant LibOQS

    Note over Client,LibOQS: OQS PKI Engine - DILITHIUM3 인증서 발급

    Client->>Vault: POST /v1/oqs-pki/root/generate/internal<br/>{"common_name": "Root CA",<br/> "algorithm": "dilithium3"}
    Vault->>PKI: Root CA 생성 요청

    PKI->>LibOQS: OQS_SIG_new("Dilithium3")
    LibOQS-->>PKI: sig 객체

    PKI->>LibOQS: OQS_SIG_keypair(pk, sk)
    LibOQS->>LibOQS: DILITHIUM3.KeyGen()
    LibOQS-->>PKI: public_key (1952 bytes)<br/>secret_key (4000 bytes)

    PKI->>PKI: X.509 인증서 구성<br/>- Subject: CN=Root CA<br/>- Public Key: DILITHIUM3<br/>- Extensions: CA:TRUE

    PKI->>LibOQS: OQS_SIG_sign(cert_tbs, sk)
    LibOQS->>LibOQS: DILITHIUM3.Sign()
    LibOQS-->>PKI: signature (3293 bytes)

    PKI->>PKI: 인증서 완성<br/>cert = TBS || signature

    PKI->>Storage: CA 인증서 및 키 저장
    Storage->>Storage: secret_key 암호화
    Storage-->>PKI: 저장 완료

    PKI-->>Vault: Root CA 생성 완료
    Vault-->>Client: 200 OK<br/>{"certificate": "-----BEGIN CERTIFICATE-----"}

    Note over Client,LibOQS: End Entity 인증서 발급

    Client->>Vault: POST /v1/oqs-pki/issue/server-role<br/>{"common_name": "server.example.com",<br/> "alt_names": "*.example.com"}
    Vault->>PKI: 인증서 발급 요청

    PKI->>PKI: Role 정책 확인<br/>(TTL, 용도 등)

    PKI->>LibOQS: OQS_SIG_new("Dilithium3")
    LibOQS-->>PKI: sig 객체

    PKI->>LibOQS: OQS_SIG_keypair(pk, sk)
    LibOQS-->>PKI: public_key, secret_key

    PKI->>PKI: CSR 생성 (내부)<br/>- Subject: CN=server.example.com<br/>- Public Key: DILITHIUM3<br/>- Extensions: serverAuth

    PKI->>Storage: CA 키 조회
    Storage-->>PKI: ca_secret_key

    PKI->>PKI: X.509 인증서 구성<br/>- Issuer: Root CA<br/>- Subject: CN=server.example.com<br/>- Validity: 365 days

    PKI->>LibOQS: OQS_SIG_sign(cert_tbs, ca_secret_key)
    LibOQS->>LibOQS: DILITHIUM3.Sign()
    LibOQS-->>PKI: signature

    PKI->>PKI: 인증서 완성

    PKI->>Storage: 인증서 일련번호 기록
    Storage-->>PKI: 완료

    PKI-->>Vault: 인증서 발급 완료
    Vault-->>Client: 200 OK<br/>{<br/>  "certificate": "...",<br/>  "private_key": "...",<br/>  "issuing_ca": "...",<br/>  "serial_number": "..."<br/>}

    Note over Client,LibOQS: 인증서 발급 완료
```

---

## 5. Keycloak PQC 인증 흐름

### 5.1 OIDC 토큰 발급 (DILITHIUM 서명)

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant Keycloak
    participant OQS_SPI as OQS Signature SPI
    participant Vault
    participant LibOQS

    Note over User,LibOQS: Keycloak OIDC 인증 - PQC 토큰 서명

    User->>Browser: 로그인 시도

    Browser->>Keycloak: GET /auth/realms/qsign/protocol/openid-connect/auth

    Keycloak-->>Browser: 로그인 페이지

    Browser-->>User: 로그인 폼 표시

    User->>Browser: username/password 입력

    Browser->>Keycloak: POST /auth/realms/qsign/login-actions/authenticate

    Keycloak->>Keycloak: 인증 확인 (DB)

    alt 인증 성공
        Keycloak->>Keycloak: 사용자 세션 생성

        Keycloak->>Keycloak: JWT Claims 구성<br/>{<br/>  "sub": "user-id",<br/>  "iss": "keycloak",<br/>  "exp": timestamp,<br/>  "roles": [...]<br/>}

        Keycloak->>OQS_SPI: 토큰 서명 요청<br/>sign(claims, algorithm="dilithium3")

        OQS_SPI->>Vault: Vault에서 서명 키 조회<br/>GET /v1/transit/keys/keycloak-signing-dilithium3
        Vault-->>OQS_SPI: secret_key (또는 로컬 캐시)

        OQS_SPI->>LibOQS: OQS_SIG_new("Dilithium3")
        LibOQS-->>OQS_SPI: sig 객체

        OQS_SPI->>OQS_SPI: 서명 데이터 준비<br/>signing_input = header + "." + payload

        OQS_SPI->>LibOQS: OQS_SIG_sign(signing_input, secret_key)
        LibOQS->>LibOQS: DILITHIUM3.Sign()
        LibOQS-->>OQS_SPI: signature (3293 bytes)

        OQS_SPI->>OQS_SPI: signature_b64 = base64url(signature)

        OQS_SPI->>OQS_SPI: token = header.payload.signature_b64

        OQS_SPI-->>Keycloak: signed_token

        Keycloak->>Keycloak: Authorization Code 생성

        Keycloak-->>Browser: 302 Redirect<br/>Location: callback?code=...

        Browser->>Keycloak: GET /callback?code=...

        Browser->>Keycloak: POST /token<br/>grant_type=authorization_code&code=...

        Keycloak->>Keycloak: Code 검증

        Keycloak->>OQS_SPI: Access Token 서명 요청

        OQS_SPI->>LibOQS: OQS_SIG_sign(access_token_claims, sk)
        LibOQS-->>OQS_SPI: signature
        OQS_SPI-->>Keycloak: access_token (DILITHIUM3 서명)

        Keycloak->>OQS_SPI: ID Token 서명 요청

        OQS_SPI->>LibOQS: OQS_SIG_sign(id_token_claims, sk)
        LibOQS-->>OQS_SPI: signature
        OQS_SPI-->>Keycloak: id_token (DILITHIUM3 서명)

        Keycloak-->>Browser: 200 OK<br/>{<br/>  "access_token": "eyJ...",<br/>  "id_token": "eyJ...",<br/>  "refresh_token": "...",<br/>  "token_type": "Bearer"<br/>}

        Browser-->>User: 로그인 성공

    else 인증 실패
        Keycloak-->>Browser: 401 Unauthorized
        Browser-->>User: 로그인 실패
    end

    Note over User,LibOQS: OIDC 인증 완료 (PQC 서명 토큰)
```

### 5.2 토큰 검증

```mermaid
sequenceDiagram
    participant Client
    participant API as API Server
    participant Keycloak
    participant OQS_SPI
    participant LibOQS

    Note over Client,LibOQS: PQC 서명 토큰 검증

    Client->>API: GET /api/resource<br/>Authorization: Bearer eyJ...

    API->>API: 토큰 추출

    API->>API: 토큰 파싱<br/>header.payload.signature

    API->>Keycloak: GET /.well-known/openid-configuration
    Keycloak-->>API: {<br/>  "jwks_uri": "/certs",<br/>  "..."<br/>}

    API->>Keycloak: GET /certs (JWKS)
    Keycloak->>Keycloak: 공개키 조회 (kid)

    Keycloak->>OQS_SPI: 공개키 요청 (DILITHIUM3)
    OQS_SPI->>OQS_SPI: 캐시 또는 Vault에서 조회
    OQS_SPI-->>Keycloak: public_key (1952 bytes)

    Keycloak->>Keycloak: JWKS 형식으로 변환<br/>{<br/>  "kty": "OQS",<br/>  "alg": "DILITHIUM3",<br/>  "kid": "...",<br/>  "x": "base64(public_key)"<br/>}

    Keycloak-->>API: JWKS

    API->>API: 토큰 header의 kid와 매칭

    API->>OQS_SPI: 서명 검증 요청<br/>verify(signing_input, signature, public_key)

    OQS_SPI->>LibOQS: OQS_SIG_new("Dilithium3")
    LibOQS-->>OQS_SPI: sig 객체

    OQS_SPI->>OQS_SPI: signature_bytes = base64url_decode(signature)

    OQS_SPI->>LibOQS: OQS_SIG_verify(signing_input, signature_bytes, public_key)
    LibOQS->>LibOQS: DILITHIUM3.Verify()

    alt 서명 유효
        LibOQS-->>OQS_SPI: OQS_SUCCESS
        OQS_SPI-->>API: 검증 성공

        API->>API: Claims 검증<br/>- exp 확인<br/>- iss 확인<br/>- aud 확인

        alt Claims 유효
            API->>API: 요청 처리
            API-->>Client: 200 OK<br/>{"data": "..."}
        else Claims 무효
            API-->>Client: 401 Unauthorized<br/>{"error": "token_expired"}
        end

    else 서명 무효
        LibOQS-->>OQS_SPI: OQS_ERROR
        OQS_SPI-->>API: 검증 실패
        API-->>Client: 401 Unauthorized<br/>{"error": "invalid_signature"}
    end

    Note over Client,LibOQS: 토큰 검증 완료
```

---

## 6. APISIX TLS-PQC 핸드셰이크

### 6.1 TLS 1.3 with KYBER768

```mermaid
sequenceDiagram
    participant Client
    participant APISIX
    participant OQS_Provider as oqs-provider
    participant LibOQS
    participant Upstream

    Note over Client,Upstream: TLS 1.3 핸드셰이크 (KYBER768 KEM)

    Client->>APISIX: ClientHello<br/>- TLS 1.3<br/>- supported_groups: x25519_kyber768, kyber768<br/>- signature_algorithms: ecdsa_p256_dilithium3

    APISIX->>APISIX: ClientHello 파싱

    APISIX->>OQS_Provider: 지원 그룹 확인
    OQS_Provider->>LibOQS: KYBER768 지원 여부
    LibOQS-->>OQS_Provider: 지원됨
    OQS_Provider-->>APISIX: x25519_kyber768 선택

    APISIX->>OQS_Provider: 서버 키 쌍 생성 (KYBER768)
    OQS_Provider->>LibOQS: OQS_KEM_keypair(kyber768)
    LibOQS->>LibOQS: KYBER768.KeyGen()
    LibOQS-->>OQS_Provider: server_pk (1184 bytes), server_sk (2400 bytes)
    OQS_Provider-->>APISIX: server_keypair

    APISIX->>APISIX: 서버 인증서 로드<br/>(DILITHIUM3 서명)

    APISIX->>Client: ServerHello<br/>- selected_group: x25519_kyber768<br/>- key_share: server_pk<br/><br/>EncryptedExtensions<br/>Certificate (DILITHIUM3)<br/>CertificateVerify (DILITHIUM3)<br/>Finished

    Note over Client,APISIX: 클라이언트: 공유 비밀 생성

    Client->>Client: 서버 인증서 파싱

    Client->>Client: DILITHIUM3 서명 검증
    Client->>Client: 인증서 체인 검증
    Client->>Client: ✓ 서버 인증 완료

    Client->>Client: KYBER768 Encapsulation
    Client->>Client: OQS_KEM_encaps(server_pk)
    Client->>Client: → ciphertext (1088 bytes)<br/>→ client_shared_secret (32 bytes)

    Client->>APISIX: ClientKeyExchange<br/>ciphertext

    Note over APISIX,LibOQS: 서버: 공유 비밀 복원

    APISIX->>OQS_Provider: KEM Decapsulation
    OQS_Provider->>LibOQS: OQS_KEM_decaps(ciphertext, server_sk)
    LibOQS->>LibOQS: KYBER768.Decaps()
    LibOQS-->>OQS_Provider: server_shared_secret (32 bytes)
    OQS_Provider-->>APISIX: shared_secret

    APISIX->>APISIX: shared_secret 검증<br/>(client == server)

    Note over Client,APISIX: 세션 키 생성

    Client->>Client: master_secret = HKDF(<br/>  shared_secret,<br/>  client_random,<br/>  server_random<br/>)

    APISIX->>APISIX: master_secret = HKDF(<br/>  shared_secret,<br/>  client_random,<br/>  server_random<br/>)

    Client->>APISIX: Finished (암호화됨)

    APISIX->>APISIX: Finished 검증

    APISIX->>Client: NewSessionTicket<br/>(세션 재개용)

    Note over Client,APISIX: TLS 핸드셰이크 완료<br/>암호화된 통신 시작

    Client->>APISIX: Application Data (암호화)<br/>GET /api/resource

    APISIX->>APISIX: 복호화

    APISIX->>APISIX: mTLS 검증 (클라이언트 인증서)<br/>Route 매칭<br/>Rate Limiting

    APISIX->>Upstream: Proxied Request<br/>(mTLS + DILITHIUM3)

    Upstream-->>APISIX: Response

    APISIX->>APISIX: 암호화

    APISIX-->>Client: Application Data (암호화)

    Client->>Client: 복호화

    Note over Client,Upstream: 요청 처리 완료
```

---

## 7. 인증서 발급 (OQS CA)

### 7.1 계층적 CA 구조

```mermaid
sequenceDiagram
    participant Admin
    participant Script
    participant OpenSSL
    participant OQS_Provider
    participant LibOQS
    participant Storage

    Note over Admin,Storage: OQS CA 계층 구조 생성

    Admin->>Script: ./create-oqs-ca.sh

    Note over Script,LibOQS: 1. Root CA 생성

    Script->>OpenSSL: genpkey -algorithm dilithium5
    OpenSSL->>OQS_Provider: 키 생성 요청
    OQS_Provider->>LibOQS: OQS_SIG_keypair(DILITHIUM5)
    LibOQS-->>OQS_Provider: pk (2592 bytes), sk (4864 bytes)
    OQS_Provider-->>OpenSSL: keypair
    OpenSSL-->>Script: root-ca.key 생성

    Script->>OpenSSL: req -x509 -new<br/>-subj "/CN=Root CA"<br/>-days 3650
    OpenSSL->>OQS_Provider: 자체 서명 인증서 생성
    OQS_Provider->>LibOQS: OQS_SIG_sign(cert_tbs, sk)
    LibOQS-->>OQS_Provider: signature (4595 bytes)
    OQS_Provider-->>OpenSSL: signed_cert
    OpenSSL-->>Script: root-ca.crt 생성

    Script->>Storage: root-ca.key → /etc/pki/qsign/private/<br/>root-ca.crt → /etc/pki/qsign/certs/
    Storage-->>Script: 저장 완료

    Note over Script,LibOQS: 2. Intermediate CA 생성

    Script->>OpenSSL: genpkey -algorithm dilithium3
    OpenSSL->>OQS_Provider: 키 생성
    OQS_Provider->>LibOQS: OQS_SIG_keypair(DILITHIUM3)
    LibOQS-->>OQS_Provider: pk, sk
    OQS_Provider-->>OpenSSL: keypair
    OpenSSL-->>Script: intermediate-ca.key

    Script->>OpenSSL: req -new<br/>-subj "/CN=Intermediate CA"
    OpenSSL-->>Script: intermediate-ca.csr

    Script->>OpenSSL: x509 -req<br/>-CA root-ca.crt<br/>-CAkey root-ca.key<br/>-extensions v3_intermediate_ca
    OpenSSL->>OQS_Provider: Root CA로 서명
    OQS_Provider->>LibOQS: OQS_SIG_sign(csr_tbs, root_sk)
    LibOQS-->>OQS_Provider: signature
    OQS_Provider-->>OpenSSL: signed_cert
    OpenSSL-->>Script: intermediate-ca.crt

    Script->>Storage: intermediate-ca.key, intermediate-ca.crt 저장
    Storage-->>Script: 완료

    Note over Script,LibOQS: 3. End Entity 인증서 발급

    Script->>OpenSSL: genpkey -algorithm dilithium3
    OpenSSL->>OQS_Provider: 키 생성
    OQS_Provider->>LibOQS: OQS_SIG_keypair(DILITHIUM3)
    LibOQS-->>OQS_Provider: pk, sk
    OpenSSL-->>Script: server.key

    Script->>OpenSSL: req -new<br/>-subj "/CN=server.example.com"
    OpenSSL-->>Script: server.csr

    Script->>OpenSSL: x509 -req<br/>-CA intermediate-ca.crt<br/>-CAkey intermediate-ca.key<br/>-extensions server_cert<br/>-extfile san.cnf
    OpenSSL->>OQS_Provider: Intermediate CA로 서명
    OQS_Provider->>LibOQS: OQS_SIG_sign(csr_tbs, int_sk)
    LibOQS-->>OQS_Provider: signature
    OpenSSL-->>Script: server.crt

    Script->>Storage: server.key, server.crt 저장
    Storage-->>Script: 완료

    Note over Script,Storage: 4. 인증서 체인 생성

    Script->>Script: cat server.crt intermediate-ca.crt > server-chain.crt

    Script->>Storage: server-chain.crt 저장

    Note over Script,Storage: 5. 검증

    Script->>OpenSSL: verify -CAfile root-ca.crt<br/>-untrusted intermediate-ca.crt<br/>server.crt
    OpenSSL->>OQS_Provider: 인증서 체인 검증
    OQS_Provider->>LibOQS: OQS_SIG_verify (각 인증서)
    LibOQS-->>OQS_Provider: ✓ 유효
    OQS_Provider-->>OpenSSL: 체인 유효
    OpenSSL-->>Script: server.crt: OK

    Script-->>Admin: CA 계층 구조 생성 완료<br/>- Root CA (DILITHIUM5)<br/>- Intermediate CA (DILITHIUM3)<br/>- Server Cert (DILITHIUM3)

    Note over Admin,Storage: OQS CA 준비 완료
```

---

## 8. 키 순환 (Key Rotation)

### 8.1 Vault Transit Key Rotation

```mermaid
sequenceDiagram
    participant Admin
    participant Vault
    participant Transit
    participant Storage
    participant LibOQS
    participant Clients

    Note over Admin,Clients: Vault Transit 키 순환

    Admin->>Vault: POST /v1/oqs-transit/keys/my-key/rotate
    Vault->>Transit: 키 순환 요청

    Transit->>Storage: 현재 키 조회
    Storage-->>Transit: current_key (version: 1)

    Transit->>LibOQS: 새 키 쌍 생성 (KYBER768)
    LibOQS->>LibOQS: OQS_KEM_keypair()
    LibOQS-->>Transit: new_pk, new_sk

    Transit->>Transit: 키 버전 증가<br/>version: 1 → 2

    Transit->>Storage: 새 키 저장<br/>version: 2<br/>latest: true
    Storage-->>Transit: 저장 완료

    Transit->>Transit: 이전 키 유지<br/>version: 1<br/>latest: false

    Transit-->>Vault: 키 순환 완료
    Vault-->>Admin: 200 OK<br/>{"version": 2}

    Note over Admin,Clients: 새로운 암호화는 v2 키 사용

    Clients->>Vault: POST /v1/oqs-transit/encrypt/my-key<br/>{"plaintext": "..."}
    Vault->>Transit: 암호화 요청

    Transit->>Storage: 최신 키 조회
    Storage-->>Transit: key (version: 2)

    Transit->>LibOQS: OQS_KEM_encaps(pk_v2)
    LibOQS-->>Transit: ct, ss

    Transit->>Transit: 데이터 암호화

    Transit-->>Vault: ciphertext (v2)
    Vault-->>Clients: {"ciphertext": "vault:v2:..."}

    Note over Admin,Clients: 기존 데이터 복호화는 v1 키 사용

    Clients->>Vault: POST /v1/oqs-transit/decrypt/my-key<br/>{"ciphertext": "vault:v1:..."}
    Vault->>Transit: 복호화 요청

    Transit->>Transit: 버전 파싱: v1

    Transit->>Storage: v1 키 조회
    Storage-->>Transit: key (version: 1)

    Transit->>LibOQS: OQS_KEM_decaps(ct, sk_v1)
    LibOQS-->>Transit: ss

    Transit->>Transit: 데이터 복호화

    Transit-->>Vault: plaintext
    Vault-->>Clients: {"plaintext": "..."}

    Note over Admin,Clients: 데이터 재암호화 (rewrap)

    Clients->>Vault: POST /v1/oqs-transit/rewrap/my-key<br/>{"ciphertext": "vault:v1:..."}
    Vault->>Transit: rewrap 요청

    Transit->>Storage: v1 키로 복호화
    Transit->>LibOQS: OQS_KEM_decaps(v1)
    LibOQS-->>Transit: plaintext

    Transit->>Storage: v2 키로 암호화
    Transit->>LibOQS: OQS_KEM_encaps(v2)
    LibOQS-->>Transit: new_ct

    Transit-->>Vault: {"ciphertext": "vault:v2:..."}
    Vault-->>Clients: 200 OK

    Note over Admin,Clients: 오래된 키 삭제

    Admin->>Vault: POST /v1/oqs-transit/keys/my-key/config<br/>{"min_decryption_version": 2}
    Vault->>Transit: 최소 버전 설정

    Transit->>Storage: v1 키 삭제
    Storage-->>Transit: 완료

    Transit-->>Vault: 설정 완료
    Vault-->>Admin: 200 OK

    Note over Admin,Clients: 이제 v1 데이터는 복호화 불가<br/>모든 데이터가 v2로 재암호화되어야 함
```

### 8.2 Keycloak 서명 키 순환

```mermaid
sequenceDiagram
    participant Admin
    participant Keycloak
    participant OQS_SPI
    participant Vault
    participant LibOQS
    participant Clients

    Note over Admin,Clients: Keycloak 서명 키 순환

    Admin->>Keycloak: Admin Console<br/>Realm Settings → Keys

    Keycloak->>Keycloak: 현재 활성 키 확인<br/>dilithium3-key-1 (kid: abc123)

    Admin->>Keycloak: "Generate New Key" 클릭

    Keycloak->>OQS_SPI: 새 키 생성 요청<br/>algorithm=DILITHIUM3

    OQS_SPI->>LibOQS: OQS_SIG_new("Dilithium3")
    LibOQS-->>OQS_SPI: sig 객체

    OQS_SPI->>LibOQS: OQS_SIG_keypair()
    LibOQS-->>OQS_SPI: new_pk, new_sk

    OQS_SPI->>OQS_SPI: kid 생성 (uuid)<br/>kid: xyz789

    OQS_SPI->>Vault: 새 키 저장<br/>POST /v1/transit/keys/keycloak-dilithium3-2
    Vault-->>OQS_SPI: 저장 완료

    OQS_SPI->>Keycloak: 키 저장 (DB)<br/>- kid: xyz789<br/>- algorithm: DILITHIUM3<br/>- status: active<br/>- created: timestamp

    Keycloak->>Keycloak: 이전 키 상태 변경<br/>abc123: active → passive

    Keycloak-->>Admin: 새 키 생성 완료<br/>kid: xyz789

    Note over Admin,Clients: 새 토큰은 새 키로 서명

    Clients->>Keycloak: POST /token (로그인)
    Keycloak->>Keycloak: 사용자 인증

    Keycloak->>OQS_SPI: 토큰 서명 요청<br/>kid: xyz789 (active)

    OQS_SPI->>Vault: 키 조회<br/>GET /v1/transit/keys/keycloak-dilithium3-2
    Vault-->>OQS_SPI: new_sk

    OQS_SPI->>LibOQS: OQS_SIG_sign(claims, new_sk)
    LibOQS-->>OQS_SPI: signature

    OQS_SPI->>OQS_SPI: 토큰 생성<br/>header: {"kid": "xyz789"}

    OQS_SPI-->>Keycloak: signed_token

    Keycloak-->>Clients: {"access_token": "eyJ..."}

    Note over Admin,Clients: 기존 토큰은 이전 키로 검증 가능

    Clients->>Keycloak: GET /userinfo<br/>Authorization: Bearer old_token

    Keycloak->>Keycloak: 토큰 파싱<br/>kid: abc123

    Keycloak->>OQS_SPI: 공개키 조회<br/>kid: abc123

    OQS_SPI->>OQS_SPI: 캐시에서 조회<br/>(passive 키도 검증 가능)

    OQS_SPI-->>Keycloak: old_pk

    Keycloak->>LibOQS: OQS_SIG_verify(old_token, old_pk)
    LibOQS-->>Keycloak: ✓ 유효

    Keycloak-->>Clients: 200 OK (사용자 정보)

    Note over Admin,Clients: JWKS 엔드포인트는 두 키 모두 포함

    Clients->>Keycloak: GET /certs (JWKS)
    Keycloak->>Keycloak: JWKS 생성

    Keycloak-->>Clients: {<br/>  "keys": [<br/>    {"kid": "xyz789", "status": "active", ...},<br/>    {"kid": "abc123", "status": "passive", ...}<br/>  ]<br/>}

    Note over Admin,Clients: 오래된 키 폐기

    Admin->>Keycloak: 키 삭제 (abc123)<br/>유예 기간 후

    Keycloak->>Keycloak: 활성 토큰 확인<br/>(kid: abc123)

    alt 활성 토큰 없음
        Keycloak->>OQS_SPI: 키 삭제 요청
        OQS_SPI->>Vault: DELETE /v1/transit/keys/keycloak-dilithium3-1
        Vault-->>OQS_SPI: 삭제 완료

        Keycloak->>Keycloak: DB에서 키 삭제

        Keycloak-->>Admin: 키 삭제 완료
    else 활성 토큰 존재
        Keycloak-->>Admin: 오류: 아직 사용 중인 키
    end

    Note over Admin,Clients: 키 순환 완료<br/>새 키만 활성 상태
```

---

## 9. 에러 처리 시나리오

### 9.1 TLS 핸드셰이크 실패

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant OQS_Provider
    participant LibOQS

    Note over Client,LibOQS: TLS 핸드셰이크 에러 시나리오

    Client->>Server: ClientHello<br/>supported_groups: kyber512 only

    Server->>OQS_Provider: 지원 그룹 확인
    OQS_Provider->>OQS_Provider: 서버 설정: kyber768, X25519
    OQS_Provider-->>Server: 공통 그룹 없음

    Server-->>Client: Alert: handshake_failure<br/>(no shared groups)

    Client->>Client: ✗ 연결 실패<br/>에러: No shared cipher groups

    Note over Client,LibOQS: 시나리오 2: 인증서 검증 실패

    Client->>Server: ClientHello (정상)

    Server->>Client: ServerHello<br/>Certificate (DILITHIUM3)<br/>CertificateVerify

    Client->>Client: 인증서 파싱

    Client->>Client: 서명 알고리즘 확인<br/>알고리즘: DILITHIUM3

    Client->>OQS_Provider: 서명 검증
    OQS_Provider->>LibOQS: OQS_SIG_verify()

    alt 서명 무효
        LibOQS-->>OQS_Provider: OQS_ERROR
        OQS_Provider-->>Client: 검증 실패

        Client-->>Server: Alert: bad_certificate

        Server->>Server: ✗ 핸드셰이크 중단

        Client->>Client: 에러: Certificate verification failed

    else 인증서 만료
        Client->>Client: 만료 시간 확인<br/>현재 > NotAfter

        Client-->>Server: Alert: certificate_expired

        Server->>Server: ✗ 핸드셰이크 중단

        Client->>Client: 에러: Certificate expired

    else 신뢰할 수 없는 CA
        Client->>Client: CA 인증서 확인<br/>Issuer not in trust store

        Client-->>Server: Alert: unknown_ca

        Server->>Server: ✗ 핸드셰이크 중단

        Client->>Client: 에러: Unknown CA
    end

    Note over Client,LibOQS: 시나리오 3: KEM 복호화 실패

    Client->>Server: ClientKeyExchange<br/>ciphertext (손상됨)

    Server->>OQS_Provider: KEM Decapsulation
    OQS_Provider->>LibOQS: OQS_KEM_decaps(damaged_ct, sk)
    LibOQS->>LibOQS: 복호화 시도

    alt 복호화 실패
        LibOQS-->>OQS_Provider: OQS_ERROR
        OQS_Provider-->>Server: 에러

        Server-->>Client: Alert: decrypt_error

        Client->>Client: ✗ 연결 실패

        Server->>Server: 로그: KEM decapsulation failed<br/>Possible tampering detected
    end

    Note over Client,LibOQS: 모든 에러는 로깅 및 모니터링됨
```

### 9.2 Vault Transit 에러

```mermaid
sequenceDiagram
    participant Client
    participant Vault
    participant Transit
    participant Storage
    participant LibOQS

    Note over Client,LibOQS: Vault Transit 에러 처리

    Note over Client,LibOQS: 시나리오 1: 키 없음

    Client->>Vault: POST /v1/oqs-transit/encrypt/nonexistent-key<br/>{"plaintext": "..."}
    Vault->>Transit: 암호화 요청

    Transit->>Storage: 키 조회
    Storage-->>Transit: 키 없음

    Transit-->>Vault: 404 Not Found
    Vault-->>Client: {<br/>  "errors": ["encryption key not found"]<br/>}

    Client->>Client: 에러 처리: 키 생성 또는 재시도

    Note over Client,LibOQS: 시나리오 2: 손상된 암호문

    Client->>Vault: POST /v1/oqs-transit/decrypt/my-key<br/>{"ciphertext": "vault:v1:corrupted..."}
    Vault->>Transit: 복호화 요청

    Transit->>Transit: 암호문 파싱

    alt Base64 디코딩 실패
        Transit-->>Vault: 400 Bad Request
        Vault-->>Client: {<br/>  "errors": ["invalid ciphertext format"]<br/>}

    else KEM 복호화 실패
        Transit->>Storage: 키 조회
        Storage-->>Transit: key

        Transit->>LibOQS: OQS_KEM_decaps(corrupted_ct, sk)
        LibOQS-->>Transit: OQS_ERROR

        Transit->>Transit: 재시도 (1회)
        Transit->>LibOQS: OQS_KEM_decaps() (재시도)
        LibOQS-->>Transit: OQS_ERROR

        Transit-->>Vault: 500 Internal Server Error
        Vault-->>Client: {<br/>  "errors": ["decryption failed"]<br/>}

        Transit->>Transit: 로그: Decryption failed for key my-key<br/>Audit: 복호화 실패 기록
    end

    Note over Client,LibOQS: 시나리오 3: 버전 불일치

    Client->>Vault: POST /v1/oqs-transit/decrypt/my-key<br/>{"ciphertext": "vault:v1:..."}
    Vault->>Transit: 복호화 요청

    Transit->>Transit: 버전 파싱: v1

    Transit->>Storage: v1 키 조회
    Storage-->>Transit: 키 없음 (min_version=2)

    Transit-->>Vault: 400 Bad Request
    Vault-->>Client: {<br/>  "errors": ["key version no longer supported"]<br/>}

    Client->>Client: 에러 처리: 데이터 재암호화 필요

    Note over Client,LibOQS: 시나리오 4: 리소스 부족

    Client->>Vault: POST /v1/oqs-transit/encrypt/my-key (대용량)
    Vault->>Transit: 암호화 요청

    Transit->>LibOQS: OQS_KEM_encaps()

    alt 메모리 부족
        LibOQS-->>Transit: 메모리 할당 실패
        Transit-->>Vault: 507 Insufficient Storage
        Vault-->>Client: {<br/>  "errors": ["insufficient resources"]<br/>}

    else 타임아웃
        LibOQS->>LibOQS: 처리 시간 초과 (30s)
        Transit->>Transit: 타임아웃 감지
        Transit-->>Vault: 504 Gateway Timeout
        Vault-->>Client: {<br/>  "errors": ["request timeout"]<br/>}
    end

    Note over Client,LibOQS: 모든 에러는 감사 로그에 기록됨
```

---

## 10. 전체 시스템 통합 흐름

### 10.1 End-to-End 요청 처리

```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant APISIX
    participant Keycloak
    participant Service
    participant Vault
    participant DB

    Note over User,DB: 전체 QSIGN + OQS 통합 흐름

    User->>Browser: 문서 서명 요청

    Note over Browser,APISIX: 1. TLS 연결 (KYBER768)

    Browser->>APISIX: ClientHello (KYBER768)
    APISIX->>APISIX: KYBER KEM 키 교환
    APISIX-->>Browser: TLS 1.3 Handshake 완료
    Browser->>Browser: ✓ 암호화 연결 수립

    Note over Browser,Keycloak: 2. 인증 (DILITHIUM3 토큰)

    Browser->>APISIX: GET /api/sign (토큰 없음)
    APISIX-->>Browser: 401 Unauthorized

    Browser->>Keycloak: POST /token (로그인)
    Keycloak->>Keycloak: 인증 확인
    Keycloak->>Keycloak: DILITHIUM3 서명 토큰 생성
    Keycloak-->>Browser: access_token (DILITHIUM3)

    Note over Browser,Service: 3. API 요청 (mTLS + DILITHIUM3)

    Browser->>APISIX: POST /api/sign<br/>Authorization: Bearer token<br/>{"document": "..."}

    APISIX->>APISIX: TLS 종료 (KYBER768)
    APISIX->>APISIX: OQS mTLS 플러그인<br/>클라이언트 인증서 검증 (선택)

    APISIX->>Keycloak: 토큰 검증
    Keycloak->>Keycloak: DILITHIUM3 서명 검증
    Keycloak-->>APISIX: ✓ 토큰 유효

    APISIX->>APISIX: Rate Limiting<br/>Route Matching

    APISIX->>Service: Forward (mTLS + DILITHIUM3)<br/>X-User-Id: user123

    Note over Service,Vault: 4. 문서 서명 (Transit Engine)

    Service->>Service: 문서 검증

    Service->>Vault: POST /v1/oqs-transit/sign/signing-key<br/>{"input": "hash(document)"}

    Vault->>Vault: Transit Engine
    Vault->>Vault: DILITHIUM3 서명 생성
    Vault-->>Service: {"signature": "..."}

    Service->>Service: 서명 첨부

    Note over Service,DB: 5. 데이터 저장 (암호화)

    Service->>Vault: POST /v1/oqs-transit/encrypt/data-key<br/>{"plaintext": "document_data"}

    Vault->>Vault: KYBER768 암호화
    Vault-->>Service: {"ciphertext": "vault:v1:..."}

    Service->>DB: INSERT INTO documents<br/>(id, encrypted_data, signature, user_id)
    DB-->>Service: 저장 완료

    Service->>Service: 감사 로그 기록

    Service-->>APISIX: 200 OK<br/>{"signed_document": "...", "signature": "..."}

    APISIX->>APISIX: Response 암호화 (KYBER768)

    APISIX-->>Browser: 200 OK (암호화됨)

    Browser->>Browser: TLS 복호화
    Browser-->>User: 서명 완료!

    Note over User,DB: 전 구간 PQC 보호<br/>- TLS: KYBER768<br/>- Auth: DILITHIUM3<br/>- Sign: DILITHIUM3<br/>- Storage: KYBER768
```

---

## 참고 자료

```yaml
시퀀스 다이어그램 도구:
  - Mermaid: https://mermaid.js.org/
  - PlantUML: https://plantuml.com/
  - Draw.io: https://app.diagrams.net/

관련 문서:
  - Q-Docs/10-OQS/LIBOQS.md
  - Q-Docs/10-OQS/OPENSSL-OQS.md
  - Q-Docs/10-OQS/OQS-QSIGN-INTEGRATION.md
  - Q-Docs/10-OQS/IMPLEMENTATION-GUIDE.md

프로토콜 명세:
  - TLS 1.3: RFC 8446
  - KYBER: NIST FIPS 203
  - DILITHIUM: NIST FIPS 204
```

---

**문서 버전:** 1.0
**최종 수정일:** 2025-01-16
**작성자:** QSIGN Documentation Team
