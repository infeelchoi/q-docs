# PQC SSL/TLS 통신 시퀀스 다이어그램

## 📘 개요

양자내성암호(Post-Quantum Cryptography)가 적용된 SSL/TLS 핸드셰이크 과정을 시퀀스 다이어그램으로 상세하게 설명합니다.

## 1️⃣ 기본 PQC SSL/TLS 핸드셰이크

### 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant C as 클라이언트
    participant S as 서버
    participant CA as CA - 인증기관

    Note over C,S: 1. 핸드셰이크 시작
    C->>S: Client Hello<br/>- 지원 PQC 알고리즘: Kyber768, Dilithium3

    Note over S: PQC 알고리즘 선택
    S->>C: Server Hello<br/>- 선택: Kyber768 키교환, Dilithium3 서명

    Note over S: 2. 인증서 전송
    S->>C: Certificate<br/>- Dilithium3로 서명된 서버 인증서

    Note over C: 3. 인증서 검증
    C->>CA: CA 공개키로 서버 인증서 검증
    CA-->>C: 검증 완료

    Note over C: 4. PQC 키 교환
    C->>S: Client Key Exchange<br/>- Kyber768로 암호화된 Pre-Master Secret

    Note over C,S: 5. 세션키 생성
    Note over C: Master Secret 생성<br/>- Pre-Master Secret 기반
    Note over S: Master Secret 생성<br/>- Pre-Master Secret 복호화

    C->>S: Change Cipher Spec<br/>- 암호화 시작 알림
    C->>S: Finished - 암호화됨

    S->>C: Change Cipher Spec
    S->>C: Finished - 암호화됨

    Note over C,S: 6. 암호화된 데이터 통신
    C->>S: Application Data - AES-256-GCM 암호화
    S->>C: Application Data - AES-256-GCM 암호화
```

### 주요 단계 설명

**1단계 - Client Hello**
- 클라이언트가 지원하는 PQC 알고리즘 목록(Kyber, Dilithium 등)을 서버에 전송

**2단계 - Server Hello**
- 서버가 사용할 PQC 알고리즘 선택 (키교환: Kyber768, 서명: Dilithium3)

**3단계 - Certificate**
- Dilithium3 알고리즘으로 서명된 서버 인증서 전송

**4단계 - 인증서 검증**
- CA의 PQC 공개키로 서버 인증서의 Dilithium3 서명 검증

**5단계 - Key Exchange**
- Kyber768 알고리즘으로 Pre-Master Secret 암호화하여 전송

**6단계 - 세션키 생성**
- 양쪽에서 동일한 Master Secret(대칭키) 생성

**7단계 - 데이터 통신**
- 생성된 대칭키(AES)로 실제 데이터 암호화 통신

## 2️⃣ 하이브리드 모드 (PQC + 기존 알고리즘)

### 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant C as 클라이언트
    participant S as 서버
    participant CA as CA - 인증기관

    Note over C,S: 호환성을 위한 하이브리드 방식

    C->>S: Client Hello<br/>- PQC: Kyber768 + 기존: ECDHE-P256
    S->>C: Server Hello<br/>- 하이브리드 모드 선택

    Note over S: 이중 인증서 체인
    S->>C: Certificate Chain<br/>1. RSA-2048 인증서<br/>2. Dilithium3 인증서

    Note over C: 이중 검증
    C->>CA: RSA 서명 검증
    CA-->>C: ✓ 검증 완료
    C->>CA: Dilithium3 서명 검증
    CA-->>C: ✓ 검증 완료

    Note over C: 이중 키 교환
    C->>S: Key Exchange 1<br/>- ECDHE-P256
    C->>S: Key Exchange 2<br/>- Kyber768

    Note over C,S: 두 키 교환 결과를 결합
    Note over C: Master Secret = <br/>KDF - ECDHE_Secret + Kyber_Secret
    Note over S: Master Secret = <br/>KDF - ECDHE_Secret + Kyber_Secret

    C->>S: Finished - 암호화됨
    S->>C: Finished - 암호화됨

    Note over C,S: 양자 안전 + 기존 보안 보장
    C->>S: Encrypted Data
    S->>C: Encrypted Data
```

### 하이브리드 모드의 장점

- **하위 호환성**: 기존 시스템과의 호환성 유지
- **이중 보안**: 기존 알고리즘 + PQC 알고리즘 동시 적용
- **점진적 전환**: PQC로의 단계적 마이그레이션 가능
- **안전성 보장**: 하나의 알고리즘이 깨져도 다른 알고리즘으로 보호

## 3️⃣ PQC 인증서 발급 과정

### 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant Server as 웹 서버
    participant CA as CA - 인증기관
    participant Root as Root CA

    Note over Server: 1. PQC 키쌍 생성
    Server->>Server: 개인키 생성<br/>- Dilithium3 알고리즘
    Server->>Server: 공개키 추출

    Note over Server: 2. CSR 생성
    Server->>CA: Certificate Signing Request<br/>- 서버 정보 + Dilithium3 공개키

    Note over CA: 3. 신원 확인
    CA->>CA: 서버 신원 검증<br/>- 도메인 소유권 확인

    Note over CA: 4. 인증서 서명
    CA->>CA: Dilithium3 개인키로<br/>서버 인증서 서명

    CA->>Server: 서명된 인증서 발급<br/>- Dilithium3 서명 포함

    Note over CA,Root: 5. CA 인증서 체인
    CA->>Root: CA 인증서 검증 요청
    Root->>Root: Root CA의 Dilithium5로<br/>CA 인증서 서명
    Root->>CA: 서명된 CA 인증서

    Note over Server: 6. 인증서 체인 구성
    Server->>Server: 인증서 체인 저장<br/>- 서버 인증서<br/>- CA 인증서<br/>- Root CA 인증서
```

### PQC 인증서 구조

| 구성요소 | PQC 알고리즘 | 기존 알고리즘 |
|---------|------------|-------------|
| 서버 인증서 서명 | Dilithium3 | RSA-2048 |
| CA 인증서 서명 | Dilithium3 | RSA-4096 |
| Root CA 서명 | Dilithium5 | RSA-4096 |
| 키 교환 | Kyber768 | ECDHE-P256 |
| 대칭키 암호화 | AES-256-GCM (양자 안전) | AES-256-GCM |

## 4️⃣ 전체 PQC SSL/TLS 통신 흐름 (상세)

### 시퀀스 다이어그램

```mermaid
sequenceDiagram
    participant Browser as 웹 브라우저
    participant Server as 웹 서버
    participant CA as CA

    Note over Browser,Server: Phase 1: TCP 연결
    Browser->>Server: TCP SYN
    Server->>Browser: TCP SYN-ACK
    Browser->>Server: TCP ACK

    Note over Browser,Server: Phase 2: TLS 핸드셰이크 - PQC
    Browser->>Server: ClientHello<br/>- TLS 1.3<br/>- Cipher Suites: TLS_KYBER768_AES256<br/>- PQC Extensions

    Server->>Browser: ServerHello<br/>- 선택된 Cipher Suite<br/>- Kyber768 공개키 - 서버

    Server->>Browser: Certificate<br/>- Dilithium3 서명 인증서<br/>- 인증서 체인

    Server->>Browser: CertificateVerify<br/>- 핸드셰이크 메시지의<br/>  Dilithium3 서명

    Server->>Browser: Finished<br/>- 암호화된 해시

    Note over Browser: CA 공개키로<br/>Dilithium3 서명 검증

    Browser->>Server: Certificate - 선택적<br/>- 클라이언트 인증서

    Browser->>Server: ClientKeyExchange<br/>- Kyber768로 암호화된<br/>  Pre-Master Secret

    Browser->>Server: Finished<br/>- 암호화된 해시

    Note over Browser,Server: Phase 3: 세션키 확립
    Note over Browser: Master Secret 계산<br/>Session Keys 생성
    Note over Server: Master Secret 계산<br/>Session Keys 생성

    Note over Browser,Server: Phase 4: 암호화 통신
    Browser->>Server: HTTP Request<br/>- AES-256-GCM 암호화
    Server->>Browser: HTTP Response<br/>- AES-256-GCM 암호화

    Note over Browser,Server: Phase 5: 연결 종료
    Browser->>Server: Close Notify<br/>- 암호화됨
    Server->>Browser: Close Notify<br/>- 암호화됨
```

## 5️⃣ PQC 알고리즘 특성 비교

### 서명 알고리즘 (인증서용)

| 알고리즘 | 공개키 크기 | 서명 크기 | 보안 수준 | 특징 |
|---------|-----------|---------|---------|-----|
| **Dilithium2** | 1,312 bytes | 2,420 bytes | NIST Level 2 | 빠른 속도, 작은 크기 |
| **Dilithium3** | 1,952 bytes | 3,293 bytes | NIST Level 3 | 균형잡힌 선택 (권장) |
| **Dilithium5** | 2,592 bytes | 4,595 bytes | NIST Level 5 | 최고 보안 |
| **Falcon512** | 897 bytes | 666 bytes | NIST Level 1 | 가장 작은 서명 |

### 키 교환 알고리즘 (핸드셰이크용)

| 알고리즘 | 공개키 크기 | 암호문 크기 | 보안 수준 | 특징 |
|---------|-----------|-----------|---------|-----|
| **Kyber512** | 800 bytes | 768 bytes | NIST Level 1 | 빠른 처리 |
| **Kyber768** | 1,184 bytes | 1,088 bytes | NIST Level 3 | 권장 (AES-128 수준) |
| **Kyber1024** | 1,568 bytes | 1,568 bytes | NIST Level 5 | 최고 보안 (AES-256 수준) |

### 알고리즘 선택 가이드

- **일반 웹사이트**: Dilithium3 + Kyber768 (권장)
- **금융/의료 시스템**: Dilithium5 + Kyber1024 (최고 보안)
- **IoT/모바일**: Dilithium2 + Kyber512 (경량)
- **하이브리드**: 기존 알고리즘 + PQC (전환기)

## 🔗 관련 문서

- [Q-TLS-OVERVIEW.md](./Q-TLS-OVERVIEW.md) - Q-TLS 개요
- [Q-TLS-ARCHITECTURE.md](./Q-TLS-ARCHITECTURE.md) - Q-TLS 아키텍처
- [HANDSHAKE-PROTOCOL.md](./HANDSHAKE-PROTOCOL.md) - 핸드셰이크 프로토콜 상세
- [CERTIFICATE-MANAGEMENT.md](./CERTIFICATE-MANAGEMENT.md) - PQC 인증서 관리
- [CIPHER-SUITES.md](./CIPHER-SUITES.md) - 암호화 스위트 설정

---

**Last Updated**: 2025-11-20
**Version**: 1.0.0
**Security Level**: PQC - NIST FIPS 203/204
**Algorithms**: Kyber (KEM), Dilithium (Signature)
