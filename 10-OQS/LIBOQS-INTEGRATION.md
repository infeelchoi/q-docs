# liboqs 통합 가이드 (liboqs Integration Guide)

> **liboqs 빌드, 설치 및 통합** - 프로젝트에 liboqs를 통합하는 완전한 가이드
> Ubuntu, RHEL, macOS 플랫폼 지원

---

## 📑 목차

1. [빌드 및 설치](#1-빌드-및-설치)
2. [CMake 통합](#2-cmake-통합)
3. [C/C++ API 사용법](#3-cc-api-사용법)
4. [Python 바인딩](#4-python-바인딩)
5. [Go 바인딩](#5-go-바인딩)
6. [알고리즘 선택 가이드](#6-알고리즘-선택-가이드)
7. [성능 튜닝](#7-성능-튜닝)
8. [트러블슈팅](#8-트러블슈팅)

---

## 1. 빌드 및 설치

### 1.1 사전 요구사항

#### Ubuntu 22.04 LTS

```bash
# 필수 패키지 설치
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    doxygen \
    graphviz

# 선택 사항: Python 바인딩
sudo apt install -y \
    python3-dev \
    python3-pip \
    python3-pytest

# 선택 사항: valgrind (메모리 검사)
sudo apt install -y valgrind
```

#### RHEL 8 / Rocky Linux 8

```bash
# 필수 패키지 설치
sudo dnf install -y \
    gcc \
    gcc-c++ \
    cmake \
    git \
    openssl-devel \
    ninja-build \
    doxygen \
    graphviz

# Python 바인딩
sudo dnf install -y \
    python3-devel \
    python3-pip \
    python3-pytest
```

#### macOS

```bash
# Homebrew 사용
brew install cmake ninja openssl@3 doxygen graphviz

# Python 바인딩
brew install python@3.11
pip3 install pytest
```

### 1.2 liboqs 소스 다운로드

```bash
# 1. Git clone
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# 2. 최신 stable 버전으로 체크아웃 (권장)
git checkout 0.10.0  # 또는 최신 릴리스

# 3. 또는 main 브랜치 사용 (최신 개발 버전)
# git checkout main
```

### 1.3 빌드 (기본)

```bash
# 빌드 디렉토리 생성
mkdir build && cd build

# CMake 설정
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    ..

# 빌드
ninja

# 테스트 실행 (선택사항, 권장)
ninja run_tests

# 설치
sudo ninja install

# 라이브러리 경로 업데이트
sudo ldconfig  # Linux only
```

**설치 확인:**

```bash
# 라이브러리 확인
ls -lh /usr/local/lib/liboqs.*

# 출력 예:
# -rw-r--r-- 1 root root 2.1M  liboqs.a
# -rwxr-xr-x 1 root root 1.8M  liboqs.so.0.10.0

# 헤더 확인
ls -lh /usr/local/include/oqs/

# 출력:
# common.h  kem.h  oqs.h  rand.h  sig.h
```

### 1.4 고급 빌드 옵션

#### 최적화 빌드 (권장 - 프로덕션)

```bash
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native" \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_SIG_SPHINCSPLUS=ON \
    -DOQS_ENABLE_SIG_FALCON=ON \
    ..

ninja
sudo ninja install
```

**옵션 설명:**

```yaml
CMAKE_BUILD_TYPE:
  - Release: 최적화 빌드 (프로덕션)
  - Debug: 디버그 심볼 포함
  - RelWithDebInfo: 최적화 + 디버그 심볼

OQS_USE_OPENSSL:
  - ON: OpenSSL 사용 (SHA, AES 등)
  - OFF: 순수 liboqs 구현

OQS_DIST_BUILD:
  - ON: 범용 바이너리 (느림, 모든 CPU 지원)
  - OFF: 현재 CPU 최적화 (빠름, 특정 CPU만)

OQS_ENABLE_KEM_*:
  - OQS_ENABLE_KEM_KYBER: KYBER KEM 활성화
  - OQS_ENABLE_KEM_CLASSIC_MCELIECE: McEliece 활성화
  - OQS_ENABLE_KEM_HQC: HQC 활성화
  - OQS_ENABLE_KEM_BIKE: BIKE 활성화

OQS_ENABLE_SIG_*:
  - OQS_ENABLE_SIG_DILITHIUM: DILITHIUM 활성화
  - OQS_ENABLE_SIG_FALCON: FALCON 활성화
  - OQS_ENABLE_SIG_SPHINCSPLUS: SPHINCS+ 활성화
  - OQS_ENABLE_SIG_MAYO: MAYO 활성화
```

#### QSIGN 최적화 빌드

```bash
#!/bin/bash
# scripts/build-liboqs-qsign.sh

set -e

BUILD_DIR="build-qsign"
INSTALL_PREFIX="/opt/qsign/liboqs"

# 빌드 디렉토리 생성
rm -rf $BUILD_DIR
mkdir $BUILD_DIR && cd $BUILD_DIR

# CMake 설정 (QSIGN 프로덕션 환경)
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
    -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -fPIC" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_DIST_BUILD=OFF \
    \
    `# QSIGN 핵심 알고리즘만 활성화` \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_SIG_SPHINCSPLUS=ON \
    -DOQS_ENABLE_SIG_FALCON=ON \
    \
    `# 기타 알고리즘 비활성화 (크기 축소)` \
    -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
    -DOQS_ENABLE_KEM_HQC=OFF \
    -DOQS_ENABLE_KEM_BIKE=OFF \
    -DOQS_ENABLE_SIG_MAYO=OFF \
    ..

# 빌드
echo "빌드 중..."
ninja

# 테스트
echo "테스트 실행 중..."
ninja run_tests

# 설치
echo "설치 중..."
sudo ninja install

# 라이브러리 경로 추가
echo "$INSTALL_PREFIX/lib" | sudo tee /etc/ld.so.conf.d/liboqs-qsign.conf
sudo ldconfig

echo "liboqs 빌드 및 설치 완료!"
echo "설치 경로: $INSTALL_PREFIX"
```

**실행:**

```bash
chmod +x scripts/build-liboqs-qsign.sh
./scripts/build-liboqs-qsign.sh
```

### 1.5 정적 라이브러리 빌드

```bash
# 정적 라이브러리만 빌드 (선택사항)
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    ..

ninja
sudo ninja install

# 확인
ls -lh /usr/local/lib/liboqs.a
```

---

## 2. CMake 통합

### 2.1 find_package 사용

```cmake
# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(qsign-app C)

# liboqs 찾기
find_package(liboqs REQUIRED)

# 실행 파일
add_executable(qsign-app main.c)

# liboqs 링크
target_link_libraries(qsign-app PRIVATE OQS::oqs)

# 헤더 경로는 자동으로 설정됨
```

**빌드:**

```bash
mkdir build && cd build
cmake ..
make

# 실행
./qsign-app
```

### 2.2 pkg-config 사용

```cmake
# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(qsign-app C)

# pkg-config 사용
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBOQS REQUIRED liboqs)

add_executable(qsign-app main.c)

# 링크
target_include_directories(qsign-app PRIVATE ${LIBOQS_INCLUDE_DIRS})
target_link_libraries(qsign-app PRIVATE ${LIBOQS_LIBRARIES})
target_link_directories(qsign-app PRIVATE ${LIBOQS_LIBRARY_DIRS})
```

### 2.3 수동 설정

```cmake
# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(qsign-app C)

# liboqs 경로 수동 설정
set(LIBOQS_INCLUDE_DIR "/usr/local/include")
set(LIBOQS_LIBRARY_DIR "/usr/local/lib")
set(LIBOQS_LIBRARY "oqs")

add_executable(qsign-app main.c)

target_include_directories(qsign-app PRIVATE ${LIBOQS_INCLUDE_DIR})
target_link_directories(qsign-app PRIVATE ${LIBOQS_LIBRARY_DIR})
target_link_libraries(qsign-app PRIVATE ${LIBOQS_LIBRARY})

# OpenSSL도 필요 (liboqs가 OpenSSL 사용 시)
find_package(OpenSSL REQUIRED)
target_link_libraries(qsign-app PRIVATE OpenSSL::Crypto)
```

---

## 3. C/C++ API 사용법

### 3.1 Hello World (KEM)

```c
// hello_kem.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    printf("liboqs KEM Hello World\n\n");

    // 1. KEM 생성
    OQS_KEM *kem = OQS_KEM_new("Kyber1024");
    if (kem == NULL) {
        fprintf(stderr, "ERROR: OQS_KEM_new failed\n");
        return 1;
    }

    printf("알고리즘: %s\n", kem->method_name);
    printf("NIST 레벨: %d\n", kem->claimed_nist_level);
    printf("공개키 크기: %zu bytes\n", kem->length_public_key);
    printf("암호문 크기: %zu bytes\n", kem->length_ciphertext);
    printf("공유 비밀 크기: %zu bytes\n\n", kem->length_shared_secret);

    // 2. 메모리 할당
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_client = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_server = malloc(kem->length_shared_secret);

    // 3. 키쌍 생성
    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: keypair failed\n");
        goto cleanup;
    }
    printf("✓ 키쌍 생성 완료\n");

    // 4. 캡슐화
    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_client, public_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: encaps failed\n");
        goto cleanup;
    }
    printf("✓ 캡슐화 완료\n");

    // 5. 디캡슐화
    if (OQS_KEM_decaps(kem, shared_secret_server, ciphertext, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: decaps failed\n");
        goto cleanup;
    }
    printf("✓ 디캡슐화 완료\n");

    // 6. 공유 비밀 비교
    if (memcmp(shared_secret_client, shared_secret_server, kem->length_shared_secret) == 0) {
        printf("✓ 공유 비밀 일치!\n\n");

        printf("공유 비밀 (hex): ");
        for (size_t i = 0; i < kem->length_shared_secret && i < 32; i++) {
            printf("%02x", shared_secret_client[i]);
        }
        printf("...\n");
    } else {
        printf("✗ 공유 비밀 불일치!\n");
    }

cleanup:
    // 7. 안전한 메모리 해제
    OQS_MEM_secure_free(secret_key, kem->length_secret_key);
    OQS_MEM_secure_free(shared_secret_client, kem->length_shared_secret);
    OQS_MEM_secure_free(shared_secret_server, kem->length_shared_secret);
    free(public_key);
    free(ciphertext);
    OQS_KEM_free(kem);

    return 0;
}
```

**컴파일 및 실행:**

```bash
# GCC
gcc hello_kem.c -o hello_kem -loqs -lssl -lcrypto

# 또는 pkg-config 사용
gcc hello_kem.c -o hello_kem $(pkg-config --cflags --libs liboqs)

# 실행
./hello_kem
```

### 3.2 Hello World (Signature)

```c
// hello_sig.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    printf("liboqs Signature Hello World\n\n");

    // 1. Signature 생성
    OQS_SIG *sig = OQS_SIG_new("Dilithium3");
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed\n");
        return 1;
    }

    printf("알고리즘: %s\n", sig->method_name);
    printf("NIST 레벨: %d\n", sig->claimed_nist_level);
    printf("공개키 크기: %zu bytes\n", sig->length_public_key);
    printf("서명 크기: %zu bytes\n\n", sig->length_signature);

    // 2. 메모리 할당
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    // 3. 키쌍 생성
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: keypair failed\n");
        goto cleanup;
    }
    printf("✓ 키쌍 생성 완료\n");

    // 4. 서명할 메시지
    const char *message = "Hello, QSIGN!";
    size_t message_len = strlen(message);
    printf("메시지: \"%s\"\n", message);

    // 5. 서명 생성
    if (OQS_SIG_sign(sig, signature, &signature_len,
                     (uint8_t*)message, message_len,
                     secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: sign failed\n");
        goto cleanup;
    }
    printf("✓ 서명 생성 완료 (%zu bytes)\n", signature_len);

    // 6. 서명 검증
    if (OQS_SIG_verify(sig, (uint8_t*)message, message_len,
                       signature, signature_len,
                       public_key) == OQS_SUCCESS) {
        printf("✓ 서명 검증 성공!\n");
    } else {
        printf("✗ 서명 검증 실패!\n");
    }

cleanup:
    // 7. 안전한 메모리 해제
    OQS_MEM_secure_free(secret_key, sig->length_secret_key);
    OQS_MEM_secure_free(signature, sig->length_signature);
    free(public_key);
    OQS_SIG_free(sig);

    return 0;
}
```

**컴파일 및 실행:**

```bash
gcc hello_sig.c -o hello_sig -loqs -lssl -lcrypto
./hello_sig
```

### 3.3 Makefile 예제

```makefile
# Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags liboqs)
LDFLAGS = $(shell pkg-config --libs liboqs)

# 타겟
TARGETS = hello_kem hello_sig qsign_example

all: $(TARGETS)

hello_kem: hello_kem.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

hello_sig: hello_sig.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

qsign_example: qsign_example.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
```

### 3.4 실전 예제: Hybrid KEM

```c
// hybrid_kem.c - ECDH + Kyber1024 Hybrid KEM

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define ECDH_KEYLEN 48  // P-384: 48 bytes
#define HYBRID_SHARED_SECRET_LEN 64  // 32 (Kyber) + 32 (ECDH 파생)

typedef struct {
    uint8_t *kyber_pk;
    uint8_t *ecdh_pk;
    size_t kyber_pk_len;
    size_t ecdh_pk_len;
} HybridPublicKey;

typedef struct {
    uint8_t *kyber_ct;
    uint8_t *ecdh_ct;
    size_t kyber_ct_len;
    size_t ecdh_ct_len;
} HybridCiphertext;

int hybrid_kem_keypair(OQS_KEM *kem, EVP_PKEY **ecdh_key, HybridPublicKey *pk) {
    // 1. Kyber 키쌍
    pk->kyber_pk_len = kem->length_public_key;
    pk->kyber_pk = malloc(pk->kyber_pk_len);
    uint8_t *kyber_sk = malloc(kem->length_secret_key);

    if (kem->keypair(pk->kyber_pk, kyber_sk) != OQS_SUCCESS) {
        free(pk->kyber_pk);
        free(kyber_sk);
        return -1;
    }

    // Kyber 비밀키는 여기서는 사용하지 않음 (서버가 보관)
    OQS_MEM_secure_free(kyber_sk, kem->length_secret_key);

    // 2. ECDH 키쌍 (P-384)
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1);
    EVP_PKEY_keygen(ctx, ecdh_key);
    EVP_PKEY_CTX_free(ctx);

    // ECDH 공개키 추출
    size_t ecdh_pk_len = 0;
    EVP_PKEY_get_octet_string_param(*ecdh_key, OSSL_PKEY_PARAM_PUB_KEY,
                                    NULL, 0, &ecdh_pk_len);
    pk->ecdh_pk = malloc(ecdh_pk_len);
    pk->ecdh_pk_len = ecdh_pk_len;
    EVP_PKEY_get_octet_string_param(*ecdh_key, OSSL_PKEY_PARAM_PUB_KEY,
                                    pk->ecdh_pk, ecdh_pk_len, NULL);

    printf("[Server] Hybrid 키쌍 생성:\n");
    printf("  Kyber PK: %zu bytes\n", pk->kyber_pk_len);
    printf("  ECDH PK: %zu bytes\n", pk->ecdh_pk_len);

    return 0;
}

int hybrid_kem_encaps(OQS_KEM *kem, HybridPublicKey *pk,
                     HybridCiphertext *ct, uint8_t *shared_secret) {
    // 1. Kyber 캡슐화
    ct->kyber_ct_len = kem->length_ciphertext;
    ct->kyber_ct = malloc(ct->kyber_ct_len);
    uint8_t kyber_ss[32];

    if (kem->encaps(ct->kyber_ct, kyber_ss, pk->kyber_pk) != OQS_SUCCESS) {
        free(ct->kyber_ct);
        return -1;
    }

    // 2. ECDH 키 교환
    EVP_PKEY *client_ecdh = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1);
    EVP_PKEY_keygen(ctx, &client_ecdh);
    EVP_PKEY_CTX_free(ctx);

    // 클라이언트 ECDH 공개키 추출 (암호문)
    size_t ecdh_ct_len = 0;
    EVP_PKEY_get_octet_string_param(client_ecdh, OSSL_PKEY_PARAM_PUB_KEY,
                                    NULL, 0, &ecdh_ct_len);
    ct->ecdh_ct = malloc(ecdh_ct_len);
    ct->ecdh_ct_len = ecdh_ct_len;
    EVP_PKEY_get_octet_string_param(client_ecdh, OSSL_PKEY_PARAM_PUB_KEY,
                                    ct->ecdh_ct, ecdh_ct_len, NULL);

    // (실제로는 서버 ECDH 공개키와 키 교환 수행 필요)
    // 여기서는 단순화를 위해 생략

    // 3. Hybrid 공유 비밀 결합 (HKDF)
    // shared_secret = HKDF(kyber_ss || ecdh_ss)
    memcpy(shared_secret, kyber_ss, 32);
    // (ECDH 공유 비밀은 생략)
    memset(shared_secret + 32, 0xAB, 32);  // Placeholder

    OQS_MEM_secure_free(kyber_ss, 32);
    EVP_PKEY_free(client_ecdh);

    printf("[Client] Hybrid 캡슐화:\n");
    printf("  Kyber CT: %zu bytes\n", ct->kyber_ct_len);
    printf("  ECDH CT: %zu bytes\n", ct->ecdh_ct_len);

    return 0;
}

int main() {
    printf("=== Hybrid KEM Example (ECDH P-384 + Kyber1024) ===\n\n");

    OQS_KEM *kem = OQS_KEM_new("Kyber1024");
    if (kem == NULL) {
        fprintf(stderr, "ERROR: Kyber1024 not supported\n");
        return 1;
    }

    // 서버: Hybrid 키쌍 생성
    HybridPublicKey pk = {0};
    EVP_PKEY *server_ecdh = NULL;

    if (hybrid_kem_keypair(kem, &server_ecdh, &pk) != 0) {
        fprintf(stderr, "ERROR: Hybrid keypair failed\n");
        return 1;
    }

    // 클라이언트: Hybrid 캡슐화
    HybridCiphertext ct = {0};
    uint8_t shared_secret[HYBRID_SHARED_SECRET_LEN];

    if (hybrid_kem_encaps(kem, &pk, &ct, shared_secret) != 0) {
        fprintf(stderr, "ERROR: Hybrid encaps failed\n");
        return 1;
    }

    printf("\n✓ Hybrid 공유 비밀 (hex): ");
    for (int i = 0; i < HYBRID_SHARED_SECRET_LEN && i < 64; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");

    // 정리
    free(pk.kyber_pk);
    free(pk.ecdh_pk);
    free(ct.kyber_ct);
    free(ct.ecdh_ct);
    EVP_PKEY_free(server_ecdh);
    OQS_MEM_secure_free(shared_secret, HYBRID_SHARED_SECRET_LEN);
    OQS_KEM_free(kem);

    return 0;
}
```

---

## 4. Python 바인딩

### 4.1 liboqs-python 설치

```bash
# 방법 1: pip 설치 (권장)
pip3 install liboqs-python

# 방법 2: 소스에서 빌드
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
pip3 install .

# 설치 확인
python3 -c "import oqs; print(oqs.OQS_VERSION)"
```

### 4.2 Python KEM 예제

```python
#!/usr/bin/env python3
# python_kem.py

import oqs

def kem_example():
    print("=== Python liboqs KEM Example ===\n")

    # 1. KEM 생성
    algorithm = "Kyber1024"
    with oqs.KeyEncapsulation(algorithm) as kem:
        print(f"알고리즘: {kem.details['name']}")
        print(f"NIST 레벨: {kem.details['claimed_nist_level']}")
        print(f"공개키 크기: {kem.details['length_public_key']} bytes")
        print(f"암호문 크기: {kem.details['length_ciphertext']} bytes")
        print(f"공유 비밀 크기: {kem.details['length_shared_secret']} bytes\n")

        # 2. 키쌍 생성
        public_key = kem.generate_keypair()
        print("✓ 키쌍 생성 완료")

        # 3. 캡슐화 (클라이언트)
        ciphertext, shared_secret_client = kem.encap_secret(public_key)
        print("✓ 캡슐화 완료")

        # 4. 디캡슐화 (서버)
        shared_secret_server = kem.decap_secret(ciphertext)
        print("✓ 디캡슐화 완료")

        # 5. 공유 비밀 비교
        if shared_secret_client == shared_secret_server:
            print("✓ 공유 비밀 일치!\n")
            print(f"공유 비밀 (hex): {shared_secret_client[:32].hex()}...")
        else:
            print("✗ 공유 비밀 불일치!")

if __name__ == "__main__":
    kem_example()
```

**실행:**

```bash
python3 python_kem.py
```

### 4.3 Python Signature 예제

```python
#!/usr/bin/env python3
# python_sig.py

import oqs

def signature_example():
    print("=== Python liboqs Signature Example ===\n")

    # 1. Signature 생성
    algorithm = "Dilithium3"
    with oqs.Signature(algorithm) as sig:
        print(f"알고리즘: {sig.details['name']}")
        print(f"NIST 레벨: {sig.details['claimed_nist_level']}")
        print(f"공개키 크기: {sig.details['length_public_key']} bytes")
        print(f"서명 크기: {sig.details['length_signature']} bytes\n")

        # 2. 키쌍 생성
        public_key = sig.generate_keypair()
        print("✓ 키쌍 생성 완료")

        # 3. 서명할 메시지
        message = b"Hello, QSIGN from Python!"
        print(f"메시지: {message.decode()}")

        # 4. 서명 생성
        signature = sig.sign(message)
        print(f"✓ 서명 생성 완료 ({len(signature)} bytes)")

        # 5. 서명 검증
        is_valid = sig.verify(message, signature, public_key)
        if is_valid:
            print("✓ 서명 검증 성공!")
        else:
            print("✗ 서명 검증 실패!")

        # 6. 변조된 메시지 검증
        tampered_message = b"Tampered message"
        is_valid = sig.verify(tampered_message, signature, public_key)
        if not is_valid:
            print("✓ 변조된 메시지 검증 실패 (정상)")
        else:
            print("✗ 변조된 메시지 검증 성공 (문제!)")

if __name__ == "__main__":
    signature_example()
```

### 4.4 Python 알고리즘 조회

```python
#!/usr/bin/env python3
# list_algorithms.py

import oqs

def list_all_algorithms():
    print("=== 지원하는 알고리즘 목록 ===\n")

    # KEM 알고리즘
    print("KEM 알고리즘:")
    print(f"{'알고리즘':<30} {'활성화':<10} {'NIST 레벨':<12}")
    print("-" * 52)

    for alg in oqs.get_enabled_kem_mechanisms():
        with oqs.KeyEncapsulation(alg) as kem:
            details = kem.details
            print(f"{alg:<30} {'✓':<10} {details['claimed_nist_level']:<12}")

    print()

    # Signature 알고리즘
    print("Signature 알고리즘:")
    print(f"{'알고리즘':<30} {'활성화':<10} {'NIST 레벨':<12}")
    print("-" * 52)

    for alg in oqs.get_enabled_sig_mechanisms():
        with oqs.Signature(alg) as sig:
            details = sig.details
            print(f"{alg:<30} {'✓':<10} {details['claimed_nist_level']:<12}")

if __name__ == "__main__":
    list_all_algorithms()
```

---

## 5. Go 바인딩

### 5.1 liboqs-go 설치

```bash
# 1. liboqs 먼저 설치 (위의 빌드 섹션 참조)

# 2. liboqs-go 설치
go get github.com/open-quantum-safe/liboqs-go/oqs

# 3. CGO 환경 변수 설정 (필요 시)
export CGO_CFLAGS="-I/usr/local/include"
export CGO_LDFLAGS="-L/usr/local/lib -loqs"
```

### 5.2 Go KEM 예제

```go
// kem_example.go
package main

import (
    "bytes"
    "fmt"
    "github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
    fmt.Println("=== Go liboqs KEM Example ===\n")

    // 1. KEM 생성
    kem := oqs.KeyEncapsulation{}
    defer kem.Clean()

    algorithm := "Kyber1024"
    if err := kem.Init(algorithm, nil); err != nil {
        panic(fmt.Sprintf("KEM 생성 실패: %v", err))
    }

    details := kem.Details()
    fmt.Printf("알고리즘: %s\n", details.Name)
    fmt.Printf("NIST 레벨: %d\n", details.ClaimedNISTLevel)
    fmt.Printf("공개키 크기: %d bytes\n", details.LengthPublicKey)
    fmt.Printf("암호문 크기: %d bytes\n", details.LengthCiphertext)
    fmt.Printf("공유 비밀 크기: %d bytes\n\n", details.LengthSharedSecret)

    // 2. 키쌍 생성
    publicKey, err := kem.GenerateKeyPair()
    if err != nil {
        panic(fmt.Sprintf("키 생성 실패: %v", err))
    }
    fmt.Println("✓ 키쌍 생성 완료")

    // 3. 캡슐화 (클라이언트)
    ciphertext, sharedSecretClient, err := kem.EncapSecret(publicKey)
    if err != nil {
        panic(fmt.Sprintf("캡슐화 실패: %v", err))
    }
    fmt.Println("✓ 캡슐화 완료")

    // 4. 디캡슐화 (서버)
    sharedSecretServer, err := kem.DecapSecret(ciphertext)
    if err != nil {
        panic(fmt.Sprintf("디캡슐화 실패: %v", err))
    }
    fmt.Println("✓ 디캡슐화 완료")

    // 5. 공유 비밀 비교
    if bytes.Equal(sharedSecretClient, sharedSecretServer) {
        fmt.Println("✓ 공유 비밀 일치!\n")
        fmt.Printf("공유 비밀 (hex): %x...\n", sharedSecretClient[:32])
    } else {
        fmt.Println("✗ 공유 비밀 불일치!")
    }
}
```

**실행:**

```bash
go run kem_example.go
```

### 5.3 Go Signature 예제

```go
// sig_example.go
package main

import (
    "fmt"
    "github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
    fmt.Println("=== Go liboqs Signature Example ===\n")

    // 1. Signature 생성
    sig := oqs.Signature{}
    defer sig.Clean()

    algorithm := "Dilithium3"
    if err := sig.Init(algorithm, nil); err != nil {
        panic(fmt.Sprintf("Signature 생성 실패: %v", err))
    }

    details := sig.Details()
    fmt.Printf("알고리즘: %s\n", details.Name)
    fmt.Printf("NIST 레벨: %d\n", details.ClaimedNISTLevel)
    fmt.Printf("공개키 크기: %d bytes\n", details.LengthPublicKey)
    fmt.Printf("서명 크기: %d bytes\n\n", details.LengthSignature)

    // 2. 키쌍 생성
    publicKey, err := sig.GenerateKeyPair()
    if err != nil {
        panic(fmt.Sprintf("키 생성 실패: %v", err))
    }
    fmt.Println("✓ 키쌍 생성 완료")

    // 3. 서명할 메시지
    message := []byte("Hello, QSIGN from Go!")
    fmt.Printf("메시지: %s\n", string(message))

    // 4. 서명 생성
    signature, err := sig.Sign(message)
    if err != nil {
        panic(fmt.Sprintf("서명 생성 실패: %v", err))
    }
    fmt.Printf("✓ 서명 생성 완료 (%d bytes)\n", len(signature))

    // 5. 서명 검증
    isValid, err := sig.Verify(message, signature, publicKey)
    if err != nil {
        panic(fmt.Sprintf("서명 검증 오류: %v", err))
    }

    if isValid {
        fmt.Println("✓ 서명 검증 성공!")
    } else {
        fmt.Println("✗ 서명 검증 실패!")
    }

    // 6. 변조된 메시지 검증
    tamperedMessage := []byte("Tampered message")
    isValid, _ = sig.Verify(tamperedMessage, signature, publicKey)
    if !isValid {
        fmt.Println("✓ 변조된 메시지 검증 실패 (정상)")
    } else {
        fmt.Println("✗ 변조된 메시지 검증 성공 (문제!)")
    }
}
```

---

## 6. 알고리즘 선택 가이드

### 6.1 선택 기준

```yaml
고려 사항:
  1. 보안 수준:
     - NIST Level 1 (128-bit): IoT, 리소스 제약
     - NIST Level 3 (192-bit): 일반 애플리케이션 (권장)
     - NIST Level 5 (256-bit): 최고 보안 요구사항

  2. 성능:
     - 키 생성 속도
     - 서명/암호화 속도
     - 검증/복호화 속도
     - TLS 핸드셰이크 영향

  3. 크기:
     - 공개키 크기 (인증서, 저장)
     - 서명/암호문 크기 (네트워크 대역폭)
     - 메모리 사용량

  4. 표준화:
     - NIST 표준 (FIPS 203/204/205)
     - IETF RFC
     - 산업 채택률
```

### 6.2 권장 조합

#### QSIGN 프로덕션 (권장)

```yaml
KEM:
  알고리즘: Kyber1024
  이유:
    - NIST Level 5 보안
    - 빠른 성능 (< 0.1 ms)
    - 합리적인 크기 (pk: 1568, ct: 1568)
    - FIPS 203 표준

Signature:
  알고리즘: Dilithium3
  이유:
    - NIST Level 3 보안 (충분)
    - 균형잡힌 성능/크기
    - 빠른 검증 (< 0.1 ms)
    - FIPS 204 표준

백업 Signature:
  알고리즘: SPHINCS+-SHA2-256s
  이유:
    - 순수 해시 기반 (검증된 안전성)
    - Stateless
    - 장기 보관 문서용
```

#### 고성능 시스템

```yaml
KEM: Kyber768
Signature: Dilithium2 또는 Falcon-512

이유:
  - 더 빠른 성능
  - 작은 크기
  - NIST Level 1-3 (대부분 충분)
```

#### 최고 보안

```yaml
KEM: Classic-McEliece-460896
Signature: SPHINCS+-SHA2-256s

이유:
  - 최고 보안 수준
  - 순수 해시 또는 code-based
  - 성능/크기 희생
```

---

## 7. 성능 튜닝

### 7.1 컴파일러 최적화

```bash
# 최대 성능 빌드
cmake -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -flto" \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_DIST_BUILD=OFF \
    ..

ninja
```

### 7.2 CPU 최적화 확인

```c
// check_cpu.c
#include <stdio.h>
#include <oqs/oqs.h>

int main() {
    OQS_init();

    printf("CPU 기능 지원:\n");
    printf("  AVX: %s\n", OQS_CPU_has_extension(OQS_CPU_EXT_AVX) ? "✓" : "✗");
    printf("  AVX2: %s\n", OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) ? "✓" : "✗");
    printf("  AVX-512: %s\n", OQS_CPU_has_extension(OQS_CPU_EXT_AVX512) ? "✓" : "✗");
    printf("  BMI2: %s\n", OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) ? "✓" : "✗");
    printf("  AES-NI: %s\n", OQS_CPU_has_extension(OQS_CPU_EXT_AES_NI) ? "✓" : "✗");

    return 0;
}
```

---

## 8. 트러블슈팅

### 8.1 일반적인 문제

#### 문제 1: `liboqs.so` 찾을 수 없음

```bash
# 증상
./hello_kem: error while loading shared libraries: liboqs.so.0.10.0: cannot open shared object file

# 해결
sudo ldconfig
# 또는
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

#### 문제 2: 헤더 파일 찾을 수 없음

```bash
# 증상
fatal error: oqs/oqs.h: No such file or directory

# 해결
# C_INCLUDE_PATH 설정
export C_INCLUDE_PATH=/usr/local/include:$C_INCLUDE_PATH

# 또는 컴파일 시 -I 옵션
gcc -I/usr/local/include hello_kem.c -o hello_kem -loqs
```

#### 문제 3: OpenSSL 연동 오류

```bash
# 증상
undefined reference to `OPENSSL_cleanse'

# 해결
# OpenSSL도 링크
gcc hello_kem.c -o hello_kem -loqs -lssl -lcrypto
```

---

**문서 정보**

```yaml
문서명: LIBOQS-INTEGRATION.md
작성일: 2025-11-16
버전: 1.0.0
상태: 최종
작성자: QSIGN Documentation Team
관련 문서:
  - OQS-OVERVIEW.md - OQS 프로젝트 개요
  - OQS-ARCHITECTURE.md - OQS 아키텍처
  - OQS-DESIGN.md - API 상세 설계
  - OQS-QSIGN-INTEGRATION.md - QSIGN 통합
```

---

**다음 단계**

1. **OpenSSL 통합**: [OPENSSL-OQS.md](./OPENSSL-OQS.md)에서 oqs-provider 사용법을 학습하세요.
2. **QSIGN 적용**: [OQS-QSIGN-INTEGRATION.md](./OQS-QSIGN-INTEGRATION.md)에서 실제 시스템 통합을 확인하세요.
3. **테스트**: [TESTING-VALIDATION.md](./TESTING-VALIDATION.md)에서 테스트 방법을 학습하세요.
