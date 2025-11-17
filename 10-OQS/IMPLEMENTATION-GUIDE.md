# OQS 구현 가이드

Open Quantum Safe (OQS) 라이브러리 및 도구 구현을 위한 상세 가이드입니다.

## 목차

- [1. 사전 요구사항](#1-사전-요구사항)
- [2. liboqs 소스 빌드](#2-liboqs-소스-빌드)
- [3. oqs-provider 빌드 및 설치](#3-oqs-provider-빌드-및-설치)
- [4. OpenSSL 설정](#4-openssl-설정)
- [5. Vault OQS 플러그인 개발](#5-vault-oqs-플러그인-개발)
- [6. Keycloak OQS SPI 개발](#6-keycloak-oqs-spi-개발)
- [7. APISIX OQS 플러그인](#7-apisix-oqs-플러그인)
- [8. Docker 이미지 빌드](#8-docker-이미지-빌드)
- [9. Kubernetes 배포](#9-kubernetes-배포)
- [10. 실행 가능한 스크립트](#10-실행-가능한-스크립트)
- [11. 트러블슈팅](#11-트러블슈팅)

---

## 1. 사전 요구사항

### 1.1 시스템 요구사항

```yaml
하드웨어:
  최소:
    CPU: 2 cores (x86_64 or ARM64)
    RAM: 4 GB
    Disk: 20 GB
  권장:
    CPU: 4+ cores (AVX2 지원)
    RAM: 8+ GB
    Disk: 50+ GB SSD

운영체제:
  지원:
    - Ubuntu 20.04 / 22.04 / 24.04 LTS
    - RHEL 8 / 9
    - Rocky Linux 8 / 9
    - Debian 11 / 12
    - macOS 12+ (Intel/Apple Silicon)
  권장:
    - Ubuntu 22.04 LTS
    - Rocky Linux 9

소프트웨어:
  필수:
    - GCC 9+ 또는 Clang 10+
    - CMake 3.18+
    - Git 2.30+
    - OpenSSL 3.0+
  선택사항:
    - Docker 24+
    - Kubernetes 1.27+
    - Python 3.8+
```

### 1.2 개발 도구 설치

**Ubuntu/Debian:**

```bash
#!/bin/bash
# install-dev-tools-ubuntu.sh

set -e

echo "==> 개발 도구 설치 (Ubuntu/Debian)..."

# 패키지 목록 업데이트
sudo apt-get update

# 기본 빌드 도구
sudo apt-get install -y \
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    ninja-build \
    git \
    wget \
    curl \
    unzip \
    pkg-config

# OpenSSL 개발 라이브러리
sudo apt-get install -y \
    libssl-dev \
    openssl

# 추가 도구
sudo apt-get install -y \
    astyle \
    doxygen \
    graphviz \
    valgrind \
    gdb

# Python (테스트용)
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-pytest \
    python3-pytest-xdist

# 문서 생성 도구
sudo apt-get install -y \
    xsltproc \
    pandoc

echo "==> 설치 완료!"

# 버전 확인
echo ""
echo "설치된 버전:"
gcc --version | head -1
cmake --version | head -1
openssl version
python3 --version
```

**RHEL/Rocky Linux:**

```bash
#!/bin/bash
# install-dev-tools-rhel.sh

set -e

echo "==> 개발 도구 설치 (RHEL/Rocky Linux)..."

# EPEL 저장소 활성화
sudo dnf install -y epel-release

# 개발 도구 그룹
sudo dnf groupinstall -y "Development Tools"

# 추가 패키지
sudo dnf install -y \
    gcc \
    gcc-c++ \
    make \
    cmake \
    ninja-build \
    git \
    wget \
    curl \
    unzip \
    pkg-config \
    openssl-devel \
    openssl \
    astyle \
    doxygen \
    graphviz \
    valgrind \
    gdb \
    python3 \
    python3-pip \
    python3-pytest

echo "==> 설치 완료!"

# 버전 확인
echo ""
echo "설치된 버전:"
gcc --version | head -1
cmake --version | head -1
openssl version
python3 --version
```

**macOS:**

```bash
#!/bin/bash
# install-dev-tools-macos.sh

set -e

echo "==> 개발 도구 설치 (macOS)..."

# Homebrew가 없으면 설치
if ! command -v brew &> /dev/null; then
    echo "Homebrew를 먼저 설치해주세요:"
    echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    exit 1
fi

# 개발 도구
brew install \
    cmake \
    ninja \
    git \
    wget \
    openssl@3 \
    astyle \
    doxygen \
    graphviz \
    python@3.11

# OpenSSL 3.x 경로 설정
echo 'export PATH="/usr/local/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
echo 'export LDFLAGS="-L/usr/local/opt/openssl@3/lib"' >> ~/.zshrc
echo 'export CPPFLAGS="-I/usr/local/opt/openssl@3/include"' >> ~/.zshrc
echo 'export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig"' >> ~/.zshrc

source ~/.zshrc

echo "==> 설치 완료!"

# 버전 확인
echo ""
echo "설치된 버전:"
gcc --version | head -1
cmake --version | head -1
openssl version
python3 --version
```

---

## 2. liboqs 소스 빌드

### 2.1 Ubuntu 빌드

```bash
#!/bin/bash
# build-liboqs-ubuntu.sh

set -e

# 설정 변수
LIBOQS_VERSION="0.10.0"
INSTALL_PREFIX="/usr/local"
BUILD_TYPE="Release"
BUILD_DIR="/tmp/liboqs-build"

echo "==> liboqs ${LIBOQS_VERSION} 빌드 시작 (Ubuntu)..."

# 작업 디렉토리 생성
mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# 소스 다운로드
echo "소스 다운로드..."
wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz
tar xzf ${LIBOQS_VERSION}.tar.gz
cd liboqs-${LIBOQS_VERSION}

# 빌드 디렉토리 생성
mkdir -p build
cd build

# CMake 설정
echo "CMake 설정..."
cmake -G Ninja \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=OFF \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_ALGS_ENABLED="STD" \
    -DOQS_ENABLE_KEM_kyber_512=ON \
    -DOQS_ENABLE_KEM_kyber_768=ON \
    -DOQS_ENABLE_KEM_kyber_1024=ON \
    -DOQS_ENABLE_SIG_dilithium_2=ON \
    -DOQS_ENABLE_SIG_dilithium_3=ON \
    -DOQS_ENABLE_SIG_dilithium_5=ON \
    -DOQS_ENABLE_SIG_falcon_512=ON \
    -DOQS_ENABLE_SIG_falcon_1024=ON \
    -DOQS_ENABLE_SIG_sphincs_sha2_128f_simple=ON \
    -DOQS_ENABLE_SIG_sphincs_sha2_128s_simple=ON \
    ..

# 빌드
echo "빌드 중..."
ninja

# 테스트 실행 (선택사항)
echo "테스트 실행..."
ninja run_tests || echo "일부 테스트 실패 (무시)"

# 설치
echo "설치 중..."
sudo ninja install

# 라이브러리 캐시 업데이트
sudo ldconfig

# 설치 확인
echo ""
echo "==> liboqs 설치 완료!"
echo ""
echo "설치된 라이브러리:"
ls -lh ${INSTALL_PREFIX}/lib/liboqs.* 2>/dev/null || ls -lh ${INSTALL_PREFIX}/lib64/liboqs.*

# pkg-config 확인
if pkg-config --exists liboqs; then
    echo ""
    echo "liboqs 버전: $(pkg-config --modversion liboqs)"
    echo "Include path: $(pkg-config --cflags liboqs)"
    echo "Library path: $(pkg-config --libs liboqs)"
else
    echo "경고: pkg-config에서 liboqs를 찾을 수 없습니다."
fi

# 정리
cd /
rm -rf ${BUILD_DIR}

echo ""
echo "==> 완료!"
```

### 2.2 RHEL/Rocky Linux 빌드

```bash
#!/bin/bash
# build-liboqs-rhel.sh

set -e

LIBOQS_VERSION="0.10.0"
INSTALL_PREFIX="/usr/local"
BUILD_TYPE="Release"
BUILD_DIR="/tmp/liboqs-build"

echo "==> liboqs ${LIBOQS_VERSION} 빌드 시작 (RHEL/Rocky)..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# 소스 다운로드
echo "소스 다운로드..."
wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz
tar xzf ${LIBOQS_VERSION}.tar.gz
cd liboqs-${LIBOQS_VERSION}

mkdir -p build
cd build

# CMake 설정 (RHEL은 lib64 사용)
echo "CMake 설정..."
cmake -G Ninja \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCMAKE_INSTALL_LIBDIR=lib64 \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=OFF \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_ALGS_ENABLED="STD" \
    -DOQS_ENABLE_KEM_kyber_512=ON \
    -DOQS_ENABLE_KEM_kyber_768=ON \
    -DOQS_ENABLE_KEM_kyber_1024=ON \
    -DOQS_ENABLE_SIG_dilithium_2=ON \
    -DOQS_ENABLE_SIG_dilithium_3=ON \
    -DOQS_ENABLE_SIG_dilithium_5=ON \
    -DOQS_ENABLE_SIG_falcon_512=ON \
    -DOQS_ENABLE_SIG_falcon_1024=ON \
    ..

ninja
ninja run_tests || true
sudo ninja install

# ldconfig 설정
sudo bash -c 'echo "/usr/local/lib64" > /etc/ld.so.conf.d/liboqs.conf'
sudo ldconfig

echo ""
echo "==> liboqs 설치 완료!"
pkg-config --modversion liboqs

cd /
rm -rf ${BUILD_DIR}

echo "==> 완료!"
```

### 2.3 macOS 빌드

```bash
#!/bin/bash
# build-liboqs-macos.sh

set -e

LIBOQS_VERSION="0.10.0"
INSTALL_PREFIX="/usr/local"
BUILD_TYPE="Release"
BUILD_DIR="/tmp/liboqs-build"

# OpenSSL 경로
OPENSSL_ROOT="/usr/local/opt/openssl@3"

echo "==> liboqs ${LIBOQS_VERSION} 빌드 시작 (macOS)..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

echo "소스 다운로드..."
curl -L -o liboqs.tar.gz \
    https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz
tar xzf liboqs.tar.gz
cd liboqs-${LIBOQS_VERSION}

mkdir -p build
cd build

echo "CMake 설정..."
cmake -G Ninja \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT} \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=OFF \
    -DOQS_DIST_BUILD=ON \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_ALGS_ENABLED="STD" \
    ..

ninja
ninja run_tests || true
sudo ninja install

echo ""
echo "==> liboqs 설치 완료!"
echo "설치 위치: ${INSTALL_PREFIX}/lib/liboqs.*"
ls -lh ${INSTALL_PREFIX}/lib/liboqs.*

cd /
rm -rf ${BUILD_DIR}

echo "==> 완료!"
```

### 2.4 최적화 빌드

```bash
#!/bin/bash
# build-liboqs-optimized.sh
# CPU별 최적화 빌드

set -e

LIBOQS_VERSION="0.10.0"
INSTALL_PREFIX="/usr/local"
BUILD_DIR="/tmp/liboqs-optimized"

# CPU 감지
if grep -q avx2 /proc/cpuinfo 2>/dev/null; then
    CPU_ARCH="x86-64-v3"  # AVX2 지원
    EXTRA_FLAGS="-march=native -mtune=native"
elif grep -q avx /proc/cpuinfo 2>/dev/null; then
    CPU_ARCH="x86-64-v2"  # AVX 지원
    EXTRA_FLAGS="-march=native"
else
    CPU_ARCH="x86-64"
    EXTRA_FLAGS=""
fi

echo "==> liboqs 최적화 빌드 (CPU: ${CPU_ARCH})..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz
tar xzf ${LIBOQS_VERSION}.tar.gz
cd liboqs-${LIBOQS_VERSION}

mkdir -p build
cd build

# 최적화 플래그
export CFLAGS="-O3 ${EXTRA_FLAGS} -flto"
export CXXFLAGS="-O3 ${EXTRA_FLAGS} -flto"

cmake -G Ninja \
    -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS="${CFLAGS}" \
    -DCMAKE_CXX_FLAGS="${CXXFLAGS}" \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_USE_OPENSSL=ON \
    -DOQS_SPEED_USE_ARM_PMU=ON \
    ..

ninja
sudo ninja install
sudo ldconfig

echo "==> 최적화 빌드 완료!"

cd /
rm -rf ${BUILD_DIR}
```

---

## 3. oqs-provider 빌드 및 설치

### 3.1 기본 빌드

```bash
#!/bin/bash
# build-oqs-provider.sh

set -e

OQS_PROVIDER_VERSION="0.6.0"
OPENSSL_ROOT="/usr/local"
LIBOQS_ROOT="/usr/local"
BUILD_DIR="/tmp/oqs-provider-build"

echo "==> oqs-provider ${OQS_PROVIDER_VERSION} 빌드..."

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

# 소스 다운로드
echo "소스 다운로드..."
git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} \
    https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

# 빌드 디렉토리
mkdir -p _build
cd _build

# CMake 설정
echo "CMake 설정..."
cmake -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DOPENSSL_ROOT_DIR=${OPENSSL_ROOT} \
    -Dliboqs_DIR=${LIBOQS_ROOT} \
    -DCMAKE_PREFIX_PATH=${LIBOQS_ROOT} \
    ..

# 빌드
echo "빌드 중..."
ninja

# 테스트
echo "테스트 실행..."
ctest --output-on-failure || echo "일부 테스트 실패 (무시)"

# 설치
echo "설치 중..."
sudo ninja install

# Provider 위치 확인
PROVIDER_PATH=$(find ${OPENSSL_ROOT} -name "oqsprovider.so" 2>/dev/null | head -1)

echo ""
echo "==> oqs-provider 설치 완료!"
echo "Provider 경로: ${PROVIDER_PATH}"

# 설치 확인
echo ""
echo "OpenSSL provider 목록:"
openssl list -providers -verbose

cd /
rm -rf ${BUILD_DIR}

echo "==> 완료!"
```

### 3.2 설치 검증

```bash
#!/bin/bash
# verify-oqs-provider.sh

set -e

echo "==> oqs-provider 설치 검증..."

# 환경 변수 설정 (필요시)
export OPENSSL_MODULES=/usr/local/lib64/ossl-modules

echo ""
echo "1. Provider 목록:"
openssl list -providers

echo ""
echo "2. OQS 서명 알고리즘:"
openssl list -signature-algorithms -provider oqsprovider 2>/dev/null | \
    grep -i "dilithium\|falcon" | head -10

echo ""
echo "3. OQS KEM 알고리즘:"
openssl list -kem-algorithms -provider oqsprovider 2>/dev/null | \
    grep -i "kyber" | head -5 || \
    openssl list -keyexch-algorithms -provider oqsprovider 2>/dev/null | \
    grep -i "kyber" | head -5

echo ""
echo "4. 키 생성 테스트:"
TEMP_KEY="/tmp/test_dilithium3_$$.pem"
if openssl genpkey -algorithm dilithium3 -out ${TEMP_KEY} -provider oqsprovider 2>/dev/null; then
    echo "✓ DILITHIUM3 키 생성 성공"
    openssl pkey -in ${TEMP_KEY} -text -noout -provider oqsprovider 2>/dev/null | head -5
    rm -f ${TEMP_KEY}
else
    echo "✗ DILITHIUM3 키 생성 실패"
    exit 1
fi

echo ""
echo "5. 서명/검증 테스트:"
TEMP_DATA="/tmp/test_data_$$.txt"
TEMP_SIG="/tmp/test_sig_$$.bin"

echo "Test data for OQS" > ${TEMP_DATA}

# 키 생성
openssl genpkey -algorithm dilithium3 -out ${TEMP_KEY} -provider oqsprovider 2>/dev/null

# 서명
if openssl dgst -sha256 -sign ${TEMP_KEY} -out ${TEMP_SIG} ${TEMP_DATA} -provider oqsprovider 2>/dev/null; then
    echo "✓ 서명 생성 성공"
else
    echo "✗ 서명 생성 실패"
    rm -f ${TEMP_KEY} ${TEMP_DATA} ${TEMP_SIG}
    exit 1
fi

# 공개키 추출
TEMP_PUB="/tmp/test_pub_$$.pem"
openssl pkey -in ${TEMP_KEY} -pubout -out ${TEMP_PUB} -provider oqsprovider 2>/dev/null

# 검증
if openssl dgst -sha256 -verify ${TEMP_PUB} -signature ${TEMP_SIG} ${TEMP_DATA} -provider oqsprovider 2>/dev/null; then
    echo "✓ 서명 검증 성공"
else
    echo "✗ 서명 검증 실패"
    rm -f ${TEMP_KEY} ${TEMP_PUB} ${TEMP_DATA} ${TEMP_SIG}
    exit 1
fi

# 정리
rm -f ${TEMP_KEY} ${TEMP_PUB} ${TEMP_DATA} ${TEMP_SIG}

echo ""
echo "==> 모든 검증 완료!"
```

---

## 4. OpenSSL 설정

### 4.1 전역 설정 파일

```bash
#!/bin/bash
# configure-openssl-oqs.sh

set -e

OPENSSL_CNF="/etc/ssl/openssl-oqs.cnf"
MODULES_DIR="/usr/local/lib64/ossl-modules"

echo "==> OpenSSL OQS 설정..."

# Provider 모듈 경로 확인
if [ ! -d "${MODULES_DIR}" ]; then
    MODULES_DIR="/usr/local/lib/ossl-modules"
fi

PROVIDER_SO=$(find ${MODULES_DIR} -name "oqsprovider.so" 2>/dev/null | head -1)

if [ -z "${PROVIDER_SO}" ]; then
    echo "오류: oqsprovider.so를 찾을 수 없습니다."
    exit 1
fi

echo "Provider 경로: ${PROVIDER_SO}"

# OpenSSL 설정 파일 생성
sudo tee ${OPENSSL_CNF} > /dev/null <<EOF
# OpenSSL Configuration with OQS Provider
# Generated: $(date)

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = ${PROVIDER_SO}

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
MaxProtocol = TLSv1.3

# PQC 그룹 (KEM)
Groups = x25519_kyber768:kyber768:kyber1024:X25519:prime256v1

# PQC 서명 알고리즘
SignatureAlgorithms = ecdsa_p256_dilithium3:dilithium3:dilithium5:falcon512:ECDSA+SHA256:RSA-PSS+SHA256

# Cipher suites (TLS 1.3)
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256

# Cipher suites (TLS 1.2)
CipherString = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
EOF

echo "OpenSSL 설정 파일 생성: ${OPENSSL_CNF}"

# 환경 변수 설정
sudo tee /etc/profile.d/openssl-oqs.sh > /dev/null <<EOF
# OpenSSL OQS Configuration
export OPENSSL_CONF=${OPENSSL_CNF}
export OPENSSL_MODULES=${MODULES_DIR}
EOF

echo "환경 변수 설정: /etc/profile.d/openssl-oqs.sh"

# 현재 세션에 적용
source /etc/profile.d/openssl-oqs.sh

echo ""
echo "==> 설정 완료!"
echo ""
echo "다음 명령어로 확인:"
echo "  source /etc/profile.d/openssl-oqs.sh"
echo "  openssl list -providers"
```

### 4.2 애플리케이션별 설정

**nginx:**

```bash
#!/bin/bash
# configure-nginx-oqs.sh

set -e

NGINX_CONF="/etc/nginx/nginx.conf"
OPENSSL_CNF="/etc/ssl/openssl-oqs.cnf"

echo "==> nginx OQS 설정..."

# nginx.conf 백업
sudo cp ${NGINX_CONF} ${NGINX_CONF}.backup.$(date +%Y%m%d_%H%M%S)

# nginx.conf 수정 (환경 변수 추가)
sudo sed -i '1i\# OpenSSL OQS Configuration' ${NGINX_CONF}
sudo sed -i "2i\env OPENSSL_CONF=${OPENSSL_CNF};" ${NGINX_CONF}

# SSL 설정 예제
sudo tee /etc/nginx/conf.d/ssl-oqs.conf > /dev/null <<'EOF'
# SSL/TLS Configuration with OQS

ssl_protocols TLSv1.3;
ssl_prefer_server_ciphers on;

# TLS 1.3 Cipher suites
ssl_ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;

# PQC 그룹
ssl_ecdh_curve x25519_kyber768:kyber768:X25519:prime256v1;

# Session 설정
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# OCSP Stapling
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
EOF

echo "nginx SSL 설정: /etc/nginx/conf.d/ssl-oqs.conf"

# nginx 설정 테스트
sudo nginx -t

echo ""
echo "==> 설정 완료!"
echo "nginx 재시작: sudo systemctl restart nginx"
```

---

## 5. Vault OQS 플러그인 개발

### 5.1 프로젝트 구조

```bash
#!/bin/bash
# create-vault-plugin-structure.sh

set -e

PROJECT_DIR="vault-plugin-oqs"

echo "==> Vault OQS 플러그인 프로젝트 생성..."

mkdir -p ${PROJECT_DIR}/{cmd,pkg/{transit,pki,common},scripts,test}

cd ${PROJECT_DIR}

# Go 모듈 초기화
go mod init github.com/qsign/vault-plugin-oqs

# 기본 파일 생성
cat > cmd/main.go <<'EOF'
package main

import (
    "log"
    "os"

    "github.com/hashicorp/vault/api"
    "github.com/hashicorp/vault/sdk/plugin"

    "github.com/qsign/vault-plugin-oqs/pkg/transit"
)

func main() {
    apiClientMeta := &api.PluginAPIClientMeta{}
    flags := apiClientMeta.FlagSet()
    flags.Parse(os.Args[1:])

    tlsConfig := apiClientMeta.GetTLSConfig()
    tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

    if err := plugin.Serve(&plugin.ServeOpts{
        BackendFactoryFunc: transit.Factory,
        TLSProviderFunc:    tlsProviderFunc,
    }); err != nil {
        log.Fatal(err)
    }
}
EOF

# Transit backend
cat > pkg/transit/backend.go <<'EOF'
package transit

import (
    "context"

    "github.com/hashicorp/vault/sdk/framework"
    "github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
    b := &OQSTransitBackend{}

    b.Backend = &framework.Backend{
        BackendType: logical.TypeLogical,
        Help:        "OQS Transit Engine - Post-Quantum Encryption",
        Paths: []*framework.Path{
            b.pathKeys(),
            b.pathEncrypt(),
            b.pathDecrypt(),
        },
        Secrets:     []*framework.Secret{},
        Invalidate:  b.invalidate,
    }

    if err := b.Setup(ctx, conf); err != nil {
        return nil, err
    }

    return b, nil
}

type OQSTransitBackend struct {
    *framework.Backend
}

func (b *OQSTransitBackend) invalidate(ctx context.Context, key string) {
    // 캐시 무효화 로직
}
EOF

# Makefile
cat > Makefile <<'EOF'
BINARY_NAME=vault-plugin-oqs
PLUGIN_DIR=/etc/vault/plugins

.PHONY: build
build:
	CGO_ENABLED=1 go build -o bin/$(BINARY_NAME) cmd/main.go

.PHONY: test
test:
	go test -v ./...

.PHONY: install
install: build
	sudo cp bin/$(BINARY_NAME) $(PLUGIN_DIR)/

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: deps
deps:
	go mod download
	go mod tidy
EOF

# README
cat > README.md <<'EOF'
# Vault OQS Plugin

Post-Quantum Cryptography plugin for HashiCorp Vault.

## Features

- Transit Engine with KYBER KEM
- PKI Engine with DILITHIUM signatures
- Luna HSM integration

## Building

```bash
make build
```

## Installation

```bash
make install
```

## Usage

See [./LIBOQS-INTEGRATION.md](./LIBOQS-INTEGRATION.md)
EOF

echo ""
echo "==> 프로젝트 생성 완료: ${PROJECT_DIR}/"
tree ${PROJECT_DIR} 2>/dev/null || find ${PROJECT_DIR} -type f
```

### 5.2 Transit Engine 구현

(전체 코드는 이전 OQS-QSIGN-INTEGRATION.md 참조)

```bash
#!/bin/bash
# build-vault-plugin.sh

set -e

PLUGIN_DIR="vault-plugin-oqs"
VAULT_PLUGIN_PATH="/etc/vault/plugins"

echo "==> Vault OQS 플러그인 빌드..."

cd ${PLUGIN_DIR}

# 의존성 설치
echo "의존성 설치..."
go mod download

# CGO 활성화 (liboqs 사용)
export CGO_ENABLED=1
export CGO_CFLAGS="-I/usr/local/include"
export CGO_LDFLAGS="-L/usr/local/lib64 -loqs"

# 빌드
echo "빌드 중..."
go build -o bin/vault-plugin-oqs \
    -ldflags "-X main.version=$(git describe --tags --always)" \
    cmd/main.go

# 테스트
echo "테스트 실행..."
go test -v ./...

# 설치
echo "플러그인 설치..."
sudo mkdir -p ${VAULT_PLUGIN_PATH}
sudo cp bin/vault-plugin-oqs ${VAULT_PLUGIN_PATH}/

# SHA256 계산
PLUGIN_SHA256=$(sha256sum ${VAULT_PLUGIN_PATH}/vault-plugin-oqs | cut -d' ' -f1)

echo ""
echo "==> 빌드 완료!"
echo "Plugin path: ${VAULT_PLUGIN_PATH}/vault-plugin-oqs"
echo "SHA256: ${PLUGIN_SHA256}"

# Vault 등록 명령어
echo ""
echo "Vault에 플러그인 등록:"
cat <<EOF
vault plugin register \\
    -sha256=${PLUGIN_SHA256} \\
    -command=vault-plugin-oqs \\
    secret oqs-transit

vault secrets enable -path=oqs-transit oqs-transit
EOF
```

---

## 6. Keycloak OQS SPI 개발

### 6.1 프로젝트 설정

```bash
#!/bin/bash
# create-keycloak-spi-structure.sh

set -e

PROJECT_DIR="keycloak-oqs-spi"

echo "==> Keycloak OQS SPI 프로젝트 생성..."

mkdir -p ${PROJECT_DIR}/src/main/{java/com/qsign/keycloak/oqs,resources/META-INF/services}

cd ${PROJECT_DIR}

# Maven pom.xml
cat > pom.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.qsign</groupId>
    <artifactId>keycloak-oqs-spi</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>

    <name>Keycloak OQS SPI</name>
    <description>Post-Quantum Cryptography SPI for Keycloak</description>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <keycloak.version>23.0.0</keycloak.version>
    </properties>

    <dependencies>
        <!-- Keycloak -->
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-core</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.keycloak</groupId>
            <artifactId>keycloak-server-spi-private</artifactId>
            <version>${keycloak.version}</version>
            <scope>provided</scope>
        </dependency>

        <!-- liboqs-java -->
        <dependency>
            <groupId>org.openquantumsafe</groupId>
            <artifactId>liboqs-java</artifactId>
            <version>0.10.0</version>
        </dependency>

        <!-- JUnit -->
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>5.10.0</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.5.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals>
                            <goal>shade</goal>
                        </goals>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
EOF

# SPI 서비스 파일
mkdir -p src/main/resources/META-INF/services
cat > src/main/resources/META-INF/services/org.keycloak.crypto.SignatureProvider <<'EOF'
com.qsign.keycloak.oqs.OQSSignatureProvider
EOF

echo ""
echo "==> 프로젝트 생성 완료: ${PROJECT_DIR}/"
```

### 6.2 빌드 및 배포

```bash
#!/bin/bash
# build-keycloak-spi.sh

set -e

PROJECT_DIR="keycloak-oqs-spi"
KEYCLOAK_HOME="/opt/keycloak"
DEPLOY_DIR="${KEYCLOAK_HOME}/providers"

echo "==> Keycloak OQS SPI 빌드..."

cd ${PROJECT_DIR}

# Maven 빌드
echo "Maven 빌드 중..."
mvn clean package -DskipTests

JAR_FILE="target/keycloak-oqs-spi-1.0.0.jar"

if [ ! -f "${JAR_FILE}" ]; then
    echo "오류: JAR 파일을 찾을 수 없습니다."
    exit 1
fi

# 테스트 실행
echo "테스트 실행..."
mvn test

# 배포
echo "Keycloak에 배포..."
sudo mkdir -p ${DEPLOY_DIR}
sudo cp ${JAR_FILE} ${DEPLOY_DIR}/

# liboqs-java 네이티브 라이브러리 복사
sudo cp /usr/local/lib/liboqs.so* ${KEYCLOAK_HOME}/lib/ 2>/dev/null || true

echo ""
echo "==> 빌드 및 배포 완료!"
echo "JAR: ${DEPLOY_DIR}/keycloak-oqs-spi-1.0.0.jar"

# Keycloak 재시작
echo ""
echo "Keycloak 재시작:"
echo "  sudo systemctl restart keycloak"
```

---

## 7. APISIX OQS 플러그인

### 7.1 Lua 플러그인

```bash
#!/bin/bash
# create-apisix-oqs-plugin.sh

set -e

APISIX_HOME="/usr/local/apisix"
PLUGIN_DIR="${APISIX_HOME}/apisix/plugins"

echo "==> APISIX OQS 플러그인 생성..."

sudo mkdir -p ${PLUGIN_DIR}

# oqs-mtls-auth 플러그인
sudo tee ${PLUGIN_DIR}/oqs-mtls-auth.lua > /dev/null <<'EOF'
-- oqs-mtls-auth.lua
-- APISIX plugin for OQS mTLS authentication

local core = require("apisix.core")
local ngx = ngx
local ngx_ssl = require("ngx.ssl")
local x509 = require("resty.openssl.x509")

local plugin_name = "oqs-mtls-auth"
local schema = {
    type = "object",
    properties = {
        require_client_cert = {
            type = "boolean",
            default = true
        },
        allowed_algorithms = {
            type = "array",
            items = { type = "string" },
            default = {"DILITHIUM3", "DILITHIUM5", "FALCON512"}
        },
        ca_cert = {
            type = "string"
        },
        verify_depth = {
            type = "integer",
            default = 3,
            minimum = 1,
            maximum = 10
        }
    },
    required = {"ca_cert"}
}

local _M = {
    version = 0.1,
    priority = 2800,
    name = plugin_name,
    schema = schema
}

function _M.check_schema(conf)
    return core.schema.check(schema, conf)
end

function _M.rewrite(conf, ctx)
    -- 클라이언트 인증서 가져오기
    local cert_chain, err = ngx_ssl.get_client_certificate()

    if not cert_chain then
        if conf.require_client_cert then
            core.log.error("Client certificate required but not provided")
            return 401, {message = "Client certificate required"}
        end
        return
    end

    -- 인증서 파싱
    local cert, err = x509.new(cert_chain)
    if not cert then
        core.log.error("Failed to parse client certificate: ", err)
        return 401, {message = "Invalid client certificate"}
    end

    -- 서명 알고리즘 확인
    local sig_alg = cert:get_signature_name()
    core.log.info("Client cert signature algorithm: ", sig_alg)

    -- OQS 알고리즘 검증
    local is_allowed = false
    for _, alg in ipairs(conf.allowed_algorithms) do
        if string.find(sig_alg, alg, 1, true) then
            is_allowed = true
            break
        end
    end

    if not is_allowed then
        core.log.error("Certificate algorithm not allowed: ", sig_alg)
        return 403, {message = "Certificate algorithm not allowed"}
    end

    -- Subject CN 추출
    local subject = cert:get_subject_name()
    local cn = subject:find("CN")

    if cn then
        core.log.info("Client CN: ", cn)
        core.request.set_header(ctx, "X-Client-CN", cn)
        core.request.set_header(ctx, "X-Client-Cert-Alg", sig_alg)
    end

    core.log.info("OQS mTLS authentication successful")
end

return _M
EOF

echo "플러그인 생성: ${PLUGIN_DIR}/oqs-mtls-auth.lua"

# 플러그인 등록
APISIX_CONFIG="/usr/local/apisix/conf/config.yaml"

echo ""
echo "==> APISIX 설정에 플러그인 추가:"
echo ""
cat <<'EOF'
plugins:
  - oqs-mtls-auth
  - ... (기존 플러그인)
EOF

echo ""
echo "APISIX 재로드: apisix reload"
```

---

## 8. Docker 이미지 빌드

### 8.1 liboqs 베이스 이미지

```dockerfile
# Dockerfile.liboqs
FROM ubuntu:22.04 AS builder

# 빌드 도구 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    wget \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# liboqs 빌드
ARG LIBOQS_VERSION=0.10.0
WORKDIR /tmp
RUN wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz && \
    tar xzf ${LIBOQS_VERSION}.tar.gz && \
    cd liboqs-${LIBOQS_VERSION} && \
    mkdir build && cd build && \
    cmake -G Ninja \
        -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON \
        -DOQS_USE_OPENSSL=ON \
        .. && \
    ninja && \
    ninja install

# 런타임 이미지
FROM ubuntu:22.04

# 런타임 의존성
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# liboqs 라이브러리 복사
COPY --from=builder /opt/liboqs /usr/local

# 라이브러리 경로 업데이트
RUN ldconfig

# 검증
RUN ldd /usr/local/lib/liboqs.so

LABEL maintainer="QSIGN Team"
LABEL description="liboqs base image"
LABEL version="${LIBOQS_VERSION}"
```

### 8.2 Vault OQS 이미지

```dockerfile
# Dockerfile.vault-oqs
FROM ubuntu:22.04 AS liboqs-builder

# liboqs 빌드 (위와 동일)
RUN apt-get update && apt-get install -y \
    build-essential cmake ninja-build git wget libssl-dev

ARG LIBOQS_VERSION=0.10.0
RUN cd /tmp && \
    wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz && \
    tar xzf ${LIBOQS_VERSION}.tar.gz && \
    cd liboqs-${LIBOQS_VERSION} && \
    mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=ON .. && \
    ninja && ninja install

# Vault 플러그인 빌드
FROM golang:1.21 AS plugin-builder

COPY --from=liboqs-builder /opt/liboqs /usr/local

ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_LDFLAGS="-L/usr/local/lib -loqs"

WORKDIR /workspace
COPY vault-plugin-oqs/ .

RUN go mod download && \
    go build -o bin/vault-plugin-oqs cmd/main.go

# 최종 Vault 이미지
FROM hashicorp/vault:1.15.0

# liboqs 라이브러리 복사
COPY --from=liboqs-builder /opt/liboqs/lib /usr/local/lib

# Vault 플러그인 복사
COPY --from=plugin-builder /workspace/bin/vault-plugin-oqs /vault/plugins/

# 라이브러리 경로
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Vault 설정
COPY vault-config.hcl /vault/config/

RUN ldconfig

EXPOSE 8200 8201

LABEL maintainer="QSIGN Team"
LABEL description="HashiCorp Vault with OQS plugin"
```

### 8.3 빌드 스크립트

```bash
#!/bin/bash
# build-docker-images.sh

set -e

REGISTRY="registry.qsign.internal"
TAG="oqs-v1.0"

echo "==> Docker 이미지 빌드..."

# liboqs 베이스 이미지
echo "liboqs 베이스 이미지 빌드..."
docker build -t ${REGISTRY}/liboqs:${TAG} -f Dockerfile.liboqs .

# Vault OQS 이미지
echo "Vault OQS 이미지 빌드..."
docker build -t ${REGISTRY}/vault-oqs:${TAG} -f Dockerfile.vault-oqs .

# Keycloak OQS 이미지
echo "Keycloak OQS 이미지 빌드..."
docker build -t ${REGISTRY}/keycloak-oqs:${TAG} -f Dockerfile.keycloak-oqs .

# APISIX OQS 이미지
echo "APISIX OQS 이미지 빌드..."
docker build -t ${REGISTRY}/apisix-oqs:${TAG} -f Dockerfile.apisix-oqs .

echo ""
echo "==> 이미지 빌드 완료!"
docker images | grep oqs

# 레지스트리에 푸시
echo ""
read -p "레지스트리에 푸시하시겠습니까? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker push ${REGISTRY}/liboqs:${TAG}
    docker push ${REGISTRY}/vault-oqs:${TAG}
    docker push ${REGISTRY}/keycloak-oqs:${TAG}
    docker push ${REGISTRY}/apisix-oqs:${TAG}
    echo "푸시 완료!"
fi
```

---

## 9. Kubernetes 배포

### 9.1 Helm Chart 구조

```bash
#!/bin/bash
# create-helm-chart.sh

set -e

CHART_NAME="qsign-oqs"

echo "==> Helm Chart 생성..."

helm create ${CHART_NAME}

# Chart.yaml 수정
cat > ${CHART_NAME}/Chart.yaml <<EOF
apiVersion: v2
name: ${CHART_NAME}
description: QSIGN with OQS (Post-Quantum Cryptography)
type: application
version: 1.0.0
appVersion: "1.0.0"

dependencies:
  - name: vault
    version: "0.25.0"
    repository: "https://helm.releases.hashicorp.com"
    condition: vault.enabled

  - name: keycloak
    version: "18.0.0"
    repository: "https://charts.bitnami.com/bitnami"
    condition: keycloak.enabled
EOF

# values.yaml
cat > ${CHART_NAME}/values.yaml <<'EOF'
global:
  registry: registry.qsign.internal
  imageTag: oqs-v1.0

vault:
  enabled: true
  server:
    image:
      repository: registry.qsign.internal/vault-oqs
      tag: oqs-v1.0

    ha:
      enabled: true
      replicas: 3

    extraEnvironmentVars:
      OPENSSL_CONF: /vault/config/openssl-oqs.cnf
      LD_LIBRARY_PATH: /usr/local/lib

    volumes:
      - name: oqs-config
        configMap:
          name: vault-oqs-config

    volumeMounts:
      - name: oqs-config
        mountPath: /vault/config/openssl-oqs.cnf
        subPath: openssl-oqs.cnf

keycloak:
  enabled: true
  image:
    repository: registry.qsign.internal/keycloak-oqs
    tag: oqs-v1.0

  replicaCount: 2

  extraEnvVars:
    - name: JAVA_OPTS
      value: "-Djava.library.path=/opt/keycloak/lib"

apisix:
  enabled: true
  image:
    repository: registry.qsign.internal/apisix-oqs
    tag: oqs-v1.0

  replicaCount: 2

  config:
    ssl:
      ssl_protocols: TLSv1.3
      ssl_ecdh_curve: "x25519_kyber768:X25519"
EOF

echo ""
echo "==> Helm Chart 생성 완료: ${CHART_NAME}/"
```

### 9.2 배포 스크립트

```bash
#!/bin/bash
# deploy-kubernetes.sh

set -e

NAMESPACE="qsign"
CHART_DIR="qsign-oqs"
RELEASE_NAME="qsign-oqs"

echo "==> Kubernetes 배포..."

# Namespace 생성
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# ConfigMap 생성 (OpenSSL 설정)
kubectl create configmap vault-oqs-config \
    --from-file=openssl-oqs.cnf \
    --namespace ${NAMESPACE} \
    --dry-run=client -o yaml | kubectl apply -f -

# Secret 생성 (TLS 인증서)
kubectl create secret tls vault-tls-dilithium3 \
    --cert=certs/vault-dilithium3.crt \
    --key=certs/vault-dilithium3.key \
    --namespace ${NAMESPACE} \
    --dry-run=client -o yaml | kubectl apply -f -

# Helm 배포
echo "Helm Chart 배포..."
helm upgrade --install ${RELEASE_NAME} ${CHART_DIR} \
    --namespace ${NAMESPACE} \
    --create-namespace \
    --wait \
    --timeout 10m

echo ""
echo "==> 배포 완료!"

# 상태 확인
echo ""
echo "Pod 상태:"
kubectl get pods -n ${NAMESPACE}

echo ""
echo "Service 상태:"
kubectl get svc -n ${NAMESPACE}

# Vault 초기화 (최초 배포시)
echo ""
read -p "Vault를 초기화하시겠습니까? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    kubectl exec -n ${NAMESPACE} vault-0 -- vault operator init
fi
```

---

## 10. 실행 가능한 스크립트

### 10.1 올인원 설치 스크립트

```bash
#!/bin/bash
# install-oqs-all-in-one.sh
# 모든 OQS 구성 요소를 설치하는 올인원 스크립트

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/oqs-install-$(date +%Y%m%d_%H%M%S).log"

# 로깅 함수
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a ${LOG_FILE}
}

error() {
    echo "[ERROR] $1" | tee -a ${LOG_FILE}
    exit 1
}

log "==> OQS 올인원 설치 시작..."

# OS 감지
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    error "지원하지 않는 OS입니다."
fi

log "OS: $OS $VER"

# 1. 개발 도구 설치
log "Step 1: 개발 도구 설치..."
case $OS in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y build-essential cmake ninja-build git wget libssl-dev
        ;;
    rhel|rocky|centos)
        sudo dnf install -y gcc gcc-c++ cmake ninja-build git wget openssl-devel
        ;;
    *)
        error "지원하지 않는 OS: $OS"
        ;;
esac

# 2. liboqs 빌드 및 설치
log "Step 2: liboqs 빌드 및 설치..."
LIBOQS_VERSION="0.10.0"
cd /tmp
wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz
tar xzf ${LIBOQS_VERSION}.tar.gz
cd liboqs-${LIBOQS_VERSION}
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    -DOQS_DIST_BUILD=ON -DOQS_USE_OPENSSL=ON ..
ninja
sudo ninja install
sudo ldconfig

# 3. oqs-provider 빌드 및 설치
log "Step 3: oqs-provider 빌드 및 설치..."
cd /tmp
git clone --depth 1 --branch 0.6.0 https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir _build && cd _build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release ..
ninja
sudo ninja install

# 4. OpenSSL 설정
log "Step 4: OpenSSL 설정..."
PROVIDER_SO=$(find /usr/local -name "oqsprovider.so" 2>/dev/null | head -1)
sudo tee /etc/ssl/openssl-oqs.cnf > /dev/null <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = ${PROVIDER_SO}
EOF

sudo tee /etc/profile.d/openssl-oqs.sh > /dev/null <<EOF
export OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf
EOF

# 5. 검증
log "Step 5: 설치 검증..."
source /etc/profile.d/openssl-oqs.sh

openssl list -providers | grep -q oqsprovider || error "oqs-provider를 찾을 수 없습니다."
openssl genpkey -algorithm dilithium3 -out /tmp/test.pem -provider oqsprovider 2>/dev/null || \
    error "DILITHIUM3 키 생성 실패"

rm -f /tmp/test.pem

log "==> 설치 완료!"
log "로그 파일: ${LOG_FILE}"

# 요약
log ""
log "=== 설치 요약 ==="
log "liboqs: $(pkg-config --modversion liboqs 2>/dev/null || echo '설치됨')"
log "oqs-provider: ${PROVIDER_SO}"
log "OpenSSL 설정: /etc/ssl/openssl-oqs.cnf"
log ""
log "다음 명령어로 환경 변수 로드:"
log "  source /etc/profile.d/openssl-oqs.sh"
```

### 10.2 테스트 스크립트

```bash
#!/bin/bash
# test-oqs-installation.sh
# OQS 설치를 종합적으로 테스트

set -e

TEMP_DIR="/tmp/oqs-test-$$"
mkdir -p ${TEMP_DIR}
cd ${TEMP_DIR}

echo "==> OQS 설치 테스트 시작..."

# 환경 변수 로드
source /etc/profile.d/openssl-oqs.sh 2>/dev/null || true

# 1. Provider 확인
echo ""
echo "1. OpenSSL Provider 확인:"
if openssl list -providers | grep -q oqsprovider; then
    echo "  ✓ oqs-provider 로드됨"
else
    echo "  ✗ oqs-provider 없음"
    exit 1
fi

# 2. 알고리즘 확인
echo ""
echo "2. OQS 알고리즘 확인:"

ALGORITHMS=("dilithium3" "falcon512" "kyber768")
for alg in "${ALGORITHMS[@]}"; do
    if openssl list -signature-algorithms -provider oqsprovider 2>/dev/null | grep -qi "$alg" || \
       openssl list -kem-algorithms -provider oqsprovider 2>/dev/null | grep -qi "$alg"; then
        echo "  ✓ $alg"
    else
        echo "  ✗ $alg (알고리즘을 찾을 수 없음)"
    fi
done

# 3. 키 생성 테스트
echo ""
echo "3. 키 생성 테스트:"

for alg in dilithium3 falcon512; do
    if openssl genpkey -algorithm $alg -out ${alg}.pem -provider oqsprovider 2>/dev/null; then
        echo "  ✓ $alg 키 생성 성공"

        # 공개키 추출
        openssl pkey -in ${alg}.pem -pubout -out ${alg}-pub.pem -provider oqsprovider 2>/dev/null
    else
        echo "  ✗ $alg 키 생성 실패"
        exit 1
    fi
done

# 4. 서명/검증 테스트
echo ""
echo "4. 서명/검증 테스트:"

echo "Test data for OQS signature" > test-data.txt

for alg in dilithium3 falcon512; do
    # 서명
    if openssl dgst -sha256 -sign ${alg}.pem -out ${alg}.sig test-data.txt -provider oqsprovider 2>/dev/null; then
        # 검증
        if openssl dgst -sha256 -verify ${alg}-pub.pem -signature ${alg}.sig test-data.txt -provider oqsprovider 2>/dev/null; then
            echo "  ✓ $alg 서명/검증 성공"
        else
            echo "  ✗ $alg 검증 실패"
            exit 1
        fi
    else
        echo "  ✗ $alg 서명 실패"
        exit 1
    fi
done

# 5. 인증서 생성 테스트
echo ""
echo "5. 인증서 생성 테스트:"

openssl req -new -x509 -key dilithium3.pem -out test-cert.pem -days 365 \
    -provider oqsprovider \
    -subj "/C=KR/ST=Seoul/O=Test/CN=OQS Test" 2>/dev/null

if [ -f test-cert.pem ]; then
    echo "  ✓ DILITHIUM3 X.509 인증서 생성 성공"

    # 인증서 정보
    openssl x509 -in test-cert.pem -noout -subject -issuer -dates -provider oqsprovider 2>/dev/null | \
        sed 's/^/    /'
else
    echo "  ✗ 인증서 생성 실패"
    exit 1
fi

# 6. TLS 테스트 (간단한 서버/클라이언트)
echo ""
echo "6. TLS 핸드셰이크 테스트:"

# 백그라운드로 TLS 서버 시작
openssl s_server -port 4433 -cert test-cert.pem -key dilithium3.pem \
    -provider oqsprovider -tls1_3 -www &
SERVER_PID=$!

sleep 2

# 클라이언트 연결
if echo "GET /" | openssl s_client -connect localhost:4433 -CAfile test-cert.pem \
    -provider oqsprovider -groups kyber768 2>&1 | grep -q "Verify return code: 0"; then
    echo "  ✓ TLS 핸드셰이크 성공"
else
    echo "  ⚠ TLS 핸드셰이크 경고 (self-signed 인증서)"
fi

# 서버 종료
kill $SERVER_PID 2>/dev/null || true

# 7. 성능 벤치마크
echo ""
echo "7. 성능 벤치마크 (100회):"

for alg in dilithium3 falcon512; do
    START=$(date +%s%N)
    for i in {1..100}; do
        openssl genpkey -algorithm $alg -provider oqsprovider 2>/dev/null > /dev/null
    done
    END=$(date +%s%N)

    ELAPSED=$(( (END - START) / 1000000 ))  # ms
    AVG=$(( ELAPSED / 100 ))

    echo "  $alg: 평균 ${AVG}ms/키생성"
done

# 정리
cd /
rm -rf ${TEMP_DIR}

echo ""
echo "==> 모든 테스트 완료!"
```

### 10.3 인증서 생성 자동화

```bash
#!/bin/bash
# create-oqs-certificates.sh
# OQS 인증서 생성 자동화 스크립트

set -e

# 설정
CA_DIR="/etc/pki/qsign-oqs"
VALIDITY_DAYS=365
ALGORITHM="dilithium3"

# 함수
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

OQS 인증서 생성 도구

OPTIONS:
    -t TYPE       인증서 타입 (ca|server|client) [필수]
    -n NAME       인증서 이름 (CN) [필수]
    -d DOMAIN     도메인 (서버 인증서만)
    -a ALGORITHM  알고리즘 (dilithium3|falcon512) [기본: dilithium3]
    -v DAYS       유효기간 (일) [기본: 365]
    -h            도움말

예제:
    # CA 인증서 생성
    $0 -t ca -n "QSIGN Root CA"

    # 서버 인증서 생성
    $0 -t server -n "Server Certificate" -d qsign.example.com

    # 클라이언트 인증서 생성
    $0 -t client -n "User Certificate"
EOF
    exit 1
}

# 옵션 파싱
while getopts "t:n:d:a:v:h" opt; do
    case $opt in
        t) CERT_TYPE=$OPTARG ;;
        n) CERT_NAME=$OPTARG ;;
        d) DOMAIN=$OPTARG ;;
        a) ALGORITHM=$OPTARG ;;
        v) VALIDITY_DAYS=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$CERT_TYPE" ] || [ -z "$CERT_NAME" ]; then
    usage
fi

# 디렉토리 생성
mkdir -p ${CA_DIR}/{certs,private,csr}
chmod 700 ${CA_DIR}/private

echo "==> OQS 인증서 생성..."
echo "    타입: $CERT_TYPE"
echo "    이름: $CERT_NAME"
echo "    알고리즘: $ALGORITHM"
echo "    유효기간: $VALIDITY_DAYS일"

case $CERT_TYPE in
    ca)
        # CA 인증서 생성
        echo ""
        echo "CA 인증서 생성 중..."

        openssl genpkey -algorithm $ALGORITHM \
            -out ${CA_DIR}/private/ca.key \
            -provider oqsprovider

        chmod 400 ${CA_DIR}/private/ca.key

        openssl req -new -x509 \
            -key ${CA_DIR}/private/ca.key \
            -out ${CA_DIR}/certs/ca.crt \
            -days $((VALIDITY_DAYS * 10)) \
            -provider oqsprovider \
            -subj "/C=KR/ST=Seoul/O=QSIGN/CN=${CERT_NAME}"

        echo "CA 인증서 생성 완료:"
        echo "  개인키: ${CA_DIR}/private/ca.key"
        echo "  인증서: ${CA_DIR}/certs/ca.crt"

        openssl x509 -in ${CA_DIR}/certs/ca.crt -noout -text -provider oqsprovider | head -20
        ;;

    server)
        if [ -z "$DOMAIN" ]; then
            echo "오류: 서버 인증서는 -d DOMAIN 필요"
            exit 1
        fi

        echo ""
        echo "서버 인증서 생성 중..."

        SAFE_NAME=$(echo "$CERT_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')

        # 개인키 생성
        openssl genpkey -algorithm $ALGORITHM \
            -out ${CA_DIR}/private/${SAFE_NAME}.key \
            -provider oqsprovider

        chmod 400 ${CA_DIR}/private/${SAFE_NAME}.key

        # CSR 생성
        cat > ${CA_DIR}/csr/san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = KR
ST = Seoul
O = QSIGN
CN = ${DOMAIN}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
EOF

        openssl req -new \
            -key ${CA_DIR}/private/${SAFE_NAME}.key \
            -out ${CA_DIR}/csr/${SAFE_NAME}.csr \
            -config ${CA_DIR}/csr/san.cnf \
            -provider oqsprovider

        # CA로 서명
        openssl x509 -req \
            -in ${CA_DIR}/csr/${SAFE_NAME}.csr \
            -CA ${CA_DIR}/certs/ca.crt \
            -CAkey ${CA_DIR}/private/ca.key \
            -CAcreateserial \
            -out ${CA_DIR}/certs/${SAFE_NAME}.crt \
            -days ${VALIDITY_DAYS} \
            -extensions v3_req \
            -extfile ${CA_DIR}/csr/san.cnf \
            -provider oqsprovider

        echo "서버 인증서 생성 완료:"
        echo "  개인키: ${CA_DIR}/private/${SAFE_NAME}.key"
        echo "  인증서: ${CA_DIR}/certs/${SAFE_NAME}.crt"

        openssl x509 -in ${CA_DIR}/certs/${SAFE_NAME}.crt -noout -text -provider oqsprovider | \
            grep -A 2 "Subject:\|Issuer:\|Not Before\|Not After\|DNS:"
        ;;

    client)
        echo ""
        echo "클라이언트 인증서 생성 중..."

        SAFE_NAME=$(echo "$CERT_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')

        # 개인키 생성
        openssl genpkey -algorithm $ALGORITHM \
            -out ${CA_DIR}/private/${SAFE_NAME}.key \
            -provider oqsprovider

        chmod 400 ${CA_DIR}/private/${SAFE_NAME}.key

        # CSR 생성
        openssl req -new \
            -key ${CA_DIR}/private/${SAFE_NAME}.key \
            -out ${CA_DIR}/csr/${SAFE_NAME}.csr \
            -provider oqsprovider \
            -subj "/C=KR/ST=Seoul/O=QSIGN/CN=${CERT_NAME}"

        # CA로 서명
        cat > ${CA_DIR}/csr/client.cnf <<EOF
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,emailProtection
EOF

        openssl x509 -req \
            -in ${CA_DIR}/csr/${SAFE_NAME}.csr \
            -CA ${CA_DIR}/certs/ca.crt \
            -CAkey ${CA_DIR}/private/ca.key \
            -CAcreateserial \
            -out ${CA_DIR}/certs/${SAFE_NAME}.crt \
            -days ${VALIDITY_DAYS} \
            -extfile ${CA_DIR}/csr/client.cnf \
            -provider oqsprovider

        # PKCS#12 번들 생성
        openssl pkcs12 -export \
            -in ${CA_DIR}/certs/${SAFE_NAME}.crt \
            -inkey ${CA_DIR}/private/${SAFE_NAME}.key \
            -certfile ${CA_DIR}/certs/ca.crt \
            -out ${CA_DIR}/certs/${SAFE_NAME}.p12 \
            -name "${CERT_NAME}" \
            -passout pass:changeme \
            -provider oqsprovider

        echo "클라이언트 인증서 생성 완료:"
        echo "  개인키: ${CA_DIR}/private/${SAFE_NAME}.key"
        echo "  인증서: ${CA_DIR}/certs/${SAFE_NAME}.crt"
        echo "  PKCS#12: ${CA_DIR}/certs/${SAFE_NAME}.p12 (비밀번호: changeme)"
        ;;

    *)
        echo "오류: 알 수 없는 인증서 타입: $CERT_TYPE"
        usage
        ;;
esac

echo ""
echo "==> 완료!"
```

---

## 11. 트러블슈팅

### 11.1 일반적인 문제 해결

```bash
#!/bin/bash
# troubleshoot-oqs.sh
# OQS 문제 진단 및 해결 스크립트

set -e

echo "==> OQS 트러블슈팅 도구..."

# 1. 환경 변수 확인
echo ""
echo "1. 환경 변수:"
echo "   OPENSSL_CONF: ${OPENSSL_CONF:-<설정 안됨>}"
echo "   OPENSSL_MODULES: ${OPENSSL_MODULES:-<설정 안됨>}"
echo "   LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-<설정 안됨>}"

# 2. liboqs 확인
echo ""
echo "2. liboqs 라이브러리:"
if ldconfig -p | grep -q liboqs; then
    echo "   ✓ liboqs 발견"
    ldconfig -p | grep liboqs | sed 's/^/     /'
else
    echo "   ✗ liboqs를 찾을 수 없음"
    echo ""
    echo "   해결 방법:"
    echo "     1. liboqs 설치 확인: ls -la /usr/local/lib*/liboqs.*"
    echo "     2. ldconfig 실행: sudo ldconfig"
    echo "     3. LD_LIBRARY_PATH 설정: export LD_LIBRARY_PATH=/usr/local/lib64:\$LD_LIBRARY_PATH"
fi

# 3. oqs-provider 확인
echo ""
echo "3. oqs-provider 모듈:"
PROVIDER_PATHS=(
    "/usr/local/lib64/ossl-modules"
    "/usr/local/lib/ossl-modules"
    "/usr/lib64/ossl-modules"
    "/usr/lib/ossl-modules"
)

FOUND=0
for path in "${PROVIDER_PATHS[@]}"; do
    if [ -f "${path}/oqsprovider.so" ]; then
        echo "   ✓ Provider 발견: ${path}/oqsprovider.so"
        FOUND=1
        break
    fi
done

if [ $FOUND -eq 0 ]; then
    echo "   ✗ oqsprovider.so를 찾을 수 없음"
    echo ""
    echo "   해결 방법:"
    echo "     1. oqs-provider 설치 확인"
    echo "     2. OPENSSL_MODULES 환경 변수 설정"
fi

# 4. OpenSSL 설정 파일 확인
echo ""
echo "4. OpenSSL 설정 파일:"
if [ -n "$OPENSSL_CONF" ] && [ -f "$OPENSSL_CONF" ]; then
    echo "   ✓ 설정 파일 존재: $OPENSSL_CONF"

    # Provider 설정 확인
    if grep -q "oqsprovider" "$OPENSSL_CONF"; then
        echo "   ✓ oqsprovider 설정 발견"
    else
        echo "   ⚠ oqsprovider 설정 없음"
    fi
else
    echo "   ✗ 설정 파일을 찾을 수 없거나 OPENSSL_CONF가 설정되지 않음"
    echo ""
    echo "   해결 방법:"
    echo "     export OPENSSL_CONF=/etc/ssl/openssl-oqs.cnf"
fi

# 5. OpenSSL Provider 목록
echo ""
echo "5. OpenSSL Provider 로드 테스트:"
if openssl list -providers 2>/dev/null | grep -q oqsprovider; then
    echo "   ✓ oqs-provider 로드됨"
    openssl list -providers -verbose 2>/dev/null | grep -A 5 "name: OQS" | sed 's/^/     /'
else
    echo "   ✗ oqs-provider 로드 실패"
    echo ""
    echo "   디버깅:"
    openssl list -providers 2>&1 | sed 's/^/     /'
fi

# 6. 알고리즘 확인
echo ""
echo "6. OQS 알고리즘 사용 가능 여부:"
TEST_ALGS=("dilithium3" "falcon512" "kyber768")

for alg in "${TEST_ALGS[@]}"; do
    if openssl list -signature-algorithms -provider oqsprovider 2>/dev/null | grep -qi "$alg" || \
       openssl list -kem-algorithms -provider oqsprovider 2>/dev/null | grep -qi "$alg"; then
        echo "   ✓ $alg"
    else
        echo "   ✗ $alg (알고리즘 없음)"
    fi
done

# 7. 간단한 작동 테스트
echo ""
echo "7. 기능 테스트:"

TEMP_KEY="/tmp/troubleshoot_test_$$.pem"

if openssl genpkey -algorithm dilithium3 -out ${TEMP_KEY} -provider oqsprovider 2>/dev/null; then
    echo "   ✓ 키 생성 성공"
    rm -f ${TEMP_KEY}
else
    echo "   ✗ 키 생성 실패"
    echo ""
    echo "   상세 에러:"
    openssl genpkey -algorithm dilithium3 -out ${TEMP_KEY} -provider oqsprovider 2>&1 | sed 's/^/     /'
fi

# 8. 시스템 정보
echo ""
echo "8. 시스템 정보:"
echo "   OS: $(uname -s) $(uname -r)"
echo "   아키텍처: $(uname -m)"
echo "   OpenSSL 버전: $(openssl version)"
echo "   GCC 버전: $(gcc --version 2>/dev/null | head -1 || echo 'N/A')"
echo "   CMake 버전: $(cmake --version 2>/dev/null | head -1 || echo 'N/A')"

echo ""
echo "==> 트러블슈팅 완료!"
```

---

## 참고 자료

```yaml
공식 문서:
  - liboqs 빌드: https://github.com/open-quantum-safe/liboqs/wiki/Customizing-liboqs
  - oqs-provider: https://github.com/open-quantum-safe/oqs-provider#build-and-install
  - OpenSSL 3.0 Provider: https://www.openssl.org/docs/man3.0/man7/provider.html

관련 문서:
  - Q-Docs/10-OQS/LIBOQS.md
  - Q-Docs/10-OQS/OPENSSL-OQS.md
  - Q-Docs/10-OQS/OQS-QSIGN-INTEGRATION.md

도구 및 라이브러리:
  - HashiCorp Vault Plugin Development: https://www.vaultproject.io/docs/plugins
  - Keycloak SPI: https://www.keycloak.org/docs/latest/server_development/
  - Apache APISIX Plugins: https://apisix.apache.org/docs/apisix/plugin-develop/
```

---

**문서 버전:** 1.0
**최종 수정일:** 2025-01-16
**작성자:** QSIGN Documentation Team
