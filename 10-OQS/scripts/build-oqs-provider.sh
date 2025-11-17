#!/bin/bash
# oqs-provider 빌드 및 설치 스크립트 (OpenSSL 3.x Provider)
# QSIGN 시스템 통합용

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 설정
OQS_PROVIDER_VERSION="0.6.0"
LIBOQS_INSTALL_DIR="/opt/qsign/liboqs"
OPENSSL_DIR="/usr"
INSTALL_PREFIX="/opt/qsign/oqs-provider"

# OpenSSL 버전 확인
check_openssl_version() {
    log_info "OpenSSL 버전 확인 중..."

    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    OPENSSL_MAJOR=$(echo $OPENSSL_VERSION | cut -d. -f1)

    log_info "OpenSSL 버전: $OPENSSL_VERSION"

    if [ "$OPENSSL_MAJOR" != "3" ]; then
        log_error "OpenSSL 3.x가 필요합니다. 현재 버전: $OPENSSL_VERSION"
        log_error "Ubuntu: sudo apt install openssl libssl-dev"
        exit 1
    fi

    # OpenSSL modules 디렉토리 확인
    OPENSSL_MODULES_DIR=$(openssl version -m | grep -oP 'MODULESDIR: "\K[^"]+')
    log_info "OpenSSL modules 디렉토리: $OPENSSL_MODULES_DIR"
}

# liboqs 확인
check_liboqs() {
    log_info "liboqs 설치 확인 중..."

    if [ ! -f "$LIBOQS_INSTALL_DIR/lib/liboqs.so" ] && [ ! -f "$LIBOQS_INSTALL_DIR/lib/liboqs.dylib" ]; then
        log_error "liboqs를 찾을 수 없습니다: $LIBOQS_INSTALL_DIR"
        log_error "먼저 build-liboqs.sh를 실행하세요."
        exit 1
    fi

    log_info "✓ liboqs 발견: $LIBOQS_INSTALL_DIR"
}

# oqs-provider 소스 다운로드
download_oqs_provider() {
    log_info "oqs-provider 소스 다운로드 중..."

    if [ -d "oqs-provider" ]; then
        log_warn "oqs-provider 디렉토리가 이미 존재합니다."
        rm -rf oqs-provider
    fi

    git clone https://github.com/open-quantum-safe/oqs-provider.git
    cd oqs-provider
    git checkout $OQS_PROVIDER_VERSION

    log_info "oqs-provider $OQS_PROVIDER_VERSION 다운로드 완료"
}

# oqs-provider 빌드
build_oqs_provider() {
    log_info "oqs-provider 빌드 중..."

    cd oqs-provider

    # CMake 설정
    cmake -S . -B _build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
        -DCMAKE_PREFIX_PATH=$LIBOQS_INSTALL_DIR \
        -DOPENSSL_ROOT_DIR=$OPENSSL_DIR

    # 빌드
    cmake --build _build

    log_info "oqs-provider 빌드 완료"
}

# 테스트 실행
run_tests() {
    log_info "테스트 실행 중..."

    cd oqs-provider/_build

    # 환경 변수 설정
    export LD_LIBRARY_PATH=$LIBOQS_INSTALL_DIR/lib:$LD_LIBRARY_PATH

    ctest --output-on-failure

    if [ $? -eq 0 ]; then
        log_info "모든 테스트 통과 ✓"
    else
        log_warn "일부 테스트 실패 (무시하고 계속)"
    fi
}

# 설치
install_oqs_provider() {
    log_info "oqs-provider 설치 중..."

    cd oqs-provider/_build
    sudo cmake --install .

    # Provider를 OpenSSL modules 디렉토리로 복사
    if [ -n "$OPENSSL_MODULES_DIR" ]; then
        log_info "Provider를 OpenSSL modules 디렉토리로 복사 중..."
        sudo cp $INSTALL_PREFIX/lib/oqsprovider.so $OPENSSL_MODULES_DIR/
        log_info "✓ Provider 복사 완료: $OPENSSL_MODULES_DIR/oqsprovider.so"
    fi

    log_info "oqs-provider 설치 완료"
}

# OpenSSL 설정 파일 생성
create_openssl_config() {
    log_info "OpenSSL 설정 파일 생성 중..."

    OPENSSL_CONF="$INSTALL_PREFIX/openssl-oqs.cnf"

    cat > $OPENSSL_CONF <<'EOF'
# OpenSSL configuration file with OQS provider
# QSIGN Production Environment

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqs = oqs_sect

[default_sect]
activate = 1

[oqs_sect]
activate = 1
# Provider 경로 (필요 시 수정)
# module = /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so

[req]
distinguished_name = req_distinguished_name
# PQC 알고리즘 사용 시 주석 해제
# default_md = dilithium3
# default_sig_alg = dilithium3

[req_distinguished_name]
countryName = Country Name (2 letter code)
countryName_default = KR
stateOrProvinceName = State or Province Name (full name)
stateOrProvinceName_default = Seoul
localityName = Locality Name (eg, city)
localityName_default = Seoul
organizationName = Organization Name (eg, company)
organizationName_default = QSIGN
commonName = Common Name (e.g. server FQDN or YOUR name)
commonName_max = 64

EOF

    sudo mv $OPENSSL_CONF $INSTALL_PREFIX/

    log_info "✓ OpenSSL 설정 파일 생성: $INSTALL_PREFIX/openssl-oqs.cnf"
}

# 설치 확인
verify_installation() {
    log_info "설치 확인 중..."

    # Provider 파일 확인
    if [ -f "$OPENSSL_MODULES_DIR/oqsprovider.so" ]; then
        log_info "✓ Provider: $OPENSSL_MODULES_DIR/oqsprovider.so"
    else
        log_error "Provider를 찾을 수 없습니다."
        exit 1
    fi

    # Provider 로드 테스트
    log_info "Provider 로드 테스트 중..."
    export LD_LIBRARY_PATH=$LIBOQS_INSTALL_DIR/lib:$LD_LIBRARY_PATH

    openssl list -providers -provider oqs 2>&1 | grep -q "oqs"
    if [ $? -eq 0 ]; then
        log_info "✓ OQS provider 로드 성공"
        echo ""
        openssl list -providers -provider oqs -verbose
    else
        log_error "OQS provider 로드 실패"
        exit 1
    fi
}

# 사용 예제 출력
print_usage_examples() {
    log_info "사용 예제:"
    cat <<'EOF'

# 1. PQC 키 생성 (Dilithium3)
openssl genpkey -algorithm dilithium3 \
    -provider oqs \
    -provider default \
    -out dilithium3_key.pem

# 2. PQC 인증서 생성
openssl req -x509 -new -newkey dilithium3 \
    -provider oqs \
    -provider default \
    -keyout dilithium3_CA.key \
    -out dilithium3_CA.crt \
    -nodes -subj "/CN=QSIGN Root CA" \
    -days 3650

# 3. Hybrid 키 생성 (RSA + Dilithium3)
openssl genpkey -algorithm rsa:dilithium3 \
    -provider oqs \
    -provider default \
    -out hybrid_key.pem

# 4. 지원 알고리즘 목록 확인
openssl list -kem-algorithms -provider oqs
openssl list -signature-algorithms -provider oqs

# 5. 환경 변수 설정 (영구 적용)
echo "export OPENSSL_CONF=$INSTALL_PREFIX/openssl-oqs.cnf" >> ~/.bashrc
echo "export LD_LIBRARY_PATH=$LIBOQS_INSTALL_DIR/lib:\$LD_LIBRARY_PATH" >> ~/.bashrc

EOF
}

# 메인 함수
main() {
    log_info "========================================="
    log_info "oqs-provider 빌드 및 설치 (QSIGN)"
    log_info "========================================="
    echo ""

    check_openssl_version
    check_liboqs
    download_oqs_provider
    build_oqs_provider
    run_tests
    install_oqs_provider
    create_openssl_config
    verify_installation
    print_usage_examples

    echo ""
    log_info "========================================="
    log_info "oqs-provider 설치 완료! ✓"
    log_info "========================================="
    echo ""
    log_info "다음 명령어로 OQS provider를 활성화하세요:"
    echo "export OPENSSL_CONF=$INSTALL_PREFIX/openssl-oqs.cnf"
    echo "export LD_LIBRARY_PATH=$LIBOQS_INSTALL_DIR/lib:\$LD_LIBRARY_PATH"
}

main "$@"
