#!/bin/bash
# liboqs 빌드 및 설치 스크립트 (QSIGN 프로덕션 환경)
# Ubuntu 22.04 / RHEL 8 / macOS 지원

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 로그 함수
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 설정
LIBOQS_VERSION="0.10.0"
INSTALL_PREFIX="/opt/qsign/liboqs"
BUILD_DIR="build-qsign"
ENABLE_SHARED="ON"
ENABLE_STATIC="OFF"
USE_OPENSSL="ON"

# OS 감지
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$ID
            OS_VERSION=$VERSION_ID
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        OS_VERSION=$(sw_vers -productVersion)
    else
        log_error "지원하지 않는 OS: $OSTYPE"
        exit 1
    fi

    log_info "감지된 OS: $OS $OS_VERSION"
}

# 의존성 설치
install_dependencies() {
    log_info "의존성 패키지 설치 중..."

    case "$OS" in
        ubuntu|debian)
            sudo apt update
            sudo apt install -y \
                build-essential \
                cmake \
                git \
                libssl-dev \
                ninja-build \
                doxygen \
                graphviz
            ;;
        rhel|rocky|centos|fedora)
            sudo dnf install -y \
                gcc \
                gcc-c++ \
                cmake \
                git \
                openssl-devel \
                ninja-build \
                doxygen \
                graphviz
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                log_error "Homebrew가 설치되어 있지 않습니다."
                exit 1
            fi
            brew install cmake ninja openssl@3 doxygen graphviz
            ;;
        *)
            log_error "지원하지 않는 OS: $OS"
            exit 1
            ;;
    esac

    log_info "의존성 설치 완료"
}

# liboqs 소스 다운로드
download_liboqs() {
    log_info "liboqs 소스 다운로드 중..."

    if [ -d "liboqs" ]; then
        log_warn "liboqs 디렉토리가 이미 존재합니다. 삭제하고 다시 다운로드합니다."
        rm -rf liboqs
    fi

    git clone https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    git checkout $LIBOQS_VERSION

    log_info "liboqs $LIBOQS_VERSION 다운로드 완료"
}

# liboqs 빌드
build_liboqs() {
    log_info "liboqs 빌드 중..."

    cd liboqs
    rm -rf $BUILD_DIR
    mkdir $BUILD_DIR && cd $BUILD_DIR

    # CMake 설정 (QSIGN 최적화)
    cmake -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX \
        -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native -fPIC" \
        -DBUILD_SHARED_LIBS=$ENABLE_SHARED \
        -DOQS_USE_OPENSSL=$USE_OPENSSL \
        -DOQS_DIST_BUILD=OFF \
        \
        `# QSIGN 핵심 알고리즘만 활성화` \
        -DOQS_ENABLE_KEM_KYBER=ON \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        -DOQS_ENABLE_SIG_SPHINCSPLUS=ON \
        -DOQS_ENABLE_SIG_FALCON=ON \
        \
        `# 기타 알고리즘 비활성화` \
        -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
        -DOQS_ENABLE_KEM_HQC=OFF \
        -DOQS_ENABLE_KEM_BIKE=OFF \
        -DOQS_ENABLE_SIG_MAYO=OFF \
        ..

    # 빌드
    ninja

    log_info "liboqs 빌드 완료"
}

# 테스트 실행
run_tests() {
    log_info "테스트 실행 중..."

    ninja run_tests

    if [ $? -eq 0 ]; then
        log_info "모든 테스트 통과 ✓"
    else
        log_error "일부 테스트 실패"
        exit 1
    fi
}

# 설치
install_liboqs() {
    log_info "liboqs 설치 중..."

    sudo ninja install

    # 라이브러리 경로 추가
    case "$OS" in
        ubuntu|debian|rhel|rocky|centos|fedora)
            echo "$INSTALL_PREFIX/lib" | sudo tee /etc/ld.so.conf.d/liboqs-qsign.conf
            sudo ldconfig
            ;;
        macos)
            # macOS는 DYLD_LIBRARY_PATH 사용
            log_warn "macOS: ~/.bash_profile 또는 ~/.zshrc에 다음 추가:"
            log_warn "export DYLD_LIBRARY_PATH=$INSTALL_PREFIX/lib:\$DYLD_LIBRARY_PATH"
            ;;
    esac

    log_info "liboqs 설치 완료: $INSTALL_PREFIX"
}

# 설치 확인
verify_installation() {
    log_info "설치 확인 중..."

    # 라이브러리 파일 확인
    if [ -f "$INSTALL_PREFIX/lib/liboqs.so" ] || [ -f "$INSTALL_PREFIX/lib/liboqs.dylib" ]; then
        log_info "✓ 라이브러리: $(ls -lh $INSTALL_PREFIX/lib/liboqs.* | awk '{print $9, $5}')"
    else
        log_error "라이브러리를 찾을 수 없습니다."
        exit 1
    fi

    # 헤더 파일 확인
    if [ -d "$INSTALL_PREFIX/include/oqs" ]; then
        log_info "✓ 헤더: $INSTALL_PREFIX/include/oqs/"
        ls -lh $INSTALL_PREFIX/include/oqs/
    else
        log_error "헤더 파일을 찾을 수 없습니다."
        exit 1
    fi

    # pkg-config 파일 확인
    if [ -f "$INSTALL_PREFIX/lib/pkgconfig/liboqs.pc" ]; then
        log_info "✓ pkg-config: $INSTALL_PREFIX/lib/pkgconfig/liboqs.pc"
    fi
}

# 환경 변수 출력
print_env_vars() {
    log_info "환경 변수 설정:"
    echo ""
    echo "export PKG_CONFIG_PATH=$INSTALL_PREFIX/lib/pkgconfig:\$PKG_CONFIG_PATH"
    echo "export LD_LIBRARY_PATH=$INSTALL_PREFIX/lib:\$LD_LIBRARY_PATH"
    echo "export C_INCLUDE_PATH=$INSTALL_PREFIX/include:\$C_INCLUDE_PATH"
    echo ""
    log_info "위 환경 변수를 ~/.bashrc 또는 ~/.zshrc에 추가하세요."
}

# 사용법 출력
usage() {
    cat <<EOF
사용법: $0 [OPTIONS]

QSIGN 프로덕션 환경을 위한 liboqs 빌드 및 설치 스크립트

OPTIONS:
    -h, --help              이 도움말 출력
    -v, --version VERSION   liboqs 버전 지정 (기본: $LIBOQS_VERSION)
    -p, --prefix PATH       설치 경로 지정 (기본: $INSTALL_PREFIX)
    --shared                공유 라이브러리 빌드 (기본)
    --static                정적 라이브러리 빌드
    --skip-deps             의존성 설치 건너뛰기
    --skip-tests            테스트 실행 건너뛰기

EXAMPLES:
    # 기본 빌드
    $0

    # 특정 버전 및 경로로 빌드
    $0 --version 0.9.0 --prefix /usr/local

    # 정적 라이브러리 빌드
    $0 --static

    # 의존성 및 테스트 건너뛰기 (CI/CD 환경)
    $0 --skip-deps --skip-tests

EOF
}

# 메인 함수
main() {
    local SKIP_DEPS=false
    local SKIP_TESTS=false

    # 인자 파싱
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                LIBOQS_VERSION="$2"
                shift 2
                ;;
            -p|--prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --shared)
                ENABLE_SHARED="ON"
                ENABLE_STATIC="OFF"
                shift
                ;;
            --static)
                ENABLE_SHARED="OFF"
                ENABLE_STATIC="ON"
                shift
                ;;
            --skip-deps)
                SKIP_DEPS=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            *)
                log_error "알 수 없는 옵션: $1"
                usage
                exit 1
                ;;
        esac
    done

    log_info "========================================="
    log_info "liboqs 빌드 및 설치 (QSIGN Edition)"
    log_info "========================================="
    echo ""
    log_info "버전: $LIBOQS_VERSION"
    log_info "설치 경로: $INSTALL_PREFIX"
    log_info "공유 라이브러리: $ENABLE_SHARED"
    log_info "정적 라이브러리: $ENABLE_STATIC"
    echo ""

    # OS 감지
    detect_os

    # 의존성 설치
    if [ "$SKIP_DEPS" = false ]; then
        install_dependencies
    else
        log_warn "의존성 설치 건너뛰기"
    fi

    # 빌드 프로세스
    download_liboqs
    build_liboqs

    # 테스트
    if [ "$SKIP_TESTS" = false ]; then
        run_tests
    else
        log_warn "테스트 실행 건너뛰기"
    fi

    # 설치
    install_liboqs

    # 확인
    verify_installation

    # 환경 변수 출력
    print_env_vars

    echo ""
    log_info "========================================="
    log_info "liboqs 빌드 및 설치 완료! ✓"
    log_info "========================================="
}

# 스크립트 실행
main "$@"
