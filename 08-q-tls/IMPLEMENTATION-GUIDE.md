# Q-TLS Implementation Guide

Q-TLS (Quantum-resistant Transport Security Layer) 구현을 위한 실용적인 가이드입니다.

## 목차

1. [OpenSSL + OQS 설치 및 빌드](#1-openssl--oqs-설치-및-빌드)
2. [APISIX Gateway Q-TLS 설정](#2-apisix-gateway-q-tls-설정)
3. [Nginx Q-TLS 모듈 설정](#3-nginx-q-tls-모듈-설정)
4. [클라이언트 라이브러리](#4-클라이언트-라이브러리)
5. [Golang Q-TLS 클라이언트](#5-golang-q-tls-클라이언트)
6. [테스트 스크립트](#6-테스트-스크립트)
7. [성능 튜닝](#7-성능-튜닝)
8. [트러블슈팅 가이드](#8-트러블슈팅-가이드)

---

## 1. OpenSSL + OQS 설치 및 빌드

### 1.1 liboqs (Open Quantum Safe) 빌드

```bash
#!/bin/bash
# install-liboqs.sh - Install liboqs library for PQC support

set -e

LIBOQS_VERSION="0.10.1"
INSTALL_PREFIX="/opt/oqs"

echo "[1/6] Installing dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ninja-build \
    python3-pytest \
    python3-pytest-xdist \
    unzip \
    wget \
    doxygen \
    graphviz

echo "[2/6] Downloading liboqs ${LIBOQS_VERSION}..."
cd /tmp
wget "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" -O liboqs.tar.gz
tar xzf liboqs.tar.gz
cd "liboqs-${LIBOQS_VERSION}"

echo "[3/6] Configuring liboqs build..."
mkdir -p build && cd build
cmake -GNinja \
    -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
    -DOQS_USE_OPENSSL=ON \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=OFF \
    -DOQS_DIST_BUILD=ON \
    -DOQS_ENABLE_KEM_KYBER=ON \
    -DOQS_ENABLE_SIG_DILITHIUM=ON \
    -DOQS_ENABLE_SIG_SPHINCS=ON \
    ..

echo "[4/6] Building liboqs (this may take 5-10 minutes)..."
ninja

echo "[5/6] Running tests..."
ninja run_tests

echo "[6/6] Installing liboqs to ${INSTALL_PREFIX}..."
sudo ninja install

# Update library cache
sudo ldconfig "${INSTALL_PREFIX}/lib"

# Verify installation
echo ""
echo "✓ liboqs installed successfully!"
echo "  Version: ${LIBOQS_VERSION}"
echo "  Installation Path: ${INSTALL_PREFIX}"
echo "  Library Path: ${INSTALL_PREFIX}/lib"
echo "  Include Path: ${INSTALL_PREFIX}/include"

# List supported algorithms
echo ""
echo "Supported PQC Algorithms:"
"${INSTALL_PREFIX}/bin/test_kem" list 2>/dev/null | grep -E "Kyber" || true
"${INSTALL_PREFIX}/bin/test_sig" list 2>/dev/null | grep -E "Dilithium|SPHINCS" || true

# Create environment setup script
cat > /tmp/oqs-env.sh << 'EOF'
# OQS Environment Setup
export OQS_INSTALL_DIR=/opt/oqs
export LD_LIBRARY_PATH="${OQS_INSTALL_DIR}/lib:${LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="${OQS_INSTALL_DIR}/lib/pkgconfig:${PKG_CONFIG_PATH}"
export PATH="${OQS_INSTALL_DIR}/bin:${PATH}"
EOF

sudo mv /tmp/oqs-env.sh /etc/profile.d/oqs.sh
echo ""
echo "Environment setup script created: /etc/profile.d/oqs.sh"
echo "Run: source /etc/profile.d/oqs.sh"
```

### 1.2 OpenSSL 3.x with OQS Provider 빌드

```bash
#!/bin/bash
# install-openssl-oqs.sh - Install OpenSSL 3.x with OQS provider

set -e

OPENSSL_VERSION="3.2.0"
OQS_PROVIDER_VERSION="0.6.1"
OQS_INSTALL_DIR="/opt/oqs"
OPENSSL_INSTALL_DIR="/opt/openssl-oqs"

# Source OQS environment
source /etc/profile.d/oqs.sh

echo "[1/8] Downloading OpenSSL ${OPENSSL_VERSION}..."
cd /tmp
wget "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
tar xzf "openssl-${OPENSSL_VERSION}.tar.gz"
cd "openssl-${OPENSSL_VERSION}"

echo "[2/8] Configuring OpenSSL build..."
./Configure \
    --prefix="${OPENSSL_INSTALL_DIR}" \
    --openssldir="${OPENSSL_INSTALL_DIR}/ssl" \
    shared \
    enable-ktls \
    enable-tls1_3 \
    '-Wl,-rpath,$(LIBRPATH)'

echo "[3/8] Building OpenSSL (this may take 10-15 minutes)..."
make -j$(nproc)

echo "[4/8] Running OpenSSL tests..."
make test

echo "[5/8] Installing OpenSSL to ${OPENSSL_INSTALL_DIR}..."
sudo make install

echo "[6/8] Downloading OQS-Provider ${OQS_PROVIDER_VERSION}..."
cd /tmp
wget "https://github.com/open-quantum-safe/oqs-provider/archive/refs/tags/${OQS_PROVIDER_VERSION}.tar.gz" -O oqs-provider.tar.gz
tar xzf oqs-provider.tar.gz
cd "oqs-provider-${OQS_PROVIDER_VERSION}"

echo "[7/8] Building OQS-Provider..."
mkdir -p build && cd build
cmake \
    -DCMAKE_PREFIX_PATH="${OQS_INSTALL_DIR}" \
    -DOPENSSL_ROOT_DIR="${OPENSSL_INSTALL_DIR}" \
    -DCMAKE_INSTALL_PREFIX="${OPENSSL_INSTALL_DIR}" \
    ..

make -j$(nproc)

echo "[8/8] Installing OQS-Provider..."
sudo make install

# Configure OpenSSL to load OQS provider
sudo tee "${OPENSSL_INSTALL_DIR}/ssl/openssl.cnf" > /dev/null << EOF
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
module = ${OPENSSL_INSTALL_DIR}/lib/ossl-modules/oqsprovider.so
EOF

# Create environment setup script
cat > /tmp/openssl-oqs-env.sh << EOF
# OpenSSL OQS Environment Setup
export OPENSSL_OQS_DIR=${OPENSSL_INSTALL_DIR}
export PATH="${OPENSSL_INSTALL_DIR}/bin:\${PATH}"
export LD_LIBRARY_PATH="${OPENSSL_INSTALL_DIR}/lib:\${LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="${OPENSSL_INSTALL_DIR}/lib/pkgconfig:\${PKG_CONFIG_PATH}"
export OPENSSL_CONF="${OPENSSL_INSTALL_DIR}/ssl/openssl.cnf"
EOF

sudo mv /tmp/openssl-oqs-env.sh /etc/profile.d/openssl-oqs.sh

# Verify installation
echo ""
echo "✓ OpenSSL OQS installed successfully!"
echo "  OpenSSL Version: ${OPENSSL_VERSION}"
echo "  OQS Provider Version: ${OQS_PROVIDER_VERSION}"
echo "  Installation Path: ${OPENSSL_INSTALL_DIR}"

source /etc/profile.d/openssl-oqs.sh

echo ""
echo "Verifying OpenSSL OQS integration..."
"${OPENSSL_INSTALL_DIR}/bin/openssl" list -providers

echo ""
echo "Supported PQC Key Exchange Algorithms:"
"${OPENSSL_INSTALL_DIR}/bin/openssl" list -kem-algorithms -provider oqsprovider | grep -i kyber || true

echo ""
echo "Supported PQC Signature Algorithms:"
"${OPENSSL_INSTALL_DIR}/bin/openssl" list -signature-algorithms -provider oqsprovider | grep -i dilithium || true
```

### 1.3 PQC 인증서 생성 스크립트

```bash
#!/bin/bash
# generate-pqc-certificates.sh - Generate hybrid PQC certificates

set -e

source /etc/profile.d/openssl-oqs.sh

CERT_DIR="/opt/qsign/certs"
CA_DIR="${CERT_DIR}/ca"
SERVER_DIR="${CERT_DIR}/server"
CLIENT_DIR="${CERT_DIR}/client"

DOMAIN="qsign.local"
ORG="Q-Sign Enterprise"

echo "Creating certificate directories..."
sudo mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"

# ============================================================================
# 1. Generate Root CA (Dilithium3)
# ============================================================================

echo "[1/6] Generating Root CA with Dilithium3..."

sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" req -x509 -new \
    -newkey dilithium3 \
    -keyout "${CA_DIR}/root-ca.key" \
    -out "${CA_DIR}/root-ca.crt" \
    -nodes \
    -days 7300 \
    -config <(cat << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = KR
ST = Seoul
L = Gangnam
O = ${ORG}
OU = Security
CN = Q-Sign Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
)

echo "✓ Root CA created: ${CA_DIR}/root-ca.crt"

# ============================================================================
# 2. Generate Intermediate CA
# ============================================================================

echo "[2/6] Generating Intermediate CA with Dilithium3..."

# Generate intermediate CA private key
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" genpkey \
    -algorithm dilithium3 \
    -out "${CA_DIR}/intermediate-ca.key"

# Generate intermediate CA CSR
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" req -new \
    -key "${CA_DIR}/intermediate-ca.key" \
    -out "${CA_DIR}/intermediate-ca.csr" \
    -config <(cat << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = KR
ST = Seoul
L = Gangnam
O = ${ORG}
OU = PKI
CN = Q-Sign Intermediate CA
EOF
)

# Sign intermediate CA with root CA
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" x509 -req \
    -in "${CA_DIR}/intermediate-ca.csr" \
    -CA "${CA_DIR}/root-ca.crt" \
    -CAkey "${CA_DIR}/root-ca.key" \
    -CAcreateserial \
    -out "${CA_DIR}/intermediate-ca.crt" \
    -days 3650 \
    -extfile <(cat << EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

echo "✓ Intermediate CA created: ${CA_DIR}/intermediate-ca.crt"

# ============================================================================
# 3. Generate Server Certificate (Hybrid: RSA + Dilithium3)
# ============================================================================

echo "[3/6] Generating Server Certificate (Hybrid)..."

# Generate RSA-4096 key
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -out "${SERVER_DIR}/server-rsa.key"

# Generate Dilithium3 key
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" genpkey \
    -algorithm dilithium3 \
    -out "${SERVER_DIR}/server-dilithium3.key"

# Generate CSR with RSA key
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" req -new \
    -key "${SERVER_DIR}/server-rsa.key" \
    -out "${SERVER_DIR}/server.csr" \
    -config <(cat << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = KR
ST = Seoul
L = Gangnam
O = ${ORG}
OU = API Gateway
CN = api.${DOMAIN}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = api.${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = 192.168.1.100
EOF
)

# Sign server certificate
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" x509 -req \
    -in "${SERVER_DIR}/server.csr" \
    -CA "${CA_DIR}/intermediate-ca.crt" \
    -CAkey "${CA_DIR}/intermediate-ca.key" \
    -CAcreateserial \
    -out "${SERVER_DIR}/server.crt" \
    -days 365 \
    -extfile <(cat << EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:api.${DOMAIN},DNS:*.${DOMAIN},DNS:localhost,IP:127.0.0.1,IP:192.168.1.100
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

echo "✓ Server certificate created: ${SERVER_DIR}/server.crt"

# Create certificate bundle
sudo cat "${SERVER_DIR}/server.crt" \
    "${CA_DIR}/intermediate-ca.crt" \
    > "${SERVER_DIR}/server-bundle.crt"

echo "✓ Server bundle created: ${SERVER_DIR}/server-bundle.crt"

# ============================================================================
# 4. Generate Client Certificate
# ============================================================================

echo "[4/6] Generating Client Certificate..."

sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" genpkey \
    -algorithm dilithium3 \
    -out "${CLIENT_DIR}/client.key"

sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" req -new \
    -key "${CLIENT_DIR}/client.key" \
    -out "${CLIENT_DIR}/client.csr" \
    -config <(cat << EOF
[req]
distinguished_name = req_distinguished_name
prompt = no

[req_distinguished_name]
C = KR
ST = Seoul
L = Gangnam
O = ${ORG}
OU = Devices
CN = device-001.${DOMAIN}
EOF
)

sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" x509 -req \
    -in "${CLIENT_DIR}/client.csr" \
    -CA "${CA_DIR}/intermediate-ca.crt" \
    -CAkey "${CA_DIR}/intermediate-ca.key" \
    -CAcreateserial \
    -out "${CLIENT_DIR}/client.crt" \
    -days 365 \
    -extfile <(cat << EOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
)

echo "✓ Client certificate created: ${CLIENT_DIR}/client.crt"

# ============================================================================
# 5. Generate DH Parameters
# ============================================================================

echo "[5/6] Generating DH parameters (4096 bits)..."
sudo "${OPENSSL_INSTALL_DIR}/bin/openssl" dhparam -out "${CERT_DIR}/dhparam.pem" 4096

# ============================================================================
# 6. Set Permissions
# ============================================================================

echo "[6/6] Setting certificate permissions..."
sudo chmod 600 "${CA_DIR}"/*.key "${SERVER_DIR}"/*.key "${CLIENT_DIR}"/*.key
sudo chmod 644 "${CA_DIR}"/*.crt "${SERVER_DIR}"/*.crt "${CLIENT_DIR}"/*.crt
sudo chmod 644 "${CERT_DIR}/dhparam.pem"

# Summary
echo ""
echo "========================================="
echo "PQC Certificate Generation Complete!"
echo "========================================="
echo ""
echo "Certificate Directory: ${CERT_DIR}"
echo ""
echo "Root CA:"
echo "  Certificate: ${CA_DIR}/root-ca.crt"
echo "  Private Key: ${CA_DIR}/root-ca.key"
echo ""
echo "Intermediate CA:"
echo "  Certificate: ${CA_DIR}/intermediate-ca.crt"
echo "  Private Key: ${CA_DIR}/intermediate-ca.key"
echo ""
echo "Server Certificate:"
echo "  Certificate: ${SERVER_DIR}/server.crt"
echo "  Bundle: ${SERVER_DIR}/server-bundle.crt"
echo "  RSA Key: ${SERVER_DIR}/server-rsa.key"
echo "  Dilithium3 Key: ${SERVER_DIR}/server-dilithium3.key"
echo ""
echo "Client Certificate:"
echo "  Certificate: ${CLIENT_DIR}/client.crt"
echo "  Private Key: ${CLIENT_DIR}/client.key"
echo ""
echo "DH Parameters: ${CERT_DIR}/dhparam.pem"
echo ""

# Verify certificates
echo "Verifying certificates..."
"${OPENSSL_INSTALL_DIR}/bin/openssl" x509 -in "${SERVER_DIR}/server.crt" -text -noout | grep -E "Subject:|Issuer:|Not After|DNS:"
```

---

## 2. APISIX Gateway Q-TLS 설정

### 2.1 APISIX 설치 스크립트

```bash
#!/bin/bash
# install-apisix-qtsl.sh - Install APISIX with Q-TLS support

set -e

APISIX_VERSION="3.7.0"
APISIX_DIR="/opt/apisix"

echo "[1/5] Installing APISIX dependencies..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    lua5.1 \
    liblua5.1-0-dev \
    luarocks \
    make

echo "[2/5] Installing APISIX via Docker (recommended)..."
docker run -d \
    --name apisix-qtsl \
    --network host \
    -v /opt/qsign/certs:/opt/certs:ro \
    -v /opt/apisix/config:/usr/local/apisix/conf:rw \
    -e APISIX_STAND_ALONE=true \
    apache/apisix:${APISIX_VERSION}-debian

echo "[3/5] Waiting for APISIX to start..."
sleep 10

echo "[4/5] Creating APISIX configuration directory..."
sudo mkdir -p /opt/apisix/config

echo "[5/5] APISIX installed successfully!"
echo "  Container: apisix-qtsl"
echo "  Admin API: http://localhost:9180"
echo "  Gateway: http://localhost:9080 (HTTP), https://localhost:9443 (HTTPS)"
```

### 2.2 APISIX Q-TLS 설정 파일

```yaml
# /opt/apisix/config/config.yaml
# APISIX Q-TLS Configuration

apisix:
  node_listen:
    - port: 9080
      enable_http2: true
    - port: 9443
      enable_http2: true
      enable_http3: false
      ssl:
        enable: true
        ssl_protocols: "TLSv1.3"
        ssl_ciphers: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
        ssl_prefer_server_ciphers: true
        ssl_session_cache: "shared:SSL:50m"
        ssl_session_timeout: "1h"
        ssl_session_tickets: true
        ssl_stapling: true
        ssl_stapling_verify: true
        # Q-TLS Hybrid Mode (requires custom build with OQS)
        ssl_ecdh_curve: "X25519:prime256v1:secp384r1"

  enable_admin: true
  admin_key:
    - name: "admin"
      key: "edd1c9f034335f136f87ad84b625c8f1"
      role: admin

  ssl:
    enable: true
    listen:
      - port: 9443
        enable_http2: true

deployment:
  role: traditional
  role_traditional:
    config_provider: etcd

  etcd:
    host:
      - "http://127.0.0.1:2379"
    prefix: "/apisix"
    timeout: 30

plugin_attr:
  prometheus:
    enable_export_server: true
    export_addr:
      ip: "0.0.0.0"
      port: 9091

# Q-TLS specific configuration
nginx_config:
  http:
    custom_lua_shared_dict:
      qtsl-sessions: 50m
      qtsl-ocsp-cache: 10m

  http_server_configuration_snippet: |
    # Q-TLS Configuration
    ssl_certificate /opt/certs/server/server-bundle.crt;
    ssl_certificate_key /opt/certs/server/server-rsa.key;

    # SSL Session Settings
    ssl_session_cache shared:QtslSSL:50m;
    ssl_session_timeout 1h;
    ssl_session_tickets on;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /opt/certs/ca/intermediate-ca.crt;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

  http_configuration_snippet: |
    # Performance Tuning
    ssl_buffer_size 16k;

    # Client Certificate Verification (optional)
    # ssl_client_certificate /opt/certs/ca/root-ca.crt;
    # ssl_verify_client optional;
    # ssl_verify_depth 3;
```

### 2.3 APISIX Route 설정 스크립트

```bash
#!/bin/bash
# configure-apisix-routes.sh - Configure APISIX routes with Q-TLS

set -e

ADMIN_API="http://localhost:9180"
ADMIN_KEY="edd1c9f034335f136f87ad84b625c8f1"

echo "[1/4] Creating SSL certificate in APISIX..."

curl -X PUT "${ADMIN_API}/apisix/admin/ssls/1" \
  -H "X-API-KEY: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "cert": "'"$(cat /opt/qsign/certs/server/server-bundle.crt | sed ':a;N;$!ba;s/\n/\\n/g')"'",
    "key": "'"$(cat /opt/qsign/certs/server/server-rsa.key | sed ':a;N;$!ba;s/\n/\\n/g')"'",
    "snis": ["api.qsign.local", "*.qsign.local"]
  }'

echo ""
echo "[2/4] Creating upstream backend..."

curl -X PUT "${ADMIN_API}/apisix/admin/upstreams/1" \
  -H "X-API-KEY: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "roundrobin",
    "scheme": "https",
    "nodes": {
      "backend.qsign.local:8443": 1
    },
    "timeout": {
      "connect": 10,
      "send": 10,
      "read": 30
    },
    "keepalive_pool": {
      "size": 320,
      "idle_timeout": 60,
      "requests": 1000
    }
  }'

echo ""
echo "[3/4] Creating route with Q-TLS..."

curl -X PUT "${ADMIN_API}/apisix/admin/routes/1" \
  -H "X-API-KEY: ${ADMIN_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/*",
    "name": "api-route-qtsl",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "host": "api.qsign.local",
    "upstream_id": 1,
    "plugins": {
      "limit-req": {
        "rate": 500,
        "burst": 1000,
        "key": "remote_addr",
        "rejected_code": 429
      },
      "prometheus": {
        "prefer_name": true
      },
      "cors": {
        "allow_origins": "**",
        "allow_methods": "**",
        "allow_headers": "**",
        "expose_headers": "**",
        "max_age": 3600,
        "allow_credential": true
      }
    }
  }'

echo ""
echo "[4/4] Verifying routes..."

curl -s "${ADMIN_API}/apisix/admin/routes/1" \
  -H "X-API-KEY: ${ADMIN_KEY}" | jq .

echo ""
echo "✓ APISIX routes configured successfully!"
echo ""
echo "Test with:"
echo "  curl -k https://api.qsign.local:9443/api/health"
```

---

## 3. Nginx Q-TLS 모듈 설정

### 3.1 Nginx 빌드 스크립트

```bash
#!/bin/bash
# build-nginx-qtsl.sh - Build Nginx with OpenSSL OQS support

set -e

NGINX_VERSION="1.25.3"
INSTALL_DIR="/opt/nginx-qtsl"

source /etc/profile.d/openssl-oqs.sh

echo "[1/5] Downloading Nginx ${NGINX_VERSION}..."
cd /tmp
wget "http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
tar xzf "nginx-${NGINX_VERSION}.tar.gz"
cd "nginx-${NGINX_VERSION}"

echo "[2/5] Installing Nginx dependencies..."
sudo apt-get install -y \
    libpcre3-dev \
    zlib1g-dev \
    libgeoip-dev \
    libgd-dev

echo "[3/5] Configuring Nginx with OpenSSL OQS..."
./configure \
    --prefix="${INSTALL_DIR}" \
    --sbin-path="${INSTALL_DIR}/sbin/nginx" \
    --conf-path="${INSTALL_DIR}/conf/nginx.conf" \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --lock-path=/var/run/nginx.lock \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-http_realip_module \
    --with-http_stub_status_module \
    --with-http_gzip_static_module \
    --with-http_secure_link_module \
    --with-threads \
    --with-stream \
    --with-stream_ssl_module \
    --with-openssl="${OPENSSL_INSTALL_DIR}" \
    --with-openssl-opt="--prefix=${OPENSSL_INSTALL_DIR}" \
    --with-cc-opt="-I${OPENSSL_INSTALL_DIR}/include -I${OQS_INSTALL_DIR}/include" \
    --with-ld-opt="-L${OPENSSL_INSTALL_DIR}/lib -L${OQS_INSTALL_DIR}/lib -Wl,-rpath,${OPENSSL_INSTALL_DIR}/lib"

echo "[4/5] Building Nginx..."
make -j$(nproc)

echo "[5/5] Installing Nginx..."
sudo make install

# Create systemd service
sudo tee /etc/systemd/system/nginx-qtsl.service > /dev/null << EOF
[Unit]
Description=Nginx Q-TLS Web Server
After=network.target

[Service]
Type=forking
PIDFile=/var/run/nginx.pid
Environment="LD_LIBRARY_PATH=${OPENSSL_INSTALL_DIR}/lib:${OQS_INSTALL_DIR}/lib"
Environment="OPENSSL_CONF=${OPENSSL_INSTALL_DIR}/ssl/openssl.cnf"
ExecStartPre=${INSTALL_DIR}/sbin/nginx -t
ExecStart=${INSTALL_DIR}/sbin/nginx
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

echo ""
echo "✓ Nginx Q-TLS built successfully!"
echo "  Installation Path: ${INSTALL_DIR}"
echo "  Binary: ${INSTALL_DIR}/sbin/nginx"
echo "  Config: ${INSTALL_DIR}/conf/nginx.conf"
echo ""
echo "Start service: sudo systemctl start nginx-qtsl"
echo "Enable service: sudo systemctl enable nginx-qtsl"
```

### 3.2 Nginx Q-TLS 설정 파일

```nginx
# /opt/nginx-qtsl/conf/nginx.conf
# Nginx Q-TLS Configuration

user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /opt/nginx-qtsl/conf/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format qtsl '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" '
                    'ssl_protocol=$ssl_protocol ssl_cipher=$ssl_cipher '
                    'ssl_curves=$ssl_curves session_reused=$ssl_session_reused';

    access_log /var/log/nginx/access.log qtsl buffer=32k flush=5s;
    error_log /var/log/nginx/error.log warn;

    # Performance
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript
               application/json application/javascript application/xml+rss
               application/rss+xml font/truetype font/opentype
               application/vnd.ms-fontobject image/svg+xml;

    # SSL/TLS Global Settings
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";

    # SSL Session Cache
    ssl_session_cache shared:QtslSSL:50m;
    ssl_session_timeout 1h;
    ssl_session_tickets on;
    ssl_session_ticket_key /opt/qsign/certs/ticket.key;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # DH Parameters
    ssl_dhparam /opt/qsign/certs/dhparam.pem;

    # ECDH Curve (Hybrid: Classical + PQC)
    ssl_ecdh_curve X25519:prime256v1:secp384r1;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    # Upstream Backend
    upstream backend {
        least_conn;
        server backend1.qsign.local:8443 max_fails=3 fail_timeout=30s;
        server backend2.qsign.local:8443 max_fails=3 fail_timeout=30s backup;

        keepalive 32;
        keepalive_requests 1000;
        keepalive_timeout 60s;
    }

    # HTTPS Server
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name api.qsign.local;

        # Q-TLS Certificates
        ssl_certificate /opt/qsign/certs/server/server-bundle.crt;
        ssl_certificate_key /opt/qsign/certs/server/server-rsa.key;
        ssl_trusted_certificate /opt/qsign/certs/ca/root-ca.crt;

        # Client Certificate (mTLS - Optional)
        # ssl_client_certificate /opt/qsign/certs/ca/root-ca.crt;
        # ssl_verify_client optional;
        # ssl_verify_depth 3;

        # Rate Limiting
        limit_req zone=api_limit burst=200 nodelay;
        limit_conn conn_limit 100;

        # Root
        root /var/www/html;
        index index.html;

        # API Proxy
        location /api/ {
            proxy_pass https://backend;
            proxy_http_version 1.1;

            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
            proxy_set_header X-SSL-Client-S-DN $ssl_client_s_dn;

            proxy_ssl_protocols TLSv1.3;
            proxy_ssl_ciphers HIGH:!aNULL:!MD5;
            proxy_ssl_verify on;
            proxy_ssl_verify_depth 3;
            proxy_ssl_trusted_certificate /opt/qsign/certs/ca/root-ca.crt;
            proxy_ssl_session_reuse on;

            proxy_connect_timeout 10s;
            proxy_send_timeout 30s;
            proxy_read_timeout 30s;

            proxy_buffering on;
            proxy_buffer_size 16k;
            proxy_buffers 8 16k;
        }

        # Health Check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }

        # Metrics (Prometheus)
        location /metrics {
            stub_status;
            access_log off;
            allow 127.0.0.1;
            deny all;
        }
    }

    # HTTP to HTTPS Redirect
    server {
        listen 80;
        listen [::]:80;
        server_name api.qsign.local;

        location / {
            return 301 https://$server_name$request_uri;
        }
    }
}
```

### 3.3 Nginx 세션 티켓 키 생성

```bash
#!/bin/bash
# generate-nginx-session-ticket-key.sh

set -e

TICKET_KEY_DIR="/opt/qsign/certs"
TICKET_KEY_FILE="${TICKET_KEY_DIR}/ticket.key"

echo "Generating Nginx session ticket key..."

# Generate 80 bytes (48 bytes key name + 32 bytes AES key)
openssl rand 80 > "${TICKET_KEY_FILE}"

chmod 600 "${TICKET_KEY_FILE}"

echo "✓ Session ticket key generated: ${TICKET_KEY_FILE}"
```

---

## 4. 클라이언트 라이브러리

### 4.1 Python Q-TLS 클라이언트

```python
#!/usr/bin/env python3
# qtsl_client.py - Python Q-TLS Client

import ssl
import socket
import certifi
from typing import Optional

class QtslClient:
    """Q-TLS HTTPS Client with PQC support"""

    def __init__(
        self,
        ca_cert: str = "/opt/qsign/certs/ca/root-ca.crt",
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        verify_mode: int = ssl.CERT_REQUIRED
    ):
        """
        Initialize Q-TLS client

        Args:
            ca_cert: Path to CA certificate for verification
            client_cert: Path to client certificate (for mTLS)
            client_key: Path to client private key (for mTLS)
            verify_mode: Certificate verification mode
        """
        self.ca_cert = ca_cert
        self.client_cert = client_cert
        self.client_key = client_key
        self.verify_mode = verify_mode

    def create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context with Q-TLS settings"""

        # Create context (TLS 1.3 only)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Cipher suites (prefer PQC-hybrid)
        context.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")

        # Load CA certificate
        context.load_verify_locations(cafile=self.ca_cert)
        context.verify_mode = self.verify_mode
        context.check_hostname = True

        # Load client certificate (for mTLS)
        if self.client_cert and self.client_key:
            context.load_cert_chain(
                certfile=self.client_cert,
                keyfile=self.client_key
            )

        # Enable session resumption
        context.options |= ssl.OP_NO_TICKET  # Use Session ID instead of tickets

        return context

    def connect(
        self,
        hostname: str,
        port: int = 443,
        timeout: float = 30.0
    ) -> ssl.SSLSocket:
        """
        Establish Q-TLS connection

        Args:
            hostname: Server hostname
            port: Server port
            timeout: Connection timeout in seconds

        Returns:
            SSL socket object
        """
        context = self.create_ssl_context()

        # Create socket
        sock = socket.create_connection((hostname, port), timeout=timeout)

        # Wrap with SSL
        ssl_sock = context.wrap_socket(sock, server_hostname=hostname)

        return ssl_sock

    def get_connection_info(self, ssl_sock: ssl.SSLSocket) -> dict:
        """Get connection information"""

        cipher = ssl_sock.cipher()
        version = ssl_sock.version()
        cert = ssl_sock.getpeercert()

        return {
            "protocol": version,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
            "session_reused": ssl_sock.session_reused,
            "peer_cert": cert
        }

def main():
    """Example usage"""

    client = QtslClient(
        ca_cert="/opt/qsign/certs/ca/root-ca.crt",
        # Uncomment for mTLS:
        # client_cert="/opt/qsign/certs/client/client.crt",
        # client_key="/opt/qsign/certs/client/client.key"
    )

    # Connect to server
    print("Connecting to api.qsign.local:443...")
    ssl_sock = client.connect("api.qsign.local", 443)

    # Get connection info
    info = client.get_connection_info(ssl_sock)
    print(f"\n✓ Connected successfully!")
    print(f"  Protocol: {info['protocol']}")
    print(f"  Cipher: {info['cipher']}")
    print(f"  Cipher Bits: {info['cipher_bits']}")
    print(f"  Session Reused: {info['session_reused']}")

    # Send HTTP request
    request = (
        "GET /api/health HTTP/1.1\r\n"
        "Host: api.qsign.local\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    ssl_sock.sendall(request.encode())

    # Receive response
    response = b""
    while True:
        data = ssl_sock.recv(4096)
        if not data:
            break
        response += data

    print(f"\nResponse:\n{response.decode()}")

    # Close connection
    ssl_sock.close()

if __name__ == "__main__":
    main()
```

### 4.2 Node.js Q-TLS 클라이언트

```javascript
// qtsl-client.js - Node.js Q-TLS Client

const tls = require('tls');
const https = require('https');
const fs = require('fs');

class QtslClient {
    constructor(options = {}) {
        this.caFile = options.caFile || '/opt/qsign/certs/ca/root-ca.crt';
        this.certFile = options.certFile || null;  // For mTLS
        this.keyFile = options.keyFile || null;    // For mTLS
        this.rejectUnauthorized = options.rejectUnauthorized !== false;
    }

    createTlsOptions(hostname) {
        const options = {
            // TLS 1.3 only
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',

            // Cipher suites
            ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',

            // CA certificate
            ca: fs.readFileSync(this.caFile),

            // Hostname verification
            servername: hostname,
            rejectUnauthorized: this.rejectUnauthorized,

            // Enable session resumption
            sessionIdContext: 'qtsl-client',
        };

        // mTLS (client certificate)
        if (this.certFile && this.keyFile) {
            options.cert = fs.readFileSync(this.certFile);
            options.key = fs.readFileSync(this.keyFile);
        }

        return options;
    }

    async request(url, options = {}) {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;
        const port = urlObj.port || 443;
        const path = urlObj.pathname + urlObj.search;

        const tlsOptions = this.createTlsOptions(hostname);

        const requestOptions = {
            hostname,
            port,
            path,
            method: options.method || 'GET',
            headers: options.headers || {},
            ...tlsOptions
        };

        return new Promise((resolve, reject) => {
            const req = https.request(requestOptions, (res) => {
                let data = '';

                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    const tlsSocket = res.socket;

                    resolve({
                        statusCode: res.statusCode,
                        headers: res.headers,
                        body: data,
                        tlsInfo: {
                            protocol: tlsSocket.getProtocol(),
                            cipher: tlsSocket.getCipher(),
                            sessionReused: tlsSocket.isSessionReused(),
                            peerCertificate: tlsSocket.getPeerCertificate(true)
                        }
                    });
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            if (options.body) {
                req.write(options.body);
            }

            req.end();
        });
    }

    async get(url, options = {}) {
        return this.request(url, { ...options, method: 'GET' });
    }

    async post(url, body, options = {}) {
        const headers = options.headers || {};
        if (!headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }
        headers['Content-Length'] = Buffer.byteLength(body);

        return this.request(url, {
            ...options,
            method: 'POST',
            headers,
            body
        });
    }
}

// Example usage
async function main() {
    const client = new QtslClient({
        caFile: '/opt/qsign/certs/ca/root-ca.crt',
        // Uncomment for mTLS:
        // certFile: '/opt/qsign/certs/client/client.crt',
        // keyFile: '/opt/qsign/certs/client/client.key'
    });

    try {
        console.log('Connecting to https://api.qsign.local/api/health...');

        const response = await client.get('https://api.qsign.local/api/health');

        console.log('\n✓ Connected successfully!');
        console.log(`  Status Code: ${response.statusCode}`);
        console.log(`  Protocol: ${response.tlsInfo.protocol}`);
        console.log(`  Cipher: ${response.tlsInfo.cipher.name}`);
        console.log(`  Session Reused: ${response.tlsInfo.sessionReused}`);
        console.log(`\nResponse Body:\n${response.body}`);

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = QtslClient;
```

### 4.3 Java Q-TLS 클라이언트

```java
// QtslClient.java - Java Q-TLS Client

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class QtslClient {
    private final String caFile;
    private final String clientCertFile;
    private final String clientKeyFile;
    private SSLContext sslContext;

    public QtslClient(String caFile) {
        this(caFile, null, null);
    }

    public QtslClient(String caFile, String clientCertFile, String clientKeyFile) {
        this.caFile = caFile;
        this.clientCertFile = clientCertFile;
        this.clientKeyFile = clientKeyFile;
        initSSLContext();
    }

    private void initSSLContext() {
        try {
            // Load CA certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream caInputStream = new FileInputStream(caFile);
            Certificate caCert = cf.generateCertificate(caInputStream);
            caInputStream.close();

            // Create KeyStore with CA
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca-cert", caCert);

            // Create TrustManager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            );
            tmf.init(trustStore);

            // Create SSLContext (TLS 1.3)
            sslContext = SSLContext.getInstance("TLSv1.3");

            // TODO: Load client certificate for mTLS
            KeyManager[] keyManagers = null;
            if (clientCertFile != null && clientKeyFile != null) {
                // Load client certificate and key
                // Implementation depends on key format (PKCS#12, PEM, etc.)
            }

            sslContext.init(keyManagers, tmf.getTrustManagers(), new java.security.SecureRandom());

        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize SSL context", e);
        }
    }

    public String get(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();

        // Configure SSL/TLS
        conn.setSSLSocketFactory(sslContext.getSocketFactory());

        // Enable only TLS 1.3
        SSLParameters sslParams = new SSLParameters();
        sslParams.setProtocols(new String[]{"TLSv1.3"});
        sslParams.setCipherSuites(new String[]{
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256"
        });
        conn.setSSLParameters(sslParams);

        // Set request properties
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        // Connect and read response
        int responseCode = conn.getResponseCode();

        BufferedReader in = new BufferedReader(
            new InputStreamReader(conn.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            response.append(line).append("\n");
        }
        in.close();

        // Print connection info
        SSLSession session = conn.getSSLSession();
        System.out.println("✓ Connected successfully!");
        System.out.println("  Protocol: " + session.getProtocol());
        System.out.println("  Cipher Suite: " + session.getCipherSuite());
        System.out.println("  Peer Principal: " + session.getPeerPrincipal());

        conn.disconnect();
        return response.toString();
    }

    public static void main(String[] args) {
        try {
            QtslClient client = new QtslClient("/opt/qsign/certs/ca/root-ca.crt");

            System.out.println("Connecting to https://api.qsign.local/api/health...\n");
            String response = client.get("https://api.qsign.local/api/health");

            System.out.println("\nResponse:");
            System.out.println(response);

        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
```

---

## 5. Golang Q-TLS 클라이언트

### 5.1 Go Q-TLS 클라이언트 예제

```go
// qtsl_client.go - Golang Q-TLS Client

package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io"
    "net/http"
    "os"
    "time"
)

type QtslClient struct {
    caFile     string
    certFile   string
    keyFile    string
    httpClient *http.Client
}

func NewQtslClient(caFile string, certFile string, keyFile string) (*QtslClient, error) {
    client := &QtslClient{
        caFile:   caFile,
        certFile: certFile,
        keyFile:  keyFile,
    }

    if err := client.initHTTPClient(); err != nil {
        return nil, err
    }

    return client, nil
}

func (c *QtslClient) initHTTPClient() error {
    // Load CA certificate
    caCert, err := os.ReadFile(c.caFile)
    if err != nil {
        return fmt.Errorf("failed to read CA certificate: %w", err)
    }

    caCertPool := x509.NewCertPool()
    if !caCertPool.AppendCertsFromPEM(caCert) {
        return fmt.Errorf("failed to parse CA certificate")
    }

    // TLS configuration
    tlsConfig := &tls.Config{
        RootCAs:    caCertPool,
        MinVersion: tls.VersionTLS13,
        MaxVersion: tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
        },
        // Prefer server cipher suites
        PreferServerCipherSuites: true,
        // Enable session resumption
        ClientSessionCache: tls.NewLRUClientSessionCache(128),
    }

    // Load client certificate (for mTLS)
    if c.certFile != "" && c.keyFile != "" {
        cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
        if err != nil {
            return fmt.Errorf("failed to load client certificate: %w", err)
        }
        tlsConfig.Certificates = []tls.Certificate{cert}
    }

    // Create HTTP transport
    transport := &http.Transport{
        TLSClientConfig: tlsConfig,
        // Connection pooling
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        // Timeouts
        TLSHandshakeTimeout:   30 * time.Second,
        ResponseHeaderTimeout: 30 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
    }

    // Create HTTP client
    c.httpClient = &http.Client{
        Transport: transport,
        Timeout:   60 * time.Second,
    }

    return nil
}

func (c *QtslClient) Get(url string) (*http.Response, error) {
    return c.httpClient.Get(url)
}

func (c *QtslClient) Post(url string, contentType string, body io.Reader) (*http.Response, error) {
    return c.httpClient.Post(url, contentType, body)
}

func (c *QtslClient) Do(req *http.Request) (*http.Response, error) {
    return c.httpClient.Do(req)
}

func printConnectionInfo(resp *http.Response) {
    if resp.TLS != nil {
        fmt.Println("\n✓ Connected successfully!")
        fmt.Printf("  Protocol: %s\n", getTLSVersionName(resp.TLS.Version))
        fmt.Printf("  Cipher Suite: %s\n", getCipherSuiteName(resp.TLS.CipherSuite))
        fmt.Printf("  Server Name: %s\n", resp.TLS.ServerName)
        fmt.Printf("  Session Resumed: %t\n", resp.TLS.DidResume)
        fmt.Printf("  Negotiated Protocol: %s\n", resp.TLS.NegotiatedProtocol)

        if len(resp.TLS.PeerCertificates) > 0 {
            cert := resp.TLS.PeerCertificates[0]
            fmt.Printf("  Peer Certificate:\n")
            fmt.Printf("    Subject: %s\n", cert.Subject)
            fmt.Printf("    Issuer: %s\n", cert.Issuer)
            fmt.Printf("    Not Before: %s\n", cert.NotBefore)
            fmt.Printf("    Not After: %s\n", cert.NotAfter)
        }
    }
}

func getTLSVersionName(version uint16) string {
    switch version {
    case tls.VersionTLS13:
        return "TLS 1.3"
    case tls.VersionTLS12:
        return "TLS 1.2"
    default:
        return fmt.Sprintf("Unknown (0x%04x)", version)
    }
}

func getCipherSuiteName(cipherSuite uint16) string {
    switch cipherSuite {
    case tls.TLS_AES_256_GCM_SHA384:
        return "TLS_AES_256_GCM_SHA384"
    case tls.TLS_CHACHA20_POLY1305_SHA256:
        return "TLS_CHACHA20_POLY1305_SHA256"
    case tls.TLS_AES_128_GCM_SHA256:
        return "TLS_AES_128_GCM_SHA256"
    default:
        return fmt.Sprintf("Unknown (0x%04x)", cipherSuite)
    }
}

func main() {
    // Create Q-TLS client
    client, err := NewQtslClient(
        "/opt/qsign/certs/ca/root-ca.crt",
        "",  // Client cert (for mTLS)
        "",  // Client key (for mTLS)
    )
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
        os.Exit(1)
    }

    // Make request
    fmt.Println("Connecting to https://api.qsign.local/api/health...")

    resp, err := client.Get("https://api.qsign.local/api/health")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    // Print connection info
    printConnectionInfo(resp)

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("\nResponse Status: %s\n", resp.Status)
    fmt.Printf("Response Body:\n%s\n", string(body))
}
```

---

## 6. 테스트 스크립트

### 6.1 OpenSSL s_client 테스트

```bash
#!/bin/bash
# test-qtsl-openssl.sh - Test Q-TLS with OpenSSL s_client

set -e

source /etc/profile.d/openssl-oqs.sh

SERVER="api.qsign.local"
PORT="443"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"
CLIENT_CERT="/opt/qsign/certs/client/client.crt"
CLIENT_KEY="/opt/qsign/certs/client/client.key"

echo "========================================="
echo "Q-TLS Connection Test with OpenSSL"
echo "========================================="
echo ""

# Test 1: Basic connection
echo "[Test 1] Basic TLS 1.3 connection..."
echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -servername "${SERVER}" \
    -showcerts \
    -state \
    2>&1 | grep -E "Protocol|Cipher|Verify return code"

echo ""

# Test 2: Session resumption
echo "[Test 2] Session resumption test..."
SESSION_FILE=$(mktemp)

echo "First connection (full handshake)..."
echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -sess_out "${SESSION_FILE}" \
    2>&1 | grep -E "Session-ID:|New, TLSv1.3"

echo ""
echo "Second connection (session resumption)..."
echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -sess_in "${SESSION_FILE}" \
    2>&1 | grep -E "Session-ID:|Reused, TLSv1.3"

rm -f "${SESSION_FILE}"

echo ""

# Test 3: Mutual TLS (mTLS)
echo "[Test 3] Mutual TLS (mTLS) test..."
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
    echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
        -connect "${SERVER}:${PORT}" \
        -tls1_3 \
        -CAfile "${CA_CERT}" \
        -cert "${CLIENT_CERT}" \
        -key "${CLIENT_KEY}" \
        2>&1 | grep -E "Client certificate|Verify return code"
else
    echo "⚠ Client certificate not found. Skipping mTLS test."
fi

echo ""

# Test 4: Cipher suite negotiation
echo "[Test 4] Cipher suite negotiation..."
echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -ciphersuites "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256" \
    2>&1 | grep "Cipher"

echo ""

# Test 5: OCSP stapling
echo "[Test 5] OCSP stapling test..."
echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -status \
    2>&1 | grep -E "OCSP.*Response Status|Cert Status"

echo ""
echo "✓ All tests completed!"
```

### 6.2 cURL 테스트

```bash
#!/bin/bash
# test-qtsl-curl.sh - Test Q-TLS with cURL

set -e

SERVER="https://api.qsign.local"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"
CLIENT_CERT="/opt/qsign/certs/client/client.crt"
CLIENT_KEY="/opt/qsign/certs/client/client.key"

echo "========================================="
echo "Q-TLS HTTP Test with cURL"
echo "========================================="
echo ""

# Test 1: Basic GET request
echo "[Test 1] Basic GET request..."
curl -v \
    --cacert "${CA_CERT}" \
    --tls13-ciphers "TLS_AES_256_GCM_SHA384" \
    "${SERVER}/api/health" \
    2>&1 | grep -E "SSL connection|TLSv1.3|Server certificate"

echo ""

# Test 2: POST request with JSON
echo "[Test 2] POST request with JSON..."
curl -X POST \
    --cacert "${CA_CERT}" \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}' \
    "${SERVER}/api/test" \
    2>&1

echo ""

# Test 3: mTLS request
echo "[Test 3] mTLS request..."
if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
    curl -v \
        --cacert "${CA_CERT}" \
        --cert "${CLIENT_CERT}" \
        --key "${CLIENT_KEY}" \
        "${SERVER}/api/secure" \
        2>&1 | grep -E "SSL connection|Client certificate"
else
    echo "⚠ Client certificate not found. Skipping mTLS test."
fi

echo ""

# Test 4: Performance test (multiple requests)
echo "[Test 4] Performance test (10 requests)..."
time for i in {1..10}; do
    curl -s \
        --cacert "${CA_CERT}" \
        "${SERVER}/api/health" > /dev/null
done

echo ""
echo "✓ All cURL tests completed!"
```

### 6.3 성능 벤치마크 (wrk)

```bash
#!/bin/bash
# benchmark-qtsl-wrk.sh - Performance benchmark with wrk

set -e

SERVER="https://api.qsign.local"
THREADS=4
CONNECTIONS=100
DURATION="30s"

echo "========================================="
echo "Q-TLS Performance Benchmark (wrk)"
echo "========================================="
echo ""
echo "Configuration:"
echo "  Server: ${SERVER}"
echo "  Threads: ${THREADS}"
echo "  Connections: ${CONNECTIONS}"
echo "  Duration: ${DURATION}"
echo ""

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "Installing wrk..."
    sudo apt-get install -y wrk
fi

# Run benchmark
echo "Running benchmark..."
wrk -t${THREADS} -c${CONNECTIONS} -d${DURATION} \
    --latency \
    "${SERVER}/api/health"

echo ""
echo "✓ Benchmark completed!"
```

### 6.4 연결 정보 추출 스크립트

```bash
#!/bin/bash
# get-qtsl-connection-info.sh - Extract Q-TLS connection details

set -e

source /etc/profile.d/openssl-oqs.sh

SERVER="${1:-api.qsign.local}"
PORT="${2:-443}"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"

echo "========================================="
echo "Q-TLS Connection Information"
echo "========================================="
echo ""
echo "Server: ${SERVER}:${PORT}"
echo ""

# Extract connection details
CONNECTION_INFO=$(echo "Q" | "${OPENSSL_INSTALL_DIR}/bin/openssl" s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -servername "${SERVER}" \
    2>&1)

# Parse and display information
echo "TLS Protocol:"
echo "${CONNECTION_INFO}" | grep "Protocol" | head -1

echo ""
echo "Cipher Suite:"
echo "${CONNECTION_INFO}" | grep "Cipher" | head -1

echo ""
echo "Session Details:"
echo "${CONNECTION_INFO}" | grep -E "Session-ID|Session-ID-ctx|Master-Key" | head -3

echo ""
echo "Server Certificate:"
echo "${CONNECTION_INFO}" | "${OPENSSL_INSTALL_DIR}/bin/openssl" x509 -text -noout 2>/dev/null | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"

echo ""
echo "Certificate Chain:"
CERT_COUNT=$(echo "${CONNECTION_INFO}" | grep -c "BEGIN CERTIFICATE" || true)
echo "  Certificates in chain: ${CERT_COUNT}"

echo ""
echo "Verification Result:"
echo "${CONNECTION_INFO}" | grep "Verify return code"

echo ""
echo "✓ Connection information extracted!"
```

---

## 7. 성능 튜닝

### 7.1 시스템 레벨 튜닝

```bash
#!/bin/bash
# tune-system-for-qtsl.sh - System-level tuning for Q-TLS

set -e

echo "Applying system-level tuning for Q-TLS..."

# Kernel parameters
sudo tee /etc/sysctl.d/99-qtsl.conf > /dev/null << 'EOF'
# Network Performance
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_keepalive_intvl = 15

# TCP Performance
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_congestion_control = bbr

# Buffer Sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# File Descriptors
fs.file-max = 2097152
fs.nr_open = 2097152

# Security
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
EOF

sudo sysctl -p /etc/sysctl.d/99-qtsl.conf

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf > /dev/null << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

echo "✓ System tuning applied!"
echo ""
echo "⚠ Reboot required for some changes to take effect"
```

### 7.2 Nginx 성능 튜닝

```bash
#!/bin/bash
# tune-nginx-qtsl.sh - Nginx-specific tuning for Q-TLS

set -e

NGINX_CONF="/opt/nginx-qtsl/conf/nginx.conf"

echo "Applying Nginx tuning for Q-TLS..."

# Backup original configuration
sudo cp "${NGINX_CONF}" "${NGINX_CONF}.bak.$(date +%Y%m%d%H%M%S)"

# Create optimized configuration snippet
sudo tee /opt/nginx-qtsl/conf/qtsl-performance.conf > /dev/null << 'EOF'
# Q-TLS Performance Tuning

# Worker Processes
worker_processes auto;
worker_rlimit_nofile 100000;
worker_cpu_affinity auto;

events {
    worker_connections 8192;
    use epoll;
    multi_accept on;
    accept_mutex off;
}

http {
    # Timeouts
    client_body_timeout 12s;
    client_header_timeout 12s;
    send_timeout 10s;

    # Buffers
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 8k;
    output_buffers 2 32k;

    # SSL Buffers
    ssl_buffer_size 4k;  # Reduce from 16k for lower latency

    # Connection Keepalive
    keepalive_timeout 65;
    keepalive_requests 1000;

    # Sendfile Optimization
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_comp_level 5;
    gzip_min_length 256;
    gzip_proxied any;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Open File Cache
    open_file_cache max=10000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # SSL Session Cache (Large for Session Resumption)
    ssl_session_cache shared:QtslSSL:100m;
    ssl_session_timeout 4h;

    # Connection Pool to Upstreams
    upstream backend {
        keepalive 256;
        keepalive_requests 10000;
        keepalive_timeout 60s;
    }
}
EOF

echo "✓ Nginx tuning configuration created!"
echo "  File: /opt/nginx-qtsl/conf/qtsl-performance.conf"
echo ""
echo "Include this in your nginx.conf or apply settings manually."
```

### 7.3 APISIX 성능 튜닝

```yaml
# /opt/apisix/config/performance-tuning.yaml
# APISIX Performance Tuning for Q-TLS

nginx_config:
  worker_processes: auto
  worker_rlimit_nofile: 102400
  worker_cpu_affinity: auto

  event:
    worker_connections: 10620
    use: epoll
    multi_accept: on

  http:
    access_log: "off"  # or log to memory buffer
    access_log_buffer: 32768

    keepalive_timeout: 60s
    keepalive_requests: 1000

    client_body_buffer_size: 16k
    client_header_buffer_size: 2k
    large_client_header_buffers: 4 8k

    # SSL Session Cache
    ssl_session_cache: "shared:QtslSSL:200m"
    ssl_session_timeout: "4h"
    ssl_session_tickets: "on"

    # Upstream Keepalive
    upstream:
      keepalive: 320
      keepalive_requests: 1000
      keepalive_timeout: 60s

# Plugin Optimization
plugin_attr:
  prometheus:
    enable_export_server: true
    export_addr:
      ip: "0.0.0.0"
      port: 9091
    # Metrics buffer
    metrics_interval: 15

# Etcd Connection Pool
deployment:
  etcd:
    timeout: 30
    startup_retry: 2

# Custom Lua Shared Dictionaries
custom_lua_shared_dict:
  qtsl-sessions: 200m
  qtsl-ocsp-cache: 20m
  prometheus-metrics: 50m
```

---

## 8. 트러블슈팅 가이드

### 8.1 일반적인 문제 해결

```bash
#!/bin/bash
# troubleshoot-qtsl.sh - Q-TLS Troubleshooting Tool

set -e

echo "========================================="
echo "Q-TLS Troubleshooting Tool"
echo "========================================="
echo ""

# Check 1: OpenSSL OQS Installation
echo "[Check 1] OpenSSL OQS Installation"
if [[ -f /etc/profile.d/openssl-oqs.sh ]]; then
    source /etc/profile.d/openssl-oqs.sh
    echo "✓ OpenSSL OQS environment found"

    if command -v openssl &> /dev/null; then
        OPENSSL_VERSION=$(openssl version)
        echo "  OpenSSL Version: ${OPENSSL_VERSION}"

        # Check OQS provider
        if openssl list -providers 2>&1 | grep -q oqsprovider; then
            echo "  ✓ OQS Provider loaded"
        else
            echo "  ✗ OQS Provider NOT loaded"
            echo "    Fix: Check OPENSSL_CONF=${OPENSSL_CONF}"
        fi
    else
        echo "  ✗ OpenSSL command not found"
    fi
else
    echo "✗ OpenSSL OQS environment not configured"
    echo "  Fix: Run install-openssl-oqs.sh"
fi

echo ""

# Check 2: Certificates
echo "[Check 2] Certificate Files"
CERT_DIR="/opt/qsign/certs"

check_cert_file() {
    local file=$1
    if [[ -f "${file}" ]]; then
        echo "  ✓ ${file}"
        # Verify certificate
        if openssl x509 -in "${file}" -noout -text &> /dev/null; then
            echo "    Valid certificate"
        else
            echo "    ✗ Invalid certificate format"
        fi
    else
        echo "  ✗ ${file} (NOT FOUND)"
    fi
}

check_cert_file "${CERT_DIR}/ca/root-ca.crt"
check_cert_file "${CERT_DIR}/ca/intermediate-ca.crt"
check_cert_file "${CERT_DIR}/server/server.crt"
check_cert_file "${CERT_DIR}/server/server-bundle.crt"

echo ""

# Check 3: Network Connectivity
echo "[Check 3] Network Connectivity"
SERVER="api.qsign.local"
PORT="443"

if timeout 5 bash -c "cat < /dev/null > /dev/tcp/${SERVER}/${PORT}" 2>/dev/null; then
    echo "  ✓ Can connect to ${SERVER}:${PORT}"
else
    echo "  ✗ Cannot connect to ${SERVER}:${PORT}"
    echo "    Fix: Check firewall, DNS, server status"
fi

echo ""

# Check 4: TLS Handshake
echo "[Check 4] TLS Handshake Test"
if command -v openssl &> /dev/null; then
    HANDSHAKE_RESULT=$(echo "Q" | timeout 10 openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -CAfile "${CERT_DIR}/ca/root-ca.crt" \
        2>&1)

    if echo "${HANDSHAKE_RESULT}" | grep -q "Verify return code: 0"; then
        echo "  ✓ TLS handshake successful"
        echo "${HANDSHAKE_RESULT}" | grep -E "Protocol|Cipher" | head -2
    else
        echo "  ✗ TLS handshake failed"
        echo "${HANDSHAKE_RESULT}" | grep "Verify return code"
        echo ""
        echo "  Common issues:"
        echo "    - Certificate expired"
        echo "    - Certificate hostname mismatch"
        echo "    - CA not trusted"
    fi
fi

echo ""

# Check 5: System Resources
echo "[Check 5] System Resources"

FILE_LIMIT=$(ulimit -n)
echo "  File Descriptor Limit: ${FILE_LIMIT}"
if [[ ${FILE_LIMIT} -lt 10000 ]]; then
    echo "    ⚠ Low file descriptor limit (recommended: 65536+)"
fi

FREE_MEM=$(free -m | awk '/^Mem:/{print $4}')
echo "  Free Memory: ${FREE_MEM} MB"
if [[ ${FREE_MEM} -lt 1000 ]]; then
    echo "    ⚠ Low free memory"
fi

CPU_LOAD=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}')
echo "  CPU Load (1min): ${CPU_LOAD}"

echo ""

# Check 6: Service Status
echo "[Check 6] Service Status"

check_service() {
    local service=$1
    if systemctl is-active --quiet "${service}"; then
        echo "  ✓ ${service} is running"
    else
        echo "  ✗ ${service} is NOT running"
        echo "    Fix: sudo systemctl start ${service}"
    fi
}

check_service "nginx-qtsl" || true
check_service "apisix" || true

echo ""
echo "========================================="
echo "Troubleshooting Complete"
echo "========================================="
```

### 8.2 로그 분석 스크립트

```bash
#!/bin/bash
# analyze-qtsl-logs.sh - Analyze Q-TLS connection logs

set -e

LOG_FILE="${1:-/var/log/nginx/access.log}"

echo "========================================="
echo "Q-TLS Log Analysis"
echo "========================================="
echo ""
echo "Log File: ${LOG_FILE}"
echo ""

if [[ ! -f "${LOG_FILE}" ]]; then
    echo "✗ Log file not found: ${LOG_FILE}"
    exit 1
fi

# TLS Protocol Distribution
echo "[1] TLS Protocol Distribution:"
grep -oP 'ssl_protocol=\K[^ ]+' "${LOG_FILE}" | sort | uniq -c | sort -rn
echo ""

# Cipher Suite Distribution
echo "[2] Cipher Suite Distribution:"
grep -oP 'ssl_cipher=\K[^ ]+' "${LOG_FILE}" | sort | uniq -c | sort -rn
echo ""

# Session Resumption Rate
echo "[3] Session Resumption:"
TOTAL=$(grep -c 'session_reused=' "${LOG_FILE}" || echo "0")
REUSED=$(grep -c 'session_reused=r' "${LOG_FILE}" || echo "0")

if [[ ${TOTAL} -gt 0 ]]; then
    RATE=$((REUSED * 100 / TOTAL))
    echo "  Total Connections: ${TOTAL}"
    echo "  Resumed Sessions: ${REUSED}"
    echo "  Resumption Rate: ${RATE}%"
else
    echo "  No session resumption data found"
fi
echo ""

# Top Client IPs
echo "[4] Top 10 Client IPs:"
awk '{print $1}' "${LOG_FILE}" | sort | uniq -c | sort -rn | head -10
echo ""

# HTTP Status Codes
echo "[5] HTTP Status Code Distribution:"
awk '{print $9}' "${LOG_FILE}" | sort | uniq -c | sort -rn
echo ""

# Recent Errors (last 20)
echo "[6] Recent SSL/TLS Errors:"
grep -i 'ssl\|tls' /var/log/nginx/error.log 2>/dev/null | tail -20 || echo "  No errors found"

echo ""
echo "✓ Log analysis complete!"
```

---

## 관련 문서

- [Q-TLS-OVERVIEW.md](./Q-TLS-OVERVIEW.md) - Q-TLS 개요
- [Q-TLS-ARCHITECTURE.md](./Q-TLS-ARCHITECTURE.md) - 아키텍처
- [CERTIFICATE-MANAGEMENT.md](./CERTIFICATE-MANAGEMENT.md) - 인증서 관리
- [SEQUENCE-DIAGRAMS.md](./SEQUENCE-DIAGRAMS.md) - 시퀀스 다이어그램
- [INTEGRATION.md](./INTEGRATION.md) - 시스템 통합
- [TESTING-VALIDATION.md](./TESTING-VALIDATION.md) - 테스트 및 검증

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Document Status**: Complete
