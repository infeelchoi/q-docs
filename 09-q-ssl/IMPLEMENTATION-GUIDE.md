# Q-SSL 구현 가이드

Q-SSL (Quantum-resistant SSL) 구현 가이드 문서입니다.

## 목차
- [OpenSSL + OQS 통합](#openssl--oqs-통합)
- [APISIX Gateway 설정](#apisix-gateway-설정)
- [Nginx 설정](#nginx-설정)
- [클라이언트 라이브러리](#클라이언트-라이브러리)
- [테스트 및 검증](#테스트-및-검증)

---

## OpenSSL + OQS 통합

### liboqs 설치

```bash
#!/bin/bash
# Install liboqs (Open Quantum Safe)

# 1. Install dependencies
sudo apt-get update
sudo apt-get install -y \
  cmake ninja-build \
  libssl-dev \
  build-essential

# 2. Clone and build liboqs
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build

cmake -GNinja \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -DOQS_USE_OPENSSL=ON \
  ..

ninja
sudo ninja install

# 3. Update library cache
sudo ldconfig
```

### OQS-OpenSSL 빌드

```bash
#!/bin/bash
# Build OpenSSL with OQS provider

# 1. Clone OQS-OpenSSL
git clone -b OQS-OpenSSL_1_1_1-stable \
  https://github.com/open-quantum-safe/openssl.git oqs-openssl

cd oqs-openssl

# 2. Configure with OQS support
./config \
  --prefix=/opt/oqs-openssl \
  --openssldir=/opt/oqs-openssl/ssl \
  -lm

# 3. Build
make -j$(nproc)
make test
sudo make install

# 4. Set environment
export PATH=/opt/oqs-openssl/bin:$PATH
export LD_LIBRARY_PATH=/opt/oqs-openssl/lib:$LD_LIBRARY_PATH
```

### 하이브리드 인증서 생성

```bash
#!/bin/bash
# Generate hybrid PQC certificate

# 1. Generate classical ECDSA key
openssl ecparam -name secp384r1 -genkey -out ecdsa_key.pem

# 2. Generate PQC DILITHIUM3 key
openssl genpkey -algorithm dilithium3 -out dilithium_key.pem

# 3. Create CSR
openssl req -new \
  -key ecdsa_key.pem \
  -subj "/C=KR/O=QSIGN/CN=qsign.example.com" \
  -out ecdsa_csr.pem

openssl req -new \
  -key dilithium_key.pem \
  -subj "/C=KR/O=QSIGN/CN=qsign.example.com" \
  -out dilithium_csr.pem

# 4. Self-sign for testing
openssl x509 -req \
  -in ecdsa_csr.pem \
  -signkey ecdsa_key.pem \
  -out ecdsa_cert.pem \
  -days 90

openssl x509 -req \
  -in dilithium_csr.pem \
  -signkey dilithium_key.pem \
  -out dilithium_cert.pem \
  -days 90

# 5. Combine into hybrid certificate (custom script)
./combine_hybrid_cert.py \
  ecdsa_cert.pem ecdsa_key.pem \
  dilithium_cert.pem dilithium_key.pem \
  > hybrid_cert.pem
```

---

## APISIX Gateway 설정

### APISIX Q-SSL 플러그인

```yaml
# apisix/config.yaml
apisix:
  ssl:
    enable: true
    listen:
      - port: 9443
        enable_http2: true
    ssl_protocols: "TLSv1.3"
    ssl_ciphers: |
      TLS_AES_256_GCM_SHA384:
      TLS_CHACHA20_POLY1305_SHA256
    ssl_session_cache: "shared:SSL:10m"
    ssl_session_timeout: "10m"

    # Q-SSL specific
    ssl_pqc_groups: "kyber1024:kyber768:x25519:secp384r1"
    ssl_pqc_sigalgs: "dilithium3+ecdsa_secp384r1_sha384:dilithium3"

plugins:
  - qssl-auth
  - qssl-upstream
```

### SSL 인증서 설정

```bash
#!/bin/bash
# Configure SSL certificates in APISIX

# Create SSL resource
curl -X PUT http://127.0.0.1:9180/apisix/admin/ssls/1 \
  -H "X-API-KEY: $APISIX_API_KEY" \
  -d '{
    "cert": "'"$(cat hybrid_cert.pem)"'",
    "key": "'"$(cat hybrid_key.pem)"'",
    "snis": ["qsign.example.com"],
    "ssl_protocols": ["TLSv1.3"],
    "client": {
      "ca": "'"$(cat ca_chain.pem)"'",
      "depth": 2,
      "skip_mtls_uri_regex": ["/health"]
    }
  }'
```

### Route 설정 (mTLS)

```yaml
# apisix route with mTLS
routes:
  - uri: /api/*
    methods: [GET, POST, PUT, DELETE]
    plugins:
      qssl-auth:
        enable: true
        require_client_cert: true
        verify_depth: 2
        trusted_ca: /etc/apisix/certs/ca_chain.pem
    upstream:
      type: roundrobin
      scheme: https
      nodes:
        "keycloak.qsign.svc.cluster.local:8443": 1
      tls:
        client_cert: /etc/apisix/certs/gateway_cert.pem
        client_key: /etc/apisix/certs/gateway_key.pem
```

---

## Nginx 설정

### Nginx with OQS Module

```bash
#!/bin/bash
# Build Nginx with OQS module

# 1. Install dependencies
sudo apt-get install -y libpcre3-dev zlib1g-dev

# 2. Download Nginx
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
cd nginx-1.24.0

# 3. Configure with OpenSSL + OQS
./configure \
  --prefix=/etc/nginx \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-openssl=/path/to/oqs-openssl \
  --with-openssl-opt="enable-tls1_3"

# 4. Build and install
make -j$(nproc)
sudo make install
```

### Nginx Q-SSL 설정

```nginx
# nginx.conf
http {
    # SSL Configuration
    ssl_protocols TLSv1.3;
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers on;

    # Q-SSL PQC Configuration
    ssl_ecdh_curve kyber1024:x25519:secp384r1;
    ssl_conf_command Groups kyber1024:kyber768:x25519:secp384r1;
    ssl_conf_command SignatureAlgorithms dilithium3+ecdsa_secp384r1_sha384;

    # Session Configuration
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/nginx/certs/ca_chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    server {
        listen 443 ssl http2;
        server_name qsign.example.com;

        # Hybrid Certificate
        ssl_certificate /etc/nginx/certs/hybrid_cert.pem;
        ssl_certificate_key /etc/nginx/certs/hybrid_key.pem;

        # Client Certificate (mTLS)
        ssl_client_certificate /etc/nginx/certs/ca_chain.pem;
        ssl_verify_client optional;
        ssl_verify_depth 2;

        location / {
            proxy_pass https://backend;
            proxy_ssl_protocols TLSv1.3;
            proxy_ssl_ciphers TLS_AES_256_GCM_SHA384;
            proxy_ssl_certificate /etc/nginx/certs/client_cert.pem;
            proxy_ssl_certificate_key /etc/nginx/certs/client_key.pem;
        }
    }
}
```

---

## 클라이언트 라이브러리

### Python (requests + OQS)

```python
import requests
from oqs import Signature

def qssl_request(url, client_cert, client_key, ca_cert):
    """Q-SSL enabled HTTPS request"""

    session = requests.Session()

    # Configure TLS 1.3 with PQC
    session.mount('https://', requests.adapters.HTTPAdapter(
        max_retries=3
    ))

    response = session.get(
        url,
        cert=(client_cert, client_key),
        verify=ca_cert,
        headers={
            'User-Agent': 'QSIGN-Client/1.0'
        }
    )

    return response

# Example usage
response = qssl_request(
    url='https://qsign.example.com/api/data',
    client_cert='/path/to/client_cert.pem',
    client_key='/path/to/client_key.pem',
    ca_cert='/path/to/ca_chain.pem'
)

print(response.status_code)
print(response.json())
```

### Go (crypto/tls)

```go
package main

import (
    "crypto/tls"
    "crypto/x509"
    "io/ioutil"
    "net/http"
)

func qsslClient() (*http.Client, error) {
    // Load CA certificate
    caCert, err := ioutil.ReadFile("/path/to/ca_chain.pem")
    if err != nil {
        return nil, err
    }

    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    // Load client certificate
    cert, err := tls.LoadX509KeyPair(
        "/path/to/client_cert.pem",
        "/path/to/client_key.pem",
    )
    if err != nil {
        return nil, err
    }

    // Configure TLS
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        MinVersion:   tls.VersionTLS13,
        CurvePreferences: []tls.CurveID{
            tls.KYBER1024,  // PQC
            tls.X25519,     // Classical
        },
    }

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    return client, nil
}
```

---

## 테스트 및 검증

### OpenSSL s_client 테스트

```bash
#!/bin/bash
# Test Q-SSL connection

openssl s_client \
  -connect qsign.example.com:443 \
  -tls1_3 \
  -groups kyber1024:x25519 \
  -sigalgs dilithium3+ecdsa_secp384r1_sha384 \
  -cert client_cert.pem \
  -key client_key.pem \
  -CAfile ca_chain.pem \
  -showcerts \
  -state \
  -debug

# Expected output:
# ...
# SSL handshake has read 15234 bytes and written 2456 bytes
# ---
# New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
# Server public key is 1952 bit (DILITHIUM3)
# ...
```

### testssl.sh 스캔

```bash
#!/bin/bash
# Comprehensive SSL/TLS scan

# Install testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Run scan
./testssl.sh \
  --starttls https \
  --pqc \
  qsign.example.com:443

# Output:
# Testing PQC support
#  KYBER1024               offered
#  DILITHIUM3              offered
#  Hybrid mode             enabled
```

---

## 참고 자료

```yaml
프로젝트:
  - Open Quantum Safe: https://openquantumsafe.org/
  - liboqs: https://github.com/open-quantum-safe/liboqs
  - OQS-OpenSSL: https://github.com/open-quantum-safe/openssl

문서:
  - OpenSSL 3.x Documentation
  - APISIX SSL Plugin Guide
  - Nginx SSL Module
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
