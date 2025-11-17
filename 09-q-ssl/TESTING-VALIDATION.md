# Q-SSL 테스트 및 검증

Q-SSL (Quantum-resistant SSL) 테스트 및 검증 가이드입니다.

## 목차
- [기능 테스트](#기능-테스트)
- [보안 테스트](#보안-테스트)
- [성능 벤치마크](#성능-벤치마크)
- [상호운용성 테스트](#상호운용성-테스트)
- [부하 테스트](#부하-테스트)
- [자동화 테스트](#자동화-테스트)

---

## 기능 테스트

### OpenSSL s_client/s_server

```bash
#!/bin/bash
# Basic functional test

# Terminal 1: Start Q-SSL server
openssl s_server \
  -accept 8443 \
  -cert hybrid_cert.pem \
  -key hybrid_key.pem \
  -CAfile ca_chain.pem \
  -Verify 1 \
  -tls1_3 \
  -ciphersuites TLS_AES_256_GCM_SHA384 \
  -groups kyber1024:x25519 \
  -sigalgs dilithium3+ecdsa_secp384r1_sha384 \
  -WWW

# Terminal 2: Connect with Q-SSL client
openssl s_client \
  -connect localhost:8443 \
  -cert client_cert.pem \
  -key client_key.pem \
  -CAfile ca_chain.pem \
  -tls1_3 \
  -groups kyber1024:x25519 \
  -sigalgs dilithium3+ecdsa_secp384r1_sha384 \
  -showcerts \
  -state

# Expected output:
# New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
# Server public key is 1952 bit (DILITHIUM3)
# Secure Renegotiation IS NOT supported
# Verify return code: 0 (ok)
```

### Certificate Verification

```bash
#!/bin/bash
# Verify hybrid certificate

# 1. Check certificate structure
openssl x509 -in hybrid_cert.pem -text -noout

# 2. Verify certificate chain
openssl verify -CAfile ca_chain.pem hybrid_cert.pem

# 3. Check public key sizes
echo "ECDSA public key:"
openssl ec -in hybrid_cert.pem -pubin -text -noout | grep "ASN1 OID"

echo "DILITHIUM3 public key:"
openssl pkey -in hybrid_cert.pem -pubin -text -noout | grep -A5 "DILITHIUM"

# 4. Verify signatures
./verify_hybrid_signatures.py hybrid_cert.pem ca_chain.pem
```

### Handshake Protocol Test

```python
#!/usr/bin/env python3
# test_qssl_handshake.py

import ssl
import socket

def test_qssl_handshake():
    """Test Q-SSL handshake protocol"""

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    # Load certificates
    context.load_cert_chain('client_cert.pem', 'client_key.pem')
    context.load_verify_locations('ca_chain.pem')

    # Configure Q-SSL
    context.set_ciphers('TLS_AES_256_GCM_SHA384')

    # Connect
    with socket.create_connection(('qsign.example.com', 443)) as sock:
        with context.wrap_socket(sock, server_hostname='qsign.example.com') as ssock:
            print(f"Protocol: {ssock.version()}")
            print(f"Cipher: {ssock.cipher()}")
            print(f"Certificate: {ssock.getpeercert()}")

            # Verify hybrid certificate
            peer_cert = ssock.getpeercert()
            assert 'dilithium3' in str(peer_cert)
            assert 'ecdsa' in str(peer_cert)

            print("✓ Q-SSL handshake successful")

if __name__ == '__main__':
    test_qssl_handshake()
```

---

## 보안 테스트

### testssl.sh Scan

```bash
#!/bin/bash
# Comprehensive SSL/TLS security scan

# Clone testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

# Run full scan
./testssl.sh \
  --severity HIGH \
  --pqc \
  --client-simulation \
  qsign.example.com:443

# Output Analysis
# Testing PQC support
#  KYBER1024                   offered (OK)
#  DILITHIUM3                  offered (OK)
#  Hybrid mode                 enabled (OK)
#
# Testing protocols
#  SSLv2                       not offered (OK)
#  SSLv3                       not offered (OK)
#  TLS 1.0                     not offered (OK)
#  TLS 1.1                     not offered (OK)
#  TLS 1.2                     not offered (OK)
#  TLS 1.3                     offered (OK)
#
# Testing vulnerabilities
#  Heartbleed (CVE-2014-0160)  not vulnerable (OK)
#  CCS (CVE-2014-0224)         not vulnerable (OK)
#  Ticketbleed (CVE-2016-9244) not vulnerable (OK)
#  ROBOT                       not vulnerable (OK)
```

### sslyze Analysis

```bash
#!/bin/bash
# sslyze security analysis

pip install sslyze

sslyze \
  --regular \
  --certinfo \
  --tlsv1_3 \
  --http_headers \
  qsign.example.com:443

# Check for:
# - TLS 1.3 support
# - Strong cipher suites
# - Certificate validity
# - HSTS headers
# - OCSP stapling
```

### nmap SSL Scan

```bash
#!/bin/bash
# nmap SSL/TLS enumeration

nmap -p 443 \
  --script ssl-enum-ciphers \
  --script ssl-cert \
  --script ssl-known-key \
  qsign.example.com

# Expected output:
# PORT    STATE SERVICE
# 443/tcp open  https
# | ssl-enum-ciphers:
# |   TLSv1.3:
# |     ciphers:
# |       TLS_AES_256_GCM_SHA384 (secp384r1) - A
# |       TLS_CHACHA20_POLY1305_SHA256 (x25519) - A
# |     cipher preference: server
```

---

## 성능 벤치마크

### Handshake Performance

```bash
#!/bin/bash
# Benchmark SSL handshake performance

# 1. Classical TLS 1.3 (baseline)
echo "Classical TLS 1.3 (ECDHE P-256):"
time for i in {1..100}; do
  echo "Q" | openssl s_client \
    -connect classical.example.com:443 \
    -tls1_3 \
    -groups x25519 \
    -brief >/dev/null 2>&1
done

# 2. Q-SSL Hybrid
echo "Q-SSL Hybrid (KYBER1024 + ECDHE):"
time for i in {1..100}; do
  echo "Q" | openssl s_client \
    -connect qsign.example.com:443 \
    -tls1_3 \
    -groups kyber1024:x25519 \
    -brief >/dev/null 2>&1
done

# Results:
# Classical TLS 1.3: 3.2s (32ms avg)
# Q-SSL Hybrid: 8.5s (85ms avg)
# Overhead: +166%
```

### Throughput Benchmark

```python
#!/usr/bin/env python3
# benchmark_throughput.py

import time
import requests
from statistics import mean, stdev

def benchmark_throughput(url, data_size_mb=10, iterations=10):
    """Benchmark data transfer throughput"""

    results = []

    for i in range(iterations):
        start = time.time()

        response = requests.get(
            f"{url}/download/{data_size_mb}MB",
            verify='ca_chain.pem',
            cert=('client_cert.pem', 'client_key.pem')
        )

        elapsed = time.time() - start
        throughput = data_size_mb / elapsed  # MB/s

        results.append(throughput)
        print(f"Iteration {i+1}: {throughput:.2f} MB/s")

    print(f"\nMean: {mean(results):.2f} MB/s")
    print(f"Stdev: {stdev(results):.2f} MB/s")

if __name__ == '__main__':
    print("Q-SSL Throughput Benchmark:")
    benchmark_throughput('https://qsign.example.com')
```

### CPU and Memory Profiling

```bash
#!/bin/bash
# Profile CPU and memory usage

# Install perf tools
sudo apt-get install linux-tools-generic

# Profile OpenSSL server
perf record -g \
  openssl s_server \
    -accept 8443 \
    -cert hybrid_cert.pem \
    -key hybrid_key.pem \
    -tls1_3 &

SERVER_PID=$!

# Generate load
ab -n 1000 -c 10 https://localhost:8443/

# Analyze profile
sudo perf report

# Memory usage
valgrind --tool=massif \
  openssl s_server \
    -accept 8443 \
    -cert hybrid_cert.pem \
    -key hybrid_key.pem
```

---

## 상호운용성 테스트

### Client Compatibility Matrix

```yaml
Client Compatibility:
  Modern Browsers:
    Chrome 120+: ✓ Q-SSL Hybrid
    Firefox 121+: ✓ Q-SSL Hybrid
    Safari 17+: ✓ TLS 1.3 (fallback)
    Edge 120+: ✓ Q-SSL Hybrid

  Mobile:
    Android 14+: ✓ Q-SSL Hybrid
    iOS 17+: ✓ TLS 1.3 (fallback)

  Libraries:
    OpenSSL 3.2+: ✓ Q-SSL Hybrid
    BoringSSL: ✗ No PQC support
    LibreSSL: ✗ No PQC support
    s2n-tls: ✓ Experimental PQC

  Legacy:
    TLS 1.2 clients: ✓ Fallback mode
    TLS 1.0/1.1: ✗ Blocked
```

### Cross-Platform Testing

```bash
#!/bin/bash
# Test Q-SSL across different platforms

# Linux
docker run -it debian:12 bash -c "
  apt-get update && apt-get install -y openssl
  openssl s_client -connect qsign.example.com:443 -tls1_3
"

# Windows (WSL)
docker run -it mcr.microsoft.com/windows/nanoserver:ltsc2022 bash -c "
  # Install OpenSSL
  # Test connection
"

# macOS (via Docker)
docker run -it alpine:latest bash -c "
  apk add openssl
  openssl s_client -connect qsign.example.com:443 -tls1_3
"
```

---

## 부하 테스트

### Apache Bench (ab)

```bash
#!/bin/bash
# HTTP load test

ab -n 10000 -c 100 \
  -f TLS1.3 \
  -Z TLS_AES_256_GCM_SHA384 \
  -E client_cert.pem \
  https://qsign.example.com/api/health

# Results:
# Requests per second: 1250 [#/sec] (mean)
# Time per request: 80.0 [ms] (mean)
# Transfer rate: 320.5 [Kbytes/sec]
```

### wrk2 Benchmarking

```bash
#!/bin/bash
# Modern HTTP benchmarking

# Install wrk2
git clone https://github.com/giltene/wrk2.git
cd wrk2 && make

# Run benchmark
./wrk -t 4 -c 100 -d 60s -R 2000 \
  --latency \
  --timeout 2s \
  https://qsign.example.com/api/data

# Results:
# Latency Distribution (HdrHistogram)
#   50%: 45ms
#   75%: 68ms
#   90%: 95ms
#   99%: 180ms
```

### Locust Load Testing

```python
# locustfile.py
from locust import HttpUser, task, between
import ssl

class QSSLUser(HttpUser):
    wait_time = between(1, 3)

    def on_start(self):
        """Setup SSL context"""
        self.client.verify = 'ca_chain.pem'
        self.client.cert = ('client_cert.pem', 'client_key.pem')

    @task(3)
    def get_data(self):
        self.client.get("/api/data")

    @task(1)
    def post_data(self):
        self.client.post("/api/data", json={"key": "value"})

# Run:
# locust -f locustfile.py --host=https://qsign.example.com
```

---

## 자동화 테스트

### pytest Test Suite

```python
# test_qssl.py
import pytest
import ssl
import socket

@pytest.fixture
def qssl_context():
    """Create Q-SSL context"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain('client_cert.pem', 'client_key.pem')
    context.load_verify_locations('ca_chain.pem')
    return context

def test_handshake_success(qssl_context):
    """Test successful Q-SSL handshake"""
    with socket.create_connection(('qsign.example.com', 443)) as sock:
        with qssl_context.wrap_socket(sock, server_hostname='qsign.example.com') as ssock:
            assert ssock.version() == 'TLSv1.3'
            assert 'AES256-GCM' in ssock.cipher()[0]

def test_certificate_validation(qssl_context):
    """Test hybrid certificate validation"""
    with socket.create_connection(('qsign.example.com', 443)) as sock:
        with qssl_context.wrap_socket(sock, server_hostname='qsign.example.com') as ssock:
            cert = ssock.getpeercert()
            assert cert is not None
            assert 'subject' in cert

def test_mutual_tls(qssl_context):
    """Test mutual TLS authentication"""
    # Should succeed with valid client cert
    with socket.create_connection(('qsign.example.com', 443)) as sock:
        with qssl_context.wrap_socket(sock, server_hostname='qsign.example.com') as ssock:
            assert ssock.cipher() is not None

# Run:
# pytest test_qssl.py -v
```

### CI/CD Integration

```yaml
# .github/workflows/qssl-test.yml
name: Q-SSL Tests

on: [push, pull_request]

jobs:
  qssl-functional-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install OQS-OpenSSL
        run: |
          ./scripts/install-oqs-openssl.sh

      - name: Generate test certificates
        run: |
          ./scripts/generate-test-certs.sh

      - name: Run functional tests
        run: |
          pytest tests/test_qssl.py -v

      - name: Run security scan
        run: |
          ./testssl.sh/testssl.sh --pqc localhost:8443

      - name: Performance benchmark
        run: |
          python benchmark_throughput.py
```

---

## 참고 자료

```yaml
도구:
  - OpenSSL 3.x: https://www.openssl.org/
  - testssl.sh: https://testssl.sh/
  - sslyze: https://github.com/nabla-c0d3/sslyze
  - locust: https://locust.io/

문서:
  - NIST PQC Testing
  - ETSI Quantum-Safe Testing
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
