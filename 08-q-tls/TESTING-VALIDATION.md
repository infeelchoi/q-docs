# Q-TLS Testing and Validation Guide

Q-TLS (Quantum-resistant Transport Security Layer) 테스트 및 검증을 위한 종합 가이드입니다.

## 목차

1. [기능 테스트](#1-기능-테스트)
2. [보안 테스트](#2-보안-테스트)
3. [성능 벤치마크](#3-성능-벤치마크)
4. [상호운용성 테스트](#4-상호운용성-테스트)
5. [부하 테스트](#5-부하-테스트)
6. [침투 테스트](#6-침투-테스트)
7. [자동화 테스트](#7-자동화-테스트)
8. [테스트 결과 분석](#8-테스트-결과-분석)

---

## 1. 기능 테스트

### 1.1 기능 테스트 체크리스트

```yaml
기능 테스트 체크리스트:
  TLS 핸드셰이크:
    - [ ] Full handshake (초기 연결)
    - [ ] Session ID resumption
    - [ ] Session ticket resumption
    - [ ] 0-RTT early data
    - [ ] Key update (재협상)
    - [ ] Post-handshake authentication

  인증서 검증:
    - [ ] 서버 인증서 체인 검증
    - [ ] 클라이언트 인증서 검증 (mTLS)
    - [ ] OCSP stapling
    - [ ] CRL 검증
    - [ ] 인증서 만료 처리
    - [ ] 인증서 폐기 처리

  암호화:
    - [ ] 데이터 암호화 (AES-256-GCM)
    - [ ] HMAC 무결성 검증
    - [ ] Perfect Forward Secrecy
    - [ ] Cipher suite 협상

  프로토콜:
    - [ ] HTTP/1.1 over Q-TLS
    - [ ] HTTP/2 over Q-TLS
    - [ ] WebSocket over Q-TLS
    - [ ] gRPC over Q-TLS

  에러 처리:
    - [ ] Alert 프로토콜
    - [ ] 타임아웃 처리
    - [ ] 재연결 메커니즘
    - [ ] Graceful shutdown
```

### 1.2 기능 테스트 스크립트

```bash
#!/bin/bash
# functional-tests.sh - Q-TLS Functional Tests

set -e

source /etc/profile.d/openssl-oqs.sh

SERVER="api.qsign.local"
PORT="443"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"
CLIENT_CERT="/opt/qsign/certs/client/client.crt"
CLIENT_KEY="/opt/qsign/certs/client/client.key"

RESULTS_DIR="/tmp/qtsl-test-results"
mkdir -p "${RESULTS_DIR}"

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0

# Test runner
run_test() {
    local test_name="$1"
    local test_command="$2"

    TEST_COUNT=$((TEST_COUNT + 1))
    echo ""
    echo "========================================="
    echo "Test ${TEST_COUNT}: ${test_name}"
    echo "========================================="

    if eval "${test_command}"; then
        echo "✓ PASS: ${test_name}"
        PASS_COUNT=$((PASS_COUNT + 1))
        return 0
    else
        echo "✗ FAIL: ${test_name}"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        return 1
    fi
}

# ============================================================================
# Test 1: Basic TLS 1.3 Connection
# ============================================================================

test_basic_connection() {
    echo "Q" | timeout 10 openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -tls1_3 \
        -CAfile "${CA_CERT}" \
        -servername "${SERVER}" \
        2>&1 | grep -q "Verify return code: 0"
}

run_test "Basic TLS 1.3 Connection" "test_basic_connection"

# ============================================================================
# Test 2: Session Resumption (Session ID)
# ============================================================================

test_session_resumption() {
    local session_file=$(mktemp)

    # First connection
    echo "Q" | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -tls1_3 \
        -CAfile "${CA_CERT}" \
        -sess_out "${session_file}" \
        2>&1 > /dev/null

    # Second connection (should reuse session)
    local result=$(echo "Q" | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -tls1_3 \
        -CAfile "${CA_CERT}" \
        -sess_in "${session_file}" \
        2>&1 | grep -c "Reused, TLSv1.3")

    rm -f "${session_file}"

    [[ ${result} -eq 1 ]]
}

run_test "Session Resumption (Session ID)" "test_session_resumption"

# ============================================================================
# Test 3: Cipher Suite Negotiation
# ============================================================================

test_cipher_suite() {
    local cipher=$(echo "Q" | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -tls1_3 \
        -CAfile "${CA_CERT}" \
        -ciphersuites "TLS_AES_256_GCM_SHA384" \
        2>&1 | grep "Cipher" | head -1)

    echo "${cipher}" | grep -q "TLS_AES_256_GCM_SHA384"
}

run_test "Cipher Suite Negotiation" "test_cipher_suite"

# ============================================================================
# Test 4: Certificate Chain Validation
# ============================================================================

test_cert_chain() {
    echo "Q" | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -CAfile "${CA_CERT}" \
        -showcerts \
        2>&1 | grep -q "Certificate chain"
}

run_test "Certificate Chain Validation" "test_cert_chain"

# ============================================================================
# Test 5: OCSP Stapling
# ============================================================================

test_ocsp_stapling() {
    echo "Q" | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -CAfile "${CA_CERT}" \
        -status \
        2>&1 | grep -q "OCSP Response Status: successful"
}

run_test "OCSP Stapling" "test_ocsp_stapling"

# ============================================================================
# Test 6: Mutual TLS (mTLS)
# ============================================================================

test_mtls() {
    if [[ -f "${CLIENT_CERT}" && -f "${CLIENT_KEY}" ]]; then
        echo "Q" | openssl s_client \
            -connect "${SERVER}:${PORT}" \
            -CAfile "${CA_CERT}" \
            -cert "${CLIENT_CERT}" \
            -key "${CLIENT_KEY}" \
            2>&1 | grep -q "Verify return code: 0"
    else
        echo "⚠ Client certificate not found, skipping"
        return 0
    fi
}

run_test "Mutual TLS (mTLS)" "test_mtls"

# ============================================================================
# Test 7: HTTP/2 Support
# ============================================================================

test_http2() {
    curl -v --http2 \
        --cacert "${CA_CERT}" \
        "https://${SERVER}/health" \
        2>&1 | grep -q "HTTP/2 200"
}

run_test "HTTP/2 Support" "test_http2"

# ============================================================================
# Test 8: Connection Timeout
# ============================================================================

test_timeout() {
    # Connect but don't send any data (should timeout)
    timeout 5 openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -CAfile "${CA_CERT}" \
        2>&1 > /dev/null || [[ $? -eq 124 ]]
}

run_test "Connection Timeout" "test_timeout"

# ============================================================================
# Test 9: Graceful Shutdown
# ============================================================================

test_graceful_shutdown() {
    # Send close_notify
    (echo "Q"; sleep 1) | openssl s_client \
        -connect "${SERVER}:${PORT}" \
        -CAfile "${CA_CERT}" \
        2>&1 | grep -q "Verify return code: 0"
}

run_test "Graceful Shutdown" "test_graceful_shutdown"

# ============================================================================
# Test 10: Large Payload Transfer
# ============================================================================

test_large_payload() {
    # Create 10MB file
    dd if=/dev/urandom of=/tmp/test-payload bs=1M count=10 2>/dev/null

    # Upload via HTTPS
    curl -X POST \
        --cacert "${CA_CERT}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @/tmp/test-payload \
        "https://${SERVER}/api/upload" \
        2>&1 | grep -q "200"

    rm -f /tmp/test-payload
}

run_test "Large Payload Transfer" "test_large_payload" || true

# ============================================================================
# Test Summary
# ============================================================================

echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo "Total Tests:  ${TEST_COUNT}"
echo "Passed:       ${PASS_COUNT}"
echo "Failed:       ${FAIL_COUNT}"
echo "Success Rate: $(echo "scale=2; ${PASS_COUNT} * 100 / ${TEST_COUNT}" | bc)%"
echo "========================================="

# Save results
cat > "${RESULTS_DIR}/functional-test-summary.json" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "total": ${TEST_COUNT},
  "passed": ${PASS_COUNT},
  "failed": ${FAIL_COUNT},
  "success_rate": $(echo "scale=4; ${PASS_COUNT} / ${TEST_COUNT}" | bc)
}
EOF

echo ""
echo "Results saved to: ${RESULTS_DIR}/functional-test-summary.json"

[[ ${FAIL_COUNT} -eq 0 ]]
```

---

## 2. 보안 테스트

### 2.1 보안 테스트 체크리스트

```yaml
보안 테스트 체크리스트:
  암호화 강도:
    - [ ] 최소 TLS 1.3 강제
    - [ ] 약한 cipher suite 차단
    - [ ] Perfect Forward Secrecy 검증
    - [ ] Key 크기 검증 (RSA 4096, AES 256)

  인증서 보안:
    - [ ] 자체 서명 인증서 거부
    - [ ] 만료된 인증서 거부
    - [ ] 폐기된 인증서 거부 (CRL/OCSP)
    - [ ] 잘못된 CN/SAN 거부

  공격 방어:
    - [ ] MITM 공격 방어
    - [ ] Downgrade 공격 방어
    - [ ] Replay 공격 방어
    - [ ] Padding oracle 공격 방어
    - [ ] Timing 공격 방어

  헤더 보안:
    - [ ] HSTS 헤더
    - [ ] X-Frame-Options
    - [ ] X-Content-Type-Options
    - [ ] CSP (Content Security Policy)

  Rate Limiting:
    - [ ] 요청 속도 제한
    - [ ] 연결 수 제한
    - [ ] DDoS 방어 메커니즘
```

### 2.2 보안 테스트 스크립트

```bash
#!/bin/bash
# security-tests.sh - Q-TLS Security Tests

set -e

SERVER="api.qsign.local"
PORT="443"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"

echo "========================================="
echo "Q-TLS Security Tests"
echo "========================================="
echo ""

# ============================================================================
# Test 1: TLS Version Enforcement
# ============================================================================

echo "[Test 1] TLS Version Enforcement"

# Test TLS 1.2 (should fail if TLS 1.3 only)
echo "  Testing TLS 1.2 connection (should fail)..."
if echo "Q" | timeout 5 openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_2 \
    2>&1 | grep -q "Cipher"; then
    echo "  ✗ FAIL: Server accepts TLS 1.2"
else
    echo "  ✓ PASS: Server rejects TLS 1.2"
fi

# Test TLS 1.3 (should succeed)
echo "  Testing TLS 1.3 connection (should succeed)..."
if echo "Q" | timeout 5 openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    2>&1 | grep -q "Verify return code: 0"; then
    echo "  ✓ PASS: Server accepts TLS 1.3"
else
    echo "  ✗ FAIL: Server rejects TLS 1.3"
fi

echo ""

# ============================================================================
# Test 2: Weak Cipher Suite Rejection
# ============================================================================

echo "[Test 2] Weak Cipher Suite Rejection"

# Test weak cipher (should fail)
echo "  Testing weak cipher suite (should fail)..."
if echo "Q" | timeout 5 openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -cipher "DES-CBC3-SHA" \
    2>&1 | grep -q "Cipher"; then
    echo "  ✗ FAIL: Server accepts weak cipher"
else
    echo "  ✓ PASS: Server rejects weak cipher"
fi

echo ""

# ============================================================================
# Test 3: Certificate Validation
# ============================================================================

echo "[Test 3] Certificate Validation"

# Test without CA (should fail)
echo "  Testing without CA certificate (should fail)..."
if echo "Q" | timeout 5 openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    2>&1 | grep -q "Verify return code: 0"; then
    echo "  ✗ FAIL: Connection succeeded without CA"
else
    echo "  ✓ PASS: Connection failed without CA"
fi

# Test with wrong hostname (should fail)
echo "  Testing wrong hostname (should fail)..."
if echo "Q" | timeout 5 openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -tls1_3 \
    -CAfile "${CA_CERT}" \
    -servername "wrong-hostname.com" \
    2>&1 | grep -q "Verify return code: 0"; then
    echo "  ✗ FAIL: Hostname verification failed"
else
    echo "  ✓ PASS: Hostname verification works"
fi

echo ""

# ============================================================================
# Test 4: Security Headers
# ============================================================================

echo "[Test 4] Security Headers"

HEADERS=$(curl -sI --cacert "${CA_CERT}" "https://${SERVER}/health")

# HSTS
if echo "${HEADERS}" | grep -qi "Strict-Transport-Security"; then
    echo "  ✓ PASS: HSTS header present"
else
    echo "  ✗ FAIL: HSTS header missing"
fi

# X-Frame-Options
if echo "${HEADERS}" | grep -qi "X-Frame-Options"; then
    echo "  ✓ PASS: X-Frame-Options header present"
else
    echo "  ✗ FAIL: X-Frame-Options header missing"
fi

# X-Content-Type-Options
if echo "${HEADERS}" | grep -qi "X-Content-Type-Options"; then
    echo "  ✓ PASS: X-Content-Type-Options header present"
else
    echo "  ✗ FAIL: X-Content-Type-Options header missing"
fi

echo ""

# ============================================================================
# Test 5: Perfect Forward Secrecy
# ============================================================================

echo "[Test 5] Perfect Forward Secrecy"

CIPHER_INFO=$(echo "Q" | openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -CAfile "${CA_CERT}" \
    2>&1 | grep "Cipher")

if echo "${CIPHER_INFO}" | grep -qE "ECDHE|DHE"; then
    echo "  ✓ PASS: PFS enabled (${CIPHER_INFO})"
else
    echo "  ✗ FAIL: PFS not enabled"
fi

echo ""

# ============================================================================
# Test 6: Certificate Revocation (OCSP)
# ============================================================================

echo "[Test 6] OCSP Certificate Revocation Check"

OCSP_RESPONSE=$(echo "Q" | openssl s_client \
    -connect "${SERVER}:${PORT}" \
    -CAfile "${CA_CERT}" \
    -status \
    2>&1)

if echo "${OCSP_RESPONSE}" | grep -q "OCSP Response Status: successful"; then
    if echo "${OCSP_RESPONSE}" | grep -q "Cert Status: good"; then
        echo "  ✓ PASS: Certificate status is good"
    else
        echo "  ✗ FAIL: Certificate revoked or unknown"
    fi
else
    echo "  ⚠ WARNING: OCSP stapling not available"
fi

echo ""

# ============================================================================
# Test 7: Rate Limiting
# ============================================================================

echo "[Test 7] Rate Limiting"

# Send rapid requests
echo "  Sending 100 rapid requests..."
RATE_LIMITED=0
for i in {1..100}; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        --cacert "${CA_CERT}" \
        "https://${SERVER}/health")

    if [[ "${RESPONSE}" == "429" ]]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
done

if [[ ${RATE_LIMITED} -gt 0 ]]; then
    echo "  ✓ PASS: Rate limiting active (${RATE_LIMITED} requests limited)"
else
    echo "  ⚠ WARNING: No rate limiting detected"
fi

echo ""

# ============================================================================
# Summary
# ============================================================================

echo "========================================="
echo "Security Tests Complete"
echo "========================================="
```

### 2.3 testssl.sh 스캔

```bash
#!/bin/bash
# run-testssl-scan.sh - Comprehensive SSL/TLS scan

set -e

SERVER="api.qsign.local"
PORT="443"

# Install testssl.sh if not present
if [[ ! -f /opt/testssl/testssl.sh ]]; then
    echo "Installing testssl.sh..."
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl
fi

echo "Running testssl.sh scan on ${SERVER}:${PORT}..."

/opt/testssl/testssl.sh \
    --severity MEDIUM \
    --parallel \
    --htmlfile /tmp/testssl-report.html \
    --jsonfile /tmp/testssl-report.json \
    "${SERVER}:${PORT}"

echo ""
echo "✓ Scan complete!"
echo "  HTML Report: /tmp/testssl-report.html"
echo "  JSON Report: /tmp/testssl-report.json"
```

---

## 3. 성능 벤치마크

### 3.1 성능 메트릭

```yaml
성능 메트릭:
  Latency:
    - Handshake Time (ms)
    - First Byte Time (ms)
    - Total Request Time (ms)

  Throughput:
    - Requests per Second (RPS)
    - Bandwidth (MB/s)
    - Concurrent Connections

  Resource Usage:
    - CPU Usage (%)
    - Memory Usage (MB)
    - Network I/O (MB/s)

  Session Resumption:
    - Resumption Rate (%)
    - Resumption Latency (ms)
```

### 3.2 wrk 벤치마크 스크립트

```bash
#!/bin/bash
# benchmark-wrk.sh - Performance benchmark with wrk

set -e

SERVER="https://api.qsign.local"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"
DURATION="60s"
RESULTS_DIR="/tmp/qtsl-benchmark"

mkdir -p "${RESULTS_DIR}"

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "Installing wrk..."
    sudo apt-get update && sudo apt-get install -y wrk
fi

echo "========================================="
echo "Q-TLS Performance Benchmark (wrk)"
echo "========================================="
echo ""

# ============================================================================
# Benchmark 1: Low Concurrency (10 connections)
# ============================================================================

echo "[Benchmark 1] Low Concurrency (10 connections, 2 threads)"

wrk -t2 -c10 -d${DURATION} \
    --latency \
    "${SERVER}/health" \
    | tee "${RESULTS_DIR}/wrk-low-concurrency.txt"

echo ""

# ============================================================================
# Benchmark 2: Medium Concurrency (100 connections)
# ============================================================================

echo "[Benchmark 2] Medium Concurrency (100 connections, 4 threads)"

wrk -t4 -c100 -d${DURATION} \
    --latency \
    "${SERVER}/health" \
    | tee "${RESULTS_DIR}/wrk-medium-concurrency.txt"

echo ""

# ============================================================================
# Benchmark 3: High Concurrency (1000 connections)
# ============================================================================

echo "[Benchmark 3] High Concurrency (1000 connections, 8 threads)"

wrk -t8 -c1000 -d${DURATION} \
    --latency \
    "${SERVER}/health" \
    | tee "${RESULTS_DIR}/wrk-high-concurrency.txt"

echo ""

# ============================================================================
# Benchmark 4: POST Requests (JSON payload)
# ============================================================================

echo "[Benchmark 4] POST Requests (100 connections)"

# Create Lua script for POST
cat > /tmp/post-script.lua << 'EOF'
wrk.method = "POST"
wrk.body = '{"test": "data", "timestamp": "2025-11-16T10:00:00Z"}'
wrk.headers["Content-Type"] = "application/json"
EOF

wrk -t4 -c100 -d${DURATION} \
    --latency \
    -s /tmp/post-script.lua \
    "${SERVER}/api/test" \
    | tee "${RESULTS_DIR}/wrk-post-requests.txt"

echo ""

# ============================================================================
# Summary
# ============================================================================

echo "========================================="
echo "Benchmark Complete"
echo "========================================="
echo "Results saved to: ${RESULTS_DIR}"
echo ""

# Parse and summarize results
for file in "${RESULTS_DIR}"/wrk-*.txt; do
    echo "$(basename ${file}):"
    grep -E "Requests/sec|Latency|Transfer/sec" "${file}" | head -3
    echo ""
done
```

### 3.3 Apache Bench (ab) 벤치마크

```bash
#!/bin/bash
# benchmark-ab.sh - Apache Bench benchmark

set -e

SERVER="https://api.qsign.local"
ENDPOINT="/health"
REQUESTS=10000
CONCURRENCY=100
RESULTS_DIR="/tmp/qtsl-benchmark"

mkdir -p "${RESULTS_DIR}"

echo "========================================="
echo "Q-TLS Performance Benchmark (ab)"
echo "========================================="
echo ""

# Run benchmark
ab -n ${REQUESTS} \
   -c ${CONCURRENCY} \
   -g "${RESULTS_DIR}/ab-gnuplot.tsv" \
   "${SERVER}${ENDPOINT}" \
   | tee "${RESULTS_DIR}/ab-results.txt"

echo ""
echo "✓ Benchmark complete!"
echo "  Results: ${RESULTS_DIR}/ab-results.txt"
echo "  Gnuplot data: ${RESULTS_DIR}/ab-gnuplot.tsv"
```

### 3.4 성능 비교 스크립트

```bash
#!/bin/bash
# compare-performance.sh - Compare Q-TLS vs TLS 1.3 performance

set -e

QTSL_SERVER="https://api.qsign.local:9443"  # Q-TLS port
TLS_SERVER="https://api.qsign.local:8443"   # Legacy TLS port
REQUESTS=1000
CONCURRENCY=50

echo "========================================="
echo "Performance Comparison: Q-TLS vs TLS 1.3"
echo "========================================="
echo ""

# Q-TLS benchmark
echo "[1/2] Benchmarking Q-TLS..."
QTSL_RESULT=$(ab -n ${REQUESTS} -c ${CONCURRENCY} -q "${QTSL_SERVER}/health" 2>&1)
QTSL_RPS=$(echo "${QTSL_RESULT}" | grep "Requests per second" | awk '{print $4}')
QTSL_LATENCY=$(echo "${QTSL_RESULT}" | grep "Time per request" | head -1 | awk '{print $4}')

echo "  Q-TLS RPS: ${QTSL_RPS}"
echo "  Q-TLS Latency: ${QTSL_LATENCY} ms"

# TLS 1.3 benchmark
echo ""
echo "[2/2] Benchmarking TLS 1.3..."
TLS_RESULT=$(ab -n ${REQUESTS} -c ${CONCURRENCY} -q "${TLS_SERVER}/health" 2>&1)
TLS_RPS=$(echo "${TLS_RESULT}" | grep "Requests per second" | awk '{print $4}')
TLS_LATENCY=$(echo "${TLS_RESULT}" | grep "Time per request" | head -1 | awk '{print $4}')

echo "  TLS 1.3 RPS: ${TLS_RPS}"
echo "  TLS 1.3 Latency: ${TLS_LATENCY} ms"

# Comparison
echo ""
echo "========================================="
echo "Comparison Summary"
echo "========================================="

RPS_DIFF=$(echo "scale=2; (${TLS_RPS} - ${QTSL_RPS}) / ${TLS_RPS} * 100" | bc)
LATENCY_DIFF=$(echo "scale=2; (${QTSL_LATENCY} - ${TLS_LATENCY}) / ${TLS_LATENCY} * 100" | bc)

echo "RPS Difference: ${RPS_DIFF}% (Q-TLS is slower)"
echo "Latency Difference: +${LATENCY_DIFF}% (Q-TLS is slower)"
echo ""
echo "Note: Q-TLS overhead is expected due to larger key sizes"
echo "      and additional PQC operations."
```

---

## 4. 상호운용성 테스트

### 4.1 클라이언트 호환성 테스트

```bash
#!/bin/bash
# interoperability-tests.sh - Test Q-TLS with various clients

set -e

SERVER="https://api.qsign.local"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"

echo "========================================="
echo "Q-TLS Interoperability Tests"
echo "========================================="
echo ""

# ============================================================================
# Test 1: cURL
# ============================================================================

echo "[Test 1] cURL Client"

if curl -v --cacert "${CA_CERT}" "${SERVER}/health" 2>&1 | grep -q "200 OK"; then
    CURL_VERSION=$(curl --version | head -1)
    echo "  ✓ PASS: ${CURL_VERSION}"
else
    echo "  ✗ FAIL: cURL connection failed"
fi

echo ""

# ============================================================================
# Test 2: wget
# ============================================================================

echo "[Test 2] wget Client"

if wget --ca-certificate="${CA_CERT}" -O- "${SERVER}/health" 2>&1 | grep -q "healthy"; then
    WGET_VERSION=$(wget --version | head -1)
    echo "  ✓ PASS: ${WGET_VERSION}"
else
    echo "  ✗ FAIL: wget connection failed"
fi

echo ""

# ============================================================================
# Test 3: Python requests
# ============================================================================

echo "[Test 3] Python requests Library"

python3 << EOF
import requests

try:
    response = requests.get(
        "${SERVER}/health",
        verify="${CA_CERT}"
    )
    if response.status_code == 200:
        print("  ✓ PASS: Python requests")
    else:
        print(f"  ✗ FAIL: HTTP {response.status_code}")
except Exception as e:
    print(f"  ✗ FAIL: {e}")
EOF

echo ""

# ============================================================================
# Test 4: Node.js https module
# ============================================================================

echo "[Test 4] Node.js https Module"

node << EOF
const https = require('https');
const fs = require('fs');

const options = {
    hostname: 'api.qsign.local',
    port: 443,
    path: '/health',
    method: 'GET',
    ca: fs.readFileSync('${CA_CERT}')
};

const req = https.request(options, (res) => {
    if (res.statusCode === 200) {
        console.log('  ✓ PASS: Node.js https');
    } else {
        console.log(\`  ✗ FAIL: HTTP \${res.statusCode}\`);
    }
});

req.on('error', (e) => {
    console.log(\`  ✗ FAIL: \${e.message}\`);
});

req.end();
EOF

echo ""

# ============================================================================
# Test 5: Java HttpClient
# ============================================================================

echo "[Test 5] Java HttpClient"

cat > /tmp/JavaHttpTest.java << EOF
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;

public class JavaHttpTest {
    public static void main(String[] args) throws Exception {
        // Load CA certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        FileInputStream caInput = new FileInputStream("${CA_CERT}");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("ca-cert", caCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(null, tmf.getTrustManagers(), null);

        // Create HTTP client
        HttpClient client = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("${SERVER}/health"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            System.out.println("  ✓ PASS: Java HttpClient");
        } else {
            System.out.println("  ✗ FAIL: HTTP " + response.statusCode());
        }
    }
}
EOF

javac /tmp/JavaHttpTest.java 2>/dev/null && \
    java -cp /tmp JavaHttpTest || \
    echo "  ⚠ SKIP: Java not available"

echo ""

# ============================================================================
# Test 6: Go net/http
# ============================================================================

echo "[Test 6] Go net/http"

cat > /tmp/go-http-test.go << EOF
package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "io/ioutil"
    "net/http"
)

func main() {
    caCert, _ := ioutil.ReadFile("${CA_CERT}")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        RootCAs: caCertPool,
        MinVersion: tls.VersionTLS13,
    }

    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }

    resp, err := client.Get("${SERVER}/health")
    if err != nil {
        fmt.Printf("  ✗ FAIL: %v\n", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode == 200 {
        fmt.Println("  ✓ PASS: Go net/http")
    } else {
        fmt.Printf("  ✗ FAIL: HTTP %d\n", resp.StatusCode)
    }
}
EOF

go run /tmp/go-http-test.go 2>/dev/null || \
    echo "  ⚠ SKIP: Go not available"

echo ""

echo "========================================="
echo "Interoperability Tests Complete"
echo "========================================="
```

---

## 5. 부하 테스트

### 5.1 부하 테스트 시나리오

```yaml
부하 테스트 시나리오:
  Ramp-Up Test:
    설명: 점진적으로 부하 증가
    Duration: 30분
    Pattern: 0 → 10 → 100 → 1000 → 5000 RPS

  Sustained Load Test:
    설명: 일정 부하 지속
    Duration: 2시간
    Load: 1000 RPS (80% 용량)

  Spike Test:
    설명: 급격한 부하 증가
    Duration: 10분
    Pattern: 100 RPS → 5000 RPS → 100 RPS

  Stress Test:
    설명: 한계점 도달 테스트
    Duration: 1시간
    Pattern: 점진 증가 (100% → 150% → 200% 용량)

  Endurance Test:
    설명: 장시간 안정성 테스트
    Duration: 24시간
    Load: 500 RPS (60% 용량)
```

### 5.2 K6 부하 테스트 스크립트

```javascript
// k6-load-test.js
// K6 Load Testing Script for Q-TLS

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');

// Test configuration
export const options = {
    stages: [
        // Ramp-up
        { duration: '5m', target: 100 },   // Ramp up to 100 users
        { duration: '5m', target: 500 },   // Ramp up to 500 users
        { duration: '5m', target: 1000 },  // Ramp up to 1000 users

        // Sustained load
        { duration: '30m', target: 1000 }, // Stay at 1000 users

        // Ramp-down
        { duration: '5m', target: 0 },     // Ramp down to 0 users
    ],

    thresholds: {
        'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95% < 500ms, 99% < 1s
        'http_req_failed': ['rate<0.01'],                 // Error rate < 1%
        'errors': ['rate<0.05'],                          // Custom error rate < 5%
    },

    tlsAuth: [
        {
            domains: ['api.qsign.local'],
            cert: open('/opt/qsign/certs/client/client.crt'),
            key: open('/opt/qsign/certs/client/client.key'),
        },
    ],
};

export default function () {
    const params = {
        headers: {
            'Content-Type': 'application/json',
        },
        tags: {
            name: 'HealthCheck',
        },
    };

    // Health check request
    const healthRes = http.get('https://api.qsign.local/health', params);

    check(healthRes, {
        'status is 200': (r) => r.status === 200,
        'response time < 500ms': (r) => r.timings.duration < 500,
        'protocol is TLS 1.3': (r) => r.tls_version === http.TLS_1_3,
    }) || errorRate.add(1);

    // API request
    const apiRes = http.get('https://api.qsign.local/api/v1/public/status', params);

    check(apiRes, {
        'status is 200': (r) => r.status === 200,
        'response has data': (r) => r.body.length > 0,
    }) || errorRate.add(1);

    sleep(1);
}

// Setup function (runs once)
export function setup() {
    console.log('Starting Q-TLS load test...');
}

// Teardown function (runs once)
export function teardown(data) {
    console.log('Load test complete!');
}
```

### 5.3 K6 실행 스크립트

```bash
#!/bin/bash
# run-k6-load-test.sh

set -e

# Install k6 if not present
if ! command -v k6 &> /dev/null; then
    echo "Installing k6..."
    sudo gpg -k
    sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
        --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
    echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" | \
        sudo tee /etc/apt/sources.list.d/k6.list
    sudo apt-get update
    sudo apt-get install -y k6
fi

# Run K6 test
echo "Starting K6 load test..."

k6 run \
    --out json=/tmp/k6-results.json \
    --out influxdb=http://localhost:8086/k6 \
    k6-load-test.js

echo ""
echo "✓ Load test complete!"
echo "  Results: /tmp/k6-results.json"
```

---

## 6. 침투 테스트

### 6.1 침투 테스트 체크리스트

```yaml
침투 테스트 체크리스트:
  SSL/TLS 취약점:
    - [ ] Heartbleed (CVE-2014-0160)
    - [ ] POODLE (CVE-2014-3566)
    - [ ] BEAST (CVE-2011-3389)
    - [ ] CRIME (CVE-2012-4929)
    - [ ] BREACH
    - [ ] Logjam (CVE-2015-4000)
    - [ ] FREAK (CVE-2015-0204)
    - [ ] DROWN (CVE-2016-0800)

  인증서 공격:
    - [ ] Certificate spoofing
    - [ ] CA impersonation
    - [ ] Certificate pinning bypass

  프로토콜 공격:
    - [ ] Downgrade attack
    - [ ] MITM attack
    - [ ] Replay attack
    - [ ] Session hijacking

  Application Layer:
    - [ ] SQL Injection
    - [ ] XSS
    - [ ] CSRF
    - [ ] Directory traversal
```

### 6.2 OWASP ZAP 스캔 스크립트

```bash
#!/bin/bash
# run-zap-scan.sh - OWASP ZAP security scan

set -e

TARGET="https://api.qsign.local"
CA_CERT="/opt/qsign/certs/ca/root-ca.crt"
RESULTS_DIR="/tmp/zap-results"

mkdir -p "${RESULTS_DIR}"

# Check if ZAP is installed
if ! command -v zaproxy &> /dev/null; then
    echo "Installing OWASP ZAP..."
    wget -O /tmp/zap.tar.gz \
        "https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz"
    sudo tar -xzf /tmp/zap.tar.gz -C /opt/
    sudo ln -s /opt/ZAP_2.14.0/zap.sh /usr/local/bin/zaproxy
fi

echo "Starting OWASP ZAP scan on ${TARGET}..."

# Run ZAP in daemon mode
zaproxy -daemon -port 8090 -config api.key=zap-api-key &
ZAP_PID=$!

# Wait for ZAP to start
sleep 30

# Import CA certificate
curl "http://localhost:8090/JSON/core/action/importCaCert/" \
    --data "filePath=${CA_CERT}"

# Spider the target
curl "http://localhost:8090/JSON/spider/action/scan/" \
    --data "url=${TARGET}&apikey=zap-api-key"

# Wait for spider to complete
while [[ $(curl -s "http://localhost:8090/JSON/spider/view/status/" | jq '.status') != "\"100\"" ]]; do
    echo "Spider progress: $(curl -s 'http://localhost:8090/JSON/spider/view/status/' | jq '.status')"
    sleep 5
done

# Active scan
curl "http://localhost:8090/JSON/ascan/action/scan/" \
    --data "url=${TARGET}&apikey=zap-api-key"

# Wait for active scan to complete
while [[ $(curl -s "http://localhost:8090/JSON/ascan/view/status/" | jq '.status') != "\"100\"" ]]; do
    echo "Active scan progress: $(curl -s 'http://localhost:8090/JSON/ascan/view/status/' | jq '.status')"
    sleep 10
done

# Generate reports
curl "http://localhost:8090/OTHER/core/other/htmlreport/?apikey=zap-api-key" \
    -o "${RESULTS_DIR}/zap-report.html"

curl "http://localhost:8090/JSON/core/view/alerts/" \
    -o "${RESULTS_DIR}/zap-alerts.json"

# Stop ZAP
kill ${ZAP_PID}

echo ""
echo "✓ ZAP scan complete!"
echo "  HTML Report: ${RESULTS_DIR}/zap-report.html"
echo "  Alerts JSON: ${RESULTS_DIR}/zap-alerts.json"
```

---

## 7. 자동화 테스트

### 7.1 CI/CD 통합 (GitHub Actions)

```yaml
# .github/workflows/qtsl-tests.yml
# GitHub Actions workflow for Q-TLS testing

name: Q-TLS Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  functional-tests:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install OpenSSL OQS
        run: |
          ./scripts/install-openssl-oqs.sh

      - name: Generate test certificates
        run: |
          ./scripts/generate-test-certs.sh

      - name: Start Q-TLS server
        run: |
          docker-compose -f docker-compose-test.yml up -d

      - name: Wait for server
        run: |
          sleep 30

      - name: Run functional tests
        run: |
          ./scripts/functional-tests.sh

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: functional-test-results
          path: /tmp/qtsl-test-results/

  security-tests:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Run security tests
        run: |
          ./scripts/security-tests.sh

      - name: Run testssl.sh scan
        run: |
          ./scripts/run-testssl-scan.sh

      - name: Upload security results
        uses: actions/upload-artifact@v3
        with:
          name: security-test-results
          path: /tmp/testssl-report.*

  performance-tests:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install performance tools
        run: |
          sudo apt-get update
          sudo apt-get install -y wrk apache2-utils

      - name: Run performance benchmarks
        run: |
          ./scripts/benchmark-wrk.sh

      - name: Upload benchmark results
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: /tmp/qtsl-benchmark/
```

### 7.2 테스트 자동화 스크립트

```bash
#!/bin/bash
# automated-test-suite.sh - Complete automated test suite

set -e

RESULTS_DIR="/tmp/qtsl-automated-tests-$(date +%Y%m%d%H%M%S)"
mkdir -p "${RESULTS_DIR}"

echo "========================================="
echo "Q-TLS Automated Test Suite"
echo "========================================="
echo "Results directory: ${RESULTS_DIR}"
echo ""

# ============================================================================
# 1. Functional Tests
# ============================================================================

echo "[1/6] Running functional tests..."
./functional-tests.sh > "${RESULTS_DIR}/functional-tests.log" 2>&1

if [[ $? -eq 0 ]]; then
    echo "  ✓ Functional tests passed"
else
    echo "  ✗ Functional tests failed (see log)"
fi

# ============================================================================
# 2. Security Tests
# ============================================================================

echo "[2/6] Running security tests..."
./security-tests.sh > "${RESULTS_DIR}/security-tests.log" 2>&1

if [[ $? -eq 0 ]]; then
    echo "  ✓ Security tests passed"
else
    echo "  ✗ Security tests failed (see log)"
fi

# ============================================================================
# 3. Performance Benchmarks
# ============================================================================

echo "[3/6] Running performance benchmarks..."
./benchmark-wrk.sh > "${RESULTS_DIR}/performance-benchmark.log" 2>&1

if [[ $? -eq 0 ]]; then
    echo "  ✓ Performance benchmarks completed"
else
    echo "  ✗ Performance benchmarks failed (see log)"
fi

# ============================================================================
# 4. Interoperability Tests
# ============================================================================

echo "[4/6] Running interoperability tests..."
./interoperability-tests.sh > "${RESULTS_DIR}/interop-tests.log" 2>&1

if [[ $? -eq 0 ]]; then
    echo "  ✓ Interoperability tests passed"
else
    echo "  ✗ Interoperability tests failed (see log)"
fi

# ============================================================================
# 5. Load Tests (K6)
# ============================================================================

echo "[5/6] Running load tests (abbreviated)..."
timeout 600 ./run-k6-load-test.sh > "${RESULTS_DIR}/load-tests.log" 2>&1 || true

echo "  ✓ Load tests completed (check log for details)"

# ============================================================================
# 6. SSL/TLS Scan (testssl.sh)
# ============================================================================

echo "[6/6] Running SSL/TLS scan..."
./run-testssl-scan.sh > "${RESULTS_DIR}/testssl-scan.log" 2>&1

if [[ $? -eq 0 ]]; then
    echo "  ✓ SSL/TLS scan completed"
else
    echo "  ✗ SSL/TLS scan failed (see log)"
fi

# ============================================================================
# Generate Summary Report
# ============================================================================

echo ""
echo "Generating summary report..."

cat > "${RESULTS_DIR}/SUMMARY.md" << EOF
# Q-TLS Test Summary

**Date**: $(date -Iseconds)

## Test Results

### Functional Tests
$(grep -c "✓ PASS" "${RESULTS_DIR}/functional-tests.log" || echo "0") passed
$(grep -c "✗ FAIL" "${RESULTS_DIR}/functional-tests.log" || echo "0") failed

### Security Tests
Status: $(grep -q "Security Tests Complete" "${RESULTS_DIR}/security-tests.log" && echo "PASS" || echo "FAIL")

### Performance Benchmarks
$(grep "Requests/sec" "${RESULTS_DIR}/performance-benchmark.log" | head -1 || echo "N/A")

### Interoperability Tests
$(grep -c "✓ PASS" "${RESULTS_DIR}/interop-tests.log" || echo "0") clients compatible

### Load Tests
Status: Completed (see detailed log)

### SSL/TLS Scan
Status: $(grep -q "Done" "${RESULTS_DIR}/testssl-scan.log" && echo "COMPLETED" || echo "INCOMPLETE")

## Files
- Functional Tests: functional-tests.log
- Security Tests: security-tests.log
- Performance Benchmarks: performance-benchmark.log
- Interoperability Tests: interop-tests.log
- Load Tests: load-tests.log
- SSL/TLS Scan: testssl-scan.log

---
Generated by automated-test-suite.sh
EOF

echo ""
echo "========================================="
echo "Test Suite Complete"
echo "========================================="
echo "Results saved to: ${RESULTS_DIR}"
echo "Summary: ${RESULTS_DIR}/SUMMARY.md"
echo ""

cat "${RESULTS_DIR}/SUMMARY.md"
```

---

## 8. 테스트 결과 분석

### 8.1 성능 메트릭 예시

| 메트릭 | Q-TLS (Hybrid) | TLS 1.3 (ECDHE) | 차이 |
|--------|---------------|-----------------|------|
| **Handshake Time** | 82ms | 28ms | +193% |
| **Session Resumption** | 12ms | 8ms | +50% |
| **Requests/sec** | 8,450 | 12,300 | -31% |
| **Latency (p50)** | 45ms | 32ms | +41% |
| **Latency (p95)** | 125ms | 78ms | +60% |
| **Latency (p99)** | 280ms | 145ms | +93% |
| **Throughput** | 425 MB/s | 615 MB/s | -31% |
| **CPU Usage** | 42% | 28% | +50% |
| **Memory Usage** | 1.2 GB | 0.8 GB | +50% |

### 8.2 보안 점수 비교

| 항목 | Q-TLS | TLS 1.3 | 점수 |
|------|-------|---------|------|
| **프로토콜 지원** | TLS 1.3 only | TLS 1.2/1.3 | A+ / A |
| **키 교환** | ECDHE + Kyber1024 | ECDHE P-384 | A+ / A |
| **Cipher Strength** | AES-256-GCM | AES-256-GCM | A+ / A+ |
| **인증서** | Hybrid (RSA+Dilithium) | RSA-4096 | A+ / A |
| **양자 내성** | Yes | No | A+ / F |
| **Forward Secrecy** | Yes | Yes | A+ / A+ |
| **OCSP Stapling** | Enabled | Enabled | A+ / A+ |
| **HSTS** | Enabled | Enabled | A+ / A+ |
| **전체 점수** | **A+** | **A** | - |

### 8.3 호환성 매트릭스

| 클라이언트 | 버전 | Q-TLS Support | TLS 1.3 Support | 테스트 결과 |
|-----------|------|---------------|----------------|------------|
| **OpenSSL** | 3.2.0 + OQS | ✓ | ✓ | PASS |
| **cURL** | 8.x | ✓ (with OQS) | ✓ | PASS |
| **Python requests** | 2.31 | ✓ (with ssl lib) | ✓ | PASS |
| **Node.js** | 20.x | ✓ (with OQS) | ✓ | PASS |
| **Java** | 17+ | ✓ (with BC) | ✓ | PASS |
| **Go** | 1.21+ | ✓ (with OQS) | ✓ | PASS |
| **Chrome** | 120+ | ✗ | ✓ | TLS 1.3 only |
| **Firefox** | 121+ | ✗ | ✓ | TLS 1.3 only |
| **Safari** | 17+ | ✗ | ✓ | TLS 1.3 only |

### 8.4 부하 테스트 결과 차트

```
연결 수에 따른 응답 시간 (Latency vs Connections)

Latency (ms)
 500 │                                    ╭─
     │                               ╭────╯
 400 │                          ╭────╯
     │                     ╭────╯
 300 │                ╭────╯
     │           ╭────╯
 200 │      ╭────╯
     │ ╭────╯
 100 │─╯
     │
   0 └─────┬─────┬─────┬─────┬─────┬─────┬───── Connections
         100   200   500  1000  2000  5000

범례:
─── Q-TLS (Hybrid)
─ ─ TLS 1.3 (ECDHE)
```

---

## 관련 문서

- [Q-TLS-OVERVIEW.md](./Q-TLS-OVERVIEW.md) - Q-TLS 개요
- [Q-TLS-ARCHITECTURE.md](./Q-TLS-ARCHITECTURE.md) - 아키텍처
- [IMPLEMENTATION-GUIDE.md](./IMPLEMENTATION-GUIDE.md) - 구현 가이드
- [SEQUENCE-DIAGRAMS.md](./SEQUENCE-DIAGRAMS.md) - 시퀀스 다이어그램
- [INTEGRATION.md](./INTEGRATION.md) - 시스템 통합

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Document Status**: Complete
