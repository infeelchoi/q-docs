# API Reference

QSIGN 시스템의 주요 컴포넌트 API 레퍼런스 문서입니다.

## 개요

이 섹션에서는 QSIGN 시스템을 구성하는 핵심 컴포넌트들의 REST API 사용법을 제공합니다. 각 문서에는 실제 사용 가능한 예제 코드가 포함되어 있습니다.

## 문서 목록

### [Keycloak API](./KEYCLOAK-API.md)

인증 및 사용자 관리를 위한 Keycloak API 레퍼런스입니다.

**주요 내용:**
- **Token API** - Access Token 발급, 검증, 갱신, 로그아웃
- **Admin API** - Realm 관리, 시스템 설정
- **User Management API** - 사용자 생성, 조회, 업데이트, 삭제, 비밀번호 재설정
- **Client Management API** - 클라이언트 등록 및 관리, 시크릿 관리
- **예제 코드** - Python 클라이언트, Bash 스크립트

**사용 예시:**
```python
from keycloak_client import KeycloakClient

kc = KeycloakClient("http://localhost:8080/auth", "qsign", "qsign-client", "secret")
token = kc.get_user_token("admin", "password")
users = kc.get_users()
```

---

### [Vault API](./VAULT-API.md)

PQC 암호화 키 관리 및 Secret 저장을 위한 HashiCorp Vault API 레퍼런스입니다.

**주요 내용:**
- **Auth API** - Token 인증, AppRole 인증
- **Transit Engine API (PQC)** - Dilithium, SPHINCS+ 키 관리 및 서명/검증
- **KV Secret Engine API** - Secret 저장 및 버전 관리
- **Sys API** - 시스템 관리, Policy 설정, Audit 로그

**PQC 알고리즘 지원:**
- Dilithium2, Dilithium3, Dilithium5
- SPHINCS+ (SHA-256, SHAKE-256)

**사용 예시:**
```python
from vault_client import VaultClient

vault = VaultClient("http://localhost:8200", "hvs.token")
vault.create_pqc_key("qsign-dilithium3", "dilithium3")
signature = vault.sign_data("qsign-dilithium3", "document content")
is_valid = vault.verify_signature("qsign-dilithium3", "document content", signature)
```

---

### [APISIX API](./APISIX-API.md)

API Gateway 설정 및 관리를 위한 Apache APISIX Admin API 레퍼런스입니다.

**주요 내용:**
- **Admin API** - 시스템 상태 확인
- **Route 관리** - 라우팅 규칙 설정, 플러그인 적용
- **Plugin 관리** - OpenID Connect, Rate Limiting, CORS 등
- **Upstream 관리** - 백엔드 서버 그룹 및 Health Check 설정
- **Service 관리** - 공통 설정 재사용
- **Consumer 관리** - API 사용자 관리

**주요 플러그인:**
- `openid-connect` - Keycloak 인증 연동
- `limit-req` - Rate Limiting
- `cors` - CORS 설정
- `prometheus` - 메트릭 수집
- `ip-restriction` - IP 접근 제어

**사용 예시:**
```python
from apisix_admin import APISIXAdmin

apisix = APISIXAdmin("http://localhost:9180", "edd1c9f034335f136f87ad84b625c8f1")
route = apisix.create_route("1", {
    "uri": "/api/*",
    "plugins": {"openid-connect": {...}},
    "upstream": {"nodes": {"backend:8080": 1}}
})
```

---

## 통합 사용 예제

### 전체 워크플로우 예제

```python
from keycloak_client import KeycloakClient
from vault_client import VaultClient
from apisix_admin import APISIXAdmin

# 1. Keycloak에서 인증
kc = KeycloakClient("http://localhost:8080/auth", "qsign", "qsign-client", "secret")
token_info = kc.get_user_token("admin", "password")
access_token = token_info['access_token']

# 2. Vault에서 문서 서명 (PQC)
vault = VaultClient("http://localhost:8200", "hvs.vault-token")
signature = vault.sign_data("qsign-dilithium3", "important document")

# 3. APISIX로 API 요청
import requests
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.post(
    "http://localhost:9080/api/documents/sign",
    headers=headers,
    json={"content": "important document", "signature": signature}
)
```

### 문서 서명 시스템 구축

```python
class DocumentSigningSystem:
    def __init__(self, keycloak, vault, apisix_url):
        self.kc = keycloak
        self.vault = vault
        self.api_url = apisix_url

    def sign_document(self, username, password, document_content):
        # 인증
        token = self.kc.get_user_token(username, password)

        # PQC 서명
        signature = self.vault.sign_data("qsign-dilithium3", document_content)

        # API 요청
        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        response = requests.post(
            f"{self.api_url}/api/documents/sign",
            headers=headers,
            json={
                "content": document_content,
                "signature": signature,
                "algorithm": "dilithium3"
            }
        )

        return response.json()

    def verify_document(self, document_content, signature):
        # PQC 서명 검증
        is_valid = self.vault.verify_signature(
            "qsign-dilithium3",
            document_content,
            signature
        )

        return is_valid

# 사용
system = DocumentSigningSystem(kc, vault, "http://localhost:9080")
result = system.sign_document("admin", "password", "contract document")
print(f"Document signed: {result['signature'][:50]}...")
```

---

## API 인증

### Keycloak Token 사용

대부분의 QSIGN API는 Keycloak에서 발급한 JWT 토큰을 사용합니다.

```bash
# 1. Token 발급
TOKEN=$(curl -s -X POST http://localhost:8080/auth/realms/qsign/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "client_id=qsign-client" \
  -d "client_secret=your-secret" \
  -d "username=admin" \
  -d "password=password" | jq -r '.access_token')

# 2. API 요청
curl -X GET http://localhost:9080/api/documents \
  -H "Authorization: Bearer ${TOKEN}"
```

### Vault Token 사용

```bash
# Vault API 요청
curl -X POST http://localhost:8200/v1/transit/sign/qsign-dilithium3 \
  -H "X-Vault-Token: hvs.your-vault-token" \
  -H "Content-Type: application/json" \
  -d '{"input": "base64-encoded-data"}'
```

### APISIX Admin API Key

```bash
# APISIX Admin API 요청
curl -X GET http://localhost:9180/apisix/admin/routes \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## 에러 처리

### 공통 HTTP 상태 코드

- `200 OK` - 요청 성공
- `201 Created` - 리소스 생성 성공
- `204 No Content` - 성공 (응답 본문 없음)
- `400 Bad Request` - 잘못된 요청
- `401 Unauthorized` - 인증 실패
- `403 Forbidden` - 권한 없음
- `404 Not Found` - 리소스 없음
- `429 Too Many Requests` - Rate Limit 초과
- `500 Internal Server Error` - 서버 오류

### Keycloak 에러

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid user credentials"
}
```

### Vault 에러

```json
{
  "errors": [
    "permission denied"
  ]
}
```

### APISIX 에러

```json
{
  "error_msg": "failed to check the configuration of plugin openid-connect",
  "code": 400
}
```

---

## Rate Limiting

APISIX를 통한 모든 API 요청은 Rate Limiting이 적용됩니다.

**기본 설정:**
- Document API: 200 req/s (burst: 100)
- Signature API: 50 req/s (burst: 25)
- Admin API: 100 req/s (burst: 50)

**Rate Limit 초과 시:**
```json
{
  "error_msg": "Too many requests",
  "code": 429
}
```

---

## 모니터링

### Prometheus Metrics

APISIX는 Prometheus 메트릭을 제공합니다.

```bash
# 메트릭 확인
curl http://localhost:9091/apisix/prometheus/metrics
```

**주요 메트릭:**
- `apisix_http_status` - HTTP 상태 코드별 요청 수
- `apisix_http_latency` - 요청 지연시간
- `apisix_bandwidth` - 대역폭 사용량

---

## 개발 환경 설정

### 환경 변수

```bash
# Keycloak
export KEYCLOAK_URL="http://localhost:8080/auth"
export KEYCLOAK_REALM="qsign"
export KEYCLOAK_CLIENT_ID="qsign-client"
export KEYCLOAK_CLIENT_SECRET="your-secret"

# Vault
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="hvs.your-token"

# APISIX
export APISIX_ADMIN_URL="http://localhost:9180"
export APISIX_API_KEY="edd1c9f034335f136f87ad84b625c8f1"
export APISIX_GATEWAY_URL="http://localhost:9080"
```

### Python 패키지 설치

```bash
pip install requests pyjwt cryptography
```

### 테스트 도구

```bash
# HTTPie 설치
pip install httpie

# API 테스트
http POST localhost:9080/api/documents \
  Authorization:"Bearer ${TOKEN}" \
  content="test document"
```

---

## 관련 문서

### 설치 가이드
- [Keycloak 설치](../02-installation-guides/KEYCLOAK.md)
- [Vault 설치](../02-installation-guides/VAULT.md)
- [APISIX 설치](../02-installation-guides/APISIX.md)

### 아키텍처
- [인증/인가 아키텍처](../03-architecture/AUTHENTICATION.md)
- [보안 아키텍처](../03-architecture/SECURITY.md)
- [API Gateway 아키텍처](../03-architecture/API-GATEWAY.md)

### 사용자 가이드
- [PQC 알고리즘 가이드](../04-user-guides/PQC-ALGORITHMS.md)
- [문서 서명 가이드](../04-user-guides/DOCUMENT-SIGNING.md)

---

## 외부 참고 자료

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Apache APISIX Documentation](https://apisix.apache.org/docs/)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## 지원 및 문의

API 사용 중 문제가 발생하면:
1. 해당 컴포넌트의 로그 확인
2. [Troubleshooting 가이드](../07-troubleshooting/README.md) 참조
3. GitHub Issues에 문의

**로그 확인:**
```bash
# Keycloak
docker logs keycloak

# Vault
docker logs vault

# APISIX
docker logs apisix
```
