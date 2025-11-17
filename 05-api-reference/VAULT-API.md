# HashiCorp Vault API Reference

HashiCorp Vault의 주요 API 엔드포인트 및 PQC(Post-Quantum Cryptography) 사용 예제입니다.

## Base URL

```
http://localhost:8200
```

## 목차

- [Auth API](#auth-api)
- [Transit Engine API (PQC)](#transit-engine-api-pqc)
- [KV Secret Engine API](#kv-secret-engine-api)
- [Sys API](#sys-api)
- [예제 코드](#예제-코드)

---

## Auth API

### 1. Token 로그인

**Endpoint:** `POST /v1/auth/token/lookup-self`

**Headers:**
- `X-Vault-Token`: Vault token

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/auth/token/lookup-self \
  -H "X-Vault-Token: hvs.your-token-here"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "accessor": "token-accessor-id",
    "creation_time": 1699999700,
    "creation_ttl": 0,
    "display_name": "root",
    "entity_id": "",
    "expire_time": null,
    "explicit_max_ttl": 0,
    "id": "hvs.your-token-here",
    "meta": null,
    "num_uses": 0,
    "orphan": true,
    "path": "auth/token/root",
    "policies": ["root"],
    "ttl": 0,
    "type": "service"
  }
}
```

### 2. AppRole 인증

**Endpoint:** `POST /v1/auth/approle/login`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/auth/approle/login \
  -H "Content-Type: application/json" \
  -d '{
    "role_id": "your-role-id",
    "secret_id": "your-secret-id"
  }'
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": null,
  "auth": {
    "client_token": "<vault-client-token>",
    "accessor": "accessor-id",
    "policies": ["default", "qsign-policy"],
    "token_policies": ["default", "qsign-policy"],
    "metadata": {
      "role_name": "qsign-role"
    },
    "lease_duration": 2764800,
    "renewable": true,
    "entity_id": "entity-id",
    "token_type": "service"
  }
}
```

### 3. Token 갱신

**Endpoint:** `POST /v1/auth/token/renew-self`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/auth/token/renew-self \
  -H "X-Vault-Token: hvs.your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "increment": "1h"
  }'
```

### 4. Token 폐기

**Endpoint:** `POST /v1/auth/token/revoke-self`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/auth/token/revoke-self \
  -H "X-Vault-Token: hvs.your-token-here"
```

---

## Transit Engine API (PQC)

Transit Engine은 암호화 키 관리 및 암호화 작업을 제공합니다. QSIGN에서는 PQC 알고리즘을 지원합니다.

### 1. Transit Engine 활성화

**Endpoint:** `POST /v1/sys/mounts/transit`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/sys/mounts/transit \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "transit",
    "description": "PQC Transit Engine for QSIGN"
  }'
```

### 2. 키 생성 (PQC 알고리즘)

**Endpoint:** `POST /v1/transit/keys/{key_name}`

**Supported PQC Algorithms:**
- `dilithium2` - Dilithium Level 2
- `dilithium3` - Dilithium Level 3
- `dilithium5` - Dilithium Level 5
- `sphincs-sha256-128f` - SPHINCS+ SHA-256 128f
- `sphincs-shake256-256s` - SPHINCS+ SHAKE-256 256s

**Example Request (Dilithium3):**

```bash
curl -X POST http://localhost:8200/v1/transit/keys/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "dilithium3",
    "exportable": false,
    "allow_plaintext_backup": false
  }'
```

**Example Request (SPHINCS+):**

```bash
curl -X POST http://localhost:8200/v1/transit/keys/qsign-sphincs \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "sphincs-shake256-256s",
    "exportable": false,
    "allow_plaintext_backup": false
  }'
```

### 3. 키 목록 조회

**Endpoint:** `LIST /v1/transit/keys`

**Example Request:**

```bash
curl -X LIST http://localhost:8200/v1/transit/keys \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "qsign-dilithium3",
      "qsign-sphincs",
      "document-signing-key"
    ]
  }
}
```

### 4. 키 정보 조회

**Endpoint:** `GET /v1/transit/keys/{key_name}`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/transit/keys/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "type": "dilithium3",
    "deletion_allowed": false,
    "exportable": false,
    "allow_plaintext_backup": false,
    "keys": {
      "1": {
        "creation_time": "2024-01-15T10:30:00Z",
        "name": "dilithium3",
        "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
      }
    },
    "latest_version": 1,
    "min_available_version": 0,
    "min_decryption_version": 1,
    "min_encryption_version": 0,
    "name": "qsign-dilithium3",
    "supports_encryption": true,
    "supports_decryption": true,
    "supports_derivation": false,
    "supports_signing": true
  }
}
```

### 5. 데이터 서명 (PQC)

**Endpoint:** `POST /v1/transit/sign/{key_name}`

**Example Request:**

```bash
# 서명할 데이터를 base64로 인코딩
DATA_B64=$(echo -n "important document content" | base64)

curl -X POST http://localhost:8200/v1/transit/sign/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": \"${DATA_B64}\",
    \"hash_algorithm\": \"sha2-256\"
  }"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "signature": "vault:v1:dilithium3:MEUCIQDabc123...",
    "key_version": 1
  }
}
```

### 6. 서명 검증

**Endpoint:** `POST /v1/transit/verify/{key_name}`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/transit/verify/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"input\": \"${DATA_B64}\",
    \"signature\": \"vault:v1:dilithium3:MEUCIQDabc123...\",
    \"hash_algorithm\": \"sha2-256\"
  }"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "valid": true
  }
}
```

### 7. 데이터 암호화

**Endpoint:** `POST /v1/transit/encrypt/{key_name}`

**Example Request:**

```bash
PLAINTEXT_B64=$(echo -n "sensitive data" | base64)

curl -X POST http://localhost:8200/v1/transit/encrypt/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"plaintext\": \"${PLAINTEXT_B64}\"
  }"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "ciphertext": "vault:v1:abc123encrypted...",
    "key_version": 1
  }
}
```

### 8. 데이터 복호화

**Endpoint:** `POST /v1/transit/decrypt/{key_name}`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/transit/decrypt/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "ciphertext": "vault:v1:abc123encrypted..."
  }'
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "plaintext": "c2Vuc2l0aXZlIGRhdGE="
  }
}
```

### 9. 키 회전

**Endpoint:** `POST /v1/transit/keys/{key_name}/rotate`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/transit/keys/qsign-dilithium3/rotate \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 10. 키 삭제

**Endpoint:** `DELETE /v1/transit/keys/{key_name}`

**Example Request:**

```bash
# 먼저 deletion_allowed를 true로 설정
curl -X POST http://localhost:8200/v1/transit/keys/qsign-dilithium3/config \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "deletion_allowed": true
  }'

# 키 삭제
curl -X DELETE http://localhost:8200/v1/transit/keys/qsign-dilithium3 \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

---

## KV Secret Engine API

KV (Key-Value) Secret Engine은 정적 시크릿을 저장합니다.

### 1. KV v2 Engine 활성화

**Endpoint:** `POST /v1/sys/mounts/secret`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/sys/mounts/secret \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "kv-v2",
    "description": "QSIGN KV Secret Store"
  }'
```

### 2. Secret 생성/업데이트

**Endpoint:** `POST /v1/secret/data/{path}`

**Example Request:**

```bash
curl -X POST http://localhost:8200/v1/secret/data/qsign/config \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "api_key": "sk_live_abc123",
      "db_password": "supersecret",
      "encryption_key": "256bit-key-here"
    }
  }'
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "created_time": "2024-01-15T10:30:00Z",
    "custom_metadata": null,
    "deletion_time": "",
    "destroyed": false,
    "version": 1
  }
}
```

### 3. Secret 조회

**Endpoint:** `GET /v1/secret/data/{path}`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/secret/data/qsign/config \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "data": {
      "api_key": "sk_live_abc123",
      "db_password": "supersecret",
      "encryption_key": "256bit-key-here"
    },
    "metadata": {
      "created_time": "2024-01-15T10:30:00Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 1
    }
  }
}
```

### 4. Secret 버전 조회

**Endpoint:** `GET /v1/secret/data/{path}?version={version}`

**Example Request:**

```bash
curl -X GET "http://localhost:8200/v1/secret/data/qsign/config?version=2" \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 5. Secret 삭제 (소프트 삭제)

**Endpoint:** `DELETE /v1/secret/data/{path}`

**Example Request:**

```bash
curl -X DELETE http://localhost:8200/v1/secret/data/qsign/config \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 6. Secret 영구 삭제

**Endpoint:** `DELETE /v1/secret/metadata/{path}`

**Example Request:**

```bash
curl -X DELETE http://localhost:8200/v1/secret/metadata/qsign/config \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 7. Secret 목록 조회

**Endpoint:** `LIST /v1/secret/metadata/{path}`

**Example Request:**

```bash
curl -X LIST http://localhost:8200/v1/secret/metadata/qsign \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

**Response:**

```json
{
  "request_id": "abc123",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "config",
      "database/",
      "api-keys/"
    ]
  }
}
```

---

## Sys API

시스템 관리 및 상태 조회 API입니다.

### 1. Health Check

**Endpoint:** `GET /v1/sys/health`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/sys/health
```

**Response:**

```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1699999700,
  "version": "1.15.0",
  "cluster_name": "vault-cluster-abc123",
  "cluster_id": "abc123-def456-ghi789"
}
```

### 2. Seal Status

**Endpoint:** `GET /v1/sys/seal-status`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/sys/seal-status
```

**Response:**

```json
{
  "type": "shamir",
  "initialized": true,
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0,
  "nonce": "",
  "version": "1.15.0",
  "build_date": "2024-01-10T15:30:00Z",
  "migration": false,
  "cluster_name": "vault-cluster-abc123",
  "cluster_id": "abc123-def456-ghi789",
  "recovery_seal": false,
  "storage_type": "file"
}
```

### 3. Mount 목록 조회

**Endpoint:** `GET /v1/sys/mounts`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/sys/mounts \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 4. Policy 생성

**Endpoint:** `PUT /v1/sys/policies/acl/{name}`

**Example Request:**

```bash
curl -X PUT http://localhost:8200/v1/sys/policies/acl/qsign-policy \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "path \"secret/data/qsign/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\n\npath \"transit/sign/qsign-*\" {\n  capabilities = [\"create\", \"update\"]\n}\n\npath \"transit/verify/qsign-*\" {\n  capabilities = [\"create\", \"update\"]\n}"
  }'
```

### 5. Policy 조회

**Endpoint:** `GET /v1/sys/policies/acl/{name}`

**Example Request:**

```bash
curl -X GET http://localhost:8200/v1/sys/policies/acl/qsign-policy \
  -H "X-Vault-Token: ${VAULT_TOKEN}"
```

### 6. Audit 로그 활성화

**Endpoint:** `PUT /v1/sys/audit/{path}`

**Example Request:**

```bash
curl -X PUT http://localhost:8200/v1/sys/audit/file \
  -H "X-Vault-Token: ${VAULT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "file",
    "options": {
      "file_path": "/vault/logs/audit.log"
    }
  }'
```

---

## 예제 코드

### Python 예제

#### 1. Vault 클라이언트 기본 사용

```python
import requests
import json
import base64

class VaultClient:
    def __init__(self, vault_url, token):
        self.vault_url = vault_url
        self.token = token
        self.headers = {
            'X-Vault-Token': token,
            'Content-Type': 'application/json'
        }

    def health_check(self):
        """Vault 상태 확인"""
        url = f"{self.vault_url}/v1/sys/health"
        response = requests.get(url)
        return response.json()

    # Transit Engine - PQC 서명/검증
    def create_pqc_key(self, key_name, key_type='dilithium3'):
        """PQC 키 생성"""
        url = f"{self.vault_url}/v1/transit/keys/{key_name}"
        data = {
            'type': key_type,
            'exportable': False,
            'allow_plaintext_backup': False
        }
        response = requests.post(url, headers=self.headers, json=data)
        return response.status_code == 204

    def get_key_info(self, key_name):
        """키 정보 조회"""
        url = f"{self.vault_url}/v1/transit/keys/{key_name}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']

    def sign_data(self, key_name, data, hash_algorithm='sha2-256'):
        """데이터 서명 (PQC)"""
        url = f"{self.vault_url}/v1/transit/sign/{key_name}"

        # 데이터를 base64로 인코딩
        data_b64 = base64.b64encode(data.encode()).decode()

        payload = {
            'input': data_b64,
            'hash_algorithm': hash_algorithm
        }

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()['data']['signature']

    def verify_signature(self, key_name, data, signature, hash_algorithm='sha2-256'):
        """서명 검증"""
        url = f"{self.vault_url}/v1/transit/verify/{key_name}"

        # 데이터를 base64로 인코딩
        data_b64 = base64.b64encode(data.encode()).decode()

        payload = {
            'input': data_b64,
            'signature': signature,
            'hash_algorithm': hash_algorithm
        }

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()['data']['valid']

    def encrypt_data(self, key_name, plaintext):
        """데이터 암호화"""
        url = f"{self.vault_url}/v1/transit/encrypt/{key_name}"

        plaintext_b64 = base64.b64encode(plaintext.encode()).decode()
        payload = {'plaintext': plaintext_b64}

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()['data']['ciphertext']

    def decrypt_data(self, key_name, ciphertext):
        """데이터 복호화"""
        url = f"{self.vault_url}/v1/transit/decrypt/{key_name}"
        payload = {'ciphertext': ciphertext}

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()

        plaintext_b64 = response.json()['data']['plaintext']
        return base64.b64decode(plaintext_b64).decode()

    # KV Secret Engine
    def write_secret(self, path, data):
        """Secret 저장"""
        url = f"{self.vault_url}/v1/secret/data/{path}"
        payload = {'data': data}

        response = requests.post(url, headers=self.headers, json=payload)
        response.raise_for_status()
        return response.json()['data']

    def read_secret(self, path, version=None):
        """Secret 조회"""
        url = f"{self.vault_url}/v1/secret/data/{path}"
        if version:
            url += f"?version={version}"

        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']['data']

    def list_secrets(self, path):
        """Secret 목록 조회"""
        url = f"{self.vault_url}/v1/secret/metadata/{path}"
        response = requests.request('LIST', url, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']['keys']

    def delete_secret(self, path):
        """Secret 삭제"""
        url = f"{self.vault_url}/v1/secret/data/{path}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        return response.status_code == 204

# 사용 예제
if __name__ == "__main__":
    # Vault 클라이언트 초기화
    vault = VaultClient(
        vault_url="http://localhost:8200",
        token="hvs.your-token-here"
    )

    # 상태 확인
    health = vault.health_check()
    print(f"Vault Status: {'Healthy' if not health['sealed'] else 'Sealed'}")

    # PQC 키 생성 및 서명/검증
    key_name = "qsign-dilithium3"

    # 키 생성
    if vault.create_pqc_key(key_name, 'dilithium3'):
        print(f"PQC Key '{key_name}' created successfully")

    # 키 정보 조회
    key_info = vault.get_key_info(key_name)
    print(f"Key Type: {key_info['type']}")
    print(f"Key Version: {key_info['latest_version']}")

    # 데이터 서명
    document = "This is an important document"
    signature = vault.sign_data(key_name, document)
    print(f"Signature: {signature[:50]}...")

    # 서명 검증
    is_valid = vault.verify_signature(key_name, document, signature)
    print(f"Signature Valid: {is_valid}")

    # 데이터 암호화/복호화
    sensitive_data = "sensitive information"
    ciphertext = vault.encrypt_data(key_name, sensitive_data)
    print(f"Encrypted: {ciphertext[:50]}...")

    decrypted = vault.decrypt_data(key_name, ciphertext)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == sensitive_data}")

    # Secret 관리
    vault.write_secret('qsign/config', {
        'api_key': 'sk_live_abc123',
        'db_password': 'supersecret'
    })
    print("Secret written")

    config = vault.read_secret('qsign/config')
    print(f"API Key: {config['api_key']}")

    secrets = vault.list_secrets('qsign')
    print(f"Secrets: {secrets}")
```

#### 2. 문서 서명 시스템 예제

```python
import hashlib
from datetime import datetime

class DocumentSigner:
    def __init__(self, vault_client, key_name):
        self.vault = vault_client
        self.key_name = key_name

    def sign_document(self, document_content, metadata=None):
        """문서 서명"""
        # 문서 해시 생성
        doc_hash = hashlib.sha256(document_content.encode()).hexdigest()

        # 서명 데이터 준비
        sign_data = {
            'document_hash': doc_hash,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': metadata or {}
        }

        sign_string = json.dumps(sign_data, sort_keys=True)

        # PQC 서명 생성
        signature = self.vault.sign_data(self.key_name, sign_string)

        return {
            'signature': signature,
            'sign_data': sign_data,
            'algorithm': 'dilithium3'
        }

    def verify_document(self, document_content, signature_info):
        """문서 서명 검증"""
        # 문서 해시 검증
        doc_hash = hashlib.sha256(document_content.encode()).hexdigest()

        if doc_hash != signature_info['sign_data']['document_hash']:
            return False, "Document hash mismatch"

        # 서명 데이터 재구성
        sign_string = json.dumps(signature_info['sign_data'], sort_keys=True)

        # PQC 서명 검증
        is_valid = self.vault.verify_signature(
            self.key_name,
            sign_string,
            signature_info['signature']
        )

        return is_valid, "Valid" if is_valid else "Invalid signature"

# 사용 예제
if __name__ == "__main__":
    vault = VaultClient("http://localhost:8200", "hvs.your-token-here")
    signer = DocumentSigner(vault, "qsign-dilithium3")

    # 문서 서명
    document = "Contract Agreement between Party A and Party B"
    sig_info = signer.sign_document(document, {
        'signer': 'admin@example.com',
        'department': 'Legal'
    })

    print(f"Document signed at: {sig_info['sign_data']['timestamp']}")
    print(f"Signature: {sig_info['signature'][:50]}...")

    # 서명 검증
    is_valid, message = signer.verify_document(document, sig_info)
    print(f"Verification: {message}")
```

### Bash Script 예제

```bash
#!/bin/bash

# Vault 설정
VAULT_ADDR="http://localhost:8200"
VAULT_TOKEN="hvs.your-token-here"

# PQC 키 생성
create_pqc_key() {
    local key_name=$1
    local key_type=${2:-dilithium3}

    curl -X POST "${VAULT_ADDR}/v1/transit/keys/${key_name}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"type\": \"${key_type}\",
            \"exportable\": false
        }"
}

# 데이터 서명
sign_data() {
    local key_name=$1
    local data=$2

    local data_b64=$(echo -n "${data}" | base64)

    curl -s -X POST "${VAULT_ADDR}/v1/transit/sign/${key_name}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"input\": \"${data_b64}\",
            \"hash_algorithm\": \"sha2-256\"
        }" | jq -r '.data.signature'
}

# 서명 검증
verify_signature() {
    local key_name=$1
    local data=$2
    local signature=$3

    local data_b64=$(echo -n "${data}" | base64)

    curl -s -X POST "${VAULT_ADDR}/v1/transit/verify/${key_name}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"input\": \"${data_b64}\",
            \"signature\": \"${signature}\",
            \"hash_algorithm\": \"sha2-256\"
        }" | jq -r '.data.valid'
}

# Secret 저장
write_secret() {
    local path=$1
    local key=$2
    local value=$3

    curl -X POST "${VAULT_ADDR}/v1/secret/data/${path}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"data\": {
                \"${key}\": \"${value}\"
            }
        }"
}

# Secret 조회
read_secret() {
    local path=$1
    local key=$2

    curl -s -X GET "${VAULT_ADDR}/v1/secret/data/${path}" \
        -H "X-Vault-Token: ${VAULT_TOKEN}" | jq -r ".data.data.${key}"
}

# 실행 예제
echo "Creating PQC key..."
create_pqc_key "qsign-dilithium3" "dilithium3"

echo "Signing document..."
SIGNATURE=$(sign_data "qsign-dilithium3" "important document")
echo "Signature: ${SIGNATURE:0:50}..."

echo "Verifying signature..."
VALID=$(verify_signature "qsign-dilithium3" "important document" "${SIGNATURE}")
echo "Valid: ${VALID}"

echo "Writing secret..."
write_secret "qsign/config" "api_key" "sk_live_abc123"

echo "Reading secret..."
API_KEY=$(read_secret "qsign/config" "api_key")
echo "API Key: ${API_KEY}"
```

---

## 관련 문서

- [Vault 설치 가이드](../02-setup/INSTALLATION.md)
- [보안 아키텍처](../01-architecture/SECURITY-DESIGN.md)
- [PQC 알고리즘 가이드](../01-architecture/PQC-ARCHITECTURE.md)

## 참고 자료

- [HashiCorp Vault API Documentation](https://developer.hashicorp.com/vault/api-docs)
- [Transit Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
- [KV Secrets Engine v2](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
