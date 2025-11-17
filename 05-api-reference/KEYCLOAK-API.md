# Keycloak API Reference

Keycloak의 주요 REST API 엔드포인트 및 사용 예제입니다.

## Base URL

```
http://localhost:8080/auth
```

## 목차

- [Token API](#token-api)
- [Admin API](#admin-api)
- [User Management API](#user-management-api)
- [Client Management API](#client-management-api)
- [예제 코드](#예제-코드)

---

## Token API

### 1. Access Token 발급

**Endpoint:** `POST /realms/{realm}/protocol/openid-connect/token`

**Parameters:**
- `grant_type`: password, client_credentials, authorization_code, refresh_token
- `client_id`: 클라이언트 ID
- `client_secret`: 클라이언트 시크릿 (confidential client)
- `username`: 사용자명 (password grant)
- `password`: 비밀번호 (password grant)

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/realms/qsign/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=qsign-client" \
  -d "client_secret=your-client-secret" \
  -d "username=admin" \
  -d "password=admin123"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 300,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "not-before-policy": 0,
  "session_state": "d5d5d5d5-d5d5-d5d5-d5d5-d5d5d5d5d5d5",
  "scope": "profile email"
}
```

### 2. Token 검증 (Introspection)

**Endpoint:** `POST /realms/{realm}/protocol/openid-connect/token/introspect`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/realms/qsign/protocol/openid-connect/token/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d "client_id=qsign-client" \
  -d "client_secret=your-client-secret"
```

**Response:**

```json
{
  "exp": 1700000000,
  "iat": 1699999700,
  "jti": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "iss": "http://localhost:8080/auth/realms/qsign",
  "aud": "account",
  "sub": "12345678-1234-1234-1234-123456789012",
  "typ": "Bearer",
  "azp": "qsign-client",
  "session_state": "d5d5d5d5-d5d5-d5d5-d5d5-d5d5d5d5d5d5",
  "preferred_username": "admin",
  "email_verified": true,
  "name": "Admin User",
  "email": "admin@example.com",
  "active": true
}
```

### 3. Token Refresh

**Endpoint:** `POST /realms/{realm}/protocol/openid-connect/token`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/realms/qsign/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=qsign-client" \
  -d "client_secret=your-client-secret" \
  -d "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 4. Logout

**Endpoint:** `POST /realms/{realm}/protocol/openid-connect/logout`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/realms/qsign/protocol/openid-connect/logout \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=qsign-client" \
  -d "client_secret=your-client-secret" \
  -d "refresh_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

---

## Admin API

### 1. Admin Access Token 발급

**Endpoint:** `POST /realms/master/protocol/openid-connect/token`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=admin" \
  -d "password=admin"
```

### 2. Realm 목록 조회

**Endpoint:** `GET /admin/realms`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 3. Realm 생성

**Endpoint:** `POST /admin/realms`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "realm": "new-realm",
    "enabled": true,
    "displayName": "New Realm",
    "accessTokenLifespan": 300
  }'
```

### 4. Realm 정보 조회

**Endpoint:** `GET /admin/realms/{realm}`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 5. Realm 설정 업데이트

**Endpoint:** `PUT /admin/realms/{realm}`

**Example Request:**

```bash
curl -X PUT http://localhost:8080/auth/admin/realms/qsign \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "accessTokenLifespan": 600,
    "sslRequired": "external"
  }'
```

---

## User Management API

### 1. 사용자 목록 조회

**Endpoint:** `GET /admin/realms/{realm}/users`

**Parameters:**
- `briefRepresentation`: true/false (간략한 정보)
- `first`: 시작 인덱스
- `max`: 최대 결과 수
- `search`: 검색어
- `username`: 사용자명으로 검색
- `email`: 이메일로 검색

**Example Request:**

```bash
curl -X GET "http://localhost:8080/auth/admin/realms/qsign/users?max=10" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

**Response:**

```json
[
  {
    "id": "12345678-1234-1234-1234-123456789012",
    "username": "admin",
    "enabled": true,
    "emailVerified": true,
    "firstName": "Admin",
    "lastName": "User",
    "email": "admin@example.com",
    "createdTimestamp": 1699999700000
  }
]
```

### 2. 사용자 생성

**Endpoint:** `POST /admin/realms/{realm}/users`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms/qsign/users \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "enabled": true,
    "emailVerified": true,
    "firstName": "New",
    "lastName": "User",
    "email": "newuser@example.com",
    "credentials": [{
      "type": "password",
      "value": "password123",
      "temporary": false
    }]
  }'
```

### 3. 사용자 정보 조회

**Endpoint:** `GET /admin/realms/{realm}/users/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 4. 사용자 정보 업데이트

**Endpoint:** `PUT /admin/realms/{realm}/users/{id}`

**Example Request:**

```bash
curl -X PUT http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Updated",
    "lastName": "Name",
    "email": "updated@example.com"
  }'
```

### 5. 사용자 삭제

**Endpoint:** `DELETE /admin/realms/{realm}/users/{id}`

**Example Request:**

```bash
curl -X DELETE http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 6. 비밀번호 재설정

**Endpoint:** `PUT /admin/realms/{realm}/users/{id}/reset-password`

**Example Request:**

```bash
curl -X PUT http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012/reset-password \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "password",
    "value": "newpassword123",
    "temporary": false
  }'
```

### 7. 사용자 Role 할당

**Endpoint:** `POST /admin/realms/{realm}/users/{id}/role-mappings/realm`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012/role-mappings/realm \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '[{
    "id": "role-id-here",
    "name": "admin"
  }]'
```

### 8. 사용자 세션 조회

**Endpoint:** `GET /admin/realms/{realm}/users/{id}/sessions`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012/sessions \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 9. 사용자 세션 로그아웃

**Endpoint:** `POST /admin/realms/{realm}/users/{id}/logout`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms/qsign/users/12345678-1234-1234-1234-123456789012/logout \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

---

## Client Management API

### 1. 클라이언트 목록 조회

**Endpoint:** `GET /admin/realms/{realm}/clients`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign/clients \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 2. 클라이언트 생성

**Endpoint:** `POST /admin/realms/{realm}/clients`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms/qsign/clients \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "new-client",
    "enabled": true,
    "publicClient": false,
    "protocol": "openid-connect",
    "redirectUris": ["http://localhost:3000/*"],
    "webOrigins": ["http://localhost:3000"],
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": true,
    "authorizationServicesEnabled": false
  }'
```

### 3. 클라이언트 정보 조회

**Endpoint:** `GET /admin/realms/{realm}/clients/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign/clients/client-uuid-here \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 4. 클라이언트 업데이트

**Endpoint:** `PUT /admin/realms/{realm}/clients/{id}`

**Example Request:**

```bash
curl -X PUT http://localhost:8080/auth/admin/realms/qsign/clients/client-uuid-here \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "redirectUris": ["http://localhost:3000/*", "http://localhost:8080/*"]
  }'
```

### 5. 클라이언트 시크릿 조회

**Endpoint:** `GET /admin/realms/{realm}/clients/{id}/client-secret`

**Example Request:**

```bash
curl -X GET http://localhost:8080/auth/admin/realms/qsign/clients/client-uuid-here/client-secret \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

**Response:**

```json
{
  "type": "secret",
  "value": "your-client-secret-here"
}
```

### 6. 클라이언트 시크릿 재생성

**Endpoint:** `POST /admin/realms/{realm}/clients/{id}/client-secret`

**Example Request:**

```bash
curl -X POST http://localhost:8080/auth/admin/realms/qsign/clients/client-uuid-here/client-secret \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

### 7. 클라이언트 삭제

**Endpoint:** `DELETE /admin/realms/{realm}/clients/{id}`

**Example Request:**

```bash
curl -X DELETE http://localhost:8080/auth/admin/realms/qsign/clients/client-uuid-here \
  -H "Authorization: Bearer ${ADMIN_TOKEN}"
```

---

## 예제 코드

### Python 예제

#### 1. Token 발급 및 사용자 조회

```python
import requests
import json

class KeycloakClient:
    def __init__(self, base_url, realm, client_id, client_secret):
        self.base_url = base_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.admin_token = None

    def get_admin_token(self, username, password):
        """Admin Access Token 발급"""
        url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        data = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': username,
            'password': password
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        self.admin_token = response.json()['access_token']
        return self.admin_token

    def get_user_token(self, username, password):
        """사용자 Access Token 발급"""
        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        return response.json()

    def introspect_token(self, token):
        """Token 검증"""
        url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token/introspect"
        data = {
            'token': token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        response = requests.post(url, data=data)
        response.raise_for_status()
        return response.json()

    def get_users(self, max_results=100):
        """사용자 목록 조회"""
        url = f"{self.base_url}/admin/realms/{self.realm}/users"
        headers = {'Authorization': f'Bearer {self.admin_token}'}
        params = {'max': max_results}
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    def create_user(self, user_data):
        """사용자 생성"""
        url = f"{self.base_url}/admin/realms/{self.realm}/users"
        headers = {
            'Authorization': f'Bearer {self.admin_token}',
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=user_data)
        response.raise_for_status()
        return response.status_code == 201

    def update_user(self, user_id, user_data):
        """사용자 정보 업데이트"""
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}"
        headers = {
            'Authorization': f'Bearer {self.admin_token}',
            'Content-Type': 'application/json'
        }
        response = requests.put(url, headers=headers, json=user_data)
        response.raise_for_status()
        return response.status_code == 204

    def reset_password(self, user_id, new_password, temporary=False):
        """비밀번호 재설정"""
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/reset-password"
        headers = {
            'Authorization': f'Bearer {self.admin_token}',
            'Content-Type': 'application/json'
        }
        data = {
            'type': 'password',
            'value': new_password,
            'temporary': temporary
        }
        response = requests.put(url, headers=headers, json=data)
        response.raise_for_status()
        return response.status_code == 204

    def logout_user(self, user_id):
        """사용자 세션 로그아웃"""
        url = f"{self.base_url}/admin/realms/{self.realm}/users/{user_id}/logout"
        headers = {'Authorization': f'Bearer {self.admin_token}'}
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        return response.status_code == 204

# 사용 예제
if __name__ == "__main__":
    # Keycloak 클라이언트 초기화
    kc = KeycloakClient(
        base_url="http://localhost:8080/auth",
        realm="qsign",
        client_id="qsign-client",
        client_secret="your-client-secret"
    )

    # Admin 토큰 발급
    admin_token = kc.get_admin_token("admin", "admin")
    print(f"Admin Token: {admin_token[:50]}...")

    # 사용자 토큰 발급
    user_token_info = kc.get_user_token("testuser", "password123")
    print(f"Access Token: {user_token_info['access_token'][:50]}...")

    # Token 검증
    introspection = kc.introspect_token(user_token_info['access_token'])
    print(f"Token Active: {introspection['active']}")
    print(f"Username: {introspection.get('preferred_username')}")

    # 사용자 목록 조회
    users = kc.get_users(max_results=10)
    print(f"Total Users: {len(users)}")
    for user in users:
        print(f"- {user['username']} ({user['email']})")

    # 새 사용자 생성
    new_user = {
        "username": "newuser",
        "enabled": True,
        "emailVerified": True,
        "firstName": "New",
        "lastName": "User",
        "email": "newuser@example.com",
        "credentials": [{
            "type": "password",
            "value": "password123",
            "temporary": False
        }]
    }
    if kc.create_user(new_user):
        print("User created successfully")
```

#### 2. 클라이언트 관리 예제

```python
class KeycloakClientManager(KeycloakClient):
    def get_clients(self):
        """클라이언트 목록 조회"""
        url = f"{self.base_url}/admin/realms/{self.realm}/clients"
        headers = {'Authorization': f'Bearer {self.admin_token}'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def create_client(self, client_data):
        """클라이언트 생성"""
        url = f"{self.base_url}/admin/realms/{self.realm}/clients"
        headers = {
            'Authorization': f'Bearer {self.admin_token}',
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=client_data)
        response.raise_for_status()
        return response.status_code == 201

    def get_client_secret(self, client_uuid):
        """클라이언트 시크릿 조회"""
        url = f"{self.base_url}/admin/realms/{self.realm}/clients/{client_uuid}/client-secret"
        headers = {'Authorization': f'Bearer {self.admin_token}'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()['value']

# 사용 예제
if __name__ == "__main__":
    kcm = KeycloakClientManager(
        base_url="http://localhost:8080/auth",
        realm="qsign",
        client_id="admin-cli",
        client_secret=""
    )

    kcm.get_admin_token("admin", "admin")

    # 클라이언트 목록 조회
    clients = kcm.get_clients()
    for client in clients:
        print(f"Client: {client['clientId']}")

    # 새 클라이언트 생성
    new_client = {
        "clientId": "new-service",
        "enabled": True,
        "publicClient": False,
        "protocol": "openid-connect",
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": True
    }
    if kcm.create_client(new_client):
        print("Client created successfully")
```

### Bash Script 예제

```bash
#!/bin/bash

# Keycloak 설정
KEYCLOAK_URL="http://localhost:8080/auth"
REALM="qsign"
CLIENT_ID="qsign-client"
CLIENT_SECRET="your-client-secret"

# Admin 토큰 발급
get_admin_token() {
    local username=$1
    local password=$2

    curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" \
        -d "username=${username}" \
        -d "password=${password}" | jq -r '.access_token'
}

# 사용자 토큰 발급
get_user_token() {
    local username=$1
    local password=$2

    curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "username=${username}" \
        -d "password=${password}"
}

# 사용자 목록 조회
list_users() {
    local admin_token=$1

    curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
        -H "Authorization: Bearer ${admin_token}" | jq '.'
}

# 사용자 생성
create_user() {
    local admin_token=$1
    local username=$2
    local email=$3
    local password=$4

    curl -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
        -H "Authorization: Bearer ${admin_token}" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"${username}\",
            \"enabled\": true,
            \"emailVerified\": true,
            \"email\": \"${email}\",
            \"credentials\": [{
                \"type\": \"password\",
                \"value\": \"${password}\",
                \"temporary\": false
            }]
        }"
}

# 실행 예제
ADMIN_TOKEN=$(get_admin_token "admin" "admin")
echo "Admin Token: ${ADMIN_TOKEN:0:50}..."

echo "Users:"
list_users "${ADMIN_TOKEN}"

create_user "${ADMIN_TOKEN}" "testuser" "test@example.com" "password123"
echo "User created"
```

---

## 관련 문서

- [Keycloak 설치 가이드](../02-setup/INSTALLATION.md)
- [인증/인가 아키텍처](../01-architecture/ARCHITECTURE-OVERVIEW.md)
- [보안 가이드](../01-architecture/SECURITY-DESIGN.md)

## 참고 자료

- [Keycloak Admin REST API Documentation](https://www.keycloak.org/docs-api/latest/rest-api/index.html)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
- [OpenID Connect Endpoints](https://openid.net/specs/openid-connect-core-1_0.html)
