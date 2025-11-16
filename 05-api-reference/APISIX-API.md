# Apache APISIX API Reference

Apache APISIX의 Admin API 및 주요 리소스 관리 방법을 설명합니다.

## Base URL

```
http://localhost:9180
```

## Admin API Key

기본 설정:
- API Key: `edd1c9f034335f136f87ad84b625c8f1`

**헤더 설정:**
```
X-API-KEY: edd1c9f034335f136f87ad84b625c8f1
```

## 목차

- [Admin API 기본](#admin-api-기본)
- [Route 관리](#route-관리)
- [Plugin 관리](#plugin-관리)
- [Upstream 관리](#upstream-관리)
- [Service 관리](#service-관리)
- [Consumer 관리](#consumer-관리)
- [SSL 인증서 관리](#ssl-인증서-관리)
- [예제 코드](#예제-코드)

---

## Admin API 기본

### 1. APISIX 상태 확인

**Endpoint:** `GET /apisix/admin/schema`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/schema \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

### 2. 버전 정보 조회

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/routes \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -I
```

---

## Route 관리

Route는 클라이언트 요청을 Upstream으로 라우팅하는 규칙을 정의합니다.

### 1. Route 목록 조회

**Endpoint:** `GET /apisix/admin/routes`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/routes \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

**Response:**

```json
{
  "total": 2,
  "list": [
    {
      "key": "/apisix/routes/1",
      "value": {
        "id": "1",
        "uri": "/api/*",
        "name": "api-route",
        "methods": ["GET", "POST"],
        "upstream": {
          "type": "roundrobin",
          "nodes": {
            "backend1.example.com:8080": 1
          }
        },
        "create_time": 1699999700,
        "update_time": 1699999700
      }
    }
  ]
}
```

### 2. Route 생성

**Endpoint:** `PUT /apisix/admin/routes/{id}`

**Example Request (기본 라우팅):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api-route",
    "uri": "/api/*",
    "methods": ["GET", "POST"],
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend1.example.com:8080": 1,
        "backend2.example.com:8080": 1
      }
    }
  }'
```

**Example Request (플러그인 포함):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/routes/2 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "authenticated-route",
    "uri": "/secure/*",
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "plugins": {
      "openid-connect": {
        "client_id": "qsign-client",
        "client_secret": "your-client-secret",
        "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
        "scope": "openid profile email",
        "bearer_only": true,
        "realm": "qsign"
      },
      "limit-req": {
        "rate": 100,
        "burst": 50,
        "key": "remote_addr",
        "rejected_code": 429
      }
    },
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend.example.com:8080": 1
      }
    }
  }'
```

**Example Request (서비스 참조):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/routes/3 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/users/*",
    "service_id": "1"
  }'
```

### 3. Route 조회

**Endpoint:** `GET /apisix/admin/routes/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

### 4. Route 업데이트

**Endpoint:** `PATCH /apisix/admin/routes/{id}`

**Example Request:**

```bash
curl -X PATCH http://localhost:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "methods": ["GET", "POST", "PUT"]
  }'
```

### 5. Route 삭제

**Endpoint:** `DELETE /apisix/admin/routes/{id}`

**Example Request:**

```bash
curl -X DELETE http://localhost:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## Plugin 관리

### 1. 사용 가능한 플러그인 목록

**Endpoint:** `GET /apisix/admin/plugins/list`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/plugins/list \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

**Response:**

```json
[
  "limit-req",
  "limit-count",
  "openid-connect",
  "jwt-auth",
  "prometheus",
  "cors",
  "ip-restriction",
  "request-validation",
  "response-rewrite",
  "proxy-rewrite"
]
```

### 2. 주요 플러그인 설정 예제

#### OpenID Connect (Keycloak 인증)

```json
{
  "openid-connect": {
    "client_id": "qsign-client",
    "client_secret": "your-client-secret",
    "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
    "scope": "openid profile email",
    "bearer_only": true,
    "realm": "qsign",
    "introspection_endpoint_auth_method": "client_secret_post"
  }
}
```

#### JWT Authentication

```json
{
  "jwt-auth": {
    "key": "user-key",
    "secret": "my-secret-key",
    "algorithm": "HS256"
  }
}
```

#### Rate Limiting

```json
{
  "limit-req": {
    "rate": 100,
    "burst": 50,
    "key": "remote_addr",
    "key_type": "var",
    "rejected_code": 429,
    "rejected_msg": "Too many requests"
  }
}
```

#### CORS

```json
{
  "cors": {
    "allow_origins": "http://localhost:3000,http://example.com",
    "allow_methods": "GET,POST,PUT,DELETE,OPTIONS",
    "allow_headers": "Authorization,Content-Type",
    "expose_headers": "X-Custom-Header",
    "max_age": 3600,
    "allow_credential": true
  }
}
```

#### IP Restriction

```json
{
  "ip-restriction": {
    "whitelist": [
      "10.0.0.0/8",
      "192.168.1.0/24"
    ]
  }
}
```

#### Prometheus Metrics

```json
{
  "prometheus": {
    "prefer_name": true
  }
}
```

#### Request Validation

```json
{
  "request-validation": {
    "header_schema": {
      "type": "object",
      "required": ["Authorization"],
      "properties": {
        "Authorization": {
          "type": "string",
          "pattern": "^Bearer .+"
        }
      }
    },
    "body_schema": {
      "type": "object",
      "required": ["name", "email"],
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1
        },
        "email": {
          "type": "string",
          "format": "email"
        }
      }
    }
  }
}
```

#### Proxy Rewrite

```json
{
  "proxy-rewrite": {
    "uri": "/new/path",
    "scheme": "https",
    "host": "new-host.example.com",
    "headers": {
      "X-Forwarded-For": "$remote_addr",
      "X-Custom-Header": "custom-value"
    }
  }
}
```

### 3. Global Plugin 설정

**Endpoint:** `PUT /apisix/admin/global_rules/{id}`

**Example Request (전역 Prometheus):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/global_rules/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "plugins": {
      "prometheus": {
        "prefer_name": true
      }
    }
  }'
```

---

## Upstream 관리

Upstream은 백엔드 서버 그룹을 정의합니다.

### 1. Upstream 목록 조회

**Endpoint:** `GET /apisix/admin/upstreams`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/upstreams \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

### 2. Upstream 생성

**Endpoint:** `PUT /apisix/admin/upstreams/{id}`

**Example Request (Round Robin):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/upstreams/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backend-cluster",
    "type": "roundrobin",
    "nodes": {
      "backend1.example.com:8080": 1,
      "backend2.example.com:8080": 1,
      "backend3.example.com:8080": 1
    },
    "timeout": {
      "connect": 6,
      "send": 6,
      "read": 6
    }
  }'
```

**Example Request (Health Check):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/upstreams/2 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backend-with-healthcheck",
    "type": "roundrobin",
    "nodes": {
      "backend1.example.com:8080": 1,
      "backend2.example.com:8080": 1
    },
    "checks": {
      "active": {
        "type": "http",
        "http_path": "/health",
        "healthy": {
          "interval": 2,
          "successes": 2
        },
        "unhealthy": {
          "interval": 1,
          "http_failures": 2
        }
      },
      "passive": {
        "healthy": {
          "http_statuses": [200, 201],
          "successes": 3
        },
        "unhealthy": {
          "http_statuses": [500, 502, 503],
          "http_failures": 3
        }
      }
    }
  }'
```

**Example Request (서비스 디스커버리 - Consul):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/upstreams/3 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "consul-discovery",
    "type": "roundrobin",
    "discovery_type": "consul",
    "service_name": "backend-service",
    "discovery_args": {
      "host": "http://consul:8500",
      "token": "consul-token"
    }
  }'
```

### 3. Upstream 조회

**Endpoint:** `GET /apisix/admin/upstreams/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/upstreams/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

### 4. Upstream 업데이트

**Endpoint:** `PATCH /apisix/admin/upstreams/{id}`

**Example Request:**

```bash
curl -X PATCH http://localhost:9180/apisix/admin/upstreams/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "nodes": {
      "backend1.example.com:8080": 2,
      "backend2.example.com:8080": 1,
      "backend4.example.com:8080": 1
    }
  }'
```

### 5. Upstream 삭제

**Endpoint:** `DELETE /apisix/admin/upstreams/{id}`

**Example Request:**

```bash
curl -X DELETE http://localhost:9180/apisix/admin/upstreams/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## Service 관리

Service는 Route 간 공유할 수 있는 설정을 정의합니다.

### 1. Service 생성

**Endpoint:** `PUT /apisix/admin/services/{id}`

**Example Request:**

```bash
curl -X PUT http://localhost:9180/apisix/admin/services/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "user-service",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "user-service:8080": 1
      }
    },
    "plugins": {
      "openid-connect": {
        "client_id": "qsign-client",
        "client_secret": "your-client-secret",
        "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
        "bearer_only": true
      }
    }
  }'
```

### 2. Service 조회

**Endpoint:** `GET /apisix/admin/services/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/services/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## Consumer 관리

Consumer는 API 사용자를 정의합니다.

### 1. Consumer 생성

**Endpoint:** `PUT /apisix/admin/consumers/{username}`

**Example Request (JWT):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/consumers/user1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "plugins": {
      "jwt-auth": {
        "key": "user1-key",
        "secret": "user1-secret",
        "algorithm": "HS256"
      }
    }
  }'
```

**Example Request (Key Auth):**

```bash
curl -X PUT http://localhost:9180/apisix/admin/consumers/user2 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user2",
    "plugins": {
      "key-auth": {
        "key": "api-key-123456"
      }
    }
  }'
```

### 2. Consumer 조회

**Endpoint:** `GET /apisix/admin/consumers/{username}`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/consumers/user1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## SSL 인증서 관리

### 1. SSL 인증서 생성

**Endpoint:** `PUT /apisix/admin/ssls/{id}`

**Example Request:**

```bash
curl -X PUT http://localhost:9180/apisix/admin/ssls/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1" \
  -H "Content-Type: application/json" \
  -d '{
    "sni": "example.com",
    "cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

### 2. SSL 인증서 조회

**Endpoint:** `GET /apisix/admin/ssls/{id}`

**Example Request:**

```bash
curl -X GET http://localhost:9180/apisix/admin/ssls/1 \
  -H "X-API-KEY: edd1c9f034335f136f87ad84b625c8f1"
```

---

## 예제 코드

### Python 예제

#### 1. APISIX Admin 클라이언트

```python
import requests
import json

class APISIXAdmin:
    def __init__(self, admin_url, api_key):
        self.admin_url = admin_url
        self.headers = {
            'X-API-KEY': api_key,
            'Content-Type': 'application/json'
        }

    # Route 관리
    def list_routes(self):
        """Route 목록 조회"""
        url = f"{self.admin_url}/apisix/admin/routes"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def create_route(self, route_id, route_config):
        """Route 생성"""
        url = f"{self.admin_url}/apisix/admin/routes/{route_id}"
        response = requests.put(url, headers=self.headers, json=route_config)
        response.raise_for_status()
        return response.json()

    def get_route(self, route_id):
        """Route 조회"""
        url = f"{self.admin_url}/apisix/admin/routes/{route_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    def update_route(self, route_id, updates):
        """Route 업데이트"""
        url = f"{self.admin_url}/apisix/admin/routes/{route_id}"
        response = requests.patch(url, headers=self.headers, json=updates)
        response.raise_for_status()
        return response.json()

    def delete_route(self, route_id):
        """Route 삭제"""
        url = f"{self.admin_url}/apisix/admin/routes/{route_id}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()
        return response.status_code == 200

    # Upstream 관리
    def create_upstream(self, upstream_id, upstream_config):
        """Upstream 생성"""
        url = f"{self.admin_url}/apisix/admin/upstreams/{upstream_id}"
        response = requests.put(url, headers=self.headers, json=upstream_config)
        response.raise_for_status()
        return response.json()

    def get_upstream(self, upstream_id):
        """Upstream 조회"""
        url = f"{self.admin_url}/apisix/admin/upstreams/{upstream_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Service 관리
    def create_service(self, service_id, service_config):
        """Service 생성"""
        url = f"{self.admin_url}/apisix/admin/services/{service_id}"
        response = requests.put(url, headers=self.headers, json=service_config)
        response.raise_for_status()
        return response.json()

    # Plugin 관리
    def list_plugins(self):
        """사용 가능한 플러그인 목록"""
        url = f"{self.admin_url}/apisix/admin/plugins/list"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Consumer 관리
    def create_consumer(self, username, consumer_config):
        """Consumer 생성"""
        url = f"{self.admin_url}/apisix/admin/consumers/{username}"
        response = requests.put(url, headers=self.headers, json=consumer_config)
        response.raise_for_status()
        return response.json()

# 사용 예제
if __name__ == "__main__":
    # APISIX Admin 클라이언트 초기화
    apisix = APISIXAdmin(
        admin_url="http://localhost:9180",
        api_key="edd1c9f034335f136f87ad84b625c8f1"
    )

    # Upstream 생성
    upstream_config = {
        "name": "backend-cluster",
        "type": "roundrobin",
        "nodes": {
            "backend1.example.com:8080": 1,
            "backend2.example.com:8080": 1
        },
        "timeout": {
            "connect": 6,
            "send": 6,
            "read": 6
        }
    }
    upstream = apisix.create_upstream("1", upstream_config)
    print("Upstream created")

    # Route 생성 (Keycloak 인증 포함)
    route_config = {
        "name": "secure-api",
        "uri": "/api/*",
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "plugins": {
            "openid-connect": {
                "client_id": "qsign-client",
                "client_secret": "your-client-secret",
                "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
                "bearer_only": True,
                "realm": "qsign"
            },
            "limit-req": {
                "rate": 100,
                "burst": 50,
                "key": "remote_addr",
                "rejected_code": 429
            }
        },
        "upstream_id": "1"
    }
    route = apisix.create_route("1", route_config)
    print("Route created with ID: 1")

    # Route 목록 조회
    routes = apisix.list_routes()
    print(f"Total routes: {routes['total']}")

    # 플러그인 목록 조회
    plugins = apisix.list_plugins()
    print(f"Available plugins: {len(plugins)}")
    for plugin in plugins[:5]:
        print(f"  - {plugin}")
```

#### 2. QSIGN 통합 예제

```python
class QSIGNGateway:
    def __init__(self, apisix_admin):
        self.apisix = apisix_admin

    def setup_document_api(self):
        """문서 API 라우팅 설정"""
        # Document Service Upstream
        upstream_config = {
            "name": "document-service",
            "type": "roundrobin",
            "nodes": {
                "document-service:8080": 1
            },
            "checks": {
                "active": {
                    "type": "http",
                    "http_path": "/health",
                    "healthy": {
                        "interval": 10,
                        "successes": 2
                    },
                    "unhealthy": {
                        "interval": 5,
                        "http_failures": 2
                    }
                }
            }
        }
        self.apisix.create_upstream("document-service", upstream_config)

        # Document API Route
        route_config = {
            "name": "document-api",
            "uri": "/api/documents/*",
            "methods": ["GET", "POST", "PUT", "DELETE"],
            "plugins": {
                "openid-connect": {
                    "client_id": "qsign-client",
                    "client_secret": "your-client-secret",
                    "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
                    "bearer_only": True
                },
                "limit-req": {
                    "rate": 200,
                    "burst": 100,
                    "key": "remote_addr"
                },
                "cors": {
                    "allow_origins": "http://localhost:3000",
                    "allow_methods": "GET,POST,PUT,DELETE,OPTIONS",
                    "allow_headers": "Authorization,Content-Type",
                    "allow_credential": True
                }
            },
            "upstream_id": "document-service"
        }
        self.apisix.create_route("document-api", route_config)
        print("Document API configured")

    def setup_signature_api(self):
        """서명 API 라우팅 설정"""
        # Signature Service Upstream
        upstream_config = {
            "name": "signature-service",
            "type": "roundrobin",
            "nodes": {
                "signature-service:8080": 1
            }
        }
        self.apisix.create_upstream("signature-service", upstream_config)

        # Signature API Route
        route_config = {
            "name": "signature-api",
            "uri": "/api/signatures/*",
            "methods": ["POST"],
            "plugins": {
                "openid-connect": {
                    "client_id": "qsign-client",
                    "client_secret": "your-client-secret",
                    "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
                    "bearer_only": True
                },
                "limit-req": {
                    "rate": 50,
                    "burst": 25,
                    "key": "consumer_name"
                },
                "request-validation": {
                    "header_schema": {
                        "type": "object",
                        "required": ["Authorization", "Content-Type"],
                        "properties": {
                            "Authorization": {
                                "type": "string",
                                "pattern": "^Bearer .+"
                            }
                        }
                    }
                }
            },
            "upstream_id": "signature-service"
        }
        self.apisix.create_route("signature-api", route_config)
        print("Signature API configured")

# 사용 예제
if __name__ == "__main__":
    apisix = APISIXAdmin(
        admin_url="http://localhost:9180",
        api_key="edd1c9f034335f136f87ad84b625c8f1"
    )

    gateway = QSIGNGateway(apisix)
    gateway.setup_document_api()
    gateway.setup_signature_api()

    print("QSIGN Gateway configured successfully")
```

### Bash Script 예제

```bash
#!/bin/bash

# APISIX 설정
APISIX_ADMIN_URL="http://localhost:9180"
API_KEY="edd1c9f034335f136f87ad84b625c8f1"

# Route 생성
create_route() {
    local route_id=$1
    local uri=$2
    local upstream_nodes=$3

    curl -X PUT "${APISIX_ADMIN_URL}/apisix/admin/routes/${route_id}" \
        -H "X-API-KEY: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"uri\": \"${uri}\",
            \"upstream\": {
                \"type\": \"roundrobin\",
                \"nodes\": ${upstream_nodes}
            }
        }"
}

# Route 목록 조회
list_routes() {
    curl -s -X GET "${APISIX_ADMIN_URL}/apisix/admin/routes" \
        -H "X-API-KEY: ${API_KEY}" | jq '.'
}

# Upstream 생성
create_upstream() {
    local upstream_id=$1
    local nodes=$2

    curl -X PUT "${APISIX_ADMIN_URL}/apisix/admin/upstreams/${upstream_id}" \
        -H "X-API-KEY: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "{
            \"type\": \"roundrobin\",
            \"nodes\": ${nodes}
        }"
}

# Keycloak 인증이 포함된 Route 생성
create_secure_route() {
    local route_id=$1

    curl -X PUT "${APISIX_ADMIN_URL}/apisix/admin/routes/${route_id}" \
        -H "X-API-KEY: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d '{
            "uri": "/api/secure/*",
            "plugins": {
                "openid-connect": {
                    "client_id": "qsign-client",
                    "client_secret": "your-client-secret",
                    "discovery": "http://keycloak:8080/auth/realms/qsign/.well-known/openid-configuration",
                    "bearer_only": true
                }
            },
            "upstream": {
                "type": "roundrobin",
                "nodes": {
                    "backend:8080": 1
                }
            }
        }'
}

# 실행 예제
echo "Creating upstream..."
create_upstream "1" '{"backend1.example.com:8080": 1, "backend2.example.com:8080": 1}'

echo "Creating route..."
create_route "1" "/api/*" '{"backend1.example.com:8080": 1}'

echo "Creating secure route with Keycloak auth..."
create_secure_route "2"

echo "Listing routes..."
list_routes
```

---

## 관련 문서

- [APISIX 설치 가이드](../02-installation-guides/APISIX.md)
- [API Gateway 아키텍처](../03-architecture/API-GATEWAY.md)
- [인증/인가 설정](../04-user-guides/AUTHENTICATION.md)

## 참고 자료

- [Apache APISIX Admin API Documentation](https://apisix.apache.org/docs/apisix/admin-api/)
- [APISIX Plugin Hub](https://apisix.apache.org/plugins/)
- [OpenID Connect Plugin](https://apisix.apache.org/docs/apisix/plugins/openid-connect/)
