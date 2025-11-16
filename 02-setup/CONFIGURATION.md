# 환경 설정

## 📘 개요

QSIGN 시스템의 각 컴포넌트별 상세 설정 방법을 안내합니다.

## ⚙️ Vault 설정

### Vault 정책 (Policy) 설정

```bash
# Keycloak용 정책 생성
vault policy write keycloak-policy - <<EOF
# Transit Engine - 서명/암호화
path "transit/sign/dilithium3-key" {
  capabilities = ["update"]
}

path "transit/verify/dilithium3-key" {
  capabilities = ["update"]
}

path "transit/encrypt/kyber1024-key" {
  capabilities = ["update"]
}

path "transit/decrypt/kyber1024-key" {
  capabilities = ["update"]
}

# KV Secret Engine - 읽기
path "secret/data/keycloak/*" {
  capabilities = ["read"]
}
EOF

# 애플리케이션용 정책
vault policy write app-policy - <<EOF
path "transit/encrypt/*" {
  capabilities = ["update"]
}

path "transit/decrypt/*" {
  capabilities = ["update"]
}

path "secret/data/app/*" {
  capabilities = ["read"]
}
EOF
```

### Kubernetes Auth 설정

```bash
# Kubernetes Auth 활성화
vault auth enable kubernetes

# Kubernetes Auth 설정
vault write auth/kubernetes/config \
    kubernetes_host="https://kubernetes.default.svc:443"

# Keycloak Role 생성
vault write auth/kubernetes/role/keycloak \
    bound_service_account_names=keycloak \
    bound_service_account_namespaces=q-sign \
    policies=keycloak-policy \
    ttl=24h

# App Role 생성
vault write auth/kubernetes/role/app \
    bound_service_account_names=app-sa \
    bound_service_account_namespaces=q-app \
    policies=app-policy \
    ttl=1h
```

## 🔐 Keycloak 설정

### Realm 설정

```bash
# Keycloak Admin CLI 로그인
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user admin \
  --password admin

# qsign Realm 생성
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create realms \
  -s realm=qsign \
  -s enabled=true \
  -s displayName="Q-Sign Realm" \
  -s accessTokenLifespan=300 \
  -s ssoSessionIdleTimeout=1800 \
  -s ssoSessionMaxLifespan=36000
```

### Client 생성

```bash
# Web 애플리케이션 Client
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create clients -r qsign \
  -s clientId=web-app \
  -s enabled=true \
  -s publicClient=false \
  -s 'redirectUris=["http://192.168.0.11:30200/*"]' \
  -s 'webOrigins=["http://192.168.0.11:30200"]' \
  -s protocol=openid-connect

# API Client
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create clients -r qsign \
  -s clientId=api-client \
  -s enabled=true \
  -s serviceAccountsEnabled=true \
  -s 'redirectUris=["http://192.168.0.11:32602/*"]' \
  -s protocol=openid-connect
```

### 사용자 생성

```bash
# 테스트 사용자 생성
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create users -r qsign \
  -s username=testuser \
  -s enabled=true \
  -s email=testuser@example.com \
  -s firstName=Test \
  -s lastName=User

# 비밀번호 설정
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh set-password -r qsign \
  --username testuser \
  --new-password Test1234!
```

### Role 설정

```bash
# Realm Role 생성
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create roles -r qsign \
  -s name=admin \
  -s 'description=Administrator role'

kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh create roles -r qsign \
  -s name=user \
  -s 'description=Standard user role'

# 사용자에게 Role 할당
kubectl exec -it -n q-sign deployment/keycloak -- /opt/keycloak/bin/kcadm.sh add-roles -r qsign \
  --uusername testuser \
  --rolename user
```

## 🌐 APISIX 설정

### Route 설정

```bash
# Keycloak Route
curl http://192.168.0.11:9180/apisix/admin/routes/1 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "name": "keycloak-route",
  "uri": "/auth/*",
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "keycloak.q-sign.svc.cluster.local:8080": 1
    }
  },
  "plugins": {
    "cors": {
      "allow_origins": "*",
      "allow_methods": "GET,POST,PUT,DELETE,OPTIONS",
      "allow_headers": "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization"
    },
    "limit-req": {
      "rate": 100,
      "burst": 50,
      "key": "remote_addr"
    }
  }
}'

# Vault Route
curl http://192.168.0.11:9180/apisix/admin/routes/2 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "name": "vault-route",
  "uri": "/v1/*",
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "vault.q-kms.svc.cluster.local:8200": 1
    }
  },
  "plugins": {
    "ip-restriction": {
      "whitelist": [
        "192.168.0.0/24",
        "10.244.0.0/16"
      ]
    }
  }
}'

# App Route with JWT Auth
curl http://192.168.0.11:9180/apisix/admin/routes/3 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "name": "app-route",
  "uri": "/api/*",
  "upstream": {
    "type": "roundrobin",
    "nodes": {
      "app1.q-app.svc.cluster.local:8080": 1
    }
  },
  "plugins": {
    "jwt-auth": {
      "key": "keycloak-jwt",
      "secret": "your-jwt-secret"
    },
    "prometheus": {}
  }
}'
```

### Plugin 설정

```bash
# Global Rate Limiting
curl http://192.168.0.11:9180/apisix/admin/global_rules/1 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "plugins": {
    "limit-count": {
      "count": 1000,
      "time_window": 60,
      "key": "remote_addr"
    }
  }
}'

# Prometheus Metrics
curl http://192.168.0.11:9180/apisix/admin/global_rules/2 \
  -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1' \
  -X PUT -d '
{
  "plugins": {
    "prometheus": {
      "prefer_name": true
    }
  }
}'
```

## 📊 Prometheus 설정

### ServiceMonitor 생성

```yaml
# keycloak-servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: keycloak-monitor
  namespace: q-sign
spec:
  selector:
    matchLabels:
      app: keycloak
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

```bash
kubectl apply -f keycloak-servicemonitor.yaml
```

### Alert Rules

```yaml
# prometheus-alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: qsign-alerts
  namespace: qsign-prod
spec:
  groups:
  - name: qsign
    interval: 30s
    rules:
    - alert: VaultSealed
      expr: vault_core_unsealed == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Vault is sealed"
        description: "Vault {{ $labels.instance }} is sealed"

    - alert: HighMemoryUsage
      expr: (container_memory_usage_bytes / container_spec_memory_limit_bytes) > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage"
        description: "Container {{ $labels.pod }} memory usage is above 90%"

    - alert: PodCrashLooping
      expr: rate(kube_pod_container_status_restarts_total[15m]) > 0
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "Pod is crash looping"
        description: "Pod {{ $labels.pod }} is crash looping"
```

## 🔄 ArgoCD 설정

### Git Repository 연동

```bash
# Git Repository 추가
argocd repo add http://192.168.0.11:7780/root/gitops-repo.git \
  --username root \
  --password <gitlab-password> \
  --insecure-skip-server-verification

# Repository 목록 확인
argocd repo list
```

### Application 생성

```yaml
# argocd-app-qsign.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: qsign
  namespace: argocd
spec:
  project: default
  source:
    repoURL: http://192.168.0.11:7780/root/gitops-repo.git
    targetRevision: HEAD
    path: apps/q-sign
  destination:
    server: https://kubernetes.default.svc
    namespace: q-sign
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
```

```bash
kubectl apply -f argocd-app-qsign.yaml
```

## 🔧 ConfigMap 및 Secret

### Vault ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-config
  namespace: q-kms
data:
  vault.hcl: |
    ui = true
    listener "tcp" {
      address = "0.0.0.0:8200"
      tls_disable = 1
    }
    storage "file" {
      path = "/vault/data"
    }
    seal "pkcs11" {
      lib = "/usr/lib/libCryptoki2_64.so"
      slot = "0"
      pin = "vault-hsm-pin"
      key_label = "vault-hsm-key"
      hmac_key_label = "vault-hsm-hmac"
    }
```

### Keycloak Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-db-secret
  namespace: q-sign
type: Opaque
stringData:
  POSTGRES_USER: keycloak
  POSTGRES_PASSWORD: keycloak_password
  POSTGRES_DB: keycloak
```

### APISIX Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: apisix-admin-key
  namespace: qsign-prod
type: Opaque
stringData:
  admin-key: edd1c9f034335f136f87ad84b625c8f1
```

## 📝 환경 변수 설정

### Vault 환경 변수

```bash
# ~/.bashrc 또는 ~/.zshrc
export VAULT_ADDR=http://192.168.0.11:30820
export VAULT_TOKEN=<root-token>
export VAULT_SKIP_VERIFY=true
```

### Keycloak 환경 변수

```yaml
env:
- name: KEYCLOAK_ADMIN
  value: admin
- name: KEYCLOAK_ADMIN_PASSWORD
  valueFrom:
    secretKeyRef:
      name: keycloak-admin-secret
      key: password
- name: KC_DB
  value: postgres
- name: KC_DB_URL
  value: jdbc:postgresql://postgresql:5432/keycloak
- name: KC_HOSTNAME_STRICT
  value: "false"
- name: KC_HTTP_ENABLED
  value: "true"
- name: KC_PROXY
  value: edge
```

## 🔗 다음 단계

- [HSM-SETUP.md](./HSM-SETUP.md) - Luna HSM 상세 설정
- [../03-deployment/](../03-deployment/) - 배포 가이드

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
