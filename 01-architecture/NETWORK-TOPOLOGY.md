# 네트워크 토폴로지

## 📘 개요

QSIGN 시스템의 네트워크 구성은 Kubernetes 기반의 마이크로서비스 아키텍처로 설계되어 있으며, 보안, 확장성, 고가용성을 고려한 네트워크 토폴로지를 구축합니다.

## 🌐 전체 네트워크 구조

### 물리적 네트워크 토폴로지

```mermaid
graph TB
    subgraph EXTERNAL["외부 네트워크 - 192.168.0.0/24"]
        CLIENT1[클라이언트<br/>브라우저/모바일]
        DEV[개발자<br/>워크스테이션]
    end

    subgraph DMZ["DMZ 영역"]
        GW_LB[Load Balancer<br/>NodePort 서비스]
    end

    subgraph K8S["Kubernetes Cluster - 192.168.0.11"]
        subgraph INGRESS["Ingress Layer"]
            APISIX[APISIX Gateway<br/>:32602/:32294]
            APISIX_DASH[APISIX Dashboard<br/>:31281]
        end

        subgraph AUTH["Authentication Layer"]
            KC_PQC[Keycloak PQC<br/>q-sign:30181]
            KC_HSM[Keycloak HSM<br/>pqc-sso:30699]
        end

        subgraph KMS["Key Management Layer"]
            VAULT[Q-KMS Vault<br/>q-kms:30820]
            HSM[Luna HSM<br/>/dev/k7pf0]
        end

        subgraph APP["Application Layer"]
            APP1[App1-7<br/>q-app:30200-30206]
            SSO_TEST[SSO Test App<br/>pqc-sso:32127]
        end

        subgraph MONITOR["Monitoring Layer"]
            PROM[Prometheus<br/>:30092]
            GRAF[Grafana<br/>:30030]
            SKY[SkyWalking<br/>:30094]
        end

        subgraph STORAGE["Storage Layer"]
            PG1["PostgreSQL<br/>q-sign"]
            PG2["PostgreSQL<br/>pqc-sso"]
            PV[Persistent Volumes]
        end
    end

    subgraph DEVOPS["DevOps 인프라"]
        GL[GitLab<br/>:7743]
        HB[Harbor<br/>:31800]
        JK[Jenkins<br/>:7643]
        AR[ArgoCD<br/>:30080]
    end

    CLIENT1 --> GW_LB
    DEV --> GL
    DEV --> HB

    GW_LB --> APISIX
    APISIX --> KC_PQC
    APISIX --> KC_HSM
    APISIX --> APP1

    KC_PQC --> VAULT
    KC_HSM --> VAULT
    VAULT --> HSM

    KC_PQC --> PG1
    KC_HSM --> PG2

    APP1 --> KC_PQC
    SSO_TEST --> KC_HSM

    APISIX --> PROM
    KC_PQC --> PROM
    VAULT --> PROM
    PROM --> GRAF

    GL --> AR
    HB --> AR
    AR -.->|Deploy| K8S

    style EXTERNAL fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style K8S fill:#f1f8e9,stroke:#558b2f,stroke-width:3px
    style HSM fill:#fff9c4,stroke:#f57f17,stroke-width:4px
    style DEVOPS fill:#fce4ec,stroke:#c2185b,stroke-width:2px
```

## 🏗️ Kubernetes 네트워크 구조

### 네임스페이스 구성

```mermaid
graph TB
    subgraph K8S["Kubernetes Cluster"]
        subgraph NS1["Namespace: argocd"]
            AR_SVC[argocd-server<br/>ClusterIP + NodePort:30080]
            AR_REPO[argocd-repo-server<br/>ClusterIP]
            AR_CTRL[argocd-application-controller<br/>ClusterIP]
        end

        subgraph NS2["Namespace: q-sign"]
            KC_SVC[keycloak<br/>ClusterIP + NodePort:30181]
            PG_SVC[postgresql<br/>ClusterIP:5432]
        end

        subgraph NS3["Namespace: pqc-sso"]
            KC_HSM_SVC[keycloak-hsm<br/>ClusterIP + NodePort:30699]
            PG_HSM_SVC[postgresql-hsm<br/>ClusterIP:5432]
            SSO_SVC[sso-test-app<br/>ClusterIP + NodePort:32127]
        end

        subgraph NS4["Namespace: q-kms"]
            V_SVC[vault<br/>ClusterIP + NodePort:30820]
            V_AGENT[vault-agent<br/>DaemonSet]
        end

        subgraph NS5["Namespace: q-app"]
            APP_SVCS[app1-app7<br/>ClusterIP + NodePort:30200-30206]
        end

        subgraph NS6["Namespace: qsign-prod"]
            APISIX_SVC[apisix-gateway<br/>ClusterIP + NodePort:32602/32294]
            APISIX_ADMIN[apisix-admin<br/>ClusterIP:9180]
            APISIX_DASH_SVC[apisix-dashboard<br/>ClusterIP + NodePort:31281]
            PROM_SVC[prometheus<br/>ClusterIP + NodePort:30092]
            GRAF_SVC[grafana<br/>ClusterIP + NodePort:30030]
            SKY_SVC[skywalking-ui<br/>ClusterIP + NodePort:30094]
            ADMIN_SVC[admin-dashboard<br/>ClusterIP + NodePort:30093]
        end

        subgraph NS7["Namespace: harbor"]
            HB_CORE[harbor-core<br/>ClusterIP]
            HB_PORTAL[harbor-portal<br/>ClusterIP + NodePort:31800]
            HB_REG[harbor-registry<br/>ClusterIP]
        end
    end

    KC_SVC --> V_SVC
    KC_HSM_SVC --> V_SVC
    V_SVC -.->|HSM| HSM_DEV[/dev/k7pf0]

    APISIX_SVC --> KC_SVC
    APISIX_SVC --> KC_HSM_SVC
    APISIX_SVC --> APP_SVCS

    APP_SVCS --> KC_SVC
    SSO_SVC --> KC_HSM_SVC

    PROM_SVC --> KC_SVC
    PROM_SVC --> V_SVC
    PROM_SVC --> APISIX_SVC

    AR_SVC --> K8S

    style NS2 fill:#bbdefb,stroke:#1976d2,stroke-width:2px
    style NS3 fill:#b2dfdb,stroke:#00796b,stroke-width:2px
    style NS4 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
    style NS6 fill:#ffe0b2,stroke:#e64a19,stroke-width:2px
```

### Service 유형별 구성

```yaml
Service Types:

  ClusterIP (내부 통신):
    - PostgreSQL (q-sign, pqc-sso)
    - Vault (내부 API)
    - APISIX Admin API
    - ArgoCD Repo Server
    - Harbor Registry
    - Elasticsearch

  NodePort (외부 접근):
    - Keycloak PQC: 30181
    - Keycloak HSM: 30699
    - Q-KMS Vault: 30820
    - APISIX Gateway HTTP: 32602
    - APISIX Gateway HTTPS: 32294
    - APISIX Dashboard: 31281
    - Grafana: 30030
    - Prometheus: 30092
    - SkyWalking: 30094
    - ArgoCD: 30080
    - Admin Dashboard: 30093
    - App1-7: 30200-30206
    - SSO Test App: 32127
    - Harbor Portal: 31800

  LoadBalancer:
    - Not used (NodePort로 대체)

  ExternalName:
    - GitLab: gitlab.external
    - Jenkins: jenkins.external
```

## 🔒 네트워크 보안 정책

### NetworkPolicy 구성

```yaml
# q-sign 네임스페이스 NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: q-sign-network-policy
  namespace: q-sign
spec:
  podSelector:
    matchLabels:
      app: keycloak
  policyTypes:
    - Ingress
    - Egress

  ingress:
    # APISIX에서의 트래픽 허용
    - from:
      - namespaceSelector:
          matchLabels:
            name: qsign-prod
        podSelector:
          matchLabels:
            app: apisix
      ports:
      - protocol: TCP
        port: 8080

    # Prometheus 메트릭 수집 허용
    - from:
      - namespaceSelector:
          matchLabels:
            name: qsign-prod
        podSelector:
          matchLabels:
            app: prometheus
      ports:
      - protocol: TCP
        port: 9000

  egress:
    # PostgreSQL 접근 허용
    - to:
      - podSelector:
          matchLabels:
            app: postgresql
      ports:
      - protocol: TCP
        port: 5432

    # Vault 접근 허용
    - to:
      - namespaceSelector:
          matchLabels:
            name: q-kms
        podSelector:
          matchLabels:
            app: vault
      ports:
      - protocol: TCP
        port: 8200

    # DNS 쿼리 허용
    - to:
      - namespaceSelector:
          matchLabels:
            name: kube-system
        podSelector:
          matchLabels:
            k8s-app: kube-dns
      ports:
      - protocol: UDP
        port: 53
```

### 네트워크 보안 계층

```mermaid
graph TB
    subgraph L1["Layer 1: 외부 방화벽"]
        FW1[Host Firewall<br/>iptables/firewalld]
        FW2[Rate Limiting<br/>Connection Limits]
    end

    subgraph L2["Layer 2: Kubernetes NetworkPolicy"]
        NP1[Namespace Isolation]
        NP2[Pod-to-Pod Rules]
        NP3[Egress Control]
    end

    subgraph L3["Layer 3: Service Mesh (Optional)"]
        SM1[mTLS Encryption]
        SM2[Traffic Policy]
        SM3[Circuit Breaking]
    end

    subgraph L4["Layer 4: Application Security"]
        AS1[APISIX Security]
        AS2[Keycloak Auth]
        AS3[Vault Access Control]
    end

    FW1 --> NP1
    FW2 --> NP2
    NP1 --> SM1
    NP2 --> SM2
    NP3 --> SM3
    SM1 --> AS1
    SM2 --> AS2
    SM3 --> AS3

    style L1 fill:#ffebee,stroke:#c62828,stroke-width:3px
    style L2 fill:#fff3e0,stroke:#e65100,stroke-width:3px
    style L3 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
    style L4 fill:#e3f2fd,stroke:#1565c0,stroke-width:3px
```

## 📡 서비스 메시 및 DNS

### Kubernetes DNS 구조

```yaml
DNS 네이밍 컨벤션:

  서비스 FQDN:
    형식: <service>.<namespace>.svc.cluster.local
    예시:
      - keycloak.q-sign.svc.cluster.local
      - vault.q-kms.svc.cluster.local
      - apisix-gateway.qsign-prod.svc.cluster.local
      - postgresql.q-sign.svc.cluster.local

  Pod FQDN:
    형식: <pod-ip>.<namespace>.pod.cluster.local
    예시:
      - 10-244-0-10.q-sign.pod.cluster.local

  Headless Service:
    형식: <pod-name>.<service>.<namespace>.svc.cluster.local
    예시:
      - vault-0.vault.q-kms.svc.cluster.local
```

### Service Discovery

```mermaid
sequenceDiagram
    participant App as Application Pod
    participant DNS as CoreDNS
    participant SVC as Kubernetes Service
    participant EP as Endpoints
    participant POD as Backend Pods

    App->>DNS: 1. Resolve keycloak.q-sign.svc.cluster.local
    DNS->>SVC: 2. Lookup Service
    SVC->>EP: 3. Get Endpoints
    EP-->>DNS: 4. Pod IPs (10.244.1.5, 10.244.2.8)
    DNS-->>App: 5. Return IP (Load Balanced)

    App->>POD: 6. Connect to Pod IP
    POD-->>App: 7. Response

    Note over App,POD: Kubernetes handles<br/>load balancing via iptables/IPVS
```

## 🌍 IP 주소 할당

### 네트워크 범위

```yaml
IP Address Allocation:

  호스트 네트워크:
    범위: 192.168.0.0/24
    게이트웨이: 192.168.0.1
    Kubernetes Node: 192.168.0.11
    GitLab: 192.168.0.11 (NodePort)
    Harbor: 192.168.0.11 (NodePort)
    Jenkins: 192.168.0.11 (NodePort)

  Kubernetes Pod Network:
    범위: 10.244.0.0/16
    서브넷 크기: /24 per node
    예시:
      - Node 1: 10.244.0.0/24
      - Node 2: 10.244.1.0/24
      - Node 3: 10.244.2.0/24

  Kubernetes Service Network:
    범위: 10.96.0.0/12
    ClusterIP 범위: 10.96.0.1 - 10.111.255.254
    예시:
      - kube-dns: 10.96.0.10
      - keycloak: 10.96.12.45
      - vault: 10.96.34.78

  NodePort Range:
    범위: 30000-32767
    사용 중:
      - 30080 (ArgoCD)
      - 30181 (Keycloak PQC)
      - 30699 (Keycloak HSM)
      - 30820 (Vault)
      - 32602/32294 (APISIX)
      - 30030 (Grafana)
      - 30092 (Prometheus)
      - 등등...
```

### Pod IP 할당 예시

| Namespace | Pod | IP Address | Node |
|-----------|-----|------------|------|
| q-sign | keycloak-0 | 10.244.0.15 | node-1 |
| q-sign | postgresql-0 | 10.244.0.16 | node-1 |
| q-kms | vault-0 | 10.244.1.20 | node-2 |
| qsign-prod | apisix-gateway-xxx | 10.244.2.30 | node-3 |
| qsign-prod | prometheus-xxx | 10.244.0.45 | node-1 |

## 🔀 트래픽 라우팅

### APISIX Gateway 라우팅

```yaml
APISIX Routes:

  # Keycloak PQC 라우팅
  - uri: /auth/*
    upstream: keycloak.q-sign.svc.cluster.local:8080
    plugins:
      - rate-limit
      - cors
      - jwt-auth

  # Vault API 라우팅
  - uri: /v1/*
    upstream: vault.q-kms.svc.cluster.local:8200
    plugins:
      - key-auth
      - ip-restriction

  # Application 라우팅
  - uri: /app1/*
    upstream: app1.q-app.svc.cluster.local:8080
    plugins:
      - jwt-auth
      - prometheus

  # Admin Dashboard
  - uri: /admin/*
    upstream: admin-dashboard.qsign-prod.svc.cluster.local:80
    plugins:
      - jwt-auth
      - rbac
```

### 로드 밸런싱

```mermaid
graph LR
    subgraph "클라이언트"
        C1[Browser 1]
        C2[Browser 2]
        C3[API Client]
    end

    subgraph "APISIX Gateway Pods"
        GW1[apisix-gateway-1]
        GW2[apisix-gateway-2]
    end

    subgraph "Keycloak Pods"
        KC1[keycloak-1]
        KC2[keycloak-2]
        KC3[keycloak-3]
    end

    subgraph "App Pods"
        APP1[app1-pod-1]
        APP2[app1-pod-2]
    end

    C1 & C2 & C3 -->|Round Robin| GW1
    C1 & C2 & C3 -->|Round Robin| GW2

    GW1 & GW2 -->|Weighted| KC1
    GW1 & GW2 -->|Weighted| KC2
    GW1 & GW2 -->|Weighted| KC3

    KC1 & KC2 & KC3 -->|Least Conn| APP1
    KC1 & KC2 & KC3 -->|Least Conn| APP2

    style GW1 fill:#ffe0b2,stroke:#e64a19,stroke-width:2px
    style GW2 fill:#ffe0b2,stroke:#e64a19,stroke-width:2px
    style KC1 fill:#bbdefb,stroke:#1976d2,stroke-width:2px
    style KC2 fill:#bbdefb,stroke:#1976d2,stroke-width:2px
    style KC3 fill:#bbdefb,stroke:#1976d2,stroke-width:2px
```

### 로드 밸런싱 알고리즘

```yaml
Load Balancing Strategies:

  APISIX Gateway:
    알고리즘: Round Robin
    헬스 체크: Passive + Active
    장애 조치: Automatic
    세션 고정: Cookie-based (선택적)

  Keycloak:
    알고리즘: Weighted Round Robin
    가중치: Based on Pod CPU/Memory
    헬스 체크: /health endpoint
    Retry: 3 attempts

  Vault:
    알고리즘: Consistent Hashing (단일 인스턴스)
    헬스 체크: /v1/sys/health
    Standby 모드: HA 지원 시

  Applications:
    알고리즘: Least Connection
    헬스 체크: Custom endpoint
    Circuit Breaker: Enabled
```

## 🔍 네트워크 모니터링

### 메트릭 수집

```mermaid
graph TB
    subgraph "Data Sources"
        N1[Node Exporter<br/>Host Metrics]
        N2[cAdvisor<br/>Container Metrics]
        N3[APISIX<br/>Gateway Metrics]
        N4[Keycloak<br/>Auth Metrics]
    end

    subgraph "Collection"
        PROM[Prometheus<br/>Metrics DB]
    end

    subgraph "Visualization"
        GRAF[Grafana<br/>Dashboards]
    end

    subgraph "Alerting"
        AM[AlertManager]
        SLACK[Slack/Email]
    end

    N1 & N2 & N3 & N4 -->|scrape| PROM
    PROM --> GRAF
    PROM --> AM
    AM --> SLACK

    style PROM fill:#c8e6c9,stroke:#388e3c,stroke-width:3px
    style GRAF fill:#bbdefb,stroke:#1976d2,stroke-width:2px
```

### 주요 네트워크 메트릭

```yaml
Network Metrics:

  Throughput:
    - apisix_http_requests_total
    - apisix_bandwidth
    - container_network_transmit_bytes_total
    - container_network_receive_bytes_total

  Latency:
    - apisix_http_latency
    - keycloak_response_time
    - vault_core_handle_request

  Errors:
    - apisix_http_status{code="5xx"}
    - keycloak_failed_login_total
    - vault_core_unsealed{status="false"}

  Connections:
    - apisix_http_connections_total
    - postgresql_connections_active
    - vault_runtime_num_goroutines

  DNS:
    - coredns_dns_request_duration_seconds
    - coredns_cache_hits_total
    - coredns_dns_responses_total
```

## 🛡️ 네트워크 보안 Best Practices

```yaml
보안 권장사항:

1. NetworkPolicy 사용:
   ✅ 모든 네임스페이스에 NetworkPolicy 적용
   ✅ 최소 권한 원칙 (Least Privilege)
   ✅ Deny All by Default
   ✅ 명시적 Allow Rules

2. 암호화 통신:
   ✅ Pod-to-Pod: mTLS (Optional)
   ✅ External: TLS 1.3
   ✅ Database: SSL/TLS
   ✅ HSM: Encrypted PKCS#11

3. 네트워크 격리:
   ✅ 네임스페이스 분리
   ✅ 민감 데이터 격리
   ✅ DMZ 구성
   ✅ Bastion Host (관리용)

4. 모니터링 및 로깅:
   ✅ 네트워크 플로우 로그
   ✅ 침입 탐지 시스템 (IDS)
   ✅ 비정상 트래픽 감지
   ✅ 정기 보안 감사

5. Rate Limiting:
   ✅ APISIX Rate Limiting
   ✅ Connection Limits
   ✅ Request Size Limits
   ✅ DDoS 방어
```

## 📊 네트워크 다이어그램 - 상세

```mermaid
graph TB
    subgraph INTERNET["인터넷"]
        USER[사용자]
    end

    subgraph EDGE["Edge Network - 192.168.0.0/24"]
        FW[Firewall<br/>iptables]
        NODE[K8s Node<br/>192.168.0.11]
    end

    subgraph KUBE["Kubernetes CNI - 10.244.0.0/16"]
        subgraph POD_NET["Pod Network"]
            POD1[Pod 10.244.0.15]
            POD2[Pod 10.244.1.20]
            POD3[Pod 10.244.2.30]
        end

        subgraph SVC_NET["Service Network - 10.96.0.0/12"]
            SVC1[ClusterIP 10.96.12.45]
            SVC2[ClusterIP 10.96.34.78]
        end

        subgraph NODEPORT["NodePort - 30000-32767"]
            NP1[NodePort 30181]
            NP2[NodePort 30820]
            NP3[NodePort 32602]
        end
    end

    subgraph STORAGE_NET["Storage Network"]
        PV1[PersistentVolume]
        HSM_DEV[HSM Device<br/>/dev/k7pf0]
    end

    USER -->|HTTPS| FW
    FW --> NODE
    NODE --> NODEPORT

    NODEPORT --> POD_NET
    POD_NET <--> SVC_NET

    POD2 <--> HSM_DEV
    POD1 & POD2 & POD3 --> PV1

    style INTERNET fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style EDGE fill:#fff3e0,stroke:#e65100,stroke-width:2px
    style KUBE fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style STORAGE_NET fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style HSM_DEV fill:#fff9c4,stroke:#f57f17,stroke-width:4px
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Network**: Kubernetes CNI (Flannel/Calico)
**IP Range**: 192.168.0.0/24 (Host), 10.244.0.0/16 (Pod), 10.96.0.0/12 (Service)
