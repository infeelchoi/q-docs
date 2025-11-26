# QSIGN 아키텍처 개요

## 🏛️ 전체 아키텍처

```mermaid
graph TB
    subgraph External["External Access Layer"]
        GitLab["GitLab<br/>:7743"]
        Harbor["Harbor<br/>:31800"]
        Jenkins["Jenkins<br/>:7643"]
        Clients["Clients<br/>Browser"]
    end

    subgraph K8s["Kubernetes Cluster (K3s)"]
        subgraph Gateway["Ingress/Gateway Layer"]
            APISIX["APISIX Gateway<br/>:32602/:32294"]
            APIDash["APISIX Dashboard<br/>:31281"]
            ArgoUI["ArgoCD UI<br/>:30080"]
        end

        subgraph Auth["Authentication & Authorization"]
            KC_PQC["Keycloak PQC<br/>- Q-Sign<br/>Namespace: q-sign<br/>Port: 30181"]
            KC_HSM["Keycloak HSM<br/>- PQC-SSO<br/>Namespace: pqc-sso<br/>Port: 30699"]
        end

        subgraph KeyMgmt["Key Management Layer"]
            subgraph Vault["Q-KMS Vault (Namespace: q-kms)"]
                Transit["Transit Engine<br/>pqc-keys/"]
                KV["KV v2 Secrets<br/>secret/"]
                PKI["PKI Engine<br/>pki/"]
                HSM["Luna HSM Device<br/>/dev/k7pf0<br/>FIPS 140-2 Level 3<br/>PKCS#11 • Group: 997"]
                Transit --> HSM
            end
            VaultPort["Port: 30820"]
        end

        subgraph AppLayer["Application Layer"]
            App1["App1<br/>:30210"]
            App3["App3<br/>:30202"]
            App6["App6<br/>:30205"]
            SSOTest["SSO Test App<br/>:32127"]
            AppNS["Namespace: q-app"]
        end

        subgraph Monitor["Monitoring & Logging"]
            Prom["Prometheus<br/>:30092"]
            Grafana["Grafana<br/>:30030"]
            Sky["SkyWalking<br/>:30094"]
            ES["Elasticsearch<br/>ClusterIP"]
            MonNS["Namespace: qsign-prod"]
        end

        subgraph Storage["Storage & Database"]
            PG1["PostgreSQL<br/>- Q-Sign<br/>:5432"]
            PG2["PostgreSQL<br/>- PQC-SSO<br/>:5432"]
            PV["Local Path PV<br/>Storage"]
        end
    end

    GitLab --> APISIX
    Harbor --> APISIX
    Jenkins --> APISIX
    Clients --> APISIX

    APISIX --> KC_PQC
    APISIX --> KC_HSM

    KC_PQC <--> KC_HSM
    KC_PQC --> Vault
    KC_HSM --> Vault

    KC_PQC --> PG1
    KC_HSM --> PG2

    Prom --> Grafana
    Sky --> ES
    ES --> Grafana

    style External fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style Gateway fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style Auth fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style KeyMgmt fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style Vault fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style HSM fill:#ffebee,stroke:#c62828,stroke-width:3px
    style AppLayer fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    style Monitor fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    style Storage fill:#f1f8e9,stroke:#558b2f,stroke-width:2px
```

## 🎯 아키텍처 원칙

### 1. 보안 우선 (Security First)
- **Defense in Depth**: 다층 보안 구조
- **Zero Trust**: 모든 요청 검증
- **Quantum-Resistant**: PQC 알고리즘 사용
- **HSM Integration**: 하드웨어 기반 키 보호

### 2. 확장성 (Scalability)
- **Horizontal Scaling**: 수평 확장 가능
- **Stateless Design**: 상태 비저장 애플리케이션
- **Load Balancing**: 트래픽 분산
- **Auto-scaling**: 자동 스케일링 지원

### 3. 가용성 (High Availability)
- **Redundancy**: 중복 구성
- **Health Checks**: 상태 모니터링
- **Rolling Updates**: 무중단 배포
- **Backup & Recovery**: 백업 및 복구

### 4. 관찰성 (Observability)
- **Metrics**: Prometheus 메트릭
- **Logging**: Centralized 로그
- **Tracing**: 분산 추적
- **Dashboards**: 시각화

### 5. 자동화 (Automation)
- **GitOps**: Git 기반 배포
- **CI/CD**: 자동 빌드/배포
- **IaC**: Infrastructure as Code
- **Self-healing**: 자가 복구

## 🔐 보안 아키텍처

### 인증 흐름

```mermaid
flowchart TD
    Start[1. User Request] --> Gateway[2. APISIX Gateway]

    subgraph GatewayOps[" "]
        RateLimit[Rate Limiting]
        CORS[CORS Check]
        Route[Routing]
    end

    Gateway --> GatewayOps
    GatewayOps --> KC[3. Keycloak Authentication]

    subgraph KCOps[" "]
        UserVal[User Validation]
        OIDC[OIDC/OAuth 2.0]
        Session[Session Management]
    end

    KC --> KCOps
    KCOps --> Vault[4. Vault Key Management]

    subgraph VaultOps[" "]
        Transit[Transit Engine<br/>Crypto Operations]
        KVEngine[KV Engine<br/>Secret Storage]
        HSMOps[Luna HSM<br/>Hardware Security]
    end

    Vault --> VaultOps
    VaultOps --> PQC[5. PQC Token Generation]

    subgraph PQCOps[" "]
        Dilithium[DILITHIUM3 Signature]
        Hybrid[Hybrid Mode<br/>RSA + PQC]
        JWT[JWT Encoding]
    end

    PQC --> PQCOps
    PQCOps --> Response[6. Response to Client]

    style Start fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style Gateway fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style KC fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style Vault fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style PQC fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style Response fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
```

### 키 계층 구조

```mermaid
graph TB
    Root["Root CA<br/>(Vault PKI)"]

    Root --> IntCA["Intermediate CA"]
    Root --> PQCKeys["PQC Keys<br/>(Transit Engine)"]
    Root --> AppSecrets["Application Secrets<br/>(KV v2)"]

    IntCA --> ServerCert["Server Certificates"]
    IntCA --> ClientCert["Client Certificates"]

    PQCKeys --> Dilithium["DILITHIUM3<br/>(Signing)"]
    PQCKeys --> Kyber["KYBER1024<br/>(Encryption)"]
    PQCKeys --> Sphincs["SPHINCS+<br/>(Backup)"]

    AppSecrets --> DBCred["Database Credentials"]
    AppSecrets --> APIKeys["API Keys"]
    AppSecrets --> ClientSec["Client Secrets"]

    style Root fill:#ffebee,stroke:#c62828,stroke-width:3px
    style IntCA fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style PQCKeys fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style AppSecrets fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style Dilithium fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style Kyber fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style Sphincs fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

## 🌐 네트워크 아키텍처

### NodePort 매핑
| Service | Internal Port | NodePort | Protocol |
|---------|---------------|----------|----------|
| Keycloak PQC | 8080 | 30181 | HTTP |
| Keycloak HSM | 80 | 30699 | HTTP |
| Q-KMS Vault | 8200 | 30820 | HTTP |
| APISIX Gateway | 9080 | 32602 | HTTP |
| APISIX HTTPS | 9443 | 32294 | HTTPS |
| APISIX Dashboard | 9000 | 31281 | HTTP |
| Grafana | 3000 | 30030 | HTTP |
| Prometheus | 9090 | 30092 | HTTP |
| SkyWalking | 8080 | 30094 | HTTP |
| ArgoCD | 8080 | 30080 | HTTP/HTTPS |
| Admin Dashboard | 80 | 30093 | HTTP |
| Harbor | 80 | 31800 | HTTP |

### 서비스 메시

```mermaid
graph TB
    subgraph DNS["Service Discovery (K8s DNS)"]
        KC["keycloak.q-sign.svc.cluster.local"]
        KMS["q-kms.q-kms.svc.cluster.local"]
        APISIX["apisix.qsign-prod.svc.cluster.local"]
        PROM["prometheus.qsign-prod.svc.cluster.local"]
    end

    style DNS fill:#e8f5e9,stroke:#388e3c,stroke-width:2px
    style KC fill:#bbdefb,stroke:#1976d2,stroke-width:2px
    style KMS fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style APISIX fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    style PROM fill:#ffccbc,stroke:#d84315,stroke-width:2px
```

## 📊 데이터 흐름

### SSO 인증 데이터 흐름
```mermaid
sequenceDiagram
    participant U as 사용자<br/>- 브라우저
    participant APP as Q-App<br/>- 애플리케이션
    participant A as APISIX<br/>Gateway
    participant K as Keycloak<br/>- Q-Sign
    participant V as Vault<br/>- 키 관리
    participant H as Luna HSM<br/>- 하드웨어 보안
    participant D as PostgreSQL<br/>- 사용자 DB

    U->>APP: 1. 애플리케이션 접속
    APP-->>U: 2. 메인 페이지 표시<br/>- 로그인 버튼
    U->>APP: 3. 로그인 버튼 클릭
    APP->>A: 4. 로그인 요청
    A->>K: 5. Redirect to Keycloak
    K->>D: 6. 사용자 검증
    D-->>K: 7. 사용자 데이터
    K->>V: 8. PQC 키 요청
    V->>H: 9. DILITHIUM3 서명
    H-->>V: 10. 서명 결과
    V-->>K: 11. 서명된 데이터
    K->>K: 12. JWT 토큰 생성
    K-->>A: 13. 토큰 반환
    A-->>APP: 14. 액세스 토큰
    APP-->>U: 15. 인증 완료<br/>- 메인 화면 이동
```

### 키 관리 데이터 흐름

```mermaid
flowchart TD
    App1[Application] -->|1. Request Key| Transit[Vault Transit Engine]
    Transit -->|2. PKCS#11 Call| HSM[Luna HSM]
    HSM -->|3. Hardware Operation| HSM
    HSM -->|4. Return Signature| Vault[Vault]
    Vault -->|5. Encode Response| App2[Application]

    style App1 fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    style Transit fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    style HSM fill:#ffebee,stroke:#c62828,stroke-width:3px
    style Vault fill:#fff9c4,stroke:#f57f17,stroke-width:2px
    style App2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

## 🔄 GitOps 흐름

```mermaid
graph TD
    A[Developer] -->|git push| B[GitLab Repository]
    B -->|Webhook/Auto-detect| C[ArgoCD Sync]
    C --> D[Helm Chart Processing]
    D --> E[Kubernetes Apply]
    E --> F[Rolling Update]
    F --> G[Health Check]
    G -->|Success| H[Production]
    G -->|Failure| I[Rollback]
    I --> E

    style A fill:#e1f5ff,stroke:#333,stroke-width:2px
    style B fill:#fff4e1,stroke:#333,stroke-width:2px
    style C fill:#e1ffe1,stroke:#333,stroke-width:2px
    style H fill:#c8e6c9,stroke:#333,stroke-width:3px
    style I fill:#ffcdd2,stroke:#333,stroke-width:2px
```

## 📈 확장 전략

### 수평 확장

```mermaid
graph LR
    subgraph "Scalable Components"
        KC1[Keycloak<br/>Replica 1]
        KC2[Keycloak<br/>Replica 2]
        KC3[Keycloak<br/>Replica 3]

        AP1[APISIX<br/>Replica 1]
        AP2[APISIX<br/>Replica 2]

        APP1[App Pod 1]
        APP2[App Pod 2]
        APP3[App Pod N...]
    end

    subgraph "Non-Scalable Components"
        V[Vault<br/>Single Instance]
        DB[PostgreSQL<br/>Single Instance]
        HSM[Luna HSM<br/>Single Device]
    end

    LB[Load Balancer] --> AP1
    LB --> AP2
    AP1 --> KC1
    AP1 --> KC2
    AP2 --> KC2
    AP2 --> KC3
    KC1 --> V
    KC2 --> V
    KC3 --> V
    V --> HSM
    KC1 --> DB
    KC2 --> DB
    KC3 --> DB

    style V fill:#ffebee,stroke:#c62828,stroke-width:2px
    style DB fill:#ffebee,stroke:#c62828,stroke-width:2px
    style HSM fill:#ffebee,stroke:#c62828,stroke-width:2px
```

**Scalable Components:**
- Keycloak: ReplicaSet (2+)
- APISIX: ReplicaSet (2+)
- Application Pods: Auto-scaling
- Prometheus: Federation
- Grafana: Load Balanced

**Non-scalable Components:**
- Vault: Single Instance (HA requires Raft)
- PostgreSQL: Single Instance (Replication possible)
- Luna HSM: Single Device

### 리소스 최적화
```yaml
Resource Management:
  - Resource Requests/Limits
  - HPA (Horizontal Pod Autoscaler)
  - VPA (Vertical Pod Autoscaler)
  - Node Affinity
  - Pod Anti-affinity
```

## 🛡️ 재해 복구

### 백업 및 복구 플로우

```mermaid
graph TD
    subgraph "Backup Sources"
        B1[Configuration<br/>K8s Manifests<br/>Helm Charts]
        B2[Data<br/>PostgreSQL<br/>Vault Data<br/>PV]
        B3[Secrets<br/>Unseal Keys<br/>Tokens]
    end

    subgraph "Backup Storage"
        S1[GitLab<br/>Repository]
        S2[Object Storage<br/>S3/MinIO]
        S3[Secure Vault<br/>Offline Storage]
    end

    B1 -->|Automated| S1
    B2 -->|Scheduled| S2
    B3 -->|Manual| S3

    subgraph "Recovery Process"
        R1[Infrastructure<br/>Recovery]
        R2[Service<br/>Recovery]
        R3[Verification]
    end

    S1 -->|Restore| R1
    S2 -->|Restore| R2
    S3 -->|Unseal| R2
    R1 --> R2
    R2 --> R3

    style B3 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style S3 fill:#ffebee,stroke:#c62828,stroke-width:2px
    style R3 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

### 백업 대상
**1. Configuration Backups**
- Kubernetes Manifests (GitLab)
- Helm Charts (GitLab)
- ArgoCD Applications (GitLab)

**2. Data Backups**
- PostgreSQL Databases
- Vault Data
- Persistent Volumes

**3. Secrets Backups**
- Vault Unseal Keys
- Root Tokens
- Client Secrets

### 복구 절차

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant Infra as Infrastructure
    participant DB as Database
    participant Vault
    participant Apps as Applications

    Admin->>Infra: 1. Restore Kubernetes Cluster
    Infra-->>Admin: 2. Cluster Ready

    Admin->>Infra: 3. Restore Storage Volumes
    Infra-->>Admin: 4. Volumes Mounted

    Admin->>DB: 5. Restore PostgreSQL Backup
    DB-->>Admin: 6. Database Restored

    Admin->>Vault: 7. Initialize Vault
    Admin->>Vault: 8. Unseal with Keys (3/5)
    Vault-->>Admin: 9. Vault Unsealed

    Admin->>Apps: 10. Deploy Applications (ArgoCD)
    Apps->>DB: 11. Connect to Database
    Apps->>Vault: 12. Connect to Vault
    Apps-->>Admin: 13. Applications Healthy

    Admin->>Apps: 14. Run Integration Tests
    Apps-->>Admin: 15. All Tests Passed ✅
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Architecture Review**: Quarterly
