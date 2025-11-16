# ArgoCD 상세 설정 가이드

## 목차
- [ArgoCD 소개](#argocd-소개)
- [설치 및 초기 설정](#설치-및-초기-설정)
- [Application 생성 및 관리](#application-생성-및-관리)
- [Sync 정책 설정](#sync-정책-설정)
- [Repository 연동](#repository-연동)
- [다중 환경 배포](#다중-환경-배포)
- [고급 기능](#고급-기능)
- [모니터링 및 알림](#모니터링-및-알림)
- [트러블슈팅](#트러블슈팅)

## ArgoCD 소개

ArgoCD는 Kubernetes를 위한 선언적 GitOps CD(Continuous Deployment) 도구입니다. Git 저장소를 단일 진실 공급원(Single Source of Truth)으로 사용하여 애플리케이션을 배포하고 관리합니다.

### 주요 기능

- **GitOps 기반 배포**: Git 저장소의 변경사항을 자동으로 감지하여 배포
- **자동 동기화**: 클러스터 상태를 Git 저장소와 자동으로 동기화
- **멀티 클러스터 지원**: 여러 Kubernetes 클러스터 관리
- **Rollback 지원**: 이전 버전으로 쉽게 복구
- **헬스 체크**: 애플리케이션 상태 자동 모니터링
- **RBAC 통합**: 세밀한 권한 관리

### QSIGN 프로젝트 구성

```mermaid
graph TD
    ArgoCD["ArgoCD"]
    ArgoCD --> QSIGN["q-sign<br/>(Keycloak + PQC)"]
    ArgoCD --> QKMS["q-kms<br/>(Vault + Luna HSM)"]
    ArgoCD --> QAPP["q-app<br/>(Application Services)"]
    ArgoCD --> MON["monitoring<br/>(Grafana + Prometheus)"]

    style ArgoCD fill:#ff6f00,stroke:#e65100,stroke-width:3px,color:#fff
    style QSIGN fill:#1976d2,stroke:#0d47a1,stroke-width:2px,color:#fff
    style QKMS fill:#388e3c,stroke:#1b5e20,stroke-width:2px,color:#fff
    style QAPP fill:#7b1fa2,stroke:#4a148c,stroke-width:2px,color:#fff
    style MON fill:#c2185b,stroke:#880e4f,stroke-width:2px,color:#fff
```

## 설치 및 초기 설정

### 1. ArgoCD 설치

#### Namespace 생성
```bash
kubectl create namespace argocd
```

#### ArgoCD 설치
```bash
# 최신 버전 설치
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# 특정 버전 설치 (권장)
VERSION=v2.9.3
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/${VERSION}/manifests/install.yaml
```

#### 설치 확인
```bash
kubectl get pods -n argocd
kubectl get svc -n argocd
```

### 2. ArgoCD CLI 설치

```bash
# Linux
curl -sSL -o argocd-linux-amd64 https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sudo install -m 555 argocd-linux-amd64 /usr/local/bin/argocd
rm argocd-linux-amd64

# macOS
brew install argocd

# 버전 확인
argocd version
```

### 3. ArgoCD 서버 접근 설정

#### NodePort 방식 (QSIGN 환경)
```bash
kubectl patch svc argocd-server -n argocd -p '{"spec": {"type": "NodePort"}}'

# NodePort 확인
kubectl get svc argocd-server -n argocd
```

```yaml
# argocd-server-nodeport.yaml
apiVersion: v1
kind: Service
metadata:
  name: argocd-server
  namespace: argocd
spec:
  type: NodePort
  ports:
  - name: http
    port: 80
    targetPort: 8080
    nodePort: 30080
  - name: https
    port: 443
    targetPort: 8080
    nodePort: 30443
  selector:
    app.kubernetes.io/name: argocd-server
```

#### Ingress 방식
```yaml
# argocd-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server-ingress
  namespace: argocd
  annotations:
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
spec:
  ingressClassName: nginx
  rules:
  - host: argocd.qsign.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: argocd-server
            port:
              number: 443
  tls:
  - hosts:
    - argocd.qsign.local
    secretName: argocd-server-tls
```

### 4. 초기 관리자 비밀번호 확인

```bash
# 초기 비밀번호 확인
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d; echo

# CLI 로그인
argocd login 192.168.0.11:30080 --username admin --password <password> --insecure

# 비밀번호 변경
argocd account update-password
```

### 5. ArgoCD 설정 최적화

```yaml
# argocd-cm-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # Git 폴링 간격 (기본: 3분)
  timeout.reconciliation: 180s

  # 리소스 제외 설정
  resource.exclusions: |
    - apiGroups:
      - cilium.io
      kinds:
      - CiliumIdentity
      clusters:
      - "*"

  # 헬스 체크 커스터마이징
  resource.customizations: |
    argoproj.io/Application:
      health.lua: |
        hs = {}
        hs.status = "Progressing"
        hs.message = ""
        if obj.status ~= nil then
          if obj.status.health ~= nil then
            hs.status = obj.status.health.status
            if obj.status.health.message ~= nil then
              hs.message = obj.status.health.message
            end
          end
        end
        return hs

  # Dex 설정 (SSO)
  url: https://argocd.qsign.local
  dex.config: |
    connectors:
      - type: oidc
        id: keycloak
        name: Keycloak
        config:
          issuer: https://keycloak.qsign.local/auth/realms/master
          clientID: argocd
          clientSecret: $dex.keycloak.clientSecret
          insecureEnableGroups: true
```

## Application 생성 및 관리

### 1. Application 기본 구조

```yaml
# q-sign-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-sign
  namespace: argocd
  # Finalizer - 삭제 시 리소스 정리
  finalizers:
    - resources-finalizer.argocd.argoproj.io
  # 레이블
  labels:
    app.kubernetes.io/name: q-sign
    app.kubernetes.io/component: keycloak
    environment: production
  # 어노테이션
  annotations:
    notifications.argoproj.io/subscribe.on-sync-succeeded.slack: qsign-notifications
spec:
  # 프로젝트
  project: qsign-project

  # Git 소스
  source:
    repoURL: http://192.168.0.11:7780/root/q-sign.git
    targetRevision: main
    path: helm/keycloak-pqc

    # Helm 설정
    helm:
      # Values 파일 지정
      valueFiles:
        - values.yaml
        - values-prod.yaml

      # Values 오버라이드
      values: |
        image:
          repository: 192.168.0.11:30800/qsign/keycloak-pqc
          tag: "v1.0.1-qkms"

        replicaCount: 3

        service:
          type: NodePort
          port: 8080
          nodePort: 30181

        resources:
          limits:
            cpu: 2000m
            memory: 4Gi
          requests:
            cpu: 500m
            memory: 1Gi

      # Helm 파라미터 직접 설정
      parameters:
        - name: keycloak.admin.password
          value: $KEYCLOAK_ADMIN_PASSWORD
        - name: hsm.pin
          value: $HSM_PIN

      # Release name 지정
      releaseName: q-sign

      # Skip CRDs
      skipCrds: false

  # 배포 대상
  destination:
    server: https://kubernetes.default.svc
    namespace: q-sign

  # 동기화 정책
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
      - PrunePropagationPolicy=foreground
      - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m

  # 무시할 리소스 차이
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/replicas
```

### 2. Application 생성

#### CLI로 생성
```bash
# Helm Chart 애플리케이션 생성
argocd app create q-sign \
  --repo http://192.168.0.11:7780/root/q-sign.git \
  --path helm/keycloak-pqc \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace q-sign \
  --sync-policy automated \
  --auto-prune \
  --self-heal \
  --sync-option CreateNamespace=true

# YAML 매니페스트 애플리케이션 생성
argocd app create q-kms \
  --repo http://192.168.0.11:7780/root/q-kms.git \
  --path k8s/manifests \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace q-kms \
  --directory-recurse
```

#### YAML로 생성
```bash
kubectl apply -f q-sign-application.yaml
```

### 3. Application 관리 명령어

```bash
# 애플리케이션 목록 조회
argocd app list

# 애플리케이션 상세 정보
argocd app get q-sign

# 애플리케이션 동기화
argocd app sync q-sign

# 애플리케이션 상태 확인
argocd app wait q-sign --health

# 애플리케이션 삭제
argocd app delete q-sign

# 애플리케이션 롤백
argocd app rollback q-sign <revision-id>

# 애플리케이션 히스토리
argocd app history q-sign

# 리소스 트리 조회
argocd app resources q-sign

# Diff 확인
argocd app diff q-sign

# 매니페스트 확인
argocd app manifests q-sign
```

### 4. Q-KMS Application 예제

```yaml
# q-kms-application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-kms
  namespace: argocd
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default

  source:
    repoURL: http://192.168.0.11:7780/root/q-kms.git
    targetRevision: main
    path: helm/vault-hsm
    helm:
      values: |
        vault:
          image:
            repository: 192.168.0.11:30800/qsign-prod/vault-ubuntu-luna
            tag: "1.21.0"

          service:
            type: NodePort
            port: 8200
            nodePort: 30200

          ha:
            enabled: true
            replicas: 3
            raft:
              enabled: true

        lunaHsm:
          enabled: true
          devicePath: "/dev/k7pf0"
          groupId: "997"
          partitionLabel: "vault-partition"

        vaultInit:
          enabled: true
          unsealKeys:
            - "<vault-unseal-key-1>"
            - "<vault-unseal-key-2>"
            - "<vault-unseal-key-3>"
          rootToken: "<vault-root-token>"

  destination:
    server: https://kubernetes.default.svc
    namespace: q-kms

  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
    retry:
      limit: 3
      backoff:
        duration: 5s
        maxDuration: 2m
```

## Sync 정책 설정

### 1. Automated Sync (자동 동기화)

```yaml
syncPolicy:
  automated:
    # 자동 리소스 정리 (Git에서 삭제된 리소스를 클러스터에서도 삭제)
    prune: true

    # 자동 복구 (수동으로 변경된 리소스를 Git 상태로 복구)
    selfHeal: true

    # 빈 리소스 허용 여부
    allowEmpty: false

  # 동기화 옵션
  syncOptions:
    - CreateNamespace=true      # 네임스페이스 자동 생성
    - PrunePropagationPolicy=foreground  # 삭제 전파 정책
    - PruneLast=true            # 마지막에 삭제
    - ApplyOutOfSyncOnly=true   # Out of sync 리소스만 적용
    - RespectIgnoreDifferences=true

  # 재시도 정책
  retry:
    limit: 5                    # 최대 재시도 횟수
    backoff:
      duration: 5s              # 초기 대기 시간
      factor: 2                 # 백오프 증가 계수
      maxDuration: 3m           # 최대 대기 시간
```

### 2. Manual Sync (수동 동기화)

```yaml
syncPolicy:
  # automated 없음 = 수동 동기화
  syncOptions:
    - CreateNamespace=true
  retry:
    limit: 3
```

### 3. Sync Windows (동기화 시간 제한)

```yaml
# AppProject에서 설정
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: qsign-project
  namespace: argocd
spec:
  syncWindows:
    # 평일 업무 시간 동안만 자동 동기화 허용
    - kind: allow
      schedule: '0 9-18 * * 1-5'
      duration: 9h
      applications:
        - q-sign
        - q-kms
      manualSync: true

    # 주말에는 수동 동기화만 허용
    - kind: deny
      schedule: '* * * * 0,6'
      duration: 24h
      applications:
        - '*'
      manualSync: true
```

### 4. Sync Hooks

```yaml
# Pre-sync hook 예제
apiVersion: batch/v1
kind: Job
metadata:
  name: database-backup
  annotations:
    argocd.argoproj.io/hook: PreSync
    argocd.argoproj.io/hook-delete-policy: BeforeHookCreation
spec:
  template:
    spec:
      containers:
      - name: backup
        image: postgres:14
        command:
          - sh
          - -c
          - |
            pg_dump -h postgres -U postgres qsign > /backup/qsign-$(date +%Y%m%d-%H%M%S).sql
      restartPolicy: Never

---
# Post-sync hook 예제
apiVersion: batch/v1
kind: Job
metadata:
  name: smoke-test
  annotations:
    argocd.argoproj.io/hook: PostSync
    argocd.argoproj.io/hook-delete-policy: HookSucceeded
spec:
  template:
    spec:
      containers:
      - name: test
        image: curlimages/curl:latest
        command:
          - sh
          - -c
          - |
            curl -f http://keycloak:8080/auth/ || exit 1
      restartPolicy: Never
```

## Repository 연동

### 1. Git Repository 추가

#### GitLab (HTTP)
```bash
argocd repo add http://192.168.0.11:7780/root/q-sign.git \
  --username root \
  --password <gitlab-token>
```

#### GitLab (SSH)
```bash
# SSH 키 생성
ssh-keygen -t ed25519 -C "argocd@qsign.local" -f ~/.ssh/argocd

# Public 키를 GitLab에 등록

# ArgoCD에 Private 키 등록
argocd repo add git@192.168.0.11:root/q-sign.git \
  --ssh-private-key-path ~/.ssh/argocd
```

#### Helm Repository
```bash
# Harbor Helm Repository
argocd repo add https://192.168.0.11:30800/chartrepo/qsign \
  --type helm \
  --username admin \
  --password Harbor12345 \
  --insecure-skip-server-verification
```

### 2. Repository Credentials Template

```yaml
# argocd-repo-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: qsign-repo-creds
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repo-creds
stringData:
  type: git
  url: http://192.168.0.11:7780
  username: root
  password: <gitlab-token>

---
# SSH 방식
apiVersion: v1
kind: Secret
metadata:
  name: qsign-repo-ssh
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: git@192.168.0.11:root/q-sign.git
  sshPrivateKey: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    ...
    -----END OPENSSH PRIVATE KEY-----
```

### 3. Private Repository 설정

```bash
# Docker Registry Secret
kubectl create secret docker-registry harbor-registry \
  --docker-server=192.168.0.11:30800 \
  --docker-username=admin \
  --docker-password=Harbor12345 \
  --docker-email=admin@qsign.local \
  -n q-sign

# ArgoCD에서 사용
```

```yaml
# Deployment에서 사용
spec:
  template:
    spec:
      imagePullSecrets:
        - name: harbor-registry
```

## 다중 환경 배포

### 1. 환경별 Application 구성

```
environments/
├── dev/
│   ├── q-sign-app.yaml
│   └── values-dev.yaml
├── staging/
│   ├── q-sign-app.yaml
│   └── values-staging.yaml
└── production/
    ├── q-sign-app.yaml
    └── values-prod.yaml
```

### 2. Development 환경

```yaml
# environments/dev/q-sign-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-sign-dev
  namespace: argocd
  labels:
    environment: dev
spec:
  project: qsign-dev

  source:
    repoURL: http://192.168.0.11:7780/root/q-sign.git
    targetRevision: develop
    path: helm/keycloak-pqc
    helm:
      valueFiles:
        - values-dev.yaml
      values: |
        image:
          tag: "develop"
        replicaCount: 1
        resources:
          limits:
            cpu: 500m
            memory: 1Gi

  destination:
    server: https://kubernetes.default.svc
    namespace: dev

  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### 3. Staging 환경

```yaml
# environments/staging/q-sign-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-sign-staging
  namespace: argocd
  labels:
    environment: staging
spec:
  project: qsign-staging

  source:
    repoURL: http://192.168.0.11:7780/root/q-sign.git
    targetRevision: release/v1.0
    path: helm/keycloak-pqc
    helm:
      valueFiles:
        - values-staging.yaml
      values: |
        image:
          tag: "v1.0.1-rc1"
        replicaCount: 2

  destination:
    server: https://kubernetes.default.svc
    namespace: staging

  syncPolicy:
    automated:
      prune: true
      selfHeal: false  # Staging은 수동 복구
```

### 4. Production 환경

```yaml
# environments/production/q-sign-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-sign-prod
  namespace: argocd
  labels:
    environment: production
    criticality: high
spec:
  project: qsign-production

  source:
    repoURL: http://192.168.0.11:7780/root/q-sign.git
    targetRevision: v1.0.1  # Tag 사용
    path: helm/keycloak-pqc
    helm:
      valueFiles:
        - values-prod.yaml
      values: |
        image:
          tag: "v1.0.1-qkms"
        replicaCount: 3

        resources:
          limits:
            cpu: 2000m
            memory: 4Gi
          requests:
            cpu: 500m
            memory: 1Gi

        affinity:
          podAntiAffinity:
            requiredDuringSchedulingIgnoredDuringExecution:
              - labelSelector:
                  matchExpressions:
                    - key: app
                      operator: In
                      values:
                        - keycloak
                topologyKey: kubernetes.io/hostname

  destination:
    server: https://kubernetes.default.svc
    namespace: production

  syncPolicy:
    automated:
      prune: false      # Production은 자동 삭제 비활성화
      selfHeal: false   # Production은 자동 복구 비활성화
    syncOptions:
      - CreateNamespace=true

  # Production은 수동 승인 필요
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/replicas  # HPA가 관리하는 replicas 무시
```

### 5. AppProject로 환경 분리

```yaml
# dev-project.yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: qsign-dev
  namespace: argocd
spec:
  description: QSIGN Development Environment

  sourceRepos:
    - http://192.168.0.11:7780/root/q-sign.git
    - http://192.168.0.11:7780/root/q-kms.git

  destinations:
    - namespace: 'dev*'
      server: https://kubernetes.default.svc

  clusterResourceWhitelist:
    - group: ''
      kind: Namespace

  namespaceResourceWhitelist:
    - group: '*'
      kind: '*'

---
# production-project.yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: qsign-production
  namespace: argocd
spec:
  description: QSIGN Production Environment

  sourceRepos:
    - http://192.168.0.11:7780/root/q-sign.git
    - http://192.168.0.11:7780/root/q-kms.git

  destinations:
    - namespace: 'production'
      server: https://kubernetes.default.svc

  clusterResourceWhitelist:
    - group: ''
      kind: Namespace

  # Production 제한 사항
  orphanedResources:
    warn: true

  syncWindows:
    - kind: deny
      schedule: '0 0-8,18-23 * * *'  # 업무 외 시간 배포 금지
      duration: 10h
```

## 고급 기능

### 1. ApplicationSet

```yaml
# applicationset-environments.yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: q-sign-all-envs
  namespace: argocd
spec:
  generators:
    - list:
        elements:
          - env: dev
            branch: develop
            replicas: "1"
            namespace: dev
          - env: staging
            branch: release/v1.0
            replicas: "2"
            namespace: staging
          - env: production
            branch: main
            replicas: "3"
            namespace: production

  template:
    metadata:
      name: 'q-sign-{{env}}'
      labels:
        environment: '{{env}}'
    spec:
      project: 'qsign-{{env}}'
      source:
        repoURL: http://192.168.0.11:7780/root/q-sign.git
        targetRevision: '{{branch}}'
        path: helm/keycloak-pqc
        helm:
          values: |
            replicaCount: {{replicas}}
            environment: {{env}}
      destination:
        server: https://kubernetes.default.svc
        namespace: '{{namespace}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
```

### 2. Progressive Delivery (Rollout)

```yaml
# Install Argo Rollouts
kubectl create namespace argo-rollouts
kubectl apply -n argo-rollouts -f https://github.com/argoproj/argo-rollouts/releases/latest/download/install.yaml
```

```yaml
# rollout-canary.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: keycloak-rollout
  namespace: q-sign
spec:
  replicas: 5
  strategy:
    canary:
      steps:
        - setWeight: 20
        - pause: {duration: 1h}
        - setWeight: 40
        - pause: {duration: 30m}
        - setWeight: 60
        - pause: {duration: 30m}
        - setWeight: 80
        - pause: {duration: 30m}
  revisionHistoryLimit: 3
  selector:
    matchLabels:
      app: keycloak
  template:
    metadata:
      labels:
        app: keycloak
    spec:
      containers:
      - name: keycloak
        image: 192.168.0.11:30800/qsign/keycloak-pqc:v1.0.1
        ports:
        - containerPort: 8080
```

### 3. Sync Waves

```yaml
# 01-database.yaml
apiVersion: v1
kind: Service
metadata:
  name: postgres
  annotations:
    argocd.argoproj.io/sync-wave: "1"
spec:
  ports:
  - port: 5432

---
# 02-application.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
  annotations:
    argocd.argoproj.io/sync-wave: "2"
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: keycloak
        image: keycloak-pqc:latest
```

## 모니터링 및 알림

### 1. Prometheus Metrics

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: argocd-metrics
  namespace: argocd
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: argocd-metrics
  endpoints:
  - port: metrics
```

### 2. Slack 알림 설정

```yaml
# argocd-notifications-cm.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-notifications-cm
  namespace: argocd
data:
  service.slack: |
    token: $slack-token

  template.app-deployed: |
    message: |
      Application {{.app.metadata.name}} is now running new version.
    slack:
      attachments: |
        [{
          "title": "{{ .app.metadata.name}}",
          "title_link":"{{.context.argocdUrl}}/applications/{{.app.metadata.name}}",
          "color": "#18be52",
          "fields": [
          {
            "title": "Sync Status",
            "value": "{{.app.status.sync.status}}",
            "short": true
          },
          {
            "title": "Repository",
            "value": "{{.app.spec.source.repoURL}}",
            "short": true
          }
          ]
        }]

  trigger.on-deployed: |
    - description: Application is synced and healthy
      send:
      - app-deployed
      when: app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'
```

```yaml
# argocd-notifications-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: argocd-notifications-secret
  namespace: argocd
stringData:
  slack-token: xoxb-your-slack-bot-token
```

### 3. Application에 알림 설정

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: q-sign
  namespace: argocd
  annotations:
    notifications.argoproj.io/subscribe.on-deployed.slack: qsign-deployments
    notifications.argoproj.io/subscribe.on-sync-failed.slack: qsign-alerts
```

## 트러블슈팅

### 1. Out of Sync 문제

```bash
# 상태 확인
argocd app get q-sign

# Diff 확인
argocd app diff q-sign

# Hard Refresh
argocd app get q-sign --hard-refresh

# 강제 동기화
argocd app sync q-sign --force --prune --timeout 300
```

### 2. Sync Failed

```bash
# 에러 로그 확인
argocd app get q-sign
kubectl logs -n argocd deployment/argocd-application-controller

# 리소스별 상태 확인
argocd app resources q-sign

# Helm 템플릿 검증
helm template q-sign ./helm/keycloak-pqc --debug
```

### 3. Health Check Failed

```bash
# Pod 상태 확인
kubectl get pods -n q-sign
kubectl describe pod <pod-name> -n q-sign
kubectl logs <pod-name> -n q-sign

# ArgoCD 헬스 체크 로그
kubectl logs -n argocd deployment/argocd-application-controller | grep q-sign
```

### 4. Performance 문제

```yaml
# argocd-cm에서 설정
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cm
  namespace: argocd
data:
  # 동시 처리 증가
  application.resourceTrackingMethod: annotation

  # 타임아웃 증가
  timeout.reconciliation: 300s
  timeout.hard.reconciliation: 0
```

```bash
# Application Controller 리소스 증가
kubectl patch deployment argocd-application-controller -n argocd --patch '
spec:
  template:
    spec:
      containers:
      - name: argocd-application-controller
        resources:
          limits:
            cpu: 2000m
            memory: 4Gi
          requests:
            cpu: 500m
            memory: 1Gi
'
```

---

**Last Updated**: 2025-11-16
**ArgoCD Version**: v2.9.3
**Author**: QSIGN DevOps Team
