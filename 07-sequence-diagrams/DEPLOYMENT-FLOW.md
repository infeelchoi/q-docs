# GitOps 배포 플로우 시퀀스 다이어그램

## 1. 전체 CI/CD 파이프라인

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer
    participant GL as GitLab
    participant Jenkins as Jenkins CI
    participant Harbor as Harbor Registry
    participant ArgoCD as ArgoCD
    participant K8s as Kubernetes

    Note over Dev,K8s: 코드 변경 및 커밋
    Dev->>GL: 1. git push origin main<br/>(코드 변경)
    GL->>GL: 2. Webhook trigger

    Note over GL,Jenkins: CI 파이프라인
    GL->>Jenkins: 3. Webhook: Push event
    Jenkins->>GL: 4. git clone repository
    GL-->>Jenkins: 5. Source code

    Jenkins->>Jenkins: 6. mvn clean package<br/>(또는 npm build)
    Jenkins->>Jenkins: 7. Run unit tests
    Jenkins->>Jenkins: 8. docker build -t image:tag

    Note over Jenkins,Harbor: 이미지 푸시
    Jenkins->>Harbor: 9. docker login 192.168.0.11:30800
    Jenkins->>Harbor: 10. docker push qsign-prod/app:v1.0.1
    Harbor->>Harbor: 11. Vulnerability scan
    Harbor-->>Jenkins: 12. Image pushed successfully

    Note over Jenkins,GL: Helm Chart 업데이트
    Jenkins->>GL: 13. git clone helm-repo
    Jenkins->>Jenkins: 14. Update values.yaml<br/>(image.tag: v1.0.1)
    Jenkins->>GL: 15. git commit -m "Update image to v1.0.1"
    Jenkins->>GL: 16. git push origin main
    GL-->>Jenkins: 17. Helm chart updated

    Note over GL,ArgoCD: GitOps 동기화
    ArgoCD->>GL: 18. Poll repository (every 3 min)
    GL-->>ArgoCD: 19. New commit detected

    ArgoCD->>ArgoCD: 20. git pull latest changes
    ArgoCD->>ArgoCD: 21. helm template render
    ArgoCD->>ArgoCD: 22. Diff analysis

    Note over ArgoCD,K8s: 배포 실행
    ArgoCD->>K8s: 23. kubectl apply -f manifests
    K8s->>K8s: 24. Rolling update deployment
    K8s->>Harbor: 25. docker pull qsign-prod/app:v1.0.1
    Harbor-->>K8s: 26. Image layers
    K8s->>K8s: 27. Create new pod
    K8s->>K8s: 28. Health check (readiness probe)
    K8s->>K8s: 29. Terminate old pod
    K8s-->>ArgoCD: 30. Deployment successful

    ArgoCD-->>Dev: 31. 📧 Notification: Deployed v1.0.1
```

## 2. ArgoCD Application 생성

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin
    participant ArgoCD as ArgoCD API
    participant GL as GitLab
    participant K8s as Kubernetes

    Note over Admin,K8s: ArgoCD Application 정의
    Admin->>ArgoCD: 1. kubectl apply -f application.yaml<br/>apiVersion: argoproj.io/v1alpha1<br/>kind: Application

    ArgoCD->>ArgoCD: 2. Parse application spec
    ArgoCD->>ArgoCD: 3. Validate configuration

    Note over ArgoCD,GL: Git 저장소 연결
    ArgoCD->>GL: 4. Test git connection<br/>http://192.168.0.11:7780/root/q-sign.git
    GL-->>ArgoCD: 5. Connection OK

    ArgoCD->>GL: 6. git clone --depth 1<br/>--branch main
    GL-->>ArgoCD: 7. Repository cloned

    Note over ArgoCD,K8s: Helm Chart 처리
    ArgoCD->>ArgoCD: 8. helm template q-sign ./helm/keycloak-pqc<br/>--values values.yaml
    ArgoCD->>ArgoCD: 9. Generate K8s manifests

    ArgoCD->>K8s: 10. kubectl get namespace q-sign
    K8s-->>ArgoCD: 11. Namespace not found

    ArgoCD->>K8s: 12. kubectl create namespace q-sign<br/>(CreateNamespace=true)
    K8s-->>ArgoCD: 13. Namespace created

    Note over ArgoCD,K8s: 초기 동기화
    ArgoCD->>K8s: 14. kubectl apply -f deployment.yaml
    ArgoCD->>K8s: 15. kubectl apply -f service.yaml
    ArgoCD->>K8s: 16. kubectl apply -f configmap.yaml

    K8s->>K8s: 17. Create resources
    K8s-->>ArgoCD: 18. Resources created

    ArgoCD->>ArgoCD: 19. Update app status:<br/>Synced, Healthy
    ArgoCD-->>Admin: 20. ✅ Application q-sign created
```

## 3. Auto-Sync 동기화

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer
    participant GL as GitLab
    participant ArgoCD as ArgoCD Controller
    participant K8s as Kubernetes

    Note over Dev,K8s: Helm Values 변경
    Dev->>GL: 1. Update values.yaml<br/>(replicaCount: 1 → 3)
    Dev->>GL: 2. git commit & push

    Note over ArgoCD,K8s: 자동 감지 (Polling)
    loop Every 3 minutes
        ArgoCD->>GL: 3. git fetch origin
        GL-->>ArgoCD: 4. Latest commit hash
    end

    ArgoCD->>ArgoCD: 5. Compare commit hashes<br/>(HEAD vs cached)
    ArgoCD->>ArgoCD: 6. ⚠️  Difference detected!

    Note over ArgoCD,K8s: Git Pull
    ArgoCD->>GL: 7. git pull origin main
    GL-->>ArgoCD: 8. Updated files

    Note over ArgoCD,K8s: Diff 분석
    ArgoCD->>ArgoCD: 9. helm template (new)
    ArgoCD->>K8s: 10. kubectl get deployment -o yaml
    K8s-->>ArgoCD: 11. Current deployment spec

    ArgoCD->>ArgoCD: 12. Diff analysis:<br/>spec.replicas: 1 → 3

    Note over ArgoCD,K8s: Auto-Sync 실행
    ArgoCD->>ArgoCD: 13. Check syncPolicy.automated
    ArgoCD->>ArgoCD: 14. ✅ Auto-sync enabled

    ArgoCD->>K8s: 15. kubectl apply -f deployment.yaml<br/>(replicas: 3)
    K8s->>K8s: 16. Scale deployment 1→3
    K8s->>K8s: 17. Create 2 new pods
    K8s-->>ArgoCD: 18. Scaled successfully

    ArgoCD->>ArgoCD: 19. Update sync status
    ArgoCD-->>Dev: 20. 📧 Sync completed (v1.2.3)
```

## 4. Self-Heal (자동 복구)

```mermaid
sequenceDiagram
    autonumber
    participant Ops as Operator (kubectl)
    participant K8s as Kubernetes
    participant ArgoCD as ArgoCD
    participant GL as GitLab

    Note over Ops,GL: 수동 변경 발생
    Ops->>K8s: 1. kubectl scale deployment keycloak<br/>--replicas=5
    K8s->>K8s: 2. Scale to 5 replicas
    K8s-->>Ops: 3. Deployment scaled

    Note over ArgoCD,GL: ArgoCD 감지
    ArgoCD->>K8s: 4. Periodic resource check<br/>(every 3 min)
    K8s-->>ArgoCD: 5. Current state: replicas=5

    ArgoCD->>GL: 6. git pull (desired state)
    GL-->>ArgoCD: 7. values.yaml: replicas=3

    ArgoCD->>ArgoCD: 8. Compare states<br/>Desired: 3 ≠ Actual: 5
    ArgoCD->>ArgoCD: 9. ⚠️  Drift detected!

    Note over ArgoCD,GL: Self-Heal 실행
    ArgoCD->>ArgoCD: 10. Check syncPolicy.selfHeal
    ArgoCD->>ArgoCD: 11. ✅ Self-heal enabled

    ArgoCD->>K8s: 12. kubectl apply -f deployment.yaml<br/>(force sync)
    K8s->>K8s: 13. Scale down 5→3
    K8s->>K8s: 14. Terminate 2 pods
    K8s-->>ArgoCD: 15. Restored to desired state

    ArgoCD->>ArgoCD: 16. Update status: Synced
    ArgoCD-->>Ops: 17. ⚠️  Manual change reverted<br/>(self-heal triggered)
```

## 5. Rollback (이전 버전 복원)

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin
    participant ArgoCD as ArgoCD
    participant GL as GitLab
    participant K8s as Kubernetes

    Note over Admin,K8s: 배포 이력 조회
    Admin->>ArgoCD: 1. argocd app history q-sign
    ArgoCD-->>Admin: 2. Revision history:<br/>ID 5: v1.0.3 (current) ❌<br/>ID 4: v1.0.2 ✅<br/>ID 3: v1.0.1

    Note over Admin,K8s: Rollback 실행
    Admin->>ArgoCD: 3. argocd app rollback q-sign 4

    ArgoCD->>GL: 4. git checkout <commit-4>
    GL-->>ArgoCD: 5. Previous commit files

    ArgoCD->>ArgoCD: 6. helm template (revision 4)
    ArgoCD->>ArgoCD: 7. Generate manifests (v1.0.2)

    Note over ArgoCD,K8s: 이전 버전 배포
    ArgoCD->>K8s: 8. kubectl apply -f deployment.yaml<br/>(image: v1.0.2)
    K8s->>K8s: 9. Rolling update<br/>v1.0.3 → v1.0.2
    K8s->>K8s: 10. Pull image: v1.0.2
    K8s->>K8s: 11. Create new pods (v1.0.2)
    K8s->>K8s: 12. Terminate old pods (v1.0.3)
    K8s-->>ArgoCD: 13. Rollback successful

    ArgoCD->>ArgoCD: 14. Create new history entry:<br/>ID 6: Rollback to v1.0.2
    ArgoCD-->>Admin: 15. ✅ Rolled back to revision 4
```

## 6. Blue-Green 배포

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin
    participant ArgoCD as ArgoCD
    participant K8s as Kubernetes
    participant LB as Load Balancer

    Note over Admin,LB: Green 환경 배포 (신규)
    Admin->>K8s: 1. Create green-deployment.yaml<br/>(replicas: 3, version: v2.0.0)
    K8s->>K8s: 2. Deploy green environment
    K8s-->>Admin: 3. Green pods running

    Note over Admin,LB: 헬스 체크
    Admin->>K8s: 4. kubectl get pods -l version=v2.0.0
    K8s-->>Admin: 5. All pods ready (3/3)

    Admin->>K8s: 6. Smoke tests on green
    K8s-->>Admin: 7. ✅ Tests passed

    Note over Admin,LB: 트래픽 전환
    Admin->>K8s: 8. kubectl patch service app<br/>selector: version=v2.0.0
    K8s->>LB: 9. Update service endpoints
    LB->>K8s: 10. Route traffic to green pods
    K8s-->>Admin: 11. Traffic switched

    Note over Admin,LB: 모니터링
    Admin->>K8s: 12. Monitor metrics (5 min)
    K8s-->>Admin: 13. No errors detected

    Note over Admin,LB: Blue 환경 제거
    Admin->>K8s: 14. kubectl delete deployment blue<br/>(version: v1.0.0)
    K8s->>K8s: 15. Terminate blue pods
    K8s-->>Admin: 16. ✅ Blue-green deployment complete
```

## 7. Canary 배포

```mermaid
sequenceDiagram
    autonumber
    participant ArgoCD as ArgoCD
    participant K8s as Kubernetes
    participant Prometheus as Prometheus
    participant Users as Users

    Note over ArgoCD,Users: Canary 시작 (10%)
    ArgoCD->>K8s: 1. Deploy canary<br/>(replicas: 1, weight: 10%)
    K8s->>K8s: 2. Create canary pods
    K8s->>K8s: 3. Update service mesh<br/>(90% stable, 10% canary)

    Users->>K8s: 4. Traffic (100%)
    K8s->>K8s: 5. Route 90% → stable
    K8s->>K8s: 6. Route 10% → canary

    Note over ArgoCD,Users: 메트릭 분석 (5분)
    K8s->>Prometheus: 7. Report metrics<br/>(error_rate, latency)
    Prometheus-->>ArgoCD: 8. Canary metrics:<br/>error_rate: 0.1%<br/>latency_p95: 150ms

    ArgoCD->>ArgoCD: 9. Analyze metrics<br/>vs baseline

    alt Metrics good
        Note over ArgoCD,Users: Canary 확대 (50%)
        ArgoCD->>K8s: 10a. Scale canary (replicas: 5)
        K8s->>K8s: 11a. Update weights<br/>(50% stable, 50% canary)

        Note over ArgoCD,Users: 최종 전환 (100%)
        ArgoCD->>K8s: 12a. Full rollout
        K8s->>K8s: 13a. Scale canary to 100%
        K8s->>K8s: 14a. Remove stable pods
        ArgoCD-->>ArgoCD: 15a. ✅ Canary successful
    else Metrics bad
        Note over ArgoCD,Users: 롤백
        ArgoCD->>K8s: 10b. Delete canary deployment
        K8s->>K8s: 11b. Route 100% → stable
        ArgoCD-->>ArgoCD: 12b. ❌ Canary failed, rolled back
    end
```

## 8. Multi-Environment 배포

```mermaid
sequenceDiagram
    autonumber
    participant Dev as Developer
    participant GL as GitLab
    participant ArgoCD as ArgoCD
    participant DevEnv as Dev Cluster
    participant StagingEnv as Staging Cluster
    participant ProdEnv as Prod Cluster

    Note over Dev,ProdEnv: 개발 환경 배포
    Dev->>GL: 1. git push origin develop
    ArgoCD->>GL: 2. Detect change (develop branch)
    ArgoCD->>DevEnv: 3. Deploy to dev namespace<br/>(replicas: 1, resources: low)
    DevEnv-->>ArgoCD: 4. ✅ Dev deployed

    Note over Dev,ProdEnv: 스테이징 환경 배포
    Dev->>GL: 5. git merge develop → staging
    ArgoCD->>GL: 6. Detect change (staging branch)
    ArgoCD->>StagingEnv: 7. Deploy to staging namespace<br/>(replicas: 2, resources: medium)
    StagingEnv-->>ArgoCD: 8. ✅ Staging deployed

    Note over Dev,ProdEnv: 통합 테스트
    Dev->>StagingEnv: 9. Run integration tests
    StagingEnv-->>Dev: 10. ✅ All tests passed

    Note over Dev,ProdEnv: 프로덕션 배포 (승인 필요)
    Dev->>GL: 11. Create merge request<br/>staging → main
    GL->>Dev: 12. ⏸️  Waiting for approval

    Dev->>GL: 13. Approve & merge
    ArgoCD->>GL: 14. Detect change (main branch)
    ArgoCD->>ArgoCD: 15. Wait for manual sync<br/>(auto-sync: false for prod)

    Dev->>ArgoCD: 16. argocd app sync q-sign-prod
    ArgoCD->>ProdEnv: 17. Deploy to production<br/>(replicas: 3, resources: high)
    ProdEnv->>ProdEnv: 18. Rolling update
    ProdEnv-->>ArgoCD: 19. ✅ Production deployed

    ArgoCD-->>Dev: 20. 📧 Deployment notification
```

## 🔄 GitOps 워크플로우 다이어그램

```mermaid
graph LR
    A[Developer] -->|1. Code| B[GitLab]
    B -->|2. Webhook| C[Jenkins CI]
    C -->|3. Build| D[Docker Image]
    D -->|4. Push| E[Harbor Registry]
    C -->|5. Update| B
    B -->|6. Poll| F[ArgoCD]
    F -->|7. Sync| G[Kubernetes]
    G -->|8. Pull| E
    F -->|9. Monitor| G
    G -->|10. Metrics| H[Prometheus]
    H -->|11. Alert| F
```

## 📊 배포 전략 비교

| 전략 | 다운타임 | 리소스 사용 | 롤백 속도 | 위험도 | 사용 사례 |
|------|----------|-------------|-----------|---------|-----------|
| Rolling Update | 없음 | 낮음 | 중간 | 중간 | 일반 배포 |
| Blue-Green | 없음 | 높음 (2배) | 빠름 | 낮음 | 중요 배포 |
| Canary | 없음 | 중간 | 빠름 | 낮음 | 신규 기능 |
| Recreate | 있음 | 낮음 | 느림 | 높음 | 개발 환경 |

## ⚙️ ArgoCD Sync 옵션

```yaml
syncPolicy:
  automated:
    prune: true           # 불필요한 리소스 삭제
    selfHeal: true        # 수동 변경 자동 복구
    allowEmpty: false     # 빈 커밋 허용 안함
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
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**GitOps Tool**: ArgoCD 3.2.0
