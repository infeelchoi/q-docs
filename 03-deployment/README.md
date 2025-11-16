# 배포 가이드

QSIGN 시스템 배포 및 GitOps 관련 문서입니다.

## 📖 문서 목록

- [GITOPS-DEPLOYMENT.md](./GITOPS-DEPLOYMENT.md) - GitOps 배포 가이드
- ARGOCD-SETUP.md - ArgoCD 설정 및 관리
- KUBERNETES-DEPLOYMENT.md - Kubernetes 배포 상세
- HELM-CHARTS.md - Helm Chart 작성 가이드

## 🚀 빠른 배포

```bash
# ArgoCD 애플리케이션 생성
kubectl apply -f Q-SIGN/argocd/application.yaml
kubectl apply -f Q-KMS/argocd/q-kms-application.yaml
kubectl apply -f Q-APP/argocd/q-app-application.yaml

# 동기화 상태 확인
argocd app list
argocd app get q-sign
```

## 🔗 관련 문서

- [아키텍처 개요](../01-architecture/)
- [운영 가이드](../04-operations/)
