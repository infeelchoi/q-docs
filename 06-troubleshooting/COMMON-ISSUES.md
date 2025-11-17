# Common Issues

QSIGN 시스템 운영 중 발생할 수 있는 일반적인 문제와 해결 방법을 정리합니다.

## Pod 시작 실패

### Vault Pod이 시작되지 않음

**증상:**
```bash
kubectl get pods -n qsign
# vault-0   0/1   CrashLoopBackOff
```

**원인 및 해결방법:**

1. **스토리지 문제**
```bash
# PVC 상태 확인
kubectl get pvc -n qsign

# PV 상태 확인
kubectl get pv | grep vault

# 해결: PVC 재생성
kubectl delete pvc vault-data-vault-0 -n qsign
kubectl apply -f vault-pvc.yaml
```

2. **메모리 부족**
```bash
# Pod 이벤트 확인
kubectl describe pod vault-0 -n qsign

# 해결: 리소스 증가
kubectl edit statefulset vault -n qsign
# resources.limits.memory를 2Gi로 증가
```

3. **설정 오류**
```bash
# ConfigMap 확인
kubectl get configmap vault-config -n qsign -o yaml

# 로그 확인
kubectl logs vault-0 -n qsign

# 해결: 설정 수정 후 재배포
kubectl delete pod vault-0 -n qsign
```

### Keycloak Pod이 시작되지 않음

**증상:**
```bash
kubectl get pods -n qsign
# keycloak-0   0/1   Error
```

**원인 및 해결방법:**

1. **데이터베이스 연결 실패**
```bash
# 로그 확인
kubectl logs keycloak-0 -n qsign

# PostgreSQL 연결 테스트
kubectl run -it --rm psql-test --image=postgres:14 --restart=Never -- \
  psql -h postgres.qsign.svc.cluster.local -U keycloak -d keycloak

# 해결: Secret 확인 및 수정
kubectl get secret keycloak-db-secret -n qsign -o jsonpath='{.data.password}' | base64 -d
```

2. **초기화 실패**
```bash
# 초기화 로그 확인
kubectl logs keycloak-0 -n qsign -c init

# 해결: 데이터베이스 재초기화
kubectl exec -it postgres-0 -n qsign -- psql -U postgres
DROP DATABASE keycloak;
CREATE DATABASE keycloak;
\q

# Pod 재시작
kubectl delete pod keycloak-0 -n qsign
```

### SignServer Pod이 시작되지 않음

**증상:**
```bash
kubectl get pods -n qsign
# signserver-0   0/1   Init:Error
```

**원인 및 해결방법:**

1. **HSM 연결 실패**
```bash
# HSM 상태 확인
kubectl exec -it signserver-0 -n qsign -- pkcs11-tool --module /opt/nfast/toolkits/pkcs11/libcknfast.so -L

# 네트워크 확인
kubectl exec -it signserver-0 -n qsign -- nc -zv hsm-server 1500

# 해결: HSM 네트워크 설정 확인
kubectl get configmap signserver-config -n qsign -o yaml
```

2. **Vault 연결 실패**
```bash
# Vault 상태 확인
kubectl exec -it vault-0 -n qsign -- vault status

# 네트워크 확인
kubectl exec -it signserver-0 -n qsign -- nc -zv vault.qsign.svc.cluster.local 8200

# 해결: Vault unseal 수행
kubectl exec -it vault-0 -n qsign -- vault operator unseal
```

### Nginx Ingress Controller 문제

**증상:**
```bash
# 503 Service Temporarily Unavailable
```

**원인 및 해결방법:**

1. **백엔드 서비스 미준비**
```bash
# Endpoint 확인
kubectl get endpoints -n qsign

# Service 확인
kubectl describe service keycloak -n qsign

# 해결: Pod이 Ready 상태가 될 때까지 대기
kubectl wait --for=condition=ready pod -l app=keycloak -n qsign --timeout=300s
```

2. **Ingress 설정 오류**
```bash
# Ingress 확인
kubectl describe ingress qsign-ingress -n qsign

# 로그 확인
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# 해결: Ingress 재생성
kubectl delete ingress qsign-ingress -n qsign
kubectl apply -f ingress.yaml
```

## Vault Sealed

### Vault가 Sealed 상태

**증상:**
```bash
kubectl exec -it vault-0 -n qsign -- vault status
# Sealed: true
```

**해결방법:**

1. **수동 Unseal**
```bash
# Unseal Key로 unsealing (3개 필요)
kubectl exec -it vault-0 -n qsign -- vault operator unseal <UNSEAL_KEY_1>
kubectl exec -it vault-0 -n qsign -- vault operator unseal <UNSEAL_KEY_2>
kubectl exec -it vault-0 -n qsign -- vault operator unseal <UNSEAL_KEY_3>

# 상태 확인
kubectl exec -it vault-0 -n qsign -- vault status
```

2. **자동 Unseal 설정 (AWS KMS 사용)**
```hcl
# vault-config.hcl
seal "awskms" {
  region     = "ap-northeast-2"
  kms_key_id = "arn:aws:kms:ap-northeast-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}
```

3. **복구 불가능한 경우**
```bash
# Vault 재초기화 (주의: 모든 데이터 손실)
kubectl delete pod vault-0 -n qsign
kubectl delete pvc vault-data-vault-0 -n qsign

# 재배포
kubectl apply -f vault-statefulset.yaml

# 재초기화
kubectl exec -it vault-0 -n qsign -- vault operator init
```

### Vault 자동 Seal 발생

**증상:**
- Vault가 주기적으로 seal됨
- 서비스 중단 발생

**원인 및 해결방법:**

1. **메모리 부족으로 인한 재시작**
```bash
# Pod 재시작 이력 확인
kubectl get pod vault-0 -n qsign

# 메모리 사용량 확인
kubectl top pod vault-0 -n qsign

# 해결: 메모리 증가
kubectl edit statefulset vault -n qsign
# resources.limits.memory: 2Gi로 증가
```

2. **네트워크 문제**
```bash
# 네트워크 정책 확인
kubectl get networkpolicy -n qsign

# 해결: 필요한 통신 허용
kubectl apply -f network-policy.yaml
```

## Keycloak 연결 오류

### 로그인 실패

**증상:**
- 사용자가 로그인할 수 없음
- "Invalid username or password" 오류

**해결방법:**

1. **관리자 계정 초기화**
```bash
# 관리자 비밀번호 재설정
kubectl exec -it keycloak-0 -n qsign -- /opt/keycloak/bin/kc.sh \
  config credentials --server http://localhost:8080 \
  --realm master --user admin

# 새 비밀번호 설정
kubectl exec -it keycloak-0 -n qsign -- /opt/keycloak/bin/kcadm.sh \
  set-password --username admin --new-password NewPassword123!
```

2. **사용자 계정 확인**
```bash
# Keycloak 관리 콘솔 접속
https://keycloak.qsign.example.com/admin

# Users 메뉴에서 사용자 확인
# - Enabled: ON 확인
# - Email Verified: ON 확인
# - Credentials: 임시 비밀번호 재설정
```

### OIDC 인증 실패

**증상:**
```
SignServer unable to authenticate with Keycloak
Error: invalid_client
```

**해결방법:**

1. **Client Secret 확인**
```bash
# Keycloak Admin Console에서 확인
# Clients > signserver-client > Credentials > Client Secret

# SignServer Secret과 비교
kubectl get secret signserver-oidc-secret -n qsign -o jsonpath='{.data.client-secret}' | base64 -d

# 불일치 시 업데이트
kubectl create secret generic signserver-oidc-secret \
  --from-literal=client-secret=<NEW_SECRET> \
  --dry-run=client -o yaml | kubectl apply -n qsign -f -

# SignServer 재시작
kubectl rollout restart statefulset signserver -n qsign
```

2. **Redirect URI 확인**
```bash
# Keycloak Admin Console
# Clients > signserver-client > Settings > Valid Redirect URIs

# 올바른 URI 추가
https://signserver.qsign.example.com/*
https://signserver.qsign.example.com/signserver/oauth2callback
```

### 세션 타임아웃 문제

**증상:**
- 사용자가 자주 로그아웃됨
- 세션이 예상보다 빨리 만료됨

**해결방법:**

```bash
# Keycloak Admin Console
# Realm Settings > Sessions

# 설정 조정:
# - SSO Session Idle: 30 minutes -> 60 minutes
# - SSO Session Max: 10 hours -> 24 hours
# - Client Session Idle: 30 minutes -> 60 minutes
# - Client Session Max: 10 hours -> 24 hours

# 또는 CLI로 설정
kubectl exec -it keycloak-0 -n qsign -- /opt/keycloak/bin/kcadm.sh \
  update realms/qsign -s ssoSessionIdleTimeout=3600 -s ssoSessionMaxLifespan=86400
```

## HSM 문제

### HSM 연결 실패

**증상:**
```
CKR_DEVICE_ERROR
Failed to initialize PKCS#11 module
```

**해결방법:**

1. **네트워크 연결 확인**
```bash
# HSM 서버 연결 테스트
kubectl exec -it signserver-0 -n qsign -- nc -zv hsm-server 1500

# 방화벽 규칙 확인
kubectl exec -it signserver-0 -n qsign -- telnet hsm-server 1500

# 해결: 네트워크 정책 업데이트
kubectl apply -f hsm-network-policy.yaml
```

2. **HSM 클라이언트 설정**
```bash
# HSM 클라이언트 상태 확인
kubectl exec -it signserver-0 -n qsign -- /opt/nfast/bin/enquiry

# PKCS11 모듈 테스트
kubectl exec -it signserver-0 -n qsign -- \
  pkcs11-tool --module /opt/nfast/toolkits/pkcs11/libcknfast.so -L

# 해결: 클라이언트 재설정
kubectl exec -it signserver-0 -n qsign -- /opt/nfast/bin/configure-hsm
```

3. **인증서/키 문제**
```bash
# HSM에 저장된 키 확인
kubectl exec -it signserver-0 -n qsign -- \
  pkcs11-tool --module /opt/nfast/toolkits/pkcs11/libcknfast.so -O

# 키가 없는 경우 재생성
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh getkeystore -worker CryptoWorker
```

### HSM 성능 저하

**증상:**
- 서명 작업이 매우 느림
- 타임아웃 오류 발생

**해결방법:**

1. **HSM 상태 확인**
```bash
# HSM 로드 확인
kubectl exec -it signserver-0 -n qsign -- /opt/nfast/bin/nfkminfo

# HSM 세션 확인
kubectl exec -it signserver-0 -n qsign -- \
  pkcs11-tool --module /opt/nfast/toolkits/pkcs11/libcknfast.so --show-info
```

2. **연결 풀 증가**
```properties
# signserver.properties
crypto.token.p11.poolsize=10
crypto.token.p11.sessiontimeout=300000
```

3. **HSM 재시작**
```bash
# HSM 서버에서 (주의: 서비스 중단)
/opt/nfast/bin/stop-hardserver
/opt/nfast/bin/start-hardserver
```

## 네트워크 문제

### Pod 간 통신 실패

**증상:**
```
Connection refused
Connection timeout
```

**해결방법:**

1. **Service 확인**
```bash
# Service 존재 확인
kubectl get svc -n qsign

# Endpoint 확인
kubectl get endpoints -n qsign

# Service 상세 정보
kubectl describe svc vault -n qsign
```

2. **DNS 확인**
```bash
# DNS 테스트
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  nslookup vault.qsign.svc.cluster.local

# CoreDNS 로그 확인
kubectl logs -n kube-system -l k8s-app=kube-dns
```

3. **NetworkPolicy 확인**
```bash
# NetworkPolicy 확인
kubectl get networkpolicy -n qsign

# 특정 정책 상세 확인
kubectl describe networkpolicy allow-vault-access -n qsign

# 해결: 필요한 통신 허용
kubectl apply -f network-policy-fix.yaml
```

### 외부 접근 불가

**증상:**
- 브라우저에서 서비스 접근 불가
- "Connection timed out" 오류

**해결방법:**

1. **Ingress 확인**
```bash
# Ingress 상태 확인
kubectl get ingress -n qsign

# Ingress Controller 로그
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx

# 해결: Ingress 재생성
kubectl delete ingress qsign-ingress -n qsign
kubectl apply -f ingress.yaml
```

2. **LoadBalancer/NodePort 확인**
```bash
# Service 타입 확인
kubectl get svc -n ingress-nginx

# External IP 할당 확인
kubectl describe svc ingress-nginx-controller -n ingress-nginx

# 해결: LoadBalancer 서비스 재생성
kubectl delete svc ingress-nginx-controller -n ingress-nginx
kubectl apply -f ingress-nginx-svc.yaml
```

3. **방화벽 규칙 확인**
```bash
# 클라우드 제공자의 방화벽 규칙 확인
# AWS Security Group
# GCP Firewall Rules
# Azure NSG

# 80, 443 포트 허용 확인
```

### TLS/SSL 인증서 문제

**증상:**
```
SSL certificate problem: unable to get local issuer certificate
NET::ERR_CERT_AUTHORITY_INVALID
```

**해결방법:**

1. **인증서 확인**
```bash
# Secret 확인
kubectl get secret qsign-tls-cert -n qsign -o yaml

# 인증서 내용 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -text -noout

# 만료일 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -enddate -noout
```

2. **cert-manager 확인**
```bash
# Certificate 상태 확인
kubectl get certificate -n qsign

# CertificateRequest 확인
kubectl get certificaterequest -n qsign

# cert-manager 로그
kubectl logs -n cert-manager -l app=cert-manager

# 해결: Certificate 재발급
kubectl delete certificate qsign-tls -n qsign
kubectl apply -f certificate.yaml
```

3. **수동 인증서 업데이트**
```bash
# 새 인증서로 Secret 업데이트
kubectl create secret tls qsign-tls-cert \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  --dry-run=client -o yaml | kubectl apply -n qsign -f -

# Ingress Controller 재시작
kubectl rollout restart deployment ingress-nginx-controller -n ingress-nginx
```

## 데이터베이스 문제

### PostgreSQL 연결 실패

**증상:**
```
FATAL: password authentication failed for user "keycloak"
could not connect to server: Connection refused
```

**해결방법:**

1. **PostgreSQL Pod 상태 확인**
```bash
# Pod 확인
kubectl get pod postgres-0 -n qsign

# 로그 확인
kubectl logs postgres-0 -n qsign

# 재시작
kubectl delete pod postgres-0 -n qsign
```

2. **비밀번호 확인**
```bash
# Secret 확인
kubectl get secret postgres-secret -n qsign -o jsonpath='{.data.password}' | base64 -d

# 비밀번호 재설정
kubectl exec -it postgres-0 -n qsign -- psql -U postgres
ALTER USER keycloak WITH PASSWORD 'new_password';
\q

# Secret 업데이트
kubectl create secret generic postgres-secret \
  --from-literal=password=new_password \
  --dry-run=client -o yaml | kubectl apply -n qsign -f -
```

3. **연결 설정 확인**
```bash
# pg_hba.conf 확인
kubectl exec -it postgres-0 -n qsign -- cat /var/lib/postgresql/data/pg_hba.conf

# postgresql.conf 확인
kubectl exec -it postgres-0 -n qsign -- cat /var/lib/postgresql/data/postgresql.conf
```

### 데이터베이스 성능 저하

**증상:**
- 쿼리 실행이 매우 느림
- 연결 타임아웃 발생

**해결방법:**

1. **연결 수 확인**
```bash
# 현재 연결 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity;"

# 최대 연결 수 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SHOW max_connections;"

# 해결: max_connections 증가
kubectl exec -it postgres-0 -n qsign -- \
  sed -i 's/max_connections = 100/max_connections = 200/' \
  /var/lib/postgresql/data/postgresql.conf

# PostgreSQL 재시작
kubectl delete pod postgres-0 -n qsign
```

2. **디스크 I/O 확인**
```bash
# 디스크 사용량 확인
kubectl exec -it postgres-0 -n qsign -- df -h

# 느린 쿼리 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT query, calls, total_time, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"

# 해결: 인덱스 추가, VACUUM 실행
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -d keycloak -c "VACUUM ANALYZE;"
```

## 스토리지 문제

### PVC가 Bound되지 않음

**증상:**
```bash
kubectl get pvc -n qsign
# vault-data   Pending
```

**해결방법:**

1. **StorageClass 확인**
```bash
# StorageClass 존재 확인
kubectl get storageclass

# PVC 상세 정보
kubectl describe pvc vault-data -n qsign

# 해결: 올바른 StorageClass 지정
kubectl edit pvc vault-data -n qsign
# storageClassName을 사용 가능한 것으로 변경
```

2. **PV 수동 생성 (Static Provisioning)**
```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: vault-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  hostPath:
    path: /mnt/data/vault
```

### 디스크 용량 부족

**증상:**
```
no space left on device
write failed: No space left on device
```

**해결방법:**

1. **디스크 사용량 확인**
```bash
# Pod 내부 확인
kubectl exec -it vault-0 -n qsign -- df -h

# 큰 파일 찾기
kubectl exec -it vault-0 -n qsign -- du -sh /*
kubectl exec -it vault-0 -n qsign -- find /vault -type f -size +100M
```

2. **PVC 크기 확장**
```bash
# PVC 편집
kubectl edit pvc vault-data -n qsign
# storage: 10Gi -> 20Gi로 변경

# Pod 재시작 (필요한 경우)
kubectl delete pod vault-0 -n qsign
```

3. **불필요한 데이터 삭제**
```bash
# 로그 파일 정리
kubectl exec -it signserver-0 -n qsign -- find /opt/signserver/logs -name "*.log.*" -mtime +30 -delete

# 임시 파일 정리
kubectl exec -it signserver-0 -n qsign -- rm -rf /tmp/*
```

## 리소스 부족

### CPU/메모리 부족

**증상:**
```
Pod evicted due to insufficient resources
OOMKilled
CPU throttling detected
```

**해결방법:**

1. **현재 사용량 확인**
```bash
# 노드 리소스 확인
kubectl top nodes

# Pod 리소스 확인
kubectl top pods -n qsign

# 리소스 요청/제한 확인
kubectl describe pod signserver-0 -n qsign | grep -A 5 "Requests:"
```

2. **리소스 증가**
```bash
# Deployment/StatefulSet 편집
kubectl edit statefulset signserver -n qsign

# resources 섹션 수정
resources:
  requests:
    memory: "2Gi"
    cpu: "1000m"
  limits:
    memory: "4Gi"
    cpu: "2000m"
```

3. **노드 증설**
```bash
# 클라우드 제공자의 노드 그룹 크기 증가
# 또는 새 노드 추가

# 노드 확인
kubectl get nodes

# 새 노드에 Pod 재배치
kubectl drain <old-node> --ignore-daemonsets --delete-emptydir-data
```

## 참고 자료

- [Debug Guide](DEBUG-GUIDE.md) - 상세한 디버깅 방법론
- [FAQ](FAQ.md) - 자주 묻는 질문
- [Monitoring Guide](../04-operations/MONITORING.md) - 모니터링 설정
- [Backup & Recovery](../04-operations/BACKUP-RECOVERY.md) - 백업 및 복구
