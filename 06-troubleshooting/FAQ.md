# Frequently Asked Questions (FAQ)

QSIGN 시스템에 대한 자주 묻는 질문과 답변을 정리합니다.

## 목차

- [설치 및 설정](#설치-및-설정)
- [운영 관련](#운영-관련)
- [보안 관련](#보안-관련)
- [성능 관련](#성능-관련)
- [통합 관련](#통합-관련)
- [트러블슈팅](#트러블슈팅)

## 설치 및 설정

### Q1. QSIGN 설치에 필요한 최소 요구사항은?

**A:** 최소 요구사항은 다음과 같습니다:

**Kubernetes 클러스터:**
- Kubernetes 1.24 이상
- 3개 이상의 워커 노드 권장
- 노드당 최소 4 CPU, 8GB RAM

**스토리지:**
- Dynamic provisioning 지원 StorageClass
- 최소 100GB 이상의 사용 가능한 스토리지

**네트워크:**
- 클러스터 내부 통신을 위한 CNI 플러그인
- 외부 접근을 위한 Ingress Controller
- LoadBalancer 서비스 지원 (선택사항)

자세한 내용은 [Prerequisites](../01-getting-started/PREREQUISITES.md)를 참조하세요.

### Q2. Helm을 사용하지 않고 설치할 수 있나요?

**A:** 네, 가능합니다. 모든 구성 요소는 순수 Kubernetes 매니페스트로도 배포할 수 있습니다.

```bash
# kubectl로 직접 배포
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/vault/
kubectl apply -f k8s/keycloak/
kubectl apply -f k8s/signserver/
kubectl apply -f k8s/ingress/
```

Helm 차트는 편의성을 위해 제공되며, 필수는 아닙니다.

### Q3. 특정 구성 요소만 선택적으로 설치할 수 있나요?

**A:** 네, 가능합니다. 예를 들어 기존 Keycloak을 사용하는 경우:

```bash
# Keycloak 제외하고 설치
helm install qsign ./helm/qsign \
  --set keycloak.enabled=false \
  --set signserver.oidc.issuerUrl=https://your-keycloak.com/realms/qsign
```

또는 개별 구성 요소를 선택적으로 배포:

```bash
kubectl apply -f k8s/vault/
kubectl apply -f k8s/signserver/
# Keycloak 생략
```

### Q4. 개발 환경에서는 어떻게 설치하나요?

**A:** 개발 환경용 간소화된 설정을 사용할 수 있습니다:

```bash
# Minikube 사용
minikube start --cpus=4 --memory=8192

# 개발 모드로 설치 (단일 replica, 최소 리소스)
helm install qsign ./helm/qsign \
  --set global.environment=development \
  --set vault.replicas=1 \
  --set keycloak.replicas=1 \
  --set signserver.replicas=1 \
  --set resources.requests.memory=512Mi
```

[Quick Start](../01-getting-started/QUICKSTART.md)에서 상세한 개발 환경 설정을 확인하세요.

### Q5. HSM 없이도 QSIGN을 사용할 수 있나요?

**A:** 네, 소프트웨어 기반 암호화를 사용할 수 있습니다:

```properties
# signserver.properties
crypto.token.type=SOFT
crypto.token.implementation=org.signserver.server.cryptotokens.SoftCryptoToken
```

단, 프로덕션 환경에서는 보안 강화를 위해 HSM 사용을 강력히 권장합니다.

개발/테스트 목적으로만 소프트웨어 토큰을 사용하세요.

## 운영 관련

### Q6. QSIGN을 어떻게 업데이트하나요?

**A:** Rolling update를 통해 무중단 업데이트가 가능합니다:

```bash
# Helm 차트 업데이트
helm repo update
helm upgrade qsign qsign/qsign \
  --namespace qsign \
  --reuse-values \
  --version 1.1.0

# 또는 kubectl로 이미지 업데이트
kubectl set image statefulset/signserver \
  signserver=signserver:1.1.0 \
  -n qsign
```

주요 버전 업그레이드 시에는 [Upgrade Guide](../05-operations/UPGRADE-GUIDE.md)를 먼저 확인하세요.

### Q7. 백업은 어떻게 수행하나요?

**A:** 각 구성 요소별로 백업이 필요합니다:

**Vault 백업:**
```bash
kubectl exec -it vault-0 -n qsign -- vault operator raft snapshot save /tmp/vault-backup.snap
kubectl cp qsign/vault-0:/tmp/vault-backup.snap ./vault-backup-$(date +%Y%m%d).snap
```

**Keycloak 백업:**
```bash
# 데이터베이스 백업
kubectl exec -it postgres-0 -n qsign -- pg_dump -U keycloak keycloak > keycloak-backup-$(date +%Y%m%d).sql
```

**SignServer 백업:**
```bash
# 설정 백업
kubectl exec -it signserver-0 -n qsign -- /opt/signserver/bin/signserver.sh dumpproperties > signserver-config-$(date +%Y%m%d).properties
```

자세한 내용은 [Backup & Recovery](../05-operations/BACKUP-RECOVERY.md)를 참조하세요.

### Q8. 로그는 어디서 확인하나요?

**A:** 여러 방법으로 로그를 확인할 수 있습니다:

```bash
# kubectl로 실시간 로그 확인
kubectl logs -f signserver-0 -n qsign

# 최근 100줄 확인
kubectl logs --tail=100 signserver-0 -n qsign

# 이전 컨테이너 로그 확인 (crash 시)
kubectl logs signserver-0 -n qsign --previous

# 여러 Pod의 로그 확인
kubectl logs -l app=signserver -n qsign

# 중앙 로그 시스템 사용 (EFK 스택)
# Kibana 대시보드에서 확인
https://kibana.qsign.example.com
```

### Q9. 스케일링은 어떻게 하나요?

**A:** 수평 스케일링과 수직 스케일링 모두 가능합니다:

**수평 스케일링 (replica 증가):**
```bash
# SignServer replica 증가
kubectl scale statefulset signserver --replicas=5 -n qsign

# 또는 Helm values 업데이트
helm upgrade qsign qsign/qsign \
  --set signserver.replicas=5 \
  --reuse-values
```

**수직 스케일링 (리소스 증가):**
```bash
kubectl edit statefulset signserver -n qsign
# resources 섹션 수정 후 저장
# Pod이 자동으로 재시작됨
```

**자동 스케일링 (HPA):**
```bash
kubectl autoscale statefulset signserver \
  --min=2 --max=10 \
  --cpu-percent=70 \
  -n qsign
```

### Q10. 다중 클러스터 배포가 가능한가요?

**A:** 네, 여러 패턴으로 가능합니다:

**1. Active-Standby (DR 목적):**
- 주 클러스터: 프로덕션 트래픽 처리
- 대기 클러스터: 장애 시 전환

**2. Active-Active (지리적 분산):**
- 여러 지역에 독립적인 QSIGN 배포
- Global Load Balancer로 트래픽 분산
- Vault Enterprise의 Replication 기능 활용

**3. 하이브리드:**
- 온프레미스: 민감한 서명 작업
- 클라우드: 검증 및 관리 작업

자세한 아키텍처는 [Multi-Cluster Setup](../03-architecture/MULTI-CLUSTER.md)을 참조하세요.

## 보안 관련

### Q11. QSIGN의 보안 인증은?

**A:** QSIGN은 다음 보안 표준을 준수합니다:

- **FIPS 140-2**: HSM 사용 시
- **eIDAS**: EU 전자서명 규정 준수
- **Common Criteria**: EAL4+ 수준
- **ISO/IEC 27001**: 정보보안 관리

각 규정에 대한 준수 가이드는 [Compliance Guide](../04-security/COMPLIANCE.md)에서 확인하세요.

### Q12. 비밀번호와 인증서는 어떻게 관리하나요?

**A:** Vault를 사용하여 중앙 집중식으로 관리합니다:

**비밀번호 저장:**
```bash
kubectl exec -it vault-0 -n qsign -- vault kv put secret/signserver/db \
  username=signserver \
  password=SecurePassword123!
```

**인증서 관리:**
```bash
# PKI Secret Engine 활성화
kubectl exec -it vault-0 -n qsign -- vault secrets enable pki

# 루트 CA 생성
kubectl exec -it vault-0 -n qsign -- vault write pki/root/generate/internal \
  common_name="QSIGN Root CA" \
  ttl=87600h
```

**Dynamic Secrets:**
```bash
# 데이터베이스 동적 자격증명
kubectl exec -it vault-0 -n qsign -- vault read database/creds/signserver
```

### Q13. 감사 로그는 어떻게 관리하나요?

**A:** 여러 수준에서 감사 로그가 생성됩니다:

**SignServer 감사:**
```bash
# 서명 작업 감사
kubectl exec -it signserver-0 -n qsign -- \
  tail -f /opt/signserver/server/standalone/log/audit.log
```

**Vault 감사:**
```bash
# Vault 접근 감사
kubectl exec -it vault-0 -n qsign -- vault audit enable file file_path=/vault/audit/audit.log
kubectl exec -it vault-0 -n qsign -- tail -f /vault/audit/audit.log
```

**Keycloak 감사:**
```bash
# 인증 이벤트 감사
# Keycloak Admin Console > Events > Login Events
```

**Kubernetes 감사:**
```bash
# API 서버 감사 로그
kubectl logs -n kube-system kube-apiserver-<node-name>
```

모든 감사 로그는 중앙 로그 시스템(EFK/ELK)으로 수집하여 장기 보관하세요.

### Q14. 네트워크 보안은 어떻게 설정하나요?

**A:** 여러 계층에서 네트워크 보안을 적용합니다:

**1. NetworkPolicy로 Pod 간 통신 제한:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: signserver-netpol
spec:
  podSelector:
    matchLabels:
      app: signserver
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - port: 8080
```

**2. TLS/mTLS 사용:**
```yaml
# Service Mesh (Istio)로 자동 mTLS
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT
```

**3. 방화벽 규칙:**
- 클러스터 외부에서 필요한 포트만 허용
- 관리 인터페이스는 VPN/Bastion을 통해서만 접근

### Q15. 취약점 스캔은 어떻게 하나요?

**A:** 여러 도구를 사용하여 스캔합니다:

**컨테이너 이미지 스캔:**
```bash
# Trivy로 이미지 스캔
trivy image signserver:1.0.0

# Clair 사용
clairctl analyze signserver:1.0.0
```

**Kubernetes 설정 스캔:**
```bash
# kube-bench로 CIS 벤치마크 확인
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml
kubectl logs job/kube-bench

# kube-hunter로 취약점 스캔
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-hunter/main/job.yaml
```

**정기 스캔 자동화:**
```yaml
# CronJob으로 매일 스캔
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-scan
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trivy
            image: aquasec/trivy:latest
            args: ["image", "--severity", "HIGH,CRITICAL", "signserver:latest"]
```

## 성능 관련

### Q16. QSIGN의 서명 성능은?

**A:** 성능은 구성에 따라 다릅니다:

**소프트웨어 토큰:**
- RSA 2048: ~1000 signatures/sec
- ECDSA P-256: ~2000 signatures/sec
- EdDSA: ~5000 signatures/sec

**HSM (nCipher nShield):**
- RSA 2048: ~500 signatures/sec (단일 HSM)
- ECDSA P-256: ~1000 signatures/sec
- 병렬 처리 시 선형 확장 가능

**최적화 팁:**
```properties
# signserver.properties
worker.threads=50
crypto.token.p11.poolsize=10
database.pool.maxsize=100
```

자세한 성능 튜닝은 [Performance Guide](../05-operations/PERFORMANCE-TUNING.md)를 참조하세요.

### Q17. 병목 지점을 어떻게 찾나요?

**A:** 여러 모니터링 도구를 사용합니다:

**애플리케이션 레벨:**
```bash
# SignServer 통계 확인
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh getstatus brief all

# JMX 메트릭 확인
kubectl port-forward signserver-0 9990:9990 -n qsign
# JConsole로 localhost:9990 연결
```

**인프라 레벨:**
```bash
# Prometheus로 메트릭 수집
kubectl port-forward -n monitoring svc/prometheus 9090:9090

# Grafana 대시보드
kubectl port-forward -n monitoring svc/grafana 3000:3000
```

**프로파일링:**
```bash
# Java Flight Recorder
kubectl exec -it signserver-0 -n qsign -- \
  jcmd 1 JFR.start duration=60s filename=/tmp/recording.jfr
```

### Q18. 대용량 배치 서명을 어떻게 처리하나요?

**A:** 여러 전략을 조합합니다:

**1. 비동기 처리:**
```java
// REST API를 통한 비동기 서명 요청
POST /signserver/rest/v1/workers/PDFSigner/process/async
{
  "data": "base64-encoded-document"
}

// 작업 ID 반환
{"jobId": "12345"}

// 나중에 결과 조회
GET /signserver/rest/v1/jobs/12345
```

**2. 배치 서명:**
```bash
# 여러 문서를 한 번에 서명
signserver batch -worker PDFSigner -indir ./documents -outdir ./signed
```

**3. 병렬 처리:**
```bash
# SignServer replica 증가
kubectl scale statefulset signserver --replicas=10 -n qsign

# 로드 밸런서를 통해 요청 분산
```

**4. 메시지 큐 사용:**
```yaml
# RabbitMQ/Kafka로 작업 큐 구성
# Worker가 큐에서 작업을 가져와 처리
```

### Q19. 데이터베이스 성능 최적화는?

**A:** PostgreSQL 튜닝 가이드:

**1. 연결 풀 설정:**
```properties
# signserver.properties
database.pool.maxsize=100
database.pool.minsize=10
```

**2. 인덱스 추가:**
```sql
-- 자주 조회되는 컬럼에 인덱스
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_worker_id ON signatures(worker_id);
```

**3. PostgreSQL 튜닝:**
```conf
# postgresql.conf
max_connections = 200
shared_buffers = 2GB
effective_cache_size = 6GB
work_mem = 16MB
maintenance_work_mem = 512MB
```

**4. 파티셔닝:**
```sql
-- 대용량 테이블 파티셔닝
CREATE TABLE audit_log_2024 PARTITION OF audit_log
FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

### Q20. HSM 성능을 최대화하려면?

**A:** HSM 최적화 방법:

**1. 연결 풀 증가:**
```properties
crypto.token.p11.poolsize=20
crypto.token.p11.sessiontimeout=300000
```

**2. 여러 HSM 사용:**
```properties
# Load balancing across multiple HSMs
crypto.token.p11.library=/opt/nfast/toolkits/pkcs11/libcknfast.so
crypto.token.p11.slot=0,1,2,3
```

**3. 키 캐싱:**
```properties
# 키 핸들 캐싱으로 HSM 호출 최소화
crypto.token.cache.privatekeys=true
crypto.token.cache.certificates=true
```

**4. 네트워크 최적화:**
```bash
# HSM과 동일 데이터센터/가용영역 배치
# 저지연 네트워크 사용
```

## 통합 관련

### Q21. REST API는 어떻게 사용하나요?

**A:** SignServer REST API 사용 예:

**서명 요청:**
```bash
curl -X POST https://signserver.qsign.example.com/signserver/rest/v1/workers/PDFSigner/process \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": "base64-encoded-pdf-content",
    "encoding": "base64"
  }'
```

**Worker 상태 확인:**
```bash
curl https://signserver.qsign.example.com/signserver/rest/v1/workers/PDFSigner/status \
  -H "Authorization: Bearer $TOKEN"
```

**OpenAPI 문서:**
```
https://signserver.qsign.example.com/signserver/doc/api
```

자세한 API 문서는 [API Reference](../02-configuration/API-REFERENCE.md)를 참조하세요.

### Q22. 기존 애플리케이션과 통합하려면?

**A:** 여러 통합 방식을 지원합니다:

**1. REST API (권장):**
```java
// Java 클라이언트 예제
HttpClient client = HttpClient.newHttpClient();
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://signserver.qsign.example.com/signserver/rest/v1/workers/PDFSigner/process"))
    .header("Authorization", "Bearer " + token)
    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
    .build();
HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
```

**2. Java Client Library:**
```java
// SignServer Java Client
SignServerWSClientFactory factory = new SignServerWSClientFactory();
ProcessSessionRemote session = factory.getProcessSession();
GenericSignResponse response = (GenericSignResponse) session.process(
    new WorkerIdentifier("PDFSigner"),
    new GenericSignRequest(requestId, documentBytes),
    new RemoteRequestContext()
);
```

**3. CLI:**
```bash
# 명령줄에서 직접 사용
signserver signdocument \
  -host signserver.qsign.example.com \
  -port 443 \
  -worker PDFSigner \
  -infile document.pdf \
  -outfile signed.pdf
```

### Q23. CI/CD 파이프라인에서 사용하려면?

**A:** CI/CD 통합 예제:

**GitHub Actions:**
```yaml
name: Sign Release
on:
  release:
    types: [created]

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
    - name: Download artifact
      uses: actions/download-artifact@v2
      with:
        name: my-app

    - name: Sign with QSIGN
      run: |
        curl -X POST https://signserver.qsign.example.com/signserver/rest/v1/workers/CodeSigner/process \
          -H "Authorization: Bearer ${{ secrets.QSIGN_TOKEN }}" \
          -H "Content-Type: application/json" \
          -d "{\"data\": \"$(base64 -w0 my-app.exe)\"}" \
          | jq -r '.data' | base64 -d > my-app-signed.exe

    - name: Upload signed artifact
      uses: actions/upload-artifact@v2
      with:
        name: signed-app
        path: my-app-signed.exe
```

**GitLab CI:**
```yaml
sign:
  stage: sign
  script:
    - curl -X POST https://signserver.qsign.example.com/signserver/rest/v1/workers/CodeSigner/process
        -H "Authorization: Bearer $QSIGN_TOKEN"
        -F "file=@my-app.exe"
        -o my-app-signed.exe
  artifacts:
    paths:
      - my-app-signed.exe
```

### Q24. 다른 PKI 시스템과 통합이 가능한가요?

**A:** 네, 여러 PKI 시스템과 통합 가능합니다:

**EJBCA 통합:**
```properties
# SignServer에서 EJBCA CA 사용
ca.implementation=org.signserver.server.validators.EJBCAValidator
ca.ejbca.url=https://ejbca.example.com/ejbca/publicweb/webdist/certdist
```

**Microsoft AD CS:**
```properties
# AD CS에서 발급한 인증서 사용
crypto.token.keystorepath=/path/to/keystore.p12
crypto.token.keystorepassword=password
```

**외부 CA와 CSR 워크플로우:**
```bash
# 1. CSR 생성
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh generatekey \
    -worker CryptoWorker \
    -keyalg RSA \
    -keyspec 2048 \
    -alias mykey

kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh generatecertreq \
    -worker CryptoWorker \
    -alias mykey \
    -dn "CN=SignServer,O=QSIGN,C=KR"

# 2. 외부 CA에 CSR 제출 및 인증서 수령

# 3. 인증서 설치
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh installcert \
    -worker CryptoWorker \
    -certfile received-cert.pem
```

### Q25. 클라우드 네이티브 서비스와 통합하려면?

**A:** 주요 클라우드 서비스 통합:

**AWS:**
```yaml
# AWS KMS로 Vault auto-unseal
seal "awskms" {
  region     = "ap-northeast-2"
  kms_key_id = "arn:aws:kms:ap-northeast-2:123456789012:key/12345678"
}

# S3에 백업
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-to-s3
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: amazon/aws-cli
            command:
            - /bin/sh
            - -c
            - aws s3 cp /backup/vault-$(date +%Y%m%d).snap s3://qsign-backups/
```

**Azure:**
```yaml
# Azure Key Vault 통합
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-keyvault
spec:
  provider: azure
  parameters:
    keyvaultName: "qsign-keyvault"
    objects: |
      array:
        - |
          objectName: signserver-db-password
          objectType: secret
```

**GCP:**
```yaml
# GCP KMS로 암호화
apiVersion: v1
kind: Secret
metadata:
  name: signserver-secret
  annotations:
    kms.gcp.io/key: projects/PROJECT_ID/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY
```

## 트러블슈팅

### Q26. Pod이 시작되지 않으면?

**A:** 체계적으로 디버깅하세요:

```bash
# 1. Pod 상태 확인
kubectl get pod signserver-0 -n qsign

# 2. 상세 이벤트 확인
kubectl describe pod signserver-0 -n qsign

# 3. 로그 확인
kubectl logs signserver-0 -n qsign
kubectl logs signserver-0 -n qsign --previous  # 이전 컨테이너 로그

# 4. Init Container 로그 확인
kubectl logs signserver-0 -n qsign -c init-vault

# 5. 리소스 확인
kubectl top nodes
kubectl top pods -n qsign

# 6. PVC 확인
kubectl get pvc -n qsign
kubectl describe pvc signserver-data -n qsign
```

일반적인 문제는 [Common Issues](COMMON-ISSUES.md)를 참조하세요.

### Q27. 성능이 갑자기 저하되면?

**A:** 성능 진단 절차:

```bash
# 1. 현재 부하 확인
kubectl top pods -n qsign
kubectl top nodes

# 2. 애플리케이션 메트릭 확인
# Prometheus/Grafana 대시보드

# 3. 데이터베이스 성능 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# 4. 네트워크 레이턴시 확인
kubectl exec -it signserver-0 -n qsign -- \
  ping -c 10 vault.qsign.svc.cluster.local

# 5. HSM 상태 확인 (사용 시)
kubectl exec -it signserver-0 -n qsign -- \
  /opt/nfast/bin/enquiry
```

상세한 디버깅 가이드는 [Debug Guide](DEBUG-GUIDE.md)를 참조하세요.

### Q28. 인증서 오류가 발생하면?

**A:** 인증서 문제 해결:

```bash
# 1. 인증서 확인
kubectl exec -it signserver-0 -n qsign -- \
  openssl s_client -connect vault.qsign.svc.cluster.local:8200 -showcerts

# 2. 인증서 만료일 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -enddate -noout

# 3. CA 체인 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -text -noout

# 4. 인증서 재발급
kubectl delete certificate qsign-tls -n qsign
kubectl apply -f certificate.yaml

# 5. 수동 갱신 (cert-manager 사용 시)
kubectl annotate certificate qsign-tls -n qsign \
  cert-manager.io/issue-temporary-certificate="true" --overwrite
```

### Q29. Vault가 sealed 상태면?

**A:** Vault unsealing:

```bash
# 1. 상태 확인
kubectl exec -it vault-0 -n qsign -- vault status

# 2. Unseal (unseal key 3개 필요)
kubectl exec -it vault-0 -n qsign -- vault operator unseal <KEY1>
kubectl exec -it vault-0 -n qsign -- vault operator unseal <KEY2>
kubectl exec -it vault-0 -n qsign -- vault operator unseal <KEY3>

# 3. 상태 재확인
kubectl exec -it vault-0 -n qsign -- vault status
# Sealed: false 확인

# 4. 자동 unseal 설정 (권장)
# vault-config.hcl에 auto-unseal 설정 추가
```

Vault 관련 문제는 [Common Issues - Vault Sealed](COMMON-ISSUES.md#vault-sealed)를 참조하세요.

### Q30. 도움을 받으려면?

**A:** 여러 지원 채널이 있습니다:

**문서:**
- [QSIGN Documentation](../README.md)
- [SignServer Documentation](https://doc.primekey.com/signserver)
- [Vault Documentation](https://www.vaultproject.io/docs)
- [Keycloak Documentation](https://www.keycloak.org/documentation)

**커뮤니티:**
- GitHub Issues: https://github.com/your-org/qsign/issues
- Community Forum: https://community.qsign.example.com
- Slack Channel: https://qsign.slack.com

**상용 지원:**
- Technical Support: support@qsign.example.com
- Enterprise Support: 24/7 SLA 포함

**버그 리포트 시 포함할 정보:**
```bash
# 시스템 정보 수집
kubectl version
kubectl get nodes -o wide

# QSIGN 상태
kubectl get all -n qsign
kubectl describe pod <pod-name> -n qsign
kubectl logs <pod-name> -n qsign

# 설정 정보 (민감한 정보 제거 후)
kubectl get configmap -n qsign -o yaml
```

## 추가 리소스

- [Common Issues](COMMON-ISSUES.md) - 일반적인 문제 해결
- [Debug Guide](DEBUG-GUIDE.md) - 디버깅 방법론
- [Operations Guide](../05-operations/README.md) - 운영 가이드
- [Security Guide](../04-security/README.md) - 보안 가이드
