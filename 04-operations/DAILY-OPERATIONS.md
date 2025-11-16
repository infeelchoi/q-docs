# 일상 운영 작업

QSIGN 시스템의 일상적인 운영 작업 가이드입니다.

## 목차
- [일일 점검 체크리스트](#일일-점검-체크리스트)
- [Health Check](#health-check)
- [로그 확인](#로그-확인)
- [리소스 모니터링](#리소스-모니터링)
- [정기 점검 사항](#정기-점검-사항)
- [일반적인 문제 해결](#일반적인-문제-해결)

---

## 일일 점검 체크리스트

### 오전 점검 (9:00 AM)

```bash
#!/bin/bash
# daily-morning-check.sh

echo "=== QSIGN 일일 오전 점검 시작 ==="
echo "점검 시간: $(date)"

# 1. 전체 Pod 상태 확인
echo -e "\n[1] Pod 상태 확인"
kubectl get pods -n qsign

# 2. 주요 서비스 Health Check
echo -e "\n[2] Health Check"
for service in api-server signature-service hsm-adapter vault; do
    echo "Checking $service..."
    kubectl exec -n qsign deployment/$service -- curl -s http://localhost:8080/health
done

# 3. 리소스 사용률
echo -e "\n[3] 리소스 사용률"
kubectl top nodes
kubectl top pods -n qsign

# 4. 최근 1시간 에러 로그
echo -e "\n[4] 에러 로그 (최근 1시간)"
kubectl logs -n qsign -l app=api-server --since=1h | grep -i error | tail -20

# 5. Vault 상태
echo -e "\n[5] Vault 상태"
kubectl exec -n qsign vault-0 -- vault status

echo -e "\n=== 점검 완료 ==="
```

### 주요 점검 항목

#### 1. 시스템 가용성
- [ ] 모든 Pod가 Running 상태
- [ ] Replica 개수가 정상 (최소 2개 이상)
- [ ] LoadBalancer/Ingress 정상 동작
- [ ] Health Check 엔드포인트 200 OK

#### 2. 성능 지표
- [ ] CPU 사용률 < 70%
- [ ] 메모리 사용률 < 80%
- [ ] API 응답 시간 < 200ms (평균)
- [ ] 서명 처리 시간 < 500ms (평균)

#### 3. 보안
- [ ] Vault Seal 상태 확인
- [ ] HSM 연결 상태 확인
- [ ] 인증서 만료일 체크 (30일 이내)
- [ ] 비정상 접근 시도 확인

#### 4. 데이터
- [ ] PostgreSQL 백업 완료 확인
- [ ] 디스크 사용률 < 80%
- [ ] 서명 요청/완료 통계 확인
- [ ] 감사 로그 정상 기록 확인

---

## Health Check

### Kubernetes Liveness/Readiness Probe

각 서비스는 다음 Health Check 엔드포인트를 제공합니다:

```yaml
# Liveness Probe
GET /health/live
Response: 200 OK
{
  "status": "UP",
  "timestamp": "2025-11-16T09:00:00Z"
}

# Readiness Probe
GET /health/ready
Response: 200 OK
{
  "status": "UP",
  "checks": {
    "database": "UP",
    "vault": "UP",
    "hsm": "UP"
  }
}
```

### 수동 Health Check

```bash
# API Server Health Check
curl http://api-server.qsign.svc.cluster.local:8080/health

# Signature Service Health Check
curl http://signature-service.qsign.svc.cluster.local:8080/health

# HSM Adapter Health Check
curl http://hsm-adapter.qsign.svc.cluster.local:8080/health

# Vault Health Check
kubectl exec -n qsign vault-0 -- vault status

# PostgreSQL Health Check
kubectl exec -n qsign postgresql-0 -- psql -U qsign -c "SELECT 1;"
```

### Health Check 스크립트

```bash
#!/bin/bash
# health-check-all.sh

SERVICES=("api-server" "signature-service" "hsm-adapter" "vault")
NAMESPACE="qsign"

for service in "${SERVICES[@]}"; do
    echo "Checking $service..."

    # Pod 상태 확인
    POD_STATUS=$(kubectl get pods -n $NAMESPACE -l app=$service -o jsonpath='{.items[0].status.phase}')

    if [ "$POD_STATUS" != "Running" ]; then
        echo "  ERROR: Pod is not running (Status: $POD_STATUS)"
        continue
    fi

    # Health 엔드포인트 확인
    HTTP_CODE=$(kubectl exec -n $NAMESPACE deployment/$service -- \
        curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health/ready)

    if [ "$HTTP_CODE" = "200" ]; then
        echo "  OK: Health check passed"
    else
        echo "  ERROR: Health check failed (HTTP $HTTP_CODE)"
    fi
done
```

---

## 로그 확인

### 로그 조회 명령어

#### 실시간 로그 모니터링

```bash
# API Server 로그
kubectl logs -n qsign -f deployment/api-server

# Signature Service 로그
kubectl logs -n qsign -f deployment/signature-service

# 특정 Pod 로그
kubectl logs -n qsign -f api-server-7d9f8b6c5d-x7k2m

# 여러 Pod 로그 (라벨 선택)
kubectl logs -n qsign -f -l app=api-server --max-log-requests=10
```

#### 시간 범위 로그

```bash
# 최근 1시간 로그
kubectl logs -n qsign deployment/api-server --since=1h

# 최근 100줄
kubectl logs -n qsign deployment/api-server --tail=100

# 특정 시간 이후
kubectl logs -n qsign deployment/api-server --since-time=2025-11-16T09:00:00Z
```

#### 에러 로그 필터링

```bash
# ERROR 레벨 로그만
kubectl logs -n qsign -l app=api-server | grep "ERROR"

# 서명 실패 로그
kubectl logs -n qsign -l app=signature-service | grep "signature failed"

# HSM 연결 에러
kubectl logs -n qsign -l app=hsm-adapter | grep -E "(HSM|connection|timeout)"

# 에러 로그 카운트
kubectl logs -n qsign -l app=api-server --since=1h | grep -c "ERROR"
```

### 로그 분석 스크립트

```bash
#!/bin/bash
# log-analysis.sh

NAMESPACE="qsign"
SINCE="1h"

echo "=== QSIGN 로그 분석 (최근 $SINCE) ==="

# 에러 로그 통계
echo -e "\n[에러 발생 건수]"
for app in api-server signature-service hsm-adapter; do
    COUNT=$(kubectl logs -n $NAMESPACE -l app=$app --since=$SINCE 2>/dev/null | grep -c "ERROR")
    echo "$app: $COUNT"
done

# 서명 요청 통계
echo -e "\n[서명 요청 통계]"
TOTAL=$(kubectl logs -n $NAMESPACE -l app=signature-service --since=$SINCE | grep -c "Signature request received")
SUCCESS=$(kubectl logs -n $NAMESPACE -l app=signature-service --since=$SINCE | grep -c "Signature completed")
FAILED=$(kubectl logs -n $NAMESPACE -l app=signature-service --since=$SINCE | grep -c "Signature failed")

echo "총 요청: $TOTAL"
echo "성공: $SUCCESS"
echo "실패: $FAILED"

# 응답 시간 분석
echo -e "\n[평균 응답 시간]"
kubectl logs -n $NAMESPACE -l app=api-server --since=$SINCE | \
    grep "Response time" | \
    awk '{sum+=$NF; count++} END {if(count>0) print sum/count "ms"; else print "N/A"}'

# 최다 발생 에러
echo -e "\n[최다 발생 에러 TOP 5]"
kubectl logs -n $NAMESPACE --all-containers --since=$SINCE | \
    grep "ERROR" | \
    awk -F': ' '{print $2}' | \
    sort | uniq -c | sort -rn | head -5
```

### 로그 보존 정책

```yaml
# Loki 로그 보존 설정
apiVersion: v1
kind: ConfigMap
metadata:
  name: loki-config
  namespace: qsign
data:
  loki.yaml: |
    schema_config:
      configs:
        - from: 2024-01-01
          store: boltdb-shipper
          object_store: s3
          schema: v11
          index:
            prefix: loki_index_
            period: 24h

    limits_config:
      retention_period: 90d    # 90일 보존

    compactor:
      retention_enabled: true
      retention_delete_delay: 2h
```

---

## 리소스 모니터링

### CPU/메모리 모니터링

```bash
# 노드 리소스 사용률
kubectl top nodes

# Pod 리소스 사용률
kubectl top pods -n qsign

# 특정 Pod 상세 모니터링
kubectl top pod -n qsign api-server-7d9f8b6c5d-x7k2m --containers

# 리소스 사용률 정렬
kubectl top pods -n qsign --sort-by=cpu
kubectl top pods -n qsign --sort-by=memory
```

### 리소스 모니터링 스크립트

```bash
#!/bin/bash
# resource-monitor.sh

NAMESPACE="qsign"
CPU_THRESHOLD=70
MEM_THRESHOLD=80

echo "=== QSIGN 리소스 모니터링 ==="

# Pod별 리소스 사용률
kubectl top pods -n $NAMESPACE --no-headers | while read pod cpu mem; do
    cpu_value=${cpu%m}  # Remove 'm' suffix
    mem_value=${mem%Mi} # Remove 'Mi' suffix

    # CPU 임계값 체크
    if [ "$cpu_value" -gt "$CPU_THRESHOLD" ]; then
        echo "WARNING: $pod CPU usage high: $cpu"
    fi

    # 메모리 임계값 체크 (예: 500Mi 제한 기준)
    if [ "$mem_value" -gt "$((500 * MEM_THRESHOLD / 100))" ]; then
        echo "WARNING: $pod Memory usage high: $mem"
    fi
done

# 노드별 리소스
echo -e "\n[노드 리소스]"
kubectl top nodes
```

### Persistent Volume 모니터링

```bash
# PV/PVC 상태 확인
kubectl get pv,pvc -n qsign

# PVC 사용량 확인
kubectl exec -n qsign postgresql-0 -- df -h /var/lib/postgresql/data

# 디스크 사용률 알림 스크립트
#!/bin/bash
DISK_USAGE=$(kubectl exec -n qsign postgresql-0 -- df -h /var/lib/postgresql/data | tail -1 | awk '{print $5}' | sed 's/%//')

if [ "$DISK_USAGE" -gt 80 ]; then
    echo "ALERT: PostgreSQL disk usage is ${DISK_USAGE}%"
    # 알림 전송 (Slack, Email 등)
fi
```

### 네트워크 모니터링

```bash
# Service 엔드포인트 확인
kubectl get endpoints -n qsign

# Service 트래픽 확인 (Istio/Linkerd 사용 시)
kubectl top pods -n qsign --containers | grep envoy

# 네트워크 정책 확인
kubectl get networkpolicies -n qsign
```

---

## 정기 점검 사항

### 일일 점검 (Daily)

#### 1. 시스템 상태 점검
```bash
# 전체 Pod 상태
kubectl get pods -n qsign

# 이벤트 확인 (에러/경고)
kubectl get events -n qsign --sort-by='.lastTimestamp' | grep -E '(Warning|Error)'
```

#### 2. 백업 확인
```bash
# PostgreSQL 백업 확인
kubectl logs -n qsign cronjob/postgresql-backup | tail -20

# Vault 백업 확인
kubectl get cronjob -n qsign vault-backup -o yaml | grep lastScheduleTime
```

#### 3. 로그 확인
- 에러 로그 리뷰
- 서명 실패 건 분석
- 보안 이벤트 확인

### 주간 점검 (Weekly)

#### 1. 성능 분석
```bash
# 주간 성능 리포트 생성
#!/bin/bash
START_DATE=$(date -d '7 days ago' +%Y-%m-%dT00:00:00Z)
END_DATE=$(date +%Y-%m-%dT23:59:59Z)

echo "=== QSIGN 주간 성능 리포트 ==="
echo "기간: $START_DATE ~ $END_DATE"

# Prometheus 쿼리 (평균 응답 시간)
curl -s "http://prometheus:9090/api/v1/query" \
  --data-urlencode 'query=rate(http_request_duration_seconds_sum[7d])/rate(http_request_duration_seconds_count[7d])' \
  | jq '.data.result[]'
```

#### 2. 용량 계획
```bash
# 디스크 사용 추세
kubectl exec -n qsign postgresql-0 -- du -sh /var/lib/postgresql/data

# 서명 요청 증가 추세
# (Grafana 대시보드 확인)
```

#### 3. 보안 점검
- 비정상 접근 패턴 분석
- 실패한 인증 시도 확인
- Vault Audit 로그 리뷰

### 월간 점검 (Monthly)

#### 1. 인증서 만료일 확인
```bash
#!/bin/bash
# check-certificates.sh

echo "=== 인증서 만료일 점검 ==="

# TLS 인증서
kubectl get secret -n qsign -o json | \
  jq -r '.items[] | select(.type=="kubernetes.io/tls") | .metadata.name' | \
  while read cert; do
    EXPIRY=$(kubectl get secret -n qsign $cert -o json | \
      jq -r '.data."tls.crt"' | base64 -d | \
      openssl x509 -noout -enddate | cut -d= -f2)
    echo "$cert: $EXPIRY"
  done

# HSM 인증서
kubectl exec -n qsign deployment/hsm-adapter -- \
  openssl x509 -in /etc/hsm/client-cert.pem -noout -enddate
```

#### 2. 용량 확장 검토
- 리소스 사용 추세 분석
- HPA 메트릭 리뷰
- 스토리지 확장 필요성 평가

#### 3. 재해 복구 테스트
```bash
# 백업/복구 테스트
# 1. 테스트 환경에 백업 복원
# 2. 데이터 무결성 검증
# 3. 복구 시간 측정
```

#### 4. 보안 업데이트
```bash
# 이미지 취약점 스캔
trivy image qsign/api-server:latest
trivy image qsign/signature-service:latest

# Kubernetes 버전 확인
kubectl version --short

# 의존성 업데이트 확인
# (package.json, go.mod, requirements.txt 등)
```

### 분기별 점검 (Quarterly)

#### 1. 재해 복구 훈련 (DR Drill)
- 전체 시스템 복구 시뮬레이션
- RTO/RPO 달성 확인
- 복구 절차 문서 업데이트

#### 2. 보안 감사
- 접근 권한 리뷰
- RBAC 정책 점검
- 감사 로그 분석
- 취약점 스캔 및 패치

#### 3. 성능 최적화
- 데이터베이스 인덱스 최적화
- 쿼리 성능 분석
- 캐시 효율성 검토

#### 4. 아키텍처 리뷰
- 스케일링 전략 검토
- 단일 장애점 분석
- 비용 최적화 기회 탐색

---

## 일반적인 문제 해결

### Pod가 시작되지 않는 경우

```bash
# Pod 상태 확인
kubectl describe pod -n qsign <pod-name>

# 일반적인 원인
# 1. Image Pull 실패
kubectl get pods -n qsign | grep ImagePullBackOff

# 2. 리소스 부족
kubectl describe nodes | grep -A 5 "Allocated resources"

# 3. ConfigMap/Secret 누락
kubectl get configmap,secret -n qsign

# 해결방법
# - Image 경로 확인
# - 노드 리소스 확보
# - 필요한 ConfigMap/Secret 생성
```

### Health Check 실패

```bash
# Readiness Probe 실패 확인
kubectl describe pod -n qsign <pod-name> | grep -A 10 "Readiness"

# 로그에서 원인 파악
kubectl logs -n qsign <pod-name> --previous

# 일반적인 원인
# 1. Database 연결 실패
# 2. Vault Unsealed 상태
# 3. HSM 연결 끊김

# 의존성 서비스 확인
kubectl get pods -n qsign -l app=postgresql
kubectl exec -n qsign vault-0 -- vault status
```

### 높은 메모리 사용률

```bash
# 메모리 사용 Pod 확인
kubectl top pods -n qsign --sort-by=memory

# 메모리 프로파일링 (Java 예시)
kubectl exec -n qsign <pod-name> -- jmap -heap 1

# 해결방법
# 1. 메모리 제한 증가
kubectl set resources deployment -n qsign api-server --limits=memory=1Gi

# 2. HPA로 스케일 아웃
kubectl autoscale deployment -n qsign api-server --cpu-percent=70 --min=2 --max=10
```

### Vault Sealed 상태

```bash
# Vault 상태 확인
kubectl exec -n qsign vault-0 -- vault status

# Unseal 수행
kubectl exec -n qsign vault-0 -- vault operator unseal <unseal-key-1>
kubectl exec -n qsign vault-0 -- vault operator unseal <unseal-key-2>
kubectl exec -n qsign vault-0 -- vault operator unseal <unseal-key-3>

# Auto-unseal 설정 (HSM/KMS)
# vault.yaml에 seal "awskms" 또는 seal "pkcs11" 설정
```

### Database 연결 실패

```bash
# PostgreSQL 상태 확인
kubectl get pods -n qsign -l app=postgresql

# 연결 테스트
kubectl exec -n qsign postgresql-0 -- psql -U qsign -c "SELECT 1;"

# 연결 설정 확인
kubectl get secret -n qsign postgresql-secret -o jsonpath='{.data.connection-string}' | base64 -d

# 해결방법
# 1. PostgreSQL Pod 재시작
kubectl rollout restart statefulset -n qsign postgresql

# 2. 연결 풀 설정 확인
# application.yaml의 datasource.hikari 설정 확인
```

### 느린 응답 시간

```bash
# 응답 시간 모니터링
kubectl logs -n qsign -l app=api-server | grep "Response time" | tail -50

# 병목 지점 확인
# 1. Database 쿼리 시간
# 2. HSM 서명 시간
# 3. Vault 키 조회 시간

# 해결방법
# 1. Database 인덱스 추가
# 2. 캐싱 활성화
# 3. Connection Pool 크기 조정
# 4. 수평 확장 (Replica 증가)
```

---

## 운영 자동화

### 자동화된 일일 점검

```yaml
# CronJob: 일일 Health Check
apiVersion: batch/v1
kind: CronJob
metadata:
  name: daily-health-check
  namespace: qsign
spec:
  schedule: "0 9 * * *"  # 매일 오전 9시
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: health-checker
            image: curlimages/curl:latest
            command:
            - /bin/sh
            - -c
            - |
              echo "=== Daily Health Check ==="
              for svc in api-server signature-service hsm-adapter; do
                echo "Checking $svc..."
                curl -f http://$svc:8080/health || exit 1
              done
              echo "All services healthy!"
          restartPolicy: OnFailure
```

### 알림 설정

```yaml
# AlertManager 규칙
apiVersion: v1
kind: ConfigMap
metadata:
  name: alertmanager-config
  namespace: qsign
data:
  alertmanager.yml: |
    route:
      receiver: 'team-qsign'
      group_by: ['alertname', 'cluster', 'service']
      group_wait: 10s
      group_interval: 10s
      repeat_interval: 12h

    receivers:
    - name: 'team-qsign'
      slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        channel: '#qsign-alerts'
        title: 'QSIGN Alert'
        text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'

      email_configs:
      - to: 'ops-team@example.com'
        from: 'alertmanager@example.com'
        smarthost: 'smtp.example.com:587'
```

---

## 참고 자료

- [Monitoring Guide](./MONITORING.md)
- [Backup & Recovery](./BACKUP-RECOVERY.md)
- [Troubleshooting](../05-troubleshooting/COMMON-ISSUES.md)
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
