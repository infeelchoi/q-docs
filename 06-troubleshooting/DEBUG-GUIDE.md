# Debug Guide

QSIGN 시스템의 문제를 체계적으로 진단하고 해결하기 위한 디버깅 방법론을 제공합니다.

## 목차

- [디버깅 방법론](#디버깅-방법론)
- [로그 분석](#로그-분석)
- [네트워크 디버깅](#네트워크-디버깅)
- [성능 프로파일링](#성능-프로파일링)
- [데이터베이스 디버깅](#데이터베이스-디버깅)
- [보안 디버깅](#보안-디버깅)
- [유용한 명령어](#유용한-명령어)

## 디버깅 방법론

### 체계적 접근 방법

문제 해결 시 다음 단계를 따르세요:

1. **문제 정의**
   - 정확한 증상 파악
   - 재현 가능한 시나리오 작성
   - 오류 메시지 수집

2. **정보 수집**
   - 로그 수집
   - 시스템 상태 확인
   - 메트릭 분석

3. **가설 수립**
   - 가능한 원인 나열
   - 우선순위 결정

4. **가설 검증**
   - 체계적으로 테스트
   - 결과 기록

5. **해결 및 검증**
   - 해결책 적용
   - 재발 방지 조치

### 문제 분류

**긴급도와 영향도에 따른 분류:**

| 긴급도 | 영향도 | 우선순위 | 예시 |
|--------|--------|----------|------|
| High | High | P0 | 서비스 전체 중단 |
| High | Medium | P1 | 특정 기능 장애 |
| Medium | High | P1 | 성능 심각한 저하 |
| Medium | Medium | P2 | 간헐적 오류 |
| Low | Low | P3 | 사소한 UI 문제 |

## 로그 분석

### Kubernetes 로그

**기본 로그 확인:**
```bash
# 현재 Pod 로그
kubectl logs <pod-name> -n qsign

# 이전 컨테이너 로그 (crash 후)
kubectl logs <pod-name> -n qsign --previous

# 실시간 로그 (tail -f)
kubectl logs -f <pod-name> -n qsign

# 최근 100줄
kubectl logs --tail=100 <pod-name> -n qsign

# 특정 시간 이후 로그
kubectl logs --since=1h <pod-name> -n qsign

# 특정 컨테이너 로그 (multi-container Pod)
kubectl logs <pod-name> -c <container-name> -n qsign

# 모든 replica 로그
kubectl logs -l app=signserver -n qsign

# 타임스탬프 포함
kubectl logs --timestamps <pod-name> -n qsign
```

**로그 저장:**
```bash
# 로그를 파일로 저장
kubectl logs <pod-name> -n qsign > pod.log

# 모든 Pod 로그 수집
for pod in $(kubectl get pods -n qsign -o name); do
  kubectl logs -n qsign $pod > logs/$(basename $pod).log
done

# 압축 아카이브 생성
kubectl logs <pod-name> -n qsign | gzip > pod-$(date +%Y%m%d-%H%M%S).log.gz
```

### SignServer 로그

**주요 로그 파일:**
```bash
# SignServer 메인 로그
kubectl exec -it signserver-0 -n qsign -- \
  tail -f /opt/signserver/server/standalone/log/server.log

# 감사 로그
kubectl exec -it signserver-0 -n qsign -- \
  tail -f /opt/signserver/server/standalone/log/audit.log

# 접근 로그
kubectl exec -it signserver-0 -n qsign -- \
  tail -f /opt/signserver/server/standalone/log/access.log

# 트랜잭션 로그
kubectl exec -it signserver-0 -n qsign -- \
  tail -f /opt/signserver/server/standalone/log/transaction.log
```

**로그 레벨 조정:**
```bash
# 로그 레벨 변경 (런타임)
kubectl exec -it signserver-0 -n qsign -- /opt/signserver/bin/jboss-cli.sh --connect
/subsystem=logging/logger=org.signserver:write-attribute(name=level,value=DEBUG)
reload

# 영구적 변경 (standalone.xml)
kubectl exec -it signserver-0 -n qsign -- \
  sed -i 's/level="INFO"/level="DEBUG"/' \
  /opt/signserver/server/standalone/configuration/standalone.xml
```

**로그 패턴 분석:**
```bash
# 오류 로그만 필터링
kubectl logs signserver-0 -n qsign | grep -i error

# 특정 Worker 로그
kubectl logs signserver-0 -n qsign | grep "PDFSigner"

# 느린 트랜잭션 찾기 (1초 이상)
kubectl exec -it signserver-0 -n qsign -- \
  awk '$NF > 1000' /opt/signserver/server/standalone/log/transaction.log

# 시간대별 오류 빈도
kubectl logs signserver-0 -n qsign | \
  grep ERROR | \
  awk '{print $1" "$2}' | \
  cut -d: -f1 | \
  sort | uniq -c
```

### Vault 로그

**Vault 로그 확인:**
```bash
# Vault 서버 로그
kubectl logs vault-0 -n qsign

# 감사 로그 활성화
kubectl exec -it vault-0 -n qsign -- \
  vault audit enable file file_path=/vault/audit/audit.log

# 감사 로그 확인
kubectl exec -it vault-0 -n qsign -- \
  tail -f /vault/audit/audit.log

# JSON 포맷으로 예쁘게 보기
kubectl exec -it vault-0 -n qsign -- \
  tail -f /vault/audit/audit.log | jq '.'
```

**Vault 작업 추적:**
```bash
# 특정 경로 접근 로그
kubectl exec -it vault-0 -n qsign -- cat /vault/audit/audit.log | \
  jq 'select(.request.path | contains("secret/signserver"))'

# 실패한 요청만 필터링
kubectl exec -it vault-0 -n qsign -- cat /vault/audit/audit.log | \
  jq 'select(.error != null)'

# 특정 사용자의 활동
kubectl exec -it vault-0 -n qsign -- cat /vault/audit/audit.log | \
  jq 'select(.auth.display_name == "signserver-sa")'
```

### Keycloak 로그

**Keycloak 로그:**
```bash
# Keycloak 서버 로그
kubectl logs keycloak-0 -n qsign

# 로그 레벨 변경
kubectl exec -it keycloak-0 -n qsign -- \
  /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin

kubectl exec -it keycloak-0 -n qsign -- \
  /opt/keycloak/bin/kcadm.sh update /subsystem/logging/logger=org.keycloak \
    -s level=DEBUG
```

**이벤트 로그 (Admin Console):**
```bash
# Keycloak Admin Console > Events
https://keycloak.qsign.example.com/admin/master/console/#/realms/qsign/events

# CLI로 이벤트 조회
kubectl exec -it keycloak-0 -n qsign -- \
  /opt/keycloak/bin/kcadm.sh get events --realm qsign
```

### 중앙 로그 수집

**EFK (Elasticsearch, Fluentd, Kibana) 스택:**

**Fluentd DaemonSet 배포:**
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd
  namespace: kube-system
spec:
  selector:
    matchLabels:
      k8s-app: fluentd-logging
  template:
    metadata:
      labels:
        k8s-app: fluentd-logging
    spec:
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1-debian-elasticsearch
        env:
        - name: FLUENT_ELASTICSEARCH_HOST
          value: "elasticsearch.logging.svc.cluster.local"
        - name: FLUENT_ELASTICSEARCH_PORT
          value: "9200"
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
```

**Kibana에서 로그 검색:**
```
# QSIGN namespace의 모든 로그
kubernetes.namespace_name:"qsign"

# SignServer 오류 로그
kubernetes.namespace_name:"qsign" AND kubernetes.labels.app:"signserver" AND log:"ERROR"

# 특정 시간 범위
kubernetes.namespace_name:"qsign" AND @timestamp:[now-1h TO now]

# 특정 Worker 로그
kubernetes.namespace_name:"qsign" AND log:*PDFSigner*
```

**Loki + Promtail (경량 대안):**
```yaml
# Promtail DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: promtail
  namespace: logging
spec:
  selector:
    matchLabels:
      app: promtail
  template:
    metadata:
      labels:
        app: promtail
    spec:
      containers:
      - name: promtail
        image: grafana/promtail:latest
        args:
        - -config.file=/etc/promtail/promtail.yaml
        volumeMounts:
        - name: config
          mountPath: /etc/promtail
        - name: varlog
          mountPath: /var/log
      volumes:
      - name: config
        configMap:
          name: promtail-config
      - name: varlog
        hostPath:
          path: /var/log
```

**LogQL 쿼리 (Grafana):**
```
# QSIGN namespace 로그
{namespace="qsign"}

# 오류 로그만
{namespace="qsign"} |= "ERROR"

# 특정 Pod
{namespace="qsign", pod="signserver-0"}

# 로그 레이트 (초당 로그 수)
rate({namespace="qsign"}[5m])
```

## 네트워크 디버깅

### 연결 테스트

**기본 연결 확인:**
```bash
# Pod에서 다른 Service로 연결 테스트
kubectl exec -it signserver-0 -n qsign -- nc -zv vault.qsign.svc.cluster.local 8200

# HTTP 요청 테스트
kubectl exec -it signserver-0 -n qsign -- \
  curl -v http://keycloak.qsign.svc.cluster.local:8080/health

# DNS 확인
kubectl exec -it signserver-0 -n qsign -- \
  nslookup vault.qsign.svc.cluster.local

# Ping 테스트
kubectl exec -it signserver-0 -n qsign -- \
  ping -c 5 vault.qsign.svc.cluster.local
```

**디버그 Pod 실행:**
```bash
# BusyBox로 네트워크 테스트
kubectl run -it --rm debug --image=busybox --restart=Never -n qsign -- sh

# 내부에서 테스트
/ # nslookup vault.qsign.svc.cluster.local
/ # wget -O- http://vault.qsign.svc.cluster.local:8200/v1/sys/health
/ # nc -zv vault.qsign.svc.cluster.local 8200

# 더 많은 도구가 포함된 이미지
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -n qsign -- bash

# 내부에서 고급 테스트
bash-5.1# curl -v http://vault.qsign.svc.cluster.local:8200/v1/sys/health
bash-5.1# traceroute vault.qsign.svc.cluster.local
bash-5.1# tcpdump -i any -n port 8200
```

### Service와 Endpoint 확인

**Service 디버깅:**
```bash
# Service 목록
kubectl get svc -n qsign

# Service 상세 정보
kubectl describe svc vault -n qsign

# Endpoints 확인 (실제 Pod IP)
kubectl get endpoints vault -n qsign

# Endpoints가 비어있는 경우 문제
# - Pod이 Running 상태인지 확인
# - Pod의 label이 Service selector와 일치하는지 확인
# - Pod이 Ready 상태인지 확인

# Service의 ClusterIP로 직접 테스트
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  wget -O- http://<ClusterIP>:8200/v1/sys/health
```

**Service 타입별 디버깅:**

**ClusterIP:**
```bash
# 클러스터 내부에서만 접근 가능
kubectl run -it --rm debug --image=busybox --restart=Never -- \
  wget -O- http://vault.qsign.svc.cluster.local:8200
```

**NodePort:**
```bash
# 노드의 특정 포트로 접근
kubectl get svc vault -n qsign
# NodePort: 30200

# 외부에서 테스트
curl http://<node-ip>:30200/v1/sys/health
```

**LoadBalancer:**
```bash
# External IP 확인
kubectl get svc ingress-nginx-controller -n ingress-nginx
# EXTERNAL-IP: 1.2.3.4

# 외부에서 테스트
curl http://1.2.3.4/
```

### NetworkPolicy 디버깅

**NetworkPolicy 확인:**
```bash
# NetworkPolicy 목록
kubectl get networkpolicy -n qsign

# 특정 정책 상세 정보
kubectl describe networkpolicy allow-vault-access -n qsign

# NetworkPolicy 적용 여부 확인
kubectl get pod signserver-0 -n qsign --show-labels
kubectl get networkpolicy -n qsign -o yaml
```

**NetworkPolicy 테스트:**
```bash
# NetworkPolicy 없이 테스트
kubectl delete networkpolicy --all -n qsign

# 연결 테스트
kubectl exec -it signserver-0 -n qsign -- \
  nc -zv vault.qsign.svc.cluster.local 8200

# 성공하면 NetworkPolicy 문제
# NetworkPolicy 재적용 및 수정
kubectl apply -f network-policy.yaml
```

### DNS 디버깅

**CoreDNS 확인:**
```bash
# CoreDNS Pod 상태
kubectl get pods -n kube-system -l k8s-app=kube-dns

# CoreDNS 로그
kubectl logs -n kube-system -l k8s-app=kube-dns

# CoreDNS ConfigMap
kubectl get configmap coredns -n kube-system -o yaml
```

**DNS 해석 테스트:**
```bash
# Pod에서 DNS 쿼리
kubectl exec -it signserver-0 -n qsign -- nslookup vault.qsign.svc.cluster.local

# dig로 상세 정보
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- \
  dig vault.qsign.svc.cluster.local

# DNS 서버 직접 지정
kubectl exec -it signserver-0 -n qsign -- \
  nslookup vault.qsign.svc.cluster.local 10.96.0.10
```

### 패킷 캡처

**tcpdump로 패킷 캡처:**
```bash
# Pod에 tcpdump 설치된 이미지 사용
kubectl debug -it signserver-0 -n qsign --image=nicolaka/netshoot --target=signserver

# 패킷 캡처
tcpdump -i any -w /tmp/capture.pcap port 8200

# 로컬로 복사
kubectl cp qsign/signserver-0:/tmp/capture.pcap ./capture.pcap

# Wireshark로 분석
wireshark capture.pcap
```

**ksniff 플러그인 사용:**
```bash
# ksniff 설치
kubectl krew install sniff

# 패킷 캡처
kubectl sniff signserver-0 -n qsign -f "port 8200" -o capture.pcap

# Wireshark로 자동 열기
kubectl sniff signserver-0 -n qsign -f "port 8200" -o - | wireshark -k -i -
```

### TLS/SSL 디버깅

**인증서 확인:**
```bash
# openssl로 연결 테스트
kubectl exec -it signserver-0 -n qsign -- \
  openssl s_client -connect vault.qsign.svc.cluster.local:8200 -showcerts

# 인증서 체인 확인
kubectl exec -it signserver-0 -n qsign -- \
  openssl s_client -connect vault.qsign.svc.cluster.local:8200 2>/dev/null | \
  openssl x509 -text -noout

# 인증서 만료일
kubectl exec -it signserver-0 -n qsign -- \
  openssl s_client -connect vault.qsign.svc.cluster.local:8200 2>/dev/null | \
  openssl x509 -noout -dates

# curl로 TLS 디버깅
kubectl exec -it signserver-0 -n qsign -- \
  curl -v --cacert /path/to/ca.crt https://vault.qsign.svc.cluster.local:8200
```

**Secret의 인증서 확인:**
```bash
# TLS Secret 내용 확인
kubectl get secret qsign-tls-cert -n qsign -o yaml

# 인증서 디코딩 및 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -text -noout

# 개인키 확인
kubectl get secret qsign-tls-cert -n qsign -o jsonpath='{.data.tls\.key}' | \
  base64 -d | openssl rsa -check
```

## 성능 프로파일링

### 리소스 사용량 모니터링

**실시간 리소스 확인:**
```bash
# 노드 리소스
kubectl top nodes

# Pod 리소스
kubectl top pods -n qsign

# 특정 Pod의 컨테이너별 리소스
kubectl top pod signserver-0 -n qsign --containers

# 정렬해서 보기 (메모리 사용량 순)
kubectl top pods -n qsign --sort-by=memory

# CPU 사용량 순
kubectl top pods -n qsign --sort-by=cpu
```

**메트릭 서버 확인:**
```bash
# Metrics Server 설치 여부
kubectl get deployment metrics-server -n kube-system

# 없으면 설치
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
```

### JVM 프로파일링

**JVM 메트릭 확인:**
```bash
# JVM 힙 메모리 사용량
kubectl exec -it signserver-0 -n qsign -- \
  jcmd 1 VM.native_memory summary

# 가비지 컬렉션 통계
kubectl exec -it signserver-0 -n qsign -- \
  jstat -gc 1 1000 10

# 스레드 덤프
kubectl exec -it signserver-0 -n qsign -- \
  jstack 1 > thread-dump.txt

# 힙 덤프 생성
kubectl exec -it signserver-0 -n qsign -- \
  jmap -dump:format=b,file=/tmp/heap.bin 1

# 로컬로 복사
kubectl cp qsign/signserver-0:/tmp/heap.bin ./heap.bin

# VisualVM 또는 Eclipse MAT로 분석
```

**Java Flight Recorder:**
```bash
# JFR 녹화 시작 (60초)
kubectl exec -it signserver-0 -n qsign -- \
  jcmd 1 JFR.start duration=60s filename=/tmp/recording.jfr

# 녹화 중지
kubectl exec -it signserver-0 -n qsign -- \
  jcmd 1 JFR.stop name=1

# 파일 다운로드
kubectl cp qsign/signserver-0:/tmp/recording.jfr ./recording.jfr

# JDK Mission Control로 분석
jmc recording.jfr
```

**JMX 모니터링:**
```bash
# JMX 포트 포워딩
kubectl port-forward signserver-0 9990:9990 -n qsign

# JConsole 연결
jconsole localhost:9990

# 또는 VisualVM
jvisualvm
# File > Add JMX Connection > localhost:9990
```

### 애플리케이션 프로파일링

**SignServer 통계:**
```bash
# Worker 상태 확인
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh getstatus brief all

# Worker별 통계
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh getstatus complete PDFSigner

# 시스템 통계
kubectl exec -it signserver-0 -n qsign -- \
  /opt/signserver/bin/signserver.sh getstatus brief system
```

**트랜잭션 로그 분석:**
```bash
# 트랜잭션 시간 통계
kubectl exec -it signserver-0 -n qsign -- \
  awk '{sum+=$NF; count++} END {print "Avg:", sum/count, "ms"}' \
  /opt/signserver/server/standalone/log/transaction.log

# 느린 트랜잭션 (1초 이상)
kubectl exec -it signserver-0 -n qsign -- \
  awk '$NF > 1000 {print}' \
  /opt/signserver/server/standalone/log/transaction.log
```

### 데이터베이스 성능

**PostgreSQL 성능 확인:**
```bash
# 활성 쿼리 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT pid, usename, application_name, state, query, query_start
   FROM pg_stat_activity
   WHERE state = 'active';"

# 느린 쿼리 (pg_stat_statements)
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT query, calls, total_time, mean_time, max_time
   FROM pg_stat_statements
   ORDER BY mean_time DESC
   LIMIT 10;"

# 테이블 크기
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT schemaname, tablename,
   pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
   FROM pg_tables
   ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
   LIMIT 10;"

# 인덱스 사용 통계
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
   FROM pg_stat_user_indexes
   ORDER BY idx_scan DESC;"
```

**쿼리 실행 계획:**
```bash
# EXPLAIN ANALYZE
kubectl exec -it postgres-0 -n qsign -- psql -U keycloak -d keycloak -c \
  "EXPLAIN ANALYZE SELECT * FROM user_entity WHERE username = 'admin';"
```

### HSM 성능

**HSM 상태 확인:**
```bash
# HSM 정보
kubectl exec -it signserver-0 -n qsign -- /opt/nfast/bin/enquiry

# HSM 통계
kubectl exec -it signserver-0 -n qsign -- /opt/nfast/bin/nfkminfo

# PKCS11 세션 정보
kubectl exec -it signserver-0 -n qsign -- \
  pkcs11-tool --module /opt/nfast/toolkits/pkcs11/libcknfast.so --show-info
```

## 데이터베이스 디버깅

### 연결 문제

**PostgreSQL 연결 테스트:**
```bash
# Pod에서 연결 테스트
kubectl exec -it signserver-0 -n qsign -- \
  psql -h postgres.qsign.svc.cluster.local -U signserver -d signserver -c "SELECT 1;"

# 연결 수 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity;"

# 최대 연결 수
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SHOW max_connections;"

# 현재 연결 상세 정보
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "SELECT datname, usename, application_name, client_addr, state, query_start
   FROM pg_stat_activity
   ORDER BY query_start;"
```

### 데이터 무결성

**데이터베이스 검증:**
```bash
# 테이블 무결성 검사
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -d signserver -c \
  "SELECT * FROM pg_stat_user_tables WHERE n_tup_del > 1000;"

# Foreign key 제약 조건 확인
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -d signserver -c \
  "SELECT conname, conrelid::regclass, confrelid::regclass
   FROM pg_constraint
   WHERE contype = 'f';"

# 테이블 통계 업데이트
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -d signserver -c \
  "ANALYZE;"
```

### 백업 및 복구 테스트

**백업:**
```bash
# 논리 백업
kubectl exec -it postgres-0 -n qsign -- \
  pg_dump -U postgres signserver | gzip > signserver-$(date +%Y%m%d).sql.gz

# 특정 테이블만
kubectl exec -it postgres-0 -n qsign -- \
  pg_dump -U postgres -t audit_log signserver > audit_log.sql
```

**복구 테스트:**
```bash
# 테스트 데이터베이스 생성
kubectl exec -it postgres-0 -n qsign -- psql -U postgres -c \
  "CREATE DATABASE signserver_test TEMPLATE signserver;"

# 백업 복구 테스트
gunzip < signserver-20240101.sql.gz | \
  kubectl exec -i postgres-0 -n qsign -- \
  psql -U postgres signserver_test
```

## 보안 디버깅

### 권한 문제

**RBAC 확인:**
```bash
# ServiceAccount 확인
kubectl get sa -n qsign

# Role/RoleBinding 확인
kubectl get role,rolebinding -n qsign

# ClusterRole/ClusterRoleBinding 확인
kubectl get clusterrole,clusterrolebinding | grep qsign

# 특정 SA의 권한 확인
kubectl describe sa signserver-sa -n qsign

# RoleBinding 상세
kubectl describe rolebinding signserver-binding -n qsign

# 권한 테스트 (can-i)
kubectl auth can-i get secrets --as=system:serviceaccount:qsign:signserver-sa -n qsign
```

### Secret 디버깅

**Secret 확인:**
```bash
# Secret 목록
kubectl get secrets -n qsign

# Secret 상세 정보 (값은 숨김)
kubectl describe secret signserver-secret -n qsign

# Secret 값 확인 (주의: 민감한 정보)
kubectl get secret signserver-secret -n qsign -o yaml

# 특정 키 값 디코딩
kubectl get secret signserver-secret -n qsign -o jsonpath='{.data.password}' | base64 -d
```

### Vault 보안 디버깅

**Vault 인증 확인:**
```bash
# Vault 상태
kubectl exec -it vault-0 -n qsign -- vault status

# 인증 메서드 목록
kubectl exec -it vault-0 -n qsign -- vault auth list

# Kubernetes 인증 설정 확인
kubectl exec -it vault-0 -n qsign -- \
  vault read auth/kubernetes/config

# 정책 확인
kubectl exec -it vault-0 -n qsign -- vault policy list
kubectl exec -it vault-0 -n qsign -- vault policy read signserver-policy

# 토큰 정보 확인
kubectl exec -it vault-0 -n qsign -- vault token lookup
```

### 감사 로그 분석

**보안 이벤트 추출:**
```bash
# 실패한 인증 시도
kubectl logs signserver-0 -n qsign | grep "authentication failed"

# 권한 거부
kubectl logs signserver-0 -n qsign | grep "Access denied"

# Vault 감사 로그에서 거부된 요청
kubectl exec -it vault-0 -n qsign -- cat /vault/audit/audit.log | \
  jq 'select(.error != null) | select(.error | contains("permission denied"))'
```

## 유용한 명령어

### 빠른 진단 스크립트

**전체 상태 확인:**
```bash
#!/bin/bash
# qsign-status.sh

echo "=== Namespace ==="
kubectl get namespace qsign

echo "=== Pods ==="
kubectl get pods -n qsign -o wide

echo "=== Services ==="
kubectl get svc -n qsign

echo "=== Ingress ==="
kubectl get ingress -n qsign

echo "=== PVC ==="
kubectl get pvc -n qsign

echo "=== ConfigMaps ==="
kubectl get configmap -n qsign

echo "=== Secrets ==="
kubectl get secrets -n qsign

echo "=== Resource Usage ==="
kubectl top pods -n qsign 2>/dev/null || echo "Metrics server not available"

echo "=== Recent Events ==="
kubectl get events -n qsign --sort-by='.lastTimestamp' | tail -20
```

**로그 수집 스크립트:**
```bash
#!/bin/bash
# collect-logs.sh

NAMESPACE=qsign
OUTDIR="qsign-logs-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

echo "Collecting QSIGN logs to $OUTDIR"

# Pod 목록
kubectl get pods -n $NAMESPACE > "$OUTDIR/pods.txt"

# 각 Pod의 로그
for pod in $(kubectl get pods -n $NAMESPACE -o name); do
  pod_name=$(basename $pod)
  echo "Collecting logs from $pod_name"
  kubectl logs -n $NAMESPACE $pod > "$OUTDIR/$pod_name.log" 2>&1
  kubectl logs -n $NAMESPACE $pod --previous > "$OUTDIR/$pod_name-previous.log" 2>&1
  kubectl describe -n $NAMESPACE $pod > "$OUTDIR/$pod_name-describe.txt"
done

# 리소스 상태
kubectl get all -n $NAMESPACE -o yaml > "$OUTDIR/all-resources.yaml"

# 이벤트
kubectl get events -n $NAMESPACE > "$OUTDIR/events.txt"

# 압축
tar -czf "$OUTDIR.tar.gz" "$OUTDIR"
echo "Logs collected: $OUTDIR.tar.gz"
```

**헬스체크 스크립트:**
```bash
#!/bin/bash
# health-check.sh

check_component() {
  local component=$1
  local url=$2
  local expected=$3

  echo -n "Checking $component... "
  result=$(kubectl exec -it signserver-0 -n qsign -- curl -s -o /dev/null -w "%{http_code}" $url)

  if [ "$result" == "$expected" ]; then
    echo "OK ($result)"
    return 0
  else
    echo "FAIL ($result, expected $expected)"
    return 1
  fi
}

echo "=== QSIGN Health Check ==="
check_component "Vault" "http://vault.qsign.svc.cluster.local:8200/v1/sys/health" "200"
check_component "Keycloak" "http://keycloak.qsign.svc.cluster.local:8080/health" "200"
check_component "SignServer" "http://signserver.qsign.svc.cluster.local:8080/signserver/healthcheck/signserverhealth" "200"
check_component "PostgreSQL" "http://postgres.qsign.svc.cluster.local:5432" "000"  # 연결만 확인

echo "=== Pod Status ==="
kubectl get pods -n qsign
```

### kubectl 플러그인

**유용한 kubectl 플러그인:**

**krew (플러그인 매니저):**
```bash
# krew 설치
(
  set -x; cd "$(mktemp -d)" &&
  OS="$(uname | tr '[:upper:]' '[:lower:]')" &&
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&
  KREW="krew-${OS}_${ARCH}" &&
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&
  tar zxvf "${KREW}.tar.gz" &&
  ./"${KREW}" install krew
)

export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
```

**유용한 플러그인:**
```bash
# stern - 여러 Pod 로그를 동시에 tail
kubectl krew install stern
kubectl stern signserver -n qsign

# ctx - context 빠르게 전환
kubectl krew install ctx
kubectl ctx

# ns - namespace 빠르게 전환
kubectl krew install ns
kubectl ns qsign

# tree - 리소스 트리 보기
kubectl krew install tree
kubectl tree deployment signserver -n qsign

# view-secret - Secret 값 쉽게 보기
kubectl krew install view-secret
kubectl view-secret signserver-secret -n qsign

# resource-capacity - 리소스 사용량 요약
kubectl krew install resource-capacity
kubectl resource-capacity -n qsign
```

### 자동화 도구

**watch로 실시간 모니터링:**
```bash
# Pod 상태 실시간 모니터링
watch -n 1 'kubectl get pods -n qsign'

# 리소스 사용량 실시간 모니터링
watch -n 5 'kubectl top pods -n qsign'

# 이벤트 실시간 모니터링
watch -n 2 'kubectl get events -n qsign --sort-by=.lastTimestamp | tail -10'
```

**tmux/screen으로 멀티 모니터링:**
```bash
#!/bin/bash
# monitor.sh - tmux 세션으로 여러 창 동시 모니터링

tmux new-session -d -s qsign-monitor
tmux split-window -h
tmux split-window -v
tmux select-pane -t 0
tmux split-window -v

# 각 pane에 명령 실행
tmux send-keys -t 0 'kubectl get pods -n qsign -w' C-m
tmux send-keys -t 1 'kubectl logs -f signserver-0 -n qsign' C-m
tmux send-keys -t 2 'kubectl logs -f vault-0 -n qsign' C-m
tmux send-keys -t 3 'kubectl top pods -n qsign -w' C-m

tmux attach-session -t qsign-monitor
```

## 체크리스트

### 일반 문제 해결 체크리스트

- [ ] Pod 상태 확인 (`kubectl get pods`)
- [ ] 로그 확인 (`kubectl logs`)
- [ ] 이벤트 확인 (`kubectl get events`)
- [ ] 리소스 사용량 확인 (`kubectl top`)
- [ ] Service/Endpoint 확인
- [ ] NetworkPolicy 확인
- [ ] Secret/ConfigMap 확인
- [ ] PVC/PV 상태 확인

### 성능 문제 체크리스트

- [ ] CPU/메모리 사용량 확인
- [ ] 데이터베이스 쿼리 성능 확인
- [ ] 네트워크 레이턴시 측정
- [ ] HSM 응답 시간 확인 (해당 시)
- [ ] 애플리케이션 로그에서 느린 작업 확인
- [ ] JVM 메모리 및 GC 확인
- [ ] 스레드 덤프 분석

### 보안 문제 체크리스트

- [ ] RBAC 권한 확인
- [ ] Secret 접근 권한 확인
- [ ] Vault 인증/인가 확인
- [ ] TLS 인증서 유효성 확인
- [ ] NetworkPolicy 검증
- [ ] 감사 로그 분석

## 추가 리소스

- [Common Issues](COMMON-ISSUES.md) - 일반적인 문제 해결
- [FAQ](FAQ.md) - 자주 묻는 질문
- [Monitoring Guide](../05-operations/MONITORING.md) - 모니터링 설정
- [Performance Tuning](../05-operations/PERFORMANCE-TUNING.md) - 성능 최적화
