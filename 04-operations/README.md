# 04. 운영 (Operations)

QSIGN 시스템의 일상 운영, 모니터링, 백업/복구, 확장 가이드입니다.

## 목차

### 1. [일상 운영 작업](./DAILY-OPERATIONS.md)
QSIGN 시스템의 일일/주간/월간 운영 작업 가이드

**주요 내용:**
- 일일 점검 체크리스트
- Health Check 절차
- 로그 확인 및 분석
- 리소스 모니터링
- 정기 점검 사항
- 일반적인 문제 해결

**대상 독자:** 운영 엔지니어, DevOps 팀

---

### 2. [모니터링](./MONITORING.md)
시스템 모니터링 구성 및 메트릭 수집 가이드

**주요 내용:**
- Prometheus 메트릭 설정
- Grafana 대시보드 구성
- Alert 규칙 및 AlertManager 설정
- SkyWalking APM 구성
- Loki 로그 집계
- 성능 메트릭 분석

**대상 독자:** 운영 엔지니어, SRE 팀

---

### 3. [백업 및 복구](./BACKUP-RECOVERY.md)
데이터 백업 전략 및 재해 복구 절차

**주요 내용:**
- 백업 정책 (RTO/RPO)
- PostgreSQL 백업 (pgBackRest, WAL 아카이빙)
- Vault 스냅샷 백업
- HSM 키 백업 (오프라인)
- 전체/부분 복구 절차
- DR 사이트 구성
- 백업 검증 및 테스트

**대상 독자:** 운영 엔지니어, DBA, 보안 팀

---

### 4. [확장 가이드](./SCALING.md)
시스템 확장 및 성능 최적화 가이드

**주요 내용:**
- 수평 확장 (HPA)
- 수직 확장 (VPA)
- Cluster Autoscaler 설정
- 리소스 최적화
- 애플리케이션/데이터베이스 성능 튜닝
- 캐싱 전략
- 용량 계획
- 부하 테스트 (K6)

**대상 독자:** 운영 엔지니어, SRE 팀, 성능 엔지니어

---

## 빠른 참조

### 일상 점검 스크립트

```bash
# 오전 점검
./scripts/daily-morning-check.sh

# Health Check
./scripts/health-check-all.sh

# 리소스 모니터링
kubectl top nodes
kubectl top pods -n qsign

# 최근 에러 로그
kubectl logs -n qsign -l app=api-server --since=1h | grep ERROR
```

### 주요 대시보드

- **Grafana:** `https://grafana.qsign.example.com`
  - QSIGN System Overview
  - Signature Service Dashboard
  - Resource Monitoring

- **Prometheus:** `https://prometheus.qsign.example.com`

- **SkyWalking:** `https://skywalking.qsign.example.com`

- **Kibana (Logs):** `https://kibana.qsign.example.com`

### 긴급 연락처

```yaml
# 운영 팀
operations_team:
  slack: "#qsign-ops"
  email: "ops-team@example.com"
  pagerduty: "https://qsign.pagerduty.com"

# On-Call
on_call:
  primary: "ops-oncall-primary@example.com"
  secondary: "ops-oncall-secondary@example.com"

# 보안 팀
security_team:
  slack: "#qsign-security"
  email: "security-team@example.com"

# 관리자
management:
  cto: "cto@example.com"
  security_officer: "ciso@example.com"
```

---

## 운영 정책

### SLA (Service Level Agreement)

| 메트릭 | 목표 | 측정 방법 |
|--------|------|----------|
| 가용성 (Availability) | 99.9% | Uptime monitoring |
| 응답 시간 (P95) | < 500ms | API response time |
| 서명 처리 시간 (P95) | < 1s | Signature duration |
| 에러율 | < 0.1% | Error rate monitoring |

### 변경 관리

```yaml
# 변경 관리 프로세스
change_management:
  # 계획된 변경
  planned_change:
    approval_required: true
    approvers:
      - tech_lead
      - security_officer

    notification:
      advance_notice: "7 days"
      channels:
        - email
        - slack
        - status_page

    maintenance_window:
      preferred: "Sunday 02:00-06:00 KST"
      max_frequency: "monthly"

  # 긴급 변경
  emergency_change:
    approval_required: true
    approvers:
      - on_call_engineer
      - tech_lead

    notification:
      advance_notice: "immediate"
      post_mortem: "required within 48h"

  # 롤백 계획
  rollback:
    required: true
    tested: true
    automated: "preferred"
```

### 인시던트 관리

```yaml
# 인시던트 심각도
incident_severity:
  P1_critical:
    description: "서비스 완전 중단"
    response_time: "15 minutes"
    resolution_time: "4 hours"
    notification: "immediate - all stakeholders"

  P2_major:
    description: "주요 기능 장애"
    response_time: "30 minutes"
    resolution_time: "8 hours"
    notification: "1 hour - ops team + management"

  P3_minor:
    description: "일부 기능 저하"
    response_time: "2 hours"
    resolution_time: "24 hours"
    notification: "4 hours - ops team"

  P4_low:
    description: "경미한 문제"
    response_time: "8 hours"
    resolution_time: "1 week"
    notification: "daily summary"

# 인시던트 대응 절차
incident_response:
  1_detect: "모니터링/알림을 통한 감지"
  2_triage: "심각도 평가 및 담당자 할당"
  3_investigate: "근본 원인 분석"
  4_mitigate: "임시 해결책 적용"
  5_resolve: "영구 해결책 적용"
  6_verify: "시스템 정상 동작 확인"
  7_document: "Post-mortem 작성"
  8_improve: "재발 방지 조치"
```

---

## 운영 체크리스트

### 시스템 배포 전 체크리스트

- [ ] 모든 테스트 통과 (Unit, Integration, E2E)
- [ ] 보안 취약점 스캔 완료
- [ ] 성능 테스트 통과
- [ ] 백업 검증 완료
- [ ] 롤백 계획 수립
- [ ] 변경 사항 문서화
- [ ] 관계자 승인 완료
- [ ] 모니터링/알림 설정 확인
- [ ] 유지보수 공지 발송

### 시스템 배포 후 체크리스트

- [ ] Pod 정상 실행 확인
- [ ] Health Check 통과
- [ ] API 응답 정상
- [ ] 로그 정상 기록
- [ ] 메트릭 수집 정상
- [ ] Alert 정상 동작
- [ ] 성능 지표 정상 범위
- [ ] 보안 설정 확인
- [ ] 배포 완료 공지

### 월간 점검 체크리스트

- [ ] 백업 복구 테스트
- [ ] 인증서 만료일 확인
- [ ] 보안 패치 적용
- [ ] 용량 사용 추세 분석
- [ ] 성능 지표 리뷰
- [ ] 알림 규칙 검토
- [ ] 접근 권한 감사
- [ ] 비용 최적화 검토
- [ ] 문서 업데이트

---

## 운영 도구

### 필수 도구

```bash
# Kubernetes CLI
kubectl version

# Helm
helm version

# Prometheus CLI
promtool --version

# pgBackRest
pgbackrest version

# Vault CLI
vault version

# AWS CLI
aws --version

# K6 (부하 테스트)
k6 version
```

### 유용한 스크립트

```bash
# /scripts 디렉토리
scripts/
├── daily-morning-check.sh      # 일일 오전 점검
├── health-check-all.sh          # 전체 Health Check
├── log-analysis.sh              # 로그 분석
├── resource-monitor.sh          # 리소스 모니터링
├── backup-postgresql.sh         # PostgreSQL 백업
├── backup-vault-secrets.sh      # Vault 백업
├── restore-postgresql.sh        # PostgreSQL 복구
├── restore-vault-snapshot.sh    # Vault 복구
├── disaster-recovery.sh         # 전체 시스템 복구
├── verify-recovery.sh           # 복구 검증
├── run-load-test.sh             # 부하 테스트
└── capacity-planning.py         # 용량 계획
```

---

## 교육 자료

### 운영 교육 과정

1. **QSIGN 시스템 개요** (2시간)
   - 아키텍처 이해
   - 주요 컴포넌트
   - 데이터 흐름

2. **일상 운영** (4시간)
   - Health Check
   - 로그 분석
   - 리소스 모니터링
   - 문제 해결

3. **모니터링 및 알림** (4시간)
   - Prometheus/Grafana
   - Alert 설정
   - 대시보드 활용
   - 인시던트 대응

4. **백업 및 복구** (6시간)
   - 백업 절차
   - 복구 절차
   - DR 훈련
   - 백업 검증

5. **확장 및 성능** (4시간)
   - HPA/VPA 설정
   - 성능 튜닝
   - 부하 테스트
   - 용량 계획

### 실습 시나리오

1. **시나리오 1: Pod 재시작**
   - Pod가 CrashLoopBackOff 상태
   - 로그 분석 및 문제 해결

2. **시나리오 2: Database 성능 저하**
   - 쿼리 응답 시간 증가
   - Slow query 분석 및 최적화

3. **시나리오 3: Vault Sealed**
   - Vault가 Sealed 상태
   - Unseal 절차 실행

4. **시나리오 4: 백업 복구**
   - 테스트 환경에 백업 복원
   - 데이터 무결성 검증

5. **시나리오 5: 트래픽 급증**
   - HPA로 자동 확장
   - 성능 모니터링

---

## 관련 문서

### 내부 문서
- [Architecture Overview](../01-architecture/README.md)
- [Deployment Guide](../03-deployment/README.md)
- [Troubleshooting](../06-troubleshooting/README.md)
- [Security Guide](../01-architecture/SECURITY-DESIGN.md)

### 외부 참조
- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator)
- [pgBackRest Documentation](https://pgbackrest.org/)
- [Vault Operations](https://developer.hashicorp.com/vault/docs/operations)
- [Site Reliability Engineering (SRE) Book](https://sre.google/books/)

---

## 버전 이력

| 버전 | 날짜 | 변경 내역 | 작성자 |
|------|------|----------|--------|
| 1.0.0 | 2025-11-16 | 초기 작성 | Operations Team |

---

## 피드백

운영 가이드 개선 제안이나 질문은 다음 채널로 연락주세요:

- Slack: `#qsign-ops`
- Email: `ops-team@example.com`
- GitHub Issues: `https://github.com/qsign/docs/issues`
