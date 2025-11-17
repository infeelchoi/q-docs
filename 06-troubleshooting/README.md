# Troubleshooting

QSIGN 시스템 운영 중 발생할 수 있는 문제를 해결하기 위한 가이드입니다.

## 개요

이 섹션은 QSIGN 시스템의 문제를 진단하고 해결하는 데 필요한 실용적인 정보를 제공합니다. 일반적인 문제부터 복잡한 디버깅까지 단계별로 안내합니다.

## 문서 구성

### [Common Issues](COMMON-ISSUES.md)
일반적으로 발생하는 문제와 즉시 적용 가능한 해결 방법을 제공합니다.

**주요 내용:**
- **Pod 시작 실패**
  - Vault Pod이 시작되지 않음
  - Keycloak Pod이 시작되지 않음
  - SignServer Pod이 시작되지 않음
  - Nginx Ingress Controller 문제

- **Vault Sealed**
  - Vault가 Sealed 상태
  - Vault 자동 Seal 발생
  - Unseal 방법 및 자동화

- **Keycloak 연결 오류**
  - 로그인 실패
  - OIDC 인증 실패
  - 세션 타임아웃 문제

- **HSM 문제**
  - HSM 연결 실패
  - HSM 성능 저하
  - PKCS11 오류

- **네트워크 문제**
  - Pod 간 통신 실패
  - 외부 접근 불가
  - TLS/SSL 인증서 문제
  - DNS 해석 실패

- **데이터베이스 문제**
  - PostgreSQL 연결 실패
  - 데이터베이스 성능 저하
  - 연결 풀 고갈

- **스토리지 문제**
  - PVC가 Bound되지 않음
  - 디스크 용량 부족
  - 데이터 손실

- **리소스 부족**
  - CPU/메모리 부족
  - OOMKilled 오류
  - Pod Eviction

**대상 사용자:** 운영자, 관리자
**사용 시나리오:** 긴급한 문제 발생 시 빠른 해결이 필요할 때

### [FAQ](FAQ.md)
자주 묻는 질문과 답변을 카테고리별로 정리합니다.

**주요 내용:**
- **설치 및 설정 관련** (Q1-Q5)
  - 최소 요구사항
  - Helm 없이 설치
  - 선택적 구성 요소 설치
  - 개발 환경 설정
  - HSM 없이 사용

- **운영 관련** (Q6-Q10)
  - 업데이트 방법
  - 백업 수행
  - 로그 확인
  - 스케일링
  - 다중 클러스터 배포

- **보안 관련** (Q11-Q15)
  - 보안 인증 준수
  - 비밀번호/인증서 관리
  - 감사 로그 관리
  - 네트워크 보안
  - 취약점 스캔

- **성능 관련** (Q16-Q20)
  - 서명 성능
  - 병목 지점 찾기
  - 대용량 배치 처리
  - 데이터베이스 최적화
  - HSM 성능 최대화

- **통합 관련** (Q21-Q25)
  - REST API 사용
  - 기존 애플리케이션 통합
  - CI/CD 파이프라인 통합
  - 다른 PKI 시스템 통합
  - 클라우드 네이티브 서비스 통합

- **트러블슈팅** (Q26-Q30)
  - Pod 시작 실패 시 조치
  - 성능 저하 진단
  - 인증서 오류 해결
  - Vault sealed 상태 처리
  - 지원 받는 방법

**대상 사용자:** 모든 사용자
**사용 시나리오:** 특정 질문이나 사용 사례에 대한 답변이 필요할 때

### [Debug Guide](DEBUG-GUIDE.md)
체계적인 디버깅 방법론과 상세한 진단 도구 사용법을 제공합니다.

**주요 내용:**
- **디버깅 방법론**
  - 체계적 접근 방법 (문제 정의 → 정보 수집 → 가설 수립 → 검증 → 해결)
  - 문제 분류 (긴급도/영향도 매트릭스)
  - 우선순위 결정

- **로그 분석**
  - Kubernetes 로그 (kubectl logs)
  - SignServer 로그 (server.log, audit.log, transaction.log)
  - Vault 로그 및 감사 로그
  - Keycloak 로그 및 이벤트
  - 중앙 로그 수집 (EFK, Loki)
  - 로그 패턴 분석

- **네트워크 디버깅**
  - 연결 테스트 (nc, curl, ping)
  - Service와 Endpoint 확인
  - NetworkPolicy 디버깅
  - DNS 문제 해결
  - 패킷 캡처 (tcpdump, ksniff)
  - TLS/SSL 디버깅

- **성능 프로파일링**
  - 리소스 사용량 모니터링 (kubectl top)
  - JVM 프로파일링 (jcmd, jstat, jstack, jmap)
  - Java Flight Recorder (JFR)
  - JMX 모니터링
  - SignServer 통계 분석
  - 데이터베이스 성능 (pg_stat_statements)
  - HSM 성능 측정

- **데이터베이스 디버깅**
  - PostgreSQL 연결 문제
  - 쿼리 성능 분석 (EXPLAIN ANALYZE)
  - 데이터 무결성 검증
  - 백업 및 복구 테스트

- **보안 디버깅**
  - RBAC 권한 확인
  - Secret 디버깅
  - Vault 인증/인가 확인
  - 감사 로그 분석

- **유용한 명령어**
  - 빠른 진단 스크립트
  - 로그 수집 스크립트
  - 헬스체크 스크립트
  - kubectl 플러그인 (stern, ctx, ns, tree)
  - 자동화 도구 (watch, tmux)

**대상 사용자:** 고급 운영자, SRE, 개발자
**사용 시나리오:** 복잡한 문제를 심층 분석할 때, 성능 최적화가 필요할 때

## 문제 해결 프로세스

```
문제 발생
    ↓
1. FAQ 확인 (빠른 답변)
    ↓
문제 지속?
    ↓
2. Common Issues 확인 (일반적 문제)
    ↓
해결되지 않음?
    ↓
3. Debug Guide 활용 (심층 분석)
    ↓
여전히 해결 안 됨?
    ↓
4. 지원 요청 (GitHub Issues, Community, Support)
```

## 빠른 참조

### 긴급 상황별 가이드

| 상황 | 첫 번째 확인 사항 | 참조 문서 |
|------|------------------|-----------|
| 서비스 전체 중단 | Pod 상태, 노드 상태 | [Common Issues - Pod 시작 실패](COMMON-ISSUES.md#pod-시작-실패) |
| 서명 불가 | SignServer 로그, HSM 연결 | [Common Issues - HSM 문제](COMMON-ISSUES.md#hsm-문제) |
| 로그인 불가 | Keycloak 상태, OIDC 설정 | [Common Issues - Keycloak 연결 오류](COMMON-ISSUES.md#keycloak-연결-오류) |
| Vault sealed | Vault 상태, Unseal keys | [Common Issues - Vault Sealed](COMMON-ISSUES.md#vault-sealed) |
| 성능 저하 | 리소스 사용량, 데이터베이스 | [Debug Guide - 성능 프로파일링](DEBUG-GUIDE.md#성능-프로파일링) |
| 네트워크 오류 | Service, NetworkPolicy | [Debug Guide - 네트워크 디버깅](DEBUG-GUIDE.md#네트워크-디버깅) |

### 주요 명령어 치트시트

**상태 확인:**
```bash
# 전체 상태 요약
kubectl get all -n qsign

# Pod 상태
kubectl get pods -n qsign -o wide

# 리소스 사용량
kubectl top pods -n qsign

# 최근 이벤트
kubectl get events -n qsign --sort-by='.lastTimestamp' | tail -20
```

**로그 확인:**
```bash
# 실시간 로그
kubectl logs -f <pod-name> -n qsign

# 모든 replica 로그
kubectl logs -l app=signserver -n qsign

# 이전 컨테이너 로그
kubectl logs <pod-name> -n qsign --previous
```

**디버깅:**
```bash
# Pod에 접속
kubectl exec -it <pod-name> -n qsign -- bash

# 네트워크 테스트
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -n qsign -- bash

# 포트 포워딩
kubectl port-forward <pod-name> 8080:8080 -n qsign
```

**문제 해결:**
```bash
# Pod 재시작
kubectl delete pod <pod-name> -n qsign

# Deployment 재배포
kubectl rollout restart deployment <deployment-name> -n qsign

# StatefulSet 재배포
kubectl rollout restart statefulset <statefulset-name> -n qsign
```

## 모니터링 및 알람

실시간 모니터링과 알람 설정으로 문제를 조기에 발견하고 대응할 수 있습니다.

**권장 모니터링 도구:**
- **Prometheus + Grafana**: 메트릭 수집 및 시각화
- **EFK/ELK Stack**: 중앙 로그 수집 및 분석
- **Alertmanager**: 알람 규칙 및 알림

자세한 내용은 [Monitoring Guide](../04-operations/MONITORING.md)를 참조하세요.

## 지원 받기

### 셀프 서비스 리소스

1. **문서**
   - [QSIGN Documentation](../README.md)
   - [SignServer Official Docs](https://doc.primekey.com/signserver)
   - [Vault Documentation](https://www.vaultproject.io/docs)
   - [Keycloak Documentation](https://www.keycloak.org/documentation)

2. **커뮤니티**
   - GitHub Issues: 버그 리포트 및 기능 요청
   - Community Forum: 질문 및 토론
   - Slack Channel: 실시간 도움말

### 상용 지원

**Enterprise Support:**
- 24/7 기술 지원
- SLA 보장
- 전담 지원 엔지니어
- 정기 보안 업데이트
- 맞춤형 교육

**문의:**
- Email: support@qsign.example.com
- Phone: +82-2-1234-5678

### 버그 리포트 시 포함할 정보

문제를 빠르게 해결하기 위해 다음 정보를 제공해 주세요:

```bash
# 1. 환경 정보
kubectl version
kubectl get nodes -o wide

# 2. QSIGN 상태
kubectl get all -n qsign

# 3. 문제가 있는 Pod 정보
kubectl describe pod <pod-name> -n qsign
kubectl logs <pod-name> -n qsign
kubectl logs <pod-name> -n qsign --previous

# 4. 최근 이벤트
kubectl get events -n qsign --sort-by='.lastTimestamp'

# 5. 설정 정보 (민감한 정보 제거 후)
kubectl get configmap -n qsign -o yaml
kubectl get secret -n qsign  # 값은 포함하지 않음
```

**추가 정보:**
- 문제 발생 시각
- 재현 단계
- 기대했던 동작
- 실제 동작
- 스크린샷 (해당 시)

## 베스트 프랙티스

### 예방적 조치

1. **정기 모니터링**
   - 리소스 사용량 추세 확인
   - 로그 정기 검토
   - 성능 메트릭 분석

2. **정기 백업**
   - Vault 데이터
   - Keycloak 데이터베이스
   - SignServer 설정

3. **보안 패치**
   - 정기적인 업데이트
   - 취약점 스캔
   - 감사 로그 검토

4. **문서화**
   - 시스템 변경 기록
   - 장애 대응 기록
   - 사용자 정의 설정 문서화

5. **재해 복구 계획**
   - DR 사이트 구축
   - 복구 절차 테스트
   - RTO/RPO 목표 설정

### 운영 체크리스트

**일일 점검:**
- [ ] Pod 상태 확인
- [ ] 리소스 사용량 확인
- [ ] 알람 검토
- [ ] 주요 메트릭 확인

**주간 점검:**
- [ ] 로그 검토
- [ ] 성능 추세 분석
- [ ] 백업 검증
- [ ] 보안 이벤트 검토

**월간 점검:**
- [ ] 시스템 업데이트
- [ ] 용량 계획 검토
- [ ] DR 테스트
- [ ] 문서 업데이트

## 관련 문서

- [Operations Guide](../04-operations/README.md) - 일상적인 운영 작업
- [Monitoring Guide](../04-operations/MONITORING.md) - 모니터링 설정
- [Backup & Recovery](../04-operations/BACKUP-RECOVERY.md) - 백업 및 복구
- [Performance Tuning](../04-operations/SCALING.md) - 성능 최적화
- [Security Guide](../01-architecture/SECURITY-DESIGN.md) - 보안 강화

## 기여하기

이 트러블슈팅 가이드는 커뮤니티의 경험을 바탕으로 지속적으로 개선됩니다.

**기여 방법:**
1. GitHub Issues에 새로운 문제 및 해결책 제출
2. Pull Request로 문서 개선
3. Community Forum에 경험 공유

모든 기여를 환영합니다!

---

**마지막 업데이트:** 2024-01-01
**버전:** 1.0.0
