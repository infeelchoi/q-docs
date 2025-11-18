# 프로젝트 개요

QSIGN 프로젝트의 개요 및 시스템 구성 요소에 대한 문서입니다.

## 📖 문서 목록

### 핵심 문서
- [PROJECT-OVERVIEW.md](./PROJECT-OVERVIEW.md) - 프로젝트 전체 개요
- [SYSTEM-COMPONENTS.md](./SYSTEM-COMPONENTS.md) - 시스템 컴포넌트 상세
- [TECHNOLOGY-STACK.md](./TECHNOLOGY-STACK.md) - 기술 스택 및 도구

## 🎯 빠른 시작

1. [프로젝트 개요](./PROJECT-OVERVIEW.md)에서 QSIGN의 목표와 핵심 가치 확인
2. [시스템 컴포넌트](./SYSTEM-COMPONENTS.md)에서 각 컴포넌트의 역할과 구성 이해
3. [기술 스택](./TECHNOLOGY-STACK.md)에서 사용된 기술과 도구 확인

## 🏗️ QSIGN 아키텍처

### Gateway Flow (권장)
```
Q-APP (30300) → Q-GATEWAY/APISIX (32602) → Q-SIGN (30181) → Q-KMS (8200)
```
- API Gateway를 통한 중앙 집중식 라우팅
- Rate Limiting, CORS, 모니터링 통합

### Direct Flow (백업)
```
Q-APP (30300) → Q-SIGN (30181) → Q-KMS (8200)
```
- 직접 연결 방식
- 단순하고 안정적인 구조

## 🔗 다음 단계

- 아키텍처 이해: [../01-architecture/](../01-architecture/)
- 설치 및 설정: [../02-setup/](../02-setup/)
- 배포 가이드: [../03-deployment/](../03-deployment/)
- 통합 테스트: [../../QSIGN-Integration-Tests/](../../QSIGN-Integration-Tests/)

## 📚 추가 리소스

- **통합 테스트**: [QSIGN-Integration-Tests](../../QSIGN-Integration-Tests/) - Gateway Flow, Direct Flow, PQC 테스트
- **API 문서**: [../05-api-reference/](../05-api-reference/) - Keycloak, Vault, APISIX API
- **문제 해결**: [../06-troubleshooting/](../06-troubleshooting/) - 일반적인 문제 및 해결 방법

## 🔐 주요 기능

- **Post-Quantum Cryptography (PQC)**: DILITHIUM3, KYBER1024
- **Hybrid 암호화**: PQC + Classical (RSA, ECDSA)
- **HSM 통합**: Luna HSM을 통한 키 보호
- **GitOps 배포**: ArgoCD 기반 자동화 배포
- **API Gateway**: APISIX를 통한 중앙 집중식 라우팅

---

**버전**: 1.1.0 (Gateway Flow 추가)
**마지막 업데이트**: 2025-11-18
**상태**: ✅ Gateway Flow 및 Direct Flow 정상 작동
