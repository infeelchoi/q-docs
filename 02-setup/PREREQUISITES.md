# 사전 요구사항

## 📘 개요

QSIGN 시스템을 설치하기 전에 필요한 모든 사전 요구사항을 확인하고 준비합니다.

## 💻 하드웨어 요구사항

### 최소 요구사항

```yaml
서버 사양 (최소):
  CPU: 8 cores (x86_64)
  메모리: 32 GB RAM
  디스크: 500 GB SSD
  네트워크: 1 Gbps

권장 사양:
  CPU: 16 cores (x86_64)
  메모리: 64 GB RAM
  디스크: 1 TB NVMe SSD
  네트워크: 10 Gbps
```

### 컴포넌트별 리소스 요구사항

| 컴포넌트 | CPU | 메모리 | 디스크 | 비고 |
|----------|-----|--------|--------|------|
| Kubernetes (K3s) | 2 cores | 4 GB | 100 GB | Control Plane |
| Keycloak PQC | 2 cores | 4 GB | 50 GB | q-sign |
| Keycloak HSM | 2 cores | 4 GB | 50 GB | pqc-sso |
| Q-KMS Vault | 2 cores | 4 GB | 100 GB | q-kms |
| PostgreSQL (x2) | 2 cores | 4 GB | 100 GB | 데이터베이스 |
| APISIX Gateway | 2 cores | 2 GB | 20 GB | qsign-prod |
| Prometheus | 2 cores | 8 GB | 100 GB | 모니터링 |
| Grafana | 1 core | 2 GB | 20 GB | 대시보드 |
| ArgoCD | 1 core | 2 GB | 20 GB | GitOps |
| Luna HSM | - | - | - | 외부 장비 |

### HSM 요구사항

```yaml
Luna HSM:
  모델: SafeNet Luna Network HSM
  펌웨어: 7.x 이상
  PKCS#11: 2.40 이상
  인증: FIPS 140-2 Level 3
  인터페이스: USB 또는 Network
  슬롯: 최소 1개
  파티션: 최소 1개

HSM 디바이스:
  디바이스 경로: /dev/k7pf0 (또는 /dev/usb/hiddev*)
  권한: vault 사용자가 접근 가능
  그룹: hsmusers (GID 997)
```

## 🖥️ 소프트웨어 요구사항

### 운영 체제

```yaml
지원 OS:
  - Ubuntu 22.04 LTS (권장)
  - Ubuntu 20.04 LTS
  - CentOS 8 / Rocky Linux 8
  - RHEL 8.x

필수 패키지:
  - curl
  - wget
  - git
  - jq
  - openssl
  - ca-certificates
```

### Kubernetes

```yaml
Kubernetes 배포:
  옵션 1: K3s (권장, 경량)
    버전: 1.28+
    설치: curl -sfL https://get.k3s.io | sh -

  옵션 2: K8s (표준)
    버전: 1.27+
    Container Runtime: containerd
    CNI: Calico 또는 Flannel

kubectl:
  버전: Kubernetes와 동일
  설치: https://kubernetes.io/docs/tasks/tools/
```

### 컨테이너 런타임

```yaml
Container Runtime:
  containerd:
    버전: 1.6+
    설치: K3s에 포함됨

  또는 Docker (선택적):
    버전: 24.0+
    설치: https://docs.docker.com/engine/install/
```

### Helm

```yaml
Helm:
  버전: 3.12+
  설치:
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

  필수 플러그인:
    - helm-diff (ArgoCD용)
```

### ArgoCD CLI

```yaml
ArgoCD CLI:
  버전: 2.8+
  설치:
    curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
    chmod +x /usr/local/bin/argocd
```

### GitLab / Git 서버

```yaml
GitLab:
  버전: 16.0+
  설치 옵션:
    - GitLab CE (Community Edition)
    - GitLab EE (Enterprise Edition)
    - 외부 Git 서버 (GitHub, Bitbucket 등)

  저장소:
    - qsign (애플리케이션 코드)
    - gitops-repo (Kubernetes 매니페스트)
```

### Luna HSM Client

```yaml
Luna HSM Client Software:
  버전: 10.4.0+
  다운로드: Thales 고객 포털

  설치 파일:
    - lunaclient-*.tar
    - LunaClient_*.rpm (또는 .deb)

  필수 도구:
    - vtl (Vault Token Login)
    - lunacm (Luna Client Manager)
    - ckdemo (PKCS#11 테스트)
```

## 🌐 네트워크 요구사항

### 포트 매핑

```yaml
노드 외부 접근:
  HTTP 서비스:
    - 30080: ArgoCD UI
    - 30181: Keycloak PQC
    - 30699: Keycloak HSM
    - 30820: Vault UI
    - 32602: APISIX Gateway (HTTP)
    - 31281: APISIX Dashboard
    - 30030: Grafana
    - 30092: Prometheus
    - 30094: SkyWalking

  HTTPS 서비스:
    - 32294: APISIX Gateway (HTTPS)
    - 7743: GitLab (HTTPS)
    - 7643: Jenkins (HTTPS)

  Container Registry:
    - 31800: Harbor

클러스터 내부 통신:
  Kubernetes API: 6443
  etcd: 2379-2380
  kubelet: 10250
  NodePort Range: 30000-32767
```

### 방화벽 규칙

```yaml
인바운드 규칙:
  - 22/tcp (SSH)
  - 80/tcp (HTTP)
  - 443/tcp (HTTPS)
  - 6443/tcp (Kubernetes API)
  - 30000-32767/tcp (NodePort Range)
  - 7743/tcp (GitLab HTTPS)
  - 7643/tcp (Jenkins HTTPS)

아웃바운드 규칙:
  - 80/tcp (패키지 다운로드)
  - 443/tcp (HTTPS 통신)
  - 53/udp (DNS)
  - 123/udp (NTP)

HSM 통신:
  - USB: /dev/k7pf0 또는 /dev/usb/hiddev*
  - Network HSM: 1792/tcp (Luna Client-Server)
```

### DNS 요구사항

```yaml
DNS 레코드:
  외부 접근 (선택적):
    - qsign.example.com -> 192.168.0.11
    - vault.example.com -> 192.168.0.11
    - argocd.example.com -> 192.168.0.11
    - grafana.example.com -> 192.168.0.11

  내부 DNS (Kubernetes):
    - CoreDNS 자동 설정
    - *.svc.cluster.local
```

## 🔐 보안 요구사항

### SSL/TLS 인증서

```yaml
인증서 요구사항:
  옵션 1: Let's Encrypt (자동)
    - cert-manager 설치
    - DNS 또는 HTTP-01 Challenge

  옵션 2: 자체 서명 (개발/테스트)
    - openssl로 생성
    - 유효기간: 365일

  옵션 3: 내부 CA (프로덕션)
    - Vault PKI Engine
    - 자동 갱신 설정
```

### HSM 초기화

```yaml
HSM 준비사항:
  1. HSM 파티션 생성:
     - 파티션 이름: qsign-partition
     - 파티션 비밀번호: 안전한 비밀번호 설정

  2. HSM 클라이언트 등록:
     - 클라이언트 인증서 생성
     - HSM에 클라이언트 등록

  3. PKCS#11 라이브러리:
     - /usr/lib/libCryptoki2_64.so
     - 환경 변수 설정

  4. Vault 연동:
     - PKCS#11 슬롯 설정
     - 키 타입: DILITHIUM3, KYBER1024
```

### 사용자 및 권한

```yaml
필요한 사용자:
  vault:
    UID: 997
    GID: 997
    그룹: hsmusers, vault
    홈: /home/vault

  k3s (자동 생성):
    시스템 사용자

  keycloak (자동 생성):
    컨테이너 사용자

권한 설정:
  HSM 디바이스:
    소유자: root:hsmusers
    권한: 0660
    경로: /dev/k7pf0

  Vault 데이터:
    소유자: vault:vault
    권한: 0750
    경로: /vault/data
```

## 📦 스토리지 요구사항

### Persistent Volume

```yaml
스토리지 클래스:
  local-path (K3s 기본):
    Provisioner: rancher.io/local-path
    ReclaimPolicy: Delete
    VolumeBindingMode: WaitForFirstConsumer

  또는 NFS:
    Provisioner: nfs-client
    서버: NFS 서버 IP
    경로: /exports/qsign

Persistent Volumes:
  PostgreSQL (q-sign):
    크기: 50 Gi
    AccessMode: ReadWriteOnce

  PostgreSQL (pqc-sso):
    크기: 50 Gi
    AccessMode: ReadWriteOnce

  Vault:
    크기: 100 Gi
    AccessMode: ReadWriteOnce

  Prometheus:
    크기: 100 Gi
    AccessMode: ReadWriteOnce

  Grafana:
    크기: 20 Gi
    AccessMode: ReadWriteOnce
```

## 🔧 사전 준비 체크리스트

### 시스템 준비

```bash
#!/bin/bash
# 사전 요구사항 체크 스크립트

echo "=== QSIGN 사전 요구사항 체크 ==="

# 1. OS 버전 확인
echo "[1] OS 버전:"
lsb_release -a

# 2. CPU 코어 확인
echo -e "\n[2] CPU 코어:"
nproc

# 3. 메모리 확인
echo -e "\n[3] 메모리:"
free -h

# 4. 디스크 확인
echo -e "\n[4] 디스크:"
df -h

# 5. 필수 패키지 확인
echo -e "\n[5] 필수 패키지:"
for pkg in curl wget git jq openssl; do
  if command -v $pkg &> /dev/null; then
    echo "✅ $pkg: $(command -v $pkg)"
  else
    echo "❌ $pkg: NOT FOUND"
  fi
done

# 6. Kubernetes 확인
echo -e "\n[6] Kubernetes:"
if command -v kubectl &> /dev/null; then
  echo "✅ kubectl: $(kubectl version --client --short 2>/dev/null)"
else
  echo "❌ kubectl: NOT FOUND"
fi

# 7. Helm 확인
echo -e "\n[7] Helm:"
if command -v helm &> /dev/null; then
  echo "✅ helm: $(helm version --short)"
else
  echo "❌ helm: NOT FOUND"
fi

# 8. Docker/containerd 확인
echo -e "\n[8] Container Runtime:"
if command -v docker &> /dev/null; then
  echo "✅ docker: $(docker --version)"
elif command -v ctr &> /dev/null; then
  echo "✅ containerd: $(ctr --version)"
else
  echo "❌ Container Runtime: NOT FOUND"
fi

# 9. HSM 디바이스 확인
echo -e "\n[9] HSM 디바이스:"
if [ -e /dev/k7pf0 ]; then
  echo "✅ HSM: /dev/k7pf0 found"
  ls -l /dev/k7pf0
else
  echo "❌ HSM: /dev/k7pf0 NOT FOUND"
fi

# 10. Luna HSM 클라이언트 확인
echo -e "\n[10] Luna HSM Client:"
if [ -f /usr/lib/libCryptoki2_64.so ]; then
  echo "✅ PKCS#11 Library: /usr/lib/libCryptoki2_64.so"
else
  echo "❌ PKCS#11 Library: NOT FOUND"
fi

# 11. 포트 사용 확인
echo -e "\n[11] 포트 사용 확인:"
for port in 6443 30080 30181 30820 32602; do
  if netstat -tuln 2>/dev/null | grep -q ":$port "; then
    echo "⚠️  Port $port: IN USE"
  else
    echo "✅ Port $port: AVAILABLE"
  fi
done

# 12. 방화벽 상태
echo -e "\n[12] 방화벽 상태:"
if command -v ufw &> /dev/null; then
  sudo ufw status
elif command -v firewall-cmd &> /dev/null; then
  sudo firewall-cmd --state
else
  echo "방화벽 도구 없음"
fi

echo -e "\n=== 체크 완료 ==="
```

### 패키지 설치

```bash
#!/bin/bash
# 필수 패키지 설치 스크립트

# Ubuntu/Debian
if [ -f /etc/debian_version ]; then
  sudo apt-get update
  sudo apt-get install -y \
    curl \
    wget \
    git \
    jq \
    openssl \
    ca-certificates \
    apt-transport-https \
    gnupg \
    lsb-release \
    net-tools

# CentOS/RHEL
elif [ -f /etc/redhat-release ]; then
  sudo yum install -y \
    curl \
    wget \
    git \
    jq \
    openssl \
    ca-certificates \
    gnupg \
    net-tools
fi

# kubectl 설치
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Helm 설치
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# ArgoCD CLI 설치
sudo curl -sSL -o /usr/local/bin/argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
sudo chmod +x /usr/local/bin/argocd

echo "필수 패키지 설치 완료!"
```

## 📋 설치 전 체크리스트

```yaml
✅ 필수 항목:
  ☐ 하드웨어 요구사항 확인 (CPU, 메모리, 디스크)
  ☐ 운영 체제 설치 (Ubuntu 22.04 LTS 권장)
  ☐ 네트워크 구성 (고정 IP, DNS)
  ☐ 방화벽 규칙 설정
  ☐ 필수 패키지 설치
  ☐ Kubernetes (K3s) 설치 준비
  ☐ Helm 3 설치
  ☐ kubectl 설치 및 설정
  ☐ Luna HSM 하드웨어 연결
  ☐ Luna HSM Client 소프트웨어 설치
  ☐ HSM 파티션 생성 및 초기화
  ☐ 스토리지 준비 (PV/PVC)

✅ 권장 항목:
  ☐ GitLab 설치 및 설정
  ☐ Harbor Registry 설치
  ☐ Jenkins 설치 (CI/CD)
  ☐ NTP 동기화 설정
  ☐ 로그 rotation 설정
  ☐ 백업 스토리지 준비
  ☐ SSL 인증서 준비
  ☐ DNS 레코드 설정

✅ 보안 항목:
  ☐ SSH 키 기반 인증 설정
  ☐ sudo 권한 설정
  ☐ SELinux/AppArmor 정책 검토
  ☐ 최소 권한 원칙 적용
  ☐ 감사 로그 활성화
```

## 🔗 참고 자료

### 공식 문서

```yaml
Kubernetes:
  - https://kubernetes.io/docs/
  - https://k3s.io/

Helm:
  - https://helm.sh/docs/

ArgoCD:
  - https://argo-cd.readthedocs.io/

Vault:
  - https://developer.hashicorp.com/vault/docs

Keycloak:
  - https://www.keycloak.org/documentation

Luna HSM:
  - https://thalesdocs.com/gphsm/luna/
```

### 다운로드 링크

```yaml
소프트웨어 다운로드:
  K3s: https://get.k3s.io
  Helm: https://github.com/helm/helm/releases
  kubectl: https://kubernetes.io/docs/tasks/tools/
  ArgoCD CLI: https://github.com/argoproj/argo-cd/releases

Luna HSM:
  고객 포털: https://supportportal.thalesgroup.com/
  다운로드: Luna HSM Client Software
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**Required for**: QSIGN Installation
**Next Step**: [INSTALLATION.md](./INSTALLATION.md)
