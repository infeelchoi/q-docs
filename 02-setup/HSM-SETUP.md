# Luna HSM 설정

## 📘 개요

Thales Luna HSM (Hardware Security Module)의 상세 설정 및 QSIGN 시스템과의 통합 방법을 안내합니다.

## 🔐 Luna HSM 초기 설정

### HSM 정보

```yaml
모델: SafeNet Luna Network HSM 7
펌웨어: 7.x 이상
인증: FIPS 140-2 Level 3
인터페이스: USB / Network
PKCS#11: Version 2.40
```

### 디바이스 확인

```bash
# USB HSM 디바이스 확인
ls -l /dev/k7pf0
# 출력: crw-rw---- 1 root hsmusers 180, 0 Nov 16 10:00 /dev/k7pf0

# 또는
ls -l /dev/usb/hiddev*

# udev 규칙 확인
cat /etc/udev/rules.d/20-chrystoki.rules
```

### Luna Client 설치

```bash
# Luna Client 다운로드 (Thales 포털)
# lunaclient-10.4.0-linux-x86_64.tar

# 압축 해제
tar -xvf lunaclient-10.4.0-linux-x86_64.tar
cd lunaclient-10.4.0

# 설치 (standalone 모드)
sudo ./install.sh -p sa

# 설치 확인
/usr/safenet/lunaclient/bin/vtl verify
```

### 환경 변수 설정

```bash
# /etc/profile.d/luna.sh
export ChrystokiConfigurationPath=/etc/Chrystoki.conf
export LD_LIBRARY_PATH=/usr/safenet/lunaclient/lib:$LD_LIBRARY_PATH

# 적용
source /etc/profile.d/luna.sh
```

## 🔧 HSM 초기화

### Luna Client Manager 사용

```bash
# lunacm 실행
lunacm

# 슬롯 확인
lunacm:> slot list

# 출력 예:
Slot Id ->              0
Label ->                qsign-partition
Serial Number ->        123456789
Model ->                LunaUSB7
Type ->                 Luna User Slot 7.x
Firmware Version ->     7.8.3
```

### 파티션 생성 및 초기화

```bash
# 파티션 초기화 (최초 1회)
lunacm:> partition init -label qsign-partition

# SO PIN 설정 (Security Officer)
Enter new SO PIN: ********
Re-enter new SO PIN: ********

# User PIN 설정
Enter new Partition PIN: ********
Re-enter new Partition PIN: ********

# 파티션 정보 확인
lunacm:> partition show -label qsign-partition
```

### 슬롯 활성화

```bash
# 슬롯 설정
lunacm:> slot set -slot 0

# 파티션 로그인
lunacm:> partition login

# PIN 입력
Enter Partition PIN: ********

# 로그인 확인
lunacm:> partition showInfo

# 로그아웃
lunacm:> partition logout
```

## 🔑 PQC 키 생성

### PKCS#11 메커니즘

```yaml
지원 메커니즘:
  - CKM_DILITHIUM_KEY_PAIR_GEN (DILITHIUM3)
  - CKM_KYBER_KEY_PAIR_GEN (KYBER1024)
  - CKM_SPHINCS_KEY_PAIR_GEN (SPHINCS+)
  - CKM_DILITHIUM (서명/검증)
  - CKM_KYBER (암호화/복호화)
```

### DILITHIUM3 키 생성

```bash
# lunacm에서 키 생성
lunacm:> key generate -label dilithium3-sign-key \
  -keyType dilithium3 \
  -sign=1 \
  -verify=1 \
  -extractable=0 \
  -modifiable=0

# 키 확인
lunacm:> key list

# 키 속성 확인
lunacm:> key getAttribute -label dilithium3-sign-key
```

### KYBER1024 키 생성

```bash
# KYBER 키 쌍 생성
lunacm:> key generate -label kyber1024-enc-key \
  -keyType kyber1024 \
  -encrypt=1 \
  -decrypt=1 \
  -extractable=0 \
  -modifiable=0

# 키 확인
lunacm:> key list -label kyber1024-enc-key
```

## 🔗 Vault와 HSM 연동

### Vault PKCS#11 설정

```hcl
# /etc/vault.d/vault.hcl
seal "pkcs11" {
  lib            = "/usr/lib/libCryptoki2_64.so"
  slot           = "0"
  pin            = "vault-hsm-pin"
  key_label      = "vault-hsm-key"
  hmac_key_label = "vault-hsm-hmac"
  generate_key   = "true"
  mechanism      = "0x0001"  # CKM_RSA_PKCS_KEY_PAIR_GEN
}
```

### HSM 키로 Vault Unseal

```bash
# Vault 초기화 (HSM 키 사용)
vault operator init \
  -recovery-shares=5 \
  -recovery-threshold=3 \
  -format=json > vault-recovery-keys.json

# Recovery Keys 저장 (HSM Auto-Unseal 사용 시)
cat vault-recovery-keys.json

# Vault 상태 확인
vault status
# Sealed: false (HSM Auto-Unseal)
```

### Transit Engine with HSM

```bash
# Transit Engine 활성화
vault secrets enable transit

# HSM을 사용한 키 생성
vault write -f transit/keys/dilithium3-key \
  type=dilithium3 \
  derived=false \
  exportable=false \
  allow_plaintext_backup=false

# 키가 HSM에 저장되었는지 확인
lunacm:> key list
```

## 👥 사용자 및 권한 관리

### vault 사용자 HSM 접근 권한

```bash
# vault 사용자 생성
sudo useradd -r -s /bin/bash -u 997 vault

# hsmusers 그룹에 추가
sudo usermod -a -G hsmusers vault

# HSM 디바이스 권한 설정
sudo chown root:hsmusers /dev/k7pf0
sudo chmod 0660 /dev/k7pf0

# 확인
ls -l /dev/k7pf0
# crw-rw---- 1 root hsmusers 180, 0 Nov 16 10:00 /dev/k7pf0
```

### 파티션 역할 분리

```bash
# Crypto Officer 역할
lunacm:> role login -name co

# Crypto User 역할
lunacm:> role login -name cu

# Partition SO 역할
lunacm:> partition login
```

## 🔄 백업 및 복구

### 키 백업

```bash
# 키 백업 (암호화된 형태)
lunacm:> partition backup create \
  -label qsign-partition \
  -file /backup/hsm-backup-$(date +%Y%m%d).bak

# 백업 파일 보안
sudo chmod 600 /backup/hsm-backup-*.bak
sudo chown vault:vault /backup/hsm-backup-*.bak
```

### 키 복구

```bash
# 백업 복구
lunacm:> partition backup restore \
  -label qsign-partition \
  -file /backup/hsm-backup-20251116.bak

# 복구 확인
lunacm:> key list
```

### HSM 복제 (HA)

```bash
# 소스 HSM에서
lunacm:> partition clone create \
  -source qsign-partition \
  -target qsign-partition-replica

# 대상 HSM에서
lunacm:> partition clone finalize
```

## 📊 모니터링 및 감사

### HSM 상태 모니터링

```bash
# 슬롯 상태
lunacm:> slot list

# 파티션 정보
lunacm:> partition show

# HSM 통계
lunacm:> partition statistics

# 로그 확인
sudo tail -f /var/log/chrystoki.log
```

### 감사 로그

```bash
# 감사 로그 활성화
lunacm:> audit enable

# 감사 로그 조회
lunacm:> audit show

# 로그 내보내기
lunacm:> audit export -file /var/log/hsm-audit-$(date +%Y%m%d).log
```

## 🔧 문제 해결

### 일반적인 문제

```yaml
문제: HSM 디바이스를 찾을 수 없음
해결:
  - lsusb로 USB 디바이스 확인
  - udev 규칙 재로드: sudo udevadm control --reload-rules
  - lunaclient 재시작: sudo systemctl restart lunaclient

문제: CKR_PIN_INCORRECT
해결:
  - PIN 재시도 횟수 확인
  - 파티션 잠금 여부 확인
  - SO로 로그인하여 PIN 재설정

문제: CKR_TOKEN_NOT_PRESENT
해결:
  - HSM 연결 확인
  - 파티션이 초기화되었는지 확인
  - 슬롯 번호 확인

문제: Vault HSM Auto-Unseal 실패
해결:
  - PKCS#11 라이브러리 경로 확인
  - HSM 슬롯 및 PIN 확인
  - vault 사용자 권한 확인
```

### 디버깅

```bash
# PKCS#11 디버그 모드
export PKCS11_DEBUG=1

# Luna Client 디버그
export LUNA_DEBUG=1

# ckdemo 테스트 도구
/usr/safenet/lunaclient/samples/ckdemo/ckdemo

# vtl 진단
/usr/safenet/lunaclient/bin/vtl verify
```

## 📋 HSM 체크리스트

```yaml
✅ HSM 설정 체크리스트:
  ☐ Luna Client 소프트웨어 설치
  ☐ HSM 디바이스 연결 확인
  ☐ 환경 변수 설정
  ☐ 파티션 초기화
  ☐ SO PIN 설정
  ☐ User PIN 설정
  ☐ vault 사용자 권한 부여
  ☐ PQC 키 생성 (DILITHIUM3, KYBER1024)
  ☐ Vault PKCS#11 연동
  ☐ HSM Auto-Unseal 테스트
  ☐ 키 백업 생성
  ☐ 감사 로그 활성화
  ☐ 모니터링 설정

✅ 보안 체크:
  ☐ PIN 복잡도 충족
  ☐ 디바이스 물리적 보안
  ☐ 백업 암호화 및 안전한 보관
  ☐ 접근 권한 최소화
  ☐ 감사 로그 정기 검토
```

## 🔗 참고 자료

```yaml
Luna HSM 문서:
  - https://thalesdocs.com/gphsm/luna/
  - Luna HSM Client Guide
  - Luna PKCS#11 Reference

Vault HSM:
  - https://developer.hashicorp.com/vault/docs/configuration/seal/pkcs11
```

---

**Last Updated**: 2025-11-16
**Version**: 1.0.0
**HSM Model**: SafeNet Luna Network HSM 7
**FIPS**: 140-2 Level 3
