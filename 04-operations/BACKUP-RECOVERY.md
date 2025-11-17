# 백업 및 복구

QSIGN 시스템의 백업 전략 및 재해 복구 절차입니다.

## 목차
- [백업 전략](#백업-전략)
- [PostgreSQL 백업](#postgresql-백업)
- [Vault 백업](#vault-백업)
- [HSM 키 백업](#hsm-키-백업)
- [복구 절차](#복구-절차)
- [재해 복구 계획](#재해-복구-계획)
- [백업 검증](#백업-검증)

---

## 백업 전략

### 백업 정책

#### RTO/RPO 목표

| 데이터 유형 | RPO (Recovery Point Objective) | RTO (Recovery Time Objective) |
|-----------|-------------------------------|------------------------------|
| PostgreSQL (트랜잭션 데이터) | 15분 | 1시간 |
| Vault (암호화 키) | 0 (실시간 복제) | 30분 |
| HSM 키 (마스터 키) | 0 (오프라인 백업) | 2시간 |
| 애플리케이션 설정 | 1일 | 15분 |
| 감사 로그 | 1시간 | 4시간 |

#### 백업 보존 정책

```yaml
# backup-retention-policy.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backup-retention-policy
  namespace: qsign
data:
  policy.json: |
    {
      "postgresql": {
        "full_backup": {
          "frequency": "daily",
          "retention": {
            "daily": 7,
            "weekly": 4,
            "monthly": 12,
            "yearly": 7
          }
        },
        "incremental_backup": {
          "frequency": "hourly",
          "retention": 24
        },
        "wal_archive": {
          "enabled": true,
          "retention": "7 days"
        }
      },
      "vault": {
        "snapshot": {
          "frequency": "hourly",
          "retention": {
            "hourly": 24,
            "daily": 30,
            "monthly": 12
          }
        }
      },
      "hsm_keys": {
        "backup": {
          "frequency": "on_change",
          "retention": "permanent",
          "storage": "offline_secure_storage"
        }
      },
      "audit_logs": {
        "archive": {
          "frequency": "daily",
          "retention": {
            "hot": "30 days",
            "warm": "1 year",
            "cold": "7 years"
          }
        }
      }
    }
```

### 백업 저장소

#### S3 Compatible Storage

```yaml
# backup-storage-config.yaml
apiVersion: v1
kind: Secret
metadata:
  name: backup-storage-credentials
  namespace: qsign
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: "AKIA..."
  AWS_SECRET_ACCESS_KEY: "..."
  S3_ENDPOINT: "https://s3.amazonaws.com"
  S3_BUCKET: "qsign-backups"
  S3_REGION: "ap-northeast-2"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: backup-storage-config
  namespace: qsign
data:
  storage.conf: |
    # Primary backup storage (S3)
    primary:
      type: s3
      bucket: qsign-backups
      prefix: production/
      encryption: AES256
      versioning: enabled

    # Secondary backup storage (GCS)
    secondary:
      type: gcs
      bucket: qsign-backups-dr
      project: qsign-project
      location: asia-northeast3

    # Offline backup (for HSM keys)
    offline:
      type: encrypted_usb
      location: secure_vault
      encryption: AES-256-GCM
```

---

## PostgreSQL 백업

### 자동 백업 설정

#### pgBackRest 배포

```yaml
# pgbackrest-deployment.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pgbackrest-config
  namespace: qsign
data:
  pgbackrest.conf: |
    [global]
    repo1-path=/var/lib/pgbackrest
    repo1-retention-full=7
    repo1-retention-diff=7
    repo1-retention-archive=7

    repo1-s3-bucket=qsign-backups
    repo1-s3-endpoint=s3.amazonaws.com
    repo1-s3-region=ap-northeast-2
    repo1-s3-key=${AWS_ACCESS_KEY_ID}
    repo1-s3-key-secret=${AWS_SECRET_ACCESS_KEY}
    repo1-type=s3

    log-level-console=info
    log-level-file=debug

    start-fast=y
    delta=y
    compress-type=lz4
    compress-level=6

    [qsign]
    pg1-path=/var/lib/postgresql/data
    pg1-port=5432
    pg1-socket-path=/var/run/postgresql
    pg1-user=postgres
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-full-backup
  namespace: qsign
spec:
  schedule: "0 2 * * *"  # 매일 오전 2시
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup-sa
          containers:
          - name: pgbackrest
            image: pgbackrest/pgbackrest:latest
            command:
            - /bin/sh
            - -c
            - |
              echo "Starting PostgreSQL full backup..."
              pgbackrest --stanza=qsign backup --type=full

              if [ $? -eq 0 ]; then
                echo "Backup completed successfully"
                # 백업 검증
                pgbackrest --stanza=qsign info
              else
                echo "Backup failed!"
                exit 1
              fi
            env:
            - name: PGBACKREST_CONFIG
              value: /etc/pgbackrest/pgbackrest.conf
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_ACCESS_KEY_ID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_SECRET_ACCESS_KEY
            volumeMounts:
            - name: config
              mountPath: /etc/pgbackrest
            - name: pgdata
              mountPath: /var/lib/postgresql/data
          volumes:
          - name: config
            configMap:
              name: pgbackrest-config
          - name: pgdata
            persistentVolumeClaim:
              claimName: postgresql-pvc
          restartPolicy: OnFailure
---
# 증분 백업 (매시간)
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgresql-diff-backup
  namespace: qsign
spec:
  schedule: "0 * * * *"  # 매시간
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: backup-sa
          containers:
          - name: pgbackrest
            image: pgbackrest/pgbackrest:latest
            command:
            - /bin/sh
            - -c
            - |
              echo "Starting PostgreSQL differential backup..."
              pgbackrest --stanza=qsign backup --type=diff
            env:
            - name: PGBACKREST_CONFIG
              value: /etc/pgbackrest/pgbackrest.conf
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_ACCESS_KEY_ID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_SECRET_ACCESS_KEY
            volumeMounts:
            - name: config
              mountPath: /etc/pgbackrest
            - name: pgdata
              mountPath: /var/lib/postgresql/data
          volumes:
          - name: config
            configMap:
              name: pgbackrest-config
          - name: pgdata
            persistentVolumeClaim:
              claimName: postgresql-pvc
          restartPolicy: OnFailure
```

#### WAL 아카이빙

```yaml
# postgresql-wal-archiving.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: postgresql-config
  namespace: qsign
data:
  postgresql.conf: |
    # WAL 설정
    wal_level = replica
    archive_mode = on
    archive_command = 'pgbackrest --stanza=qsign archive-push %p'
    archive_timeout = 300  # 5분

    # 복제 설정
    max_wal_senders = 10
    max_replication_slots = 10
    wal_keep_size = 1GB

    # 체크포인트
    checkpoint_timeout = 5min
    max_wal_size = 1GB
    min_wal_size = 80MB
```

### 수동 백업

```bash
#!/bin/bash
# manual-postgresql-backup.sh

BACKUP_NAME="manual-$(date +%Y%m%d-%H%M%S)"
NAMESPACE="qsign"
POD="postgresql-0"

echo "Starting manual PostgreSQL backup: $BACKUP_NAME"

# 1. pgBackRest 백업
kubectl exec -n $NAMESPACE $POD -- \
  pgbackrest --stanza=qsign backup --type=full

# 2. pg_dump 백업 (추가 보험)
kubectl exec -n $NAMESPACE $POD -- \
  pg_dump -U qsign -Fc qsign > /tmp/${BACKUP_NAME}.dump

# 3. S3 업로드
aws s3 cp /tmp/${BACKUP_NAME}.dump \
  s3://qsign-backups/manual/${BACKUP_NAME}.dump

# 4. 백업 검증
kubectl exec -n $NAMESPACE $POD -- \
  pgbackrest --stanza=qsign info

echo "Backup completed: $BACKUP_NAME"
```

### PostgreSQL 복구

#### 전체 복구

```bash
#!/bin/bash
# restore-postgresql.sh

RESTORE_TARGET="${1:-latest}"  # 복구 시점
NAMESPACE="qsign"

echo "=== PostgreSQL 복구 시작 ==="
echo "복구 대상: $RESTORE_TARGET"

# 1. 기존 PostgreSQL 중지
kubectl scale statefulset -n $NAMESPACE postgresql --replicas=0

# 2. 데이터 디렉토리 정리
kubectl exec -n $NAMESPACE postgresql-0 -- \
  rm -rf /var/lib/postgresql/data/*

# 3. pgBackRest 복구
if [ "$RESTORE_TARGET" == "latest" ]; then
  kubectl exec -n $NAMESPACE postgresql-0 -- \
    pgbackrest --stanza=qsign restore
else
  # 특정 시점 복구 (Point-in-Time Recovery)
  kubectl exec -n $NAMESPACE postgresql-0 -- \
    pgbackrest --stanza=qsign restore \
    --type=time --target="$RESTORE_TARGET"
fi

# 4. PostgreSQL 시작
kubectl scale statefulset -n $NAMESPACE postgresql --replicas=1

# 5. 복구 확인
echo "대기 중... PostgreSQL 시작"
kubectl wait --for=condition=ready pod -n $NAMESPACE postgresql-0 --timeout=300s

# 6. 데이터 무결성 검증
kubectl exec -n $NAMESPACE postgresql-0 -- \
  psql -U qsign -c "SELECT COUNT(*) FROM signatures;"

echo "=== 복구 완료 ==="
```

#### Point-in-Time Recovery (PITR)

```bash
#!/bin/bash
# pitr-restore.sh

TARGET_TIME="2025-11-16 09:00:00+00"
NAMESPACE="qsign"

echo "Point-in-Time Recovery to: $TARGET_TIME"

# 1. 복구 설정 생성
cat > /tmp/recovery.conf <<EOF
restore_command = 'pgbackrest --stanza=qsign archive-get %f "%p"'
recovery_target_time = '$TARGET_TIME'
recovery_target_action = 'promote'
EOF

# 2. 복구 수행
kubectl cp /tmp/recovery.conf $NAMESPACE/postgresql-0:/var/lib/postgresql/data/

kubectl exec -n $NAMESPACE postgresql-0 -- \
  pgbackrest --stanza=qsign restore --type=time --target="$TARGET_TIME"

# 3. PostgreSQL 재시작
kubectl rollout restart statefulset -n $NAMESPACE postgresql

echo "PITR 복구 진행 중..."
```

---

## Vault 백업

### Vault Snapshot 백업

```yaml
# vault-backup-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vault-snapshot-backup
  namespace: qsign
spec:
  schedule: "0 * * * *"  # 매시간
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: vault-backup-sa
          containers:
          - name: vault-backup
            image: hashicorp/vault:1.15.0
            command:
            - /bin/sh
            - -c
            - |
              #!/bin/sh
              set -e

              BACKUP_NAME="vault-snapshot-$(date +%Y%m%d-%H%M%S).snap"

              echo "Creating Vault snapshot: $BACKUP_NAME"

              # Vault snapshot 생성
              vault operator raft snapshot save /tmp/$BACKUP_NAME

              # S3 업로드
              aws s3 cp /tmp/$BACKUP_NAME \
                s3://qsign-backups/vault/snapshots/$BACKUP_NAME \
                --server-side-encryption AES256

              # 로컬 파일 삭제
              rm /tmp/$BACKUP_NAME

              echo "Backup completed: $BACKUP_NAME"

              # 오래된 백업 정리 (30일 이상)
              aws s3 ls s3://qsign-backups/vault/snapshots/ | \
                while read -r line; do
                  createDate=$(echo $line | awk '{print $1" "$2}')
                  createDate=$(date -d "$createDate" +%s)
                  olderThan=$(date -d "30 days ago" +%s)

                  if [ $createDate -lt $olderThan ]; then
                    fileName=$(echo $line | awk '{print $4}')
                    if [ "$fileName" != "" ]; then
                      echo "Deleting old backup: $fileName"
                      aws s3 rm s3://qsign-backups/vault/snapshots/$fileName
                    fi
                  fi
                done
            env:
            - name: VAULT_ADDR
              value: "http://vault:8200"
            - name: VAULT_TOKEN
              valueFrom:
                secretKeyRef:
                  name: vault-token
                  key: token
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_ACCESS_KEY_ID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_SECRET_ACCESS_KEY
          restartPolicy: OnFailure
```

### Vault Secrets 백업

```bash
#!/bin/bash
# backup-vault-secrets.sh

VAULT_ADDR="http://vault.qsign.svc.cluster.local:8200"
VAULT_TOKEN="${VAULT_TOKEN}"
BACKUP_DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="/tmp/vault-secrets-${BACKUP_DATE}.json"

echo "Backing up Vault secrets..."

# 1. KV Secrets 백업
vault kv get -format=json -mount=secret qsign > $BACKUP_FILE

# 2. 암호화 (GPG)
gpg --encrypt --recipient ops@example.com $BACKUP_FILE

# 3. S3 업로드
aws s3 cp ${BACKUP_FILE}.gpg \
  s3://qsign-backups/vault/secrets/${BACKUP_DATE}.json.gpg \
  --server-side-encryption AES256

# 4. 로컬 파일 삭제
rm $BACKUP_FILE ${BACKUP_FILE}.gpg

echo "Vault secrets backup completed"
```

### Vault 복구

#### Snapshot 복구

```bash
#!/bin/bash
# restore-vault-snapshot.sh

SNAPSHOT_FILE="${1}"  # S3 경로 또는 로컬 경로
NAMESPACE="qsign"

echo "=== Vault Snapshot 복구 시작 ==="

# 1. Snapshot 다운로드
if [[ $SNAPSHOT_FILE == s3://* ]]; then
  echo "Downloading snapshot from S3..."
  aws s3 cp $SNAPSHOT_FILE /tmp/vault-snapshot.snap
  SNAPSHOT_FILE="/tmp/vault-snapshot.snap"
fi

# 2. Vault 중지
kubectl scale statefulset -n $NAMESPACE vault --replicas=0

# 3. Snapshot 복구
kubectl exec -n $NAMESPACE vault-0 -- \
  vault operator raft snapshot restore -force $SNAPSHOT_FILE

# 4. Vault 시작
kubectl scale statefulset -n $NAMESPACE vault --replicas=3

# 5. Unseal
echo "Vault unsealing..."
for i in 1 2 3; do
  kubectl exec -n $NAMESPACE vault-0 -- \
    vault operator unseal ${VAULT_UNSEAL_KEY[$i]}
done

# 6. 복구 확인
kubectl exec -n $NAMESPACE vault-0 -- vault status

echo "=== Vault 복구 완료 ==="
```

---

## HSM 키 백업

### HSM 마스터 키 백업

HSM의 마스터 키는 매우 중요하므로 오프라인 백업을 사용합니다.

#### 백업 절차

```bash
#!/bin/bash
# backup-hsm-keys.sh

# 주의: 이 스크립트는 HSM 관리자만 실행해야 합니다.
# 물리적으로 안전한 환경에서만 실행하세요.

echo "=== HSM 키 백업 (오프라인) ==="

# 1. HSM 키 추출 (HSM 제조사별로 다름)
# 예시: Luna HSM
lunacm -e "partition backup -partition qsign_partition -file /secure/hsm-backup.tar"

# 2. 백업 암호화
openssl enc -aes-256-gcm -salt \
  -in /secure/hsm-backup.tar \
  -out /secure/hsm-backup-$(date +%Y%m%d).tar.enc \
  -pass file:/secure/backup-key.txt

# 3. 체크섬 생성
sha256sum /secure/hsm-backup-$(date +%Y%m%d).tar.enc > \
  /secure/hsm-backup-$(date +%Y%m%d).tar.enc.sha256

# 4. 암호화된 USB에 복사
cp /secure/hsm-backup-$(date +%Y%m%d).tar.enc* /media/encrypted-usb/

# 5. 원본 파일 안전 삭제
shred -u /secure/hsm-backup.tar
shred -u /secure/hsm-backup-$(date +%Y%m%d).tar.enc

echo "백업 완료. 암호화된 USB를 금고에 보관하세요."
```

### HSM 키 복구

```bash
#!/bin/bash
# restore-hsm-keys.sh

BACKUP_FILE="${1}"
DECRYPT_KEY="${2}"

echo "=== HSM 키 복구 ==="

# 1. 체크섬 검증
sha256sum -c ${BACKUP_FILE}.sha256

if [ $? -ne 0 ]; then
  echo "ERROR: 체크섬 불일치! 백업이 손상되었을 수 있습니다."
  exit 1
fi

# 2. 복호화
openssl enc -aes-256-gcm -d \
  -in $BACKUP_FILE \
  -out /tmp/hsm-backup.tar \
  -pass file:$DECRYPT_KEY

# 3. HSM 복구 (Luna HSM 예시)
lunacm -e "partition restore -partition qsign_partition -file /tmp/hsm-backup.tar"

# 4. 임시 파일 안전 삭제
shred -u /tmp/hsm-backup.tar

echo "HSM 키 복구 완료"
```

### HSM 키 백업 보관 정책

```yaml
# HSM 키 백업 정책
hsm_key_backup_policy:
  # 백업 생성
  creation:
    frequency: "on_key_generation"  # 키 생성 시마다
    method: "offline"
    encryption: "AES-256-GCM"

  # 보관
  storage:
    primary:
      location: "secure_vault_site_a"
      type: "encrypted_usb"
      access_control: "dual_control"

    secondary:
      location: "secure_vault_site_b"
      type: "encrypted_usb"
      access_control: "dual_control"

    tertiary:
      location: "offsite_secure_facility"
      type: "encrypted_tape"
      access_control: "triple_control"

  # 접근 제어
  access:
    authorization: "minimum_2_persons"
    approval: "security_officer + cto"
    audit: "all_access_logged"

  # 검증
  verification:
    frequency: "quarterly"
    procedure: "test_restore_on_dev_hsm"
    documentation: "required"
```

---

## 복구 절차

### 전체 시스템 복구

```bash
#!/bin/bash
# disaster-recovery.sh

echo "=== QSIGN 재해 복구 시작 ==="
echo "현재 시각: $(date)"

NAMESPACE="qsign"
RESTORE_POINT="${1:-latest}"

# 1. Namespace 생성
kubectl create namespace $NAMESPACE

# 2. Secrets 복원
echo "[1/5] Secrets 복원 중..."
kubectl apply -f /backup/secrets/

# 3. PostgreSQL 복구
echo "[2/5] PostgreSQL 복구 중..."
./restore-postgresql.sh $RESTORE_POINT

# 4. Vault 복구
echo "[3/5] Vault 복구 중..."
./restore-vault-snapshot.sh latest

# 5. 애플리케이션 배포
echo "[4/5] 애플리케이션 배포 중..."
kubectl apply -f /manifests/qsign/

# 6. 검증
echo "[5/5] 시스템 검증 중..."
./verify-recovery.sh

echo "=== 재해 복구 완료 ==="
```

### 복구 검증 스크립트

```bash
#!/bin/bash
# verify-recovery.sh

NAMESPACE="qsign"
ERRORS=0

echo "=== 복구 검증 시작 ==="

# 1. Pod 상태 확인
echo "[1/5] Pod 상태 확인..."
RUNNING_PODS=$(kubectl get pods -n $NAMESPACE --field-selector=status.phase=Running --no-headers | wc -l)
TOTAL_PODS=$(kubectl get pods -n $NAMESPACE --no-headers | wc -l)

if [ $RUNNING_PODS -eq $TOTAL_PODS ]; then
  echo "  OK: 모든 Pod 실행 중 ($RUNNING_PODS/$TOTAL_PODS)"
else
  echo "  ERROR: 일부 Pod가 실행되지 않음 ($RUNNING_PODS/$TOTAL_PODS)"
  ERRORS=$((ERRORS + 1))
fi

# 2. Database 연결 확인
echo "[2/5] Database 연결 확인..."
kubectl exec -n $NAMESPACE postgresql-0 -- \
  psql -U qsign -c "SELECT 1;" > /dev/null 2>&1

if [ $? -eq 0 ]; then
  echo "  OK: PostgreSQL 연결 성공"
else
  echo "  ERROR: PostgreSQL 연결 실패"
  ERRORS=$((ERRORS + 1))
fi

# 3. Vault 상태 확인
echo "[3/5] Vault 상태 확인..."
VAULT_STATUS=$(kubectl exec -n $NAMESPACE vault-0 -- vault status -format=json | jq -r '.sealed')

if [ "$VAULT_STATUS" == "false" ]; then
  echo "  OK: Vault unsealed"
else
  echo "  ERROR: Vault is sealed"
  ERRORS=$((ERRORS + 1))
fi

# 4. API Health Check
echo "[4/5] API Health Check..."
API_HEALTH=$(kubectl exec -n $NAMESPACE deployment/api-server -- \
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health)

if [ "$API_HEALTH" == "200" ]; then
  echo "  OK: API Server healthy"
else
  echo "  ERROR: API Server health check failed (HTTP $API_HEALTH)"
  ERRORS=$((ERRORS + 1))
fi

# 5. 데이터 무결성 확인
echo "[5/5] 데이터 무결성 확인..."
SIGNATURE_COUNT=$(kubectl exec -n $NAMESPACE postgresql-0 -- \
  psql -U qsign -t -c "SELECT COUNT(*) FROM signatures;")

echo "  서명 레코드 수: $SIGNATURE_COUNT"

# 결과 요약
echo ""
echo "=== 검증 결과 ==="
if [ $ERRORS -eq 0 ]; then
  echo "SUCCESS: 모든 검증 통과"
  exit 0
else
  echo "FAILED: $ERRORS 개의 검증 실패"
  exit 1
fi
```

### 부분 복구 (특정 서비스만)

#### API Server만 복구

```bash
#!/bin/bash
# restore-api-server.sh

NAMESPACE="qsign"
BACKUP_CONFIG="/backup/api-server-config-20251116.yaml"

echo "API Server 복구 중..."

# 1. ConfigMap 복원
kubectl apply -f $BACKUP_CONFIG

# 2. Deployment 재배포
kubectl rollout restart deployment -n $NAMESPACE api-server

# 3. 확인
kubectl wait --for=condition=available deployment -n $NAMESPACE api-server --timeout=300s

echo "API Server 복구 완료"
```

---

## 재해 복구 계획

### DR 사이트 구성

```yaml
# dr-site-config.yaml
disaster_recovery:
  # Primary Site
  primary_site:
    region: ap-northeast-2
    availability_zones:
      - ap-northeast-2a
      - ap-northeast-2b
      - ap-northeast-2c

    services:
      kubernetes_cluster: qsign-prod
      database: postgresql-primary
      vault: vault-primary-cluster
      hsm: ncipher-hsm-primary

  # DR Site
  dr_site:
    region: ap-northeast-1
    availability_zones:
      - ap-northeast-1a
      - ap-northeast-1b

    services:
      kubernetes_cluster: qsign-dr
      database: postgresql-standby
      vault: vault-dr-cluster
      hsm: ncipher-hsm-dr

    replication:
      database:
        type: streaming_replication
        lag: "<10 seconds"

      vault:
        type: performance_replication
        mode: async

      hsm:
        type: manual_backup_restore
        frequency: daily

  # Failover
  failover:
    trigger: manual  # or automatic
    rto_target: 1_hour
    rpo_target: 15_minutes

    procedure:
      - verify_primary_down
      - promote_dr_database
      - activate_dr_vault
      - update_dns
      - validate_dr_site
      - notify_stakeholders
```

### DR 훈련 계획

```yaml
# dr-drill-plan.yaml
dr_drill_schedule:
  - name: "Quarterly Full DR Drill"
    frequency: quarterly
    scope: full_system
    duration: 4_hours
    participants:
      - platform_team
      - security_team
      - management

    steps:
      - simulate_primary_site_failure
      - execute_failover_procedure
      - validate_dr_site_functionality
      - perform_failback
      - document_lessons_learned

  - name: "Monthly Database Recovery Test"
    frequency: monthly
    scope: database_only
    duration: 1_hour

    steps:
      - restore_latest_backup_to_test_env
      - validate_data_integrity
      - measure_recovery_time
      - cleanup_test_env

  - name: "Weekly Backup Verification"
    frequency: weekly
    scope: all_backups
    duration: 30_minutes

    steps:
      - verify_backup_completion
      - check_backup_size_consistency
      - validate_backup_checksums
      - test_random_backup_restore
```

---

## 백업 검증

### 자동 백업 검증

```yaml
# backup-verification-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup-verification
  namespace: qsign
spec:
  schedule: "0 6 * * *"  # 매일 오전 6시
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: verify-backups
            image: qsign/backup-verifier:latest
            command:
            - /bin/sh
            - -c
            - |
              #!/bin/sh
              set -e

              echo "=== 백업 검증 시작 ==="

              # 1. PostgreSQL 백업 검증
              echo "[1/3] PostgreSQL 백업 검증..."
              pgbackrest --stanza=qsign info

              # 2. Vault 스냅샷 검증
              echo "[2/3] Vault 스냅샷 검증..."
              LATEST_SNAPSHOT=$(aws s3 ls s3://qsign-backups/vault/snapshots/ | tail -1 | awk '{print $4}')
              aws s3 cp s3://qsign-backups/vault/snapshots/$LATEST_SNAPSHOT /tmp/

              # Snapshot 무결성 확인
              vault operator raft snapshot inspect /tmp/$LATEST_SNAPSHOT

              # 3. S3 백업 무결성 확인
              echo "[3/3] S3 백업 무결성 확인..."
              aws s3api head-object \
                --bucket qsign-backups \
                --key vault/snapshots/$LATEST_SNAPSHOT \
                --checksum-mode ENABLED

              echo "=== 백업 검증 완료 ==="
            env:
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_ACCESS_KEY_ID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: backup-storage-credentials
                  key: AWS_SECRET_ACCESS_KEY
          restartPolicy: OnFailure
```

### 백업 복구 테스트

```bash
#!/bin/bash
# test-backup-restore.sh

TEST_NAMESPACE="qsign-restore-test"
BACKUP_DATE="${1:-latest}"

echo "=== 백업 복구 테스트 시작 ==="

# 1. 테스트 환경 생성
kubectl create namespace $TEST_NAMESPACE

# 2. PostgreSQL 복구 테스트
echo "PostgreSQL 복구 테스트..."
./restore-postgresql.sh $BACKUP_DATE --namespace=$TEST_NAMESPACE

# 3. 데이터 검증
echo "데이터 검증..."
PROD_COUNT=$(kubectl exec -n qsign postgresql-0 -- \
  psql -U qsign -t -c "SELECT COUNT(*) FROM signatures;")

TEST_COUNT=$(kubectl exec -n $TEST_NAMESPACE postgresql-0 -- \
  psql -U qsign -t -c "SELECT COUNT(*) FROM signatures;")

if [ "$PROD_COUNT" -eq "$TEST_COUNT" ]; then
  echo "SUCCESS: 데이터 일치 ($TEST_COUNT rows)"
else
  echo "ERROR: 데이터 불일치 (Prod: $PROD_COUNT, Test: $TEST_COUNT)"
fi

# 4. 정리
kubectl delete namespace $TEST_NAMESPACE

echo "=== 백업 복구 테스트 완료 ==="
```

---

## 백업 모니터링

### Prometheus Alerts

```yaml
# backup-alerts.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backup-alerts
  namespace: monitoring
data:
  backup-rules.yml: |
    groups:
    - name: backup_alerts
      rules:
      # 백업 실패
      - alert: BackupFailed
        expr: backup_job_success{job="postgresql-backup"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Backup job failed"
          description: "{{ $labels.job }} has failed for the last run."

      # 백업이 24시간 이상 실행되지 않음
      - alert: BackupNotRun
        expr: time() - backup_last_success_timestamp > 86400
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Backup not run for 24 hours"
          description: "Last successful backup was {{ $value | humanizeDuration }} ago."

      # 백업 크기 이상
      - alert: BackupSizeAnomaly
        expr: |
          abs(backup_size_bytes - backup_size_bytes offset 1d)
          / backup_size_bytes offset 1d > 0.5
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Backup size anomaly detected"
          description: "Backup size changed by {{ $value | humanizePercentage }} compared to yesterday."
```

---

## 참고 자료

- [Daily Operations](./DAILY-OPERATIONS.md)
- [Disaster Recovery Runbook](../04-operations/BACKUP-RECOVERY.md)
- [pgBackRest Documentation](https://pgbackrest.org/user-guide.html)
- [Vault Backup Documentation](https://developer.hashicorp.com/vault/docs/commands/operator/raft)
