/*
 * liboqs KEM 예제 - Kyber1024
 * QSIGN Production Environment
 *
 * 컴파일:
 *   gcc kem_example.c -o kem_example -loqs -lssl -lcrypto
 *
 * 실행:
 *   ./kem_example
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// 16진수 출력 함수
void print_hex(const char *label, const uint8_t *data, size_t len, size_t max_len) {
    printf("%s (처음 %zu bytes): ", label, max_len < len ? max_len : len);
    for (size_t i = 0; i < len && i < max_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > max_len) {
        printf("...");
    }
    printf("\n");
}

int main() {
    printf("===========================================\n");
    printf("liboqs KEM 예제 - Kyber1024 (QSIGN)\n");
    printf("===========================================\n\n");

    // 1. KEM 알고리즘 객체 생성
    const char *algorithm = "Kyber1024";
    OQS_KEM *kem = OQS_KEM_new(algorithm);

    if (kem == NULL) {
        fprintf(stderr, "ERROR: %s 알고리즘을 지원하지 않습니다.\n", algorithm);
        fprintf(stderr, "liboqs가 올바르게 설치되었는지 확인하세요.\n");
        return 1;
    }

    printf("✓ KEM 알고리즘: %s\n", kem->method_name);
    printf("  버전: %s\n", kem->alg_version);
    printf("  NIST 보안 레벨: %d (256-bit equivalent)\n", kem->claimed_nist_level);
    printf("  IND-CCA 보안: %s\n\n", kem->ind_cca ? "Yes" : "No");

    printf("크기 정보:\n");
    printf("  공개키: %zu bytes\n", kem->length_public_key);
    printf("  비밀키: %zu bytes\n", kem->length_secret_key);
    printf("  암호문: %zu bytes\n", kem->length_ciphertext);
    printf("  공유 비밀: %zu bytes\n\n", kem->length_shared_secret);

    // 2. 메모리 할당
    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_client = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_server = malloc(kem->length_shared_secret);

    if (public_key == NULL || secret_key == NULL || ciphertext == NULL ||
        shared_secret_client == NULL || shared_secret_server == NULL) {
        fprintf(stderr, "ERROR: 메모리 할당 실패\n");
        goto cleanup;
    }

    printf("===========================================\n");
    printf("키 교환 시뮬레이션 시작\n");
    printf("===========================================\n\n");

    // 3. 서버: 키쌍 생성
    printf("[서버] 키쌍 생성 중...\n");
    OQS_STATUS rc = kem->keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: 키 생성 실패\n");
        goto cleanup;
    }
    printf("✓ 키쌍 생성 완료\n");
    print_hex("  공개키", public_key, kem->length_public_key, 32);
    print_hex("  비밀키", secret_key, kem->length_secret_key, 32);
    printf("\n");

    // 4. 클라이언트: 캡슐화 (공유 비밀 생성 및 암호화)
    printf("[클라이언트] 캡슐화 (키 교환) 중...\n");
    rc = kem->encaps(ciphertext, shared_secret_client, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: 캡슐화 실패\n");
        goto cleanup;
    }
    printf("✓ 캡슐화 완료\n");
    print_hex("  암호문", ciphertext, kem->length_ciphertext, 32);
    print_hex("  공유 비밀 (클라이언트)", shared_secret_client, kem->length_shared_secret, 32);
    printf("\n");

    // 5. 서버: 디캡슐화 (공유 비밀 복구)
    printf("[서버] 디캡슐화 (공유 비밀 복구) 중...\n");
    rc = kem->decaps(shared_secret_server, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: 디캡슐화 실패\n");
        goto cleanup;
    }
    printf("✓ 디캡슐화 완료\n");
    print_hex("  공유 비밀 (서버)", shared_secret_server, kem->length_shared_secret, 32);
    printf("\n");

    // 6. 공유 비밀 비교 및 검증
    printf("===========================================\n");
    printf("키 교환 검증\n");
    printf("===========================================\n\n");

    if (memcmp(shared_secret_client, shared_secret_server, kem->length_shared_secret) == 0) {
        printf("✓ 성공: 클라이언트와 서버의 공유 비밀이 일치합니다!\n\n");

        printf("공유 비밀 (전체 32 bytes, hex):\n");
        for (size_t i = 0; i < kem->length_shared_secret; i++) {
            printf("%02x", shared_secret_client[i]);
            if ((i + 1) % 32 == 0) printf("\n");
        }
        printf("\n\n");

        printf("이 공유 비밀은 다음 용도로 사용할 수 있습니다:\n");
        printf("  - AES-256-GCM 키 유도 (HKDF)\n");
        printf("  - TLS 1.3 마스터 시크릿\n");
        printf("  - VPN 세션 키\n");
        printf("  - 파일 암호화 키\n");
    } else {
        fprintf(stderr, "✗ 실패: 공유 비밀이 일치하지 않습니다!\n");
        goto cleanup;
    }

cleanup:
    // 7. 안전한 메모리 해제
    printf("\n메모리 정리 중...\n");
    if (kem != NULL) {
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        OQS_MEM_secure_free(shared_secret_client, kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_server, kem->length_shared_secret);
    }
    free(public_key);
    free(ciphertext);
    OQS_KEM_free(kem);

    printf("✓ 메모리 정리 완료\n\n");
    printf("===========================================\n");
    printf("프로그램 종료\n");
    printf("===========================================\n");

    return 0;
}
