/*
 * liboqs Signature 예제 - Dilithium3
 * QSIGN Production Environment
 *
 * 컴파일:
 *   gcc signature_example.c -o signature_example -loqs -lssl -lcrypto
 *
 * 실행:
 *   ./signature_example
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
    printf("liboqs Signature 예제 - Dilithium3 (QSIGN)\n");
    printf("===========================================\n\n");

    // 1. Signature 알고리즘 객체 생성
    const char *algorithm = "Dilithium3";
    OQS_SIG *sig = OQS_SIG_new(algorithm);

    if (sig == NULL) {
        fprintf(stderr, "ERROR: %s 알고리즘을 지원하지 않습니다.\n", algorithm);
        fprintf(stderr, "liboqs가 올바르게 설치되었는지 확인하세요.\n");
        return 1;
    }

    printf("✓ Signature 알고리즘: %s\n", sig->method_name);
    printf("  버전: %s\n", sig->alg_version);
    printf("  NIST 보안 레벨: %d (192-bit equivalent)\n", sig->claimed_nist_level);
    printf("  EUF-CMA 보안: %s\n\n", sig->euf_cma ? "Yes" : "No");

    printf("크기 정보:\n");
    printf("  공개키: %zu bytes\n", sig->length_public_key);
    printf("  비밀키: %zu bytes\n", sig->length_secret_key);
    printf("  최대 서명: %zu bytes\n\n", sig->length_signature);

    // 2. 메모리 할당
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    if (public_key == NULL || secret_key == NULL || signature == NULL) {
        fprintf(stderr, "ERROR: 메모리 할당 실패\n");
        goto cleanup;
    }

    printf("===========================================\n");
    printf("디지털 서명 시뮬레이션 시작\n");
    printf("===========================================\n\n");

    // 3. 키쌍 생성
    printf("[1] 키쌍 생성 중...\n");
    OQS_STATUS rc = sig->keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: 키 생성 실패\n");
        goto cleanup;
    }
    printf("✓ 키쌍 생성 완료\n");
    print_hex("  공개키", public_key, sig->length_public_key, 32);
    print_hex("  비밀키", secret_key, sig->length_secret_key, 32);
    printf("\n");

    // 4. 서명할 메시지
    const char *message = "QSIGN - Quantum-resistant Digital Signature Platform\n"
                         "문서 ID: DOC-2025-001\n"
                         "발급일: 2025-11-16\n"
                         "발급자: QSIGN CA";
    size_t message_len = strlen(message);

    printf("[2] 서명할 메시지:\n");
    printf("----------------------------------------\n");
    printf("%s\n", message);
    printf("----------------------------------------\n");
    printf("메시지 길이: %zu bytes\n\n", message_len);

    // 5. 서명 생성
    printf("[3] 디지털 서명 생성 중...\n");
    rc = sig->sign(signature, &signature_len,
                   (const uint8_t*)message, message_len,
                   secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: 서명 생성 실패\n");
        goto cleanup;
    }
    printf("✓ 서명 생성 완료\n");
    printf("  서명 길이: %zu bytes (최대 %zu bytes)\n", signature_len, sig->length_signature);
    print_hex("  서명", signature, signature_len, 64);
    printf("\n");

    // 6. 서명 검증 (정상 메시지)
    printf("[4] 서명 검증 중 (정상 메시지)...\n");
    rc = sig->verify((const uint8_t*)message, message_len,
                     signature, signature_len,
                     public_key);

    if (rc == OQS_SUCCESS) {
        printf("✓ 서명 검증 성공!\n");
        printf("  → 메시지가 변조되지 않았으며, 서명이 유효합니다.\n\n");
    } else {
        fprintf(stderr, "✗ 서명 검증 실패!\n\n");
        goto cleanup;
    }

    // 7. 서명 검증 (변조된 메시지)
    printf("[5] 서명 검증 중 (변조된 메시지)...\n");
    char tampered_message[] = "QSIGN - TAMPERED MESSAGE!!!";
    rc = sig->verify((const uint8_t*)tampered_message, strlen(tampered_message),
                     signature, signature_len,
                     public_key);

    if (rc == OQS_SUCCESS) {
        fprintf(stderr, "✗ 경고: 변조된 메시지 검증 성공 (문제!)\n\n");
    } else {
        printf("✓ 변조된 메시지 검증 실패 (정상)\n");
        printf("  → 메시지 변조가 감지되었습니다.\n\n");
    }

    // 8. 서명 검증 (변조된 서명)
    printf("[6] 서명 검증 중 (변조된 서명)...\n");
    signature[0] ^= 0x01;  // 1 bit 변조
    rc = sig->verify((const uint8_t*)message, message_len,
                     signature, signature_len,
                     public_key);

    if (rc == OQS_SUCCESS) {
        fprintf(stderr, "✗ 경고: 변조된 서명 검증 성공 (문제!)\n\n");
    } else {
        printf("✓ 변조된 서명 검증 실패 (정상)\n");
        printf("  → 서명 변조가 감지되었습니다.\n\n");
    }

    // 9. 사용 사례 출력
    printf("===========================================\n");
    printf("QSIGN 사용 사례\n");
    printf("===========================================\n\n");

    printf("Dilithium3 디지털 서명은 다음과 같이 사용됩니다:\n\n");

    printf("1. X.509 인증서 서명:\n");
    printf("   - CA Root Certificate 서명\n");
    printf("   - 중간 인증서 발급\n");
    printf("   - 서버/클라이언트 인증서\n\n");

    printf("2. JWT 토큰 서명 (Keycloak):\n");
    printf("   - Access Token 서명\n");
    printf("   - Refresh Token 서명\n");
    printf("   - ID Token 서명\n\n");

    printf("3. 문서 서명:\n");
    printf("   - 전자 계약서\n");
    printf("   - 공문서\n");
    printf("   - 금융 거래 확인서\n\n");

    printf("4. 코드 서명:\n");
    printf("   - Docker 이미지 서명\n");
    printf("   - Kubernetes manifest 서명\n");
    printf("   - 소프트웨어 패키지 서명\n\n");

    printf("5. API 요청 서명:\n");
    printf("   - HTTP 요청 무결성 검증\n");
    printf("   - Webhook 서명\n");
    printf("   - gRPC 메시지 서명\n\n");

cleanup:
    // 10. 안전한 메모리 해제
    printf("메모리 정리 중...\n");
    if (sig != NULL) {
        OQS_MEM_secure_free(secret_key, sig->length_secret_key);
        OQS_MEM_secure_free(signature, sig->length_signature);
    }
    free(public_key);
    OQS_SIG_free(sig);

    printf("✓ 메모리 정리 완료\n\n");
    printf("===========================================\n");
    printf("프로그램 종료\n");
    printf("===========================================\n");

    return 0;
}
