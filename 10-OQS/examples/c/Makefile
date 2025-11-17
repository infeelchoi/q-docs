# Makefile for liboqs C examples
# QSIGN Production Environment

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -loqs -lssl -lcrypto

# pkg-config 지원 (선택사항)
ifneq ($(shell which pkg-config),)
    CFLAGS += $(shell pkg-config --cflags liboqs 2>/dev/null)
    LDFLAGS = $(shell pkg-config --libs liboqs 2>/dev/null) -lssl -lcrypto
endif

# 타겟
TARGETS = kem_example signature_example hybrid_example

.PHONY: all clean run-all

all: $(TARGETS)

kem_example: kem_example.c
	@echo "컴파일 중: $@"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "✓ $@ 컴파일 완료"

signature_example: signature_example.c
	@echo "컴파일 중: $@"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "✓ $@ 컴파일 완료"

hybrid_example: hybrid_example.c
	@echo "컴파일 중: $@"
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
	@echo "✓ $@ 컴파일 완료"

run-all: all
	@echo ""
	@echo "========================================="
	@echo "KEM Example 실행:"
	@echo "========================================="
	./kem_example
	@echo ""
	@echo "========================================="
	@echo "Signature Example 실행:"
	@echo "========================================="
	./signature_example

clean:
	@echo "정리 중..."
	rm -f $(TARGETS)
	@echo "✓ 정리 완료"

help:
	@echo "사용법:"
	@echo "  make          - 모든 예제 컴파일"
	@echo "  make clean    - 빌드 파일 삭제"
	@echo "  make run-all  - 모든 예제 컴파일 및 실행"
	@echo "  make help     - 도움말 출력"
	@echo ""
	@echo "개별 타겟:"
	@echo "  make kem_example        - KEM 예제만 컴파일"
	@echo "  make signature_example  - Signature 예제만 컴파일"
	@echo "  make hybrid_example     - Hybrid 예제만 컴파일"
