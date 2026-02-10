.PHONY: clean

AVX512_SUPPORTED := $(shell if (grep -q avx512f /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.features 2>/dev/null | grep -q AVX512F); then echo 1; else echo 0; fi)
AVX2_SUPPORTED := $(shell if (grep -q avx2 /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.leaf7_features 2>/dev/null | grep -q AVX2); then echo 1; else echo 0; fi)

ifeq ($(AVX512_SUPPORTED),1)
    KECCAK_SRC = KeccakP-1600-AVX512.c
    KECCAK_OBJ = KeccakP-1600-AVX512.o
    CFLAGS += -march=skylake-avx512
    INFO_MSG = "Using AVX512-optimized Keccak implementation"
else ifeq ($(AVX2_SUPPORTED),1)
    KECCAK_SRC = KeccakP-1600-AVX2.s
    KECCAK_OBJ = KeccakP-1600-AVX2.o
    CFLAGS += -mavx2 -DUSE_AVX2
    INFO_MSG = "Using AVX2-optimized Keccak implementation"
else
    KECCAK_SRC = KeccakP-1600-reference.c
    KECCAK_OBJ = KeccakP-1600-reference.o
    INFO_MSG = "Using Reference Keccak implementation"
endif

trxn:
    @echo $(INFO_MSG)
    gcc $(CFLAGS) trxn.c external.c internal.c $(KECCAK_OBJ) KeccakSpongeWidth1600.c \
        fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c \
        -o trxn -O3 -lgcrypt -lsodium -lm -lcjson
trxn:
	@echo $(INFO_MSG)
	gcc $(CFLAGS) trxn.c external.c internal.c $(KECCAK_OBJ) KeccakSpongeWidth1600.c \
	    fors.c hypertree.c xmss.c wots.c adrs.c shake.c params.c \
        -o trxn -O3 -lgcrypt -lsodium -lm -lcjson

    rm -f trxn *.o
