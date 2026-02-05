#pragma once

#include <stdint.h>

#define ADRS_SIZE 32

typedef struct {
    uint8_t adrs[ADRS_SIZE];
} ADRS;

void toByte(uint64_t x, uint64_t n, uint8_t *S);

uint64_t toInt(uint8_t *X, uint64_t n);

void initADRS(ADRS *adrs);

void setLayerAddress(ADRS *adrs, uint64_t l);

void setTreeAddress(ADRS *adrs, uint64_t t);

void setTypeAndClear(ADRS *adrs, uint64_t Y);

void setKeyPairAddress(ADRS *adrs, uint64_t i);

void setChainAddress(ADRS *adrs, uint64_t i);

void setTreeHeight(ADRS *adrs, uint64_t i);

void setHashAddress(ADRS *adrs, uint64_t i);

void setTreeIndex(ADRS *adrs, uint64_t i);

uint64_t getKeyPairAddress(ADRS *adrs);

uint64_t getTreeIndex(ADRS *adrs);
