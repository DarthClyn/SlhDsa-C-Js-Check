#pragma once

#include "adrs.h"
#include "params.h"

uint8_t gen_len2(uint32_t n, uint32_t lg_w);

void base_2b(const uint8_t *X, uint64_t b, uint32_t out_len, uint32_t *baseb);

void chain(Parameters *prm, const uint8_t *X, uint64_t i, uint64_t s, const uint8_t *PK_seed, ADRS *adrs, uint8_t *buffer);

void wots_pkGen(Parameters *prm, const uint8_t *SK_seed, const uint8_t *PK_seed, ADRS adrs, uint8_t *pk);

void wots_sign(Parameters *prm, const uint8_t *M, const uint8_t *SK_seed, const uint8_t *PK_seed, ADRS adrs, uint8_t *sig);

void wots_pkFromSig(Parameters *prm, uint8_t *sig, const uint8_t *M, const uint8_t *PK_seed, ADRS adrs, uint8_t *pksig);
