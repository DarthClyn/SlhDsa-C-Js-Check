#pragma once

#include <stdlib.h>
#include "adrs.h"
#include "params.h"

void H_msg(Parameters *prm, const uint8_t *R, const uint8_t *pk_seed, const uint8_t *pk_root, const uint8_t *M, size_t M_len, uint8_t *buffer);

void PRF_msg(Parameters *prm, const uint8_t *sk_prf, const uint8_t *opt_rand, const uint8_t *M, size_t M_len, uint8_t *buffer);

void H(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M2, uint8_t *buffer);

void F(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M1, uint8_t *buffer);

void Tlen(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, uint8_t *Ml, size_t Ml_len, uint8_t *buffer);

void PRF(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *sk_seed, uint8_t *buffer);

void SHA_256(const uint8_t *M, size_t M_len, uint8_t *buffer);

void SHA_512(const uint8_t *M, size_t M_len, uint8_t *buffer);

void SHAKE_128(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len);

void SHAKE_256(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len);
