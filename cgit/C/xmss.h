#pragma once

#include "adrs.h"
#include "params.h"

void xmss_node(Parameters *prm, const uint8_t* sk_seed, uint64_t i, uint64_t z, const uint8_t* pk_seed, ADRS adrs, uint8_t *buffer);

void xmss_sign(Parameters *prm, const uint8_t *M, const uint8_t *sk_seed, uint64_t idx, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer);

void xmss_pkFromSig(Parameters *prm, uint64_t idx, const uint8_t *sig_xmss, const uint8_t *M, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer);
