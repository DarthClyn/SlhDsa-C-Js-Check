#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include "params.h"

void slh_keygen_internal(Parameters *prm, uint8_t *sk_seed, uint8_t *sk_prf, uint8_t *pk_seed, uint8_t *SK, uint8_t *PK);

void slh_sign_internal(Parameters *prm, uint8_t *M, size_t M_len, const uint8_t *SK, const uint8_t *addrnd, uint8_t *buffer);

bool slh_verify_internal(Parameters *prm, uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *PK);
