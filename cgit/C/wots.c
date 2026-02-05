#include <string.h>
#include "params.h"
#include "shake.h"
#include "wots.h"

// Algorithm 4 (Computes the base 2^b representation of X)
void base_2b(const uint8_t *X, uint64_t b, uint32_t out_len, uint32_t *baseb)
{
    uint64_t in_index = 0;                           // Equivalent to `in` in pseudocode
    uint64_t bits = 0;                               // Number of bits currently in `total`
    uint64_t total = 0;               // Accumulates the bit representation

    for (uint32_t out = 0; out < out_len; out++) {
        while (bits < b) {                      // Fill `total` with bits until it has at least `b` bits
            total = (total << 8) + X[in_index]; // Add 8 bits from X[in_index]
            in_index += 1;
            bits += 8;
        }

        baseb[out] = (total >> (bits - b)) & ((1ULL << b) - 1); // Extract the `b` least significant bits
        bits -= b;                              // Reduce `bits` by `b` as we've used them
    }
}

// Algorithm 5 (Chaining function used in WOTS+)
void chain(Parameters *prm, const uint8_t *X, uint64_t i, uint64_t s, const uint8_t *PK_seed, ADRS *adrs, uint8_t *buffer)
{
    uint8_t tmp[prm->n];
    memcpy(tmp, X, prm->n);

    for (uint32_t j = i; j < i + s; j++) {
        setHashAddress(adrs, j);
        F(prm, PK_seed, adrs, tmp, tmp);
    }
    memcpy(buffer, tmp, prm->n);
}

// Algorithm 6 (Generates a WOTS+ public key)
void wots_pkGen(Parameters *prm, const uint8_t *SK_seed, const uint8_t *PK_seed, ADRS adrs, uint8_t *pk)
{
    ADRS skADRS;
    skADRS = adrs;
    setTypeAndClear(&skADRS, prm->WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(&adrs));

    uint8_t sk[prm->n];
    uint8_t tmp[prm->len * prm->n];
    for (uint32_t i = 0; i < prm->len; i++) {
        setChainAddress(&skADRS, i);
        PRF(prm, PK_seed, &skADRS, SK_seed, sk);
        setChainAddress(&adrs, i);
        chain(prm, sk, 0, prm->w - 1, PK_seed, &adrs, tmp + i * prm->n);
    }

    ADRS wotspkADRS;
    wotspkADRS = adrs;
    setTypeAndClear(&wotspkADRS, prm->WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(&adrs));
    Tlen(prm, PK_seed, &wotspkADRS, tmp, prm->len * prm->n, pk);
}

// Algorithm 7 (Generates a WOTS+ signature on an n-byte message)
void wots_sign(Parameters *prm, const uint8_t *M, const uint8_t *SK_seed, const uint8_t *PK_seed, ADRS adrs, uint8_t *sig) {
    uint64_t csum = 0;
    uint32_t msg[prm->len];

    base_2b(M, prm->lg_w, prm->len1, msg);       // Convert message to base w
    for (uint32_t i = 0; i < prm->len1; i++) {
        csum += prm->w - 1 - msg[i];            // Compute checksum
    }

    csum <<= 4;

    // csum_bytes has length ceil((prm->len2 * prm->lg_w) / 8.0), which is always 2
    // since len2 and lg_w are static across all parameter sets
    uint8_t csum_bytes[2];
    toByte(csum, 2, csum_bytes);
    base_2b(csum_bytes, prm->lg_w, prm->len2, msg + prm->len1); // Convert to base w

    ADRS skADRS;
    skADRS = adrs;
    setTypeAndClear(&skADRS, prm->WOTS_PRF);
    setKeyPairAddress(&skADRS, getKeyPairAddress(&adrs));

    uint8_t sk[prm->n];
    for (uint32_t i = 0; i < prm->len; i++) {
        setChainAddress(&skADRS, i);
        PRF(prm, PK_seed, &skADRS, SK_seed, sk);
        setChainAddress(&adrs, i);
        chain(prm, sk, 0, msg[i], PK_seed, &adrs, sig + i * prm->n);
    }
}

// Algorithm 8 (Computes a WOTS+ public key from a message and its signature)
void wots_pkFromSig(Parameters *prm, uint8_t *sig, const uint8_t *M, const uint8_t *PK_seed, ADRS adrs, uint8_t *pksig) {
    uint64_t csum = 0;
    uint32_t msg[prm->len];

    base_2b(M, prm->lg_w, prm->len1, msg);       // Convert message to base w
    for (uint32_t i = 0; i < prm->len1; i++) {
        csum += prm->w - 1 - msg[i];            // Compute checksum
    }

    csum <<= 4;
    uint8_t csum_bytes[2];
    toByte(csum, 2, csum_bytes);
    base_2b(csum_bytes, prm->lg_w, prm->len2, msg + prm->len1); // Convert to base w

    uint8_t tmp[prm->len * prm->n];
    for (uint32_t i = 0; i < prm->len; i++) {
        setChainAddress(&adrs, i);
        chain(prm, sig + i * prm->n, msg[i], prm->w - 1 - msg[i], PK_seed, &adrs, tmp + i * prm->n);
    }

    ADRS wotspkADRS;
    wotspkADRS = adrs;
    setTypeAndClear(&wotspkADRS, prm->WOTS_PK);
    setKeyPairAddress(&wotspkADRS, getKeyPairAddress(&adrs));

    Tlen(prm, PK_seed, &wotspkADRS, tmp, prm->len * prm->n, pksig);
}
