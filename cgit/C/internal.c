#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "adrs.h"
#include "fors.h"
#include "hypertree.h"
#include "params.h"
#include "shake.h"
#include "xmss.h"

// // algorithm 18
// void slh_keygen_internal(Parameters *prm, uint8_t *sk_seed, uint8_t *sk_prf, uint8_t *pk_seed, uint8_t *SK, uint8_t *PK)
// {
//     ADRS adrs;
//     initADRS(&adrs);

//     setLayerAddress(&adrs, prm->d - 1);
//     uint8_t pk_root[prm->n];
//     xmss_node(prm, sk_seed, 0, prm->h_, pk_seed, adrs, pk_root);

//     memcpy(SK + 0 * prm->n, sk_seed, prm->n);
//     memcpy(SK + 1 * prm->n, sk_prf,  prm->n);
//     memcpy(SK + 2 * prm->n, pk_seed, prm->n);
//     memcpy(SK + 3 * prm->n, pk_root, prm->n);

//     memcpy(PK + 0 * prm->n, pk_seed, prm->n);
//     memcpy(PK + 1 * prm->n, pk_root, prm->n);
// }

// algorithm 19
void slh_sign_internal(Parameters *prm, uint8_t *M, size_t M_len, const uint8_t *SK, const uint8_t *addrnd, uint8_t *buffer)
{
    // precompute these values to make the code cleaner
    uint64_t index1 = (prm->k * prm->a + 7) / 8;
    uint64_t index2 = ((prm->h - (prm->h / prm->d)) + 7) / 8;
    uint64_t index3 = ((prm->h / prm->d) + 7) / 8;

    ADRS adrs;
    initADRS(&adrs);

    uint8_t sk_seed[prm->n];
    uint8_t sk_prf[prm->n];
    uint8_t pk_seed[prm->n];
    uint8_t pk_root[prm->n];
    memcpy(sk_seed, SK + 0 * prm->n, prm->n);
    memcpy(sk_prf,  SK + 1 * prm->n, prm->n);
    memcpy(pk_seed, SK + 2 * prm->n, prm->n);
    memcpy(pk_root, SK + 3 * prm->n, prm->n);

    uint32_t sig_fors_len = prm->k * (1 + prm->a) * prm->n;
    uint32_t sig_ht_len = (prm->h + prm->d * prm->len) * prm->n;
    // signature = Randomness + FORS signature + HT signature
    uint8_t SIG[prm->n + sig_fors_len + sig_ht_len];

    // Generate R using PRF
    uint8_t R[prm->n];
    PRF_msg(prm, sk_prf, addrnd, M, M_len, R);
    memcpy(SIG, R, prm->n);

    // Generate message digest
    uint8_t digest[prm->m];
    H_msg(prm, R, pk_seed, pk_root, M, M_len, digest);

    uint8_t md[index1];
    memcpy(md, digest, index1);

    uint8_t tmp_idx_tree[index2];
    uint8_t tmp_idx_leaf[index3];
    memcpy(tmp_idx_tree, digest + index1, index2);
    memcpy(tmp_idx_leaf, digest + index1 + index2, index3);

    uint64_t bitmask;
    if (prm->h - prm->h_ >= 64) {
        bitmask = UINT64_MAX;
    } else {
        bitmask = (UINT64_C(1) << (prm->h - prm->h_)) - UINT64_C(1);
    }
    uint64_t idx_tree = toInt(tmp_idx_tree, index2) & bitmask;
    uint64_t idx_leaf = toInt(tmp_idx_leaf, index3) & (1 << prm->h_) - 1;

    setTreeAddress(&adrs, idx_tree);
    setTypeAndClear(&adrs, prm->FORS_TREE);
    setKeyPairAddress(&adrs, idx_leaf);

    // Generate FORS signature
    uint8_t SIG_FORS[sig_fors_len];
    fors_sign(prm, md, sk_seed, pk_seed, adrs, SIG_FORS);

    // Copy FORS signature to main signature
    memcpy(SIG + prm->n, SIG_FORS, sig_fors_len);

    uint8_t PK_FORS[prm->n];
    fors_pkFromSig(prm, SIG_FORS, md, pk_seed, adrs, PK_FORS);

    // Generate and append HT signature
    uint8_t SIG_HT[sig_ht_len];
    ht_sign(prm, PK_FORS, sk_seed, pk_seed, idx_tree, idx_leaf, SIG_HT);
    memcpy(SIG + prm->n + sig_fors_len, SIG_HT, sig_ht_len);
    memcpy(buffer, SIG, prm->n + sig_fors_len + sig_ht_len);
}

// // algorithm 20
// bool slh_verify_internal(Parameters *prm, uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *PK)
// {
//     uint64_t index1 = (prm->k * prm->a + 7) / 8;
//     uint64_t index2 = ((prm->h - (prm->h / prm->d)) + 7) / 8;
//     uint64_t index3 = ((prm->h / prm->d) + 7) / 8;

//     uint32_t sig_fors_len = prm->k * (1 + prm->a) * prm->n;
//     uint32_t sig_ht_len = (prm->h + prm->d * prm->len) * prm->n;
//     uint32_t sig_len = prm->n + sig_fors_len + sig_ht_len;

//     uint8_t pk_seed[prm->n];
//     uint8_t pk_root[prm->n];
//     memcpy(pk_seed, PK + 0 * prm->n, prm->n);
//     memcpy(pk_root, PK + 1 * prm->n, prm->n);

//     if (SIG_len != sig_len) {
//         printf("Signature has invalid length\n");
//         return false;
//     }

//     ADRS adrs;
//     initADRS(&adrs);

//     uint8_t R[prm->n];
//     memcpy(R, SIG, prm->n);

//     // Extract FORS and HT signatures
//     uint8_t SIG_FORS[sig_fors_len];
//     memcpy(SIG_FORS, SIG + prm->n, sig_fors_len);

//     uint8_t SIG_HT[sig_ht_len];
//     memcpy(SIG_HT, SIG + prm->n + sig_fors_len, sig_ht_len);

//     uint8_t digest[prm->m];
//     H_msg(prm, R, pk_seed, pk_root, M, M_len, digest);
//     uint8_t md[index1];
//     memcpy(md, digest, index1);

//     uint8_t tmp_idx_tree[index2];
//     uint8_t tmp_idx_leaf[index3];
//     memcpy(tmp_idx_tree, digest + index1, index2);
//     memcpy(tmp_idx_leaf, digest + index1 + index2, index3);

//     uint64_t idx_tree = toInt(tmp_idx_tree, index2) & (UINT64_MAX >> (64 - (prm->h - prm->h / prm->d)));
//     uint64_t idx_leaf = toInt(tmp_idx_leaf, index3) & (UINT64_MAX >> (64 - prm->h / prm->d));

//     setTreeAddress(&adrs, idx_tree);
//     setTypeAndClear(&adrs, prm->FORS_TREE);
//     setKeyPairAddress(&adrs, idx_leaf);

//     uint8_t PK_FORS[prm->n];
//     fors_pkFromSig(prm, SIG_FORS, md, pk_seed, adrs, PK_FORS);

//     return ht_verify(prm, PK_FORS, SIG_HT, pk_seed, idx_tree, idx_leaf, pk_root);
// }
