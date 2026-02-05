#include <string.h>
#include "wots.h"
#include "shake.h"
#include "xmss.h"

// algorithm 9
void xmss_node(Parameters *prm, const uint8_t* sk_seed, uint64_t i, uint64_t z, const uint8_t* pk_seed, ADRS adrs, uint8_t *buffer)
{
    uint8_t node[prm->n];

    if (z == 0) {
        setTypeAndClear(&adrs, prm->WOTS_HASH);
        setKeyPairAddress(&adrs, i);
        wots_pkGen(prm, sk_seed, pk_seed, adrs, node);
    } else {
        uint8_t lnode[prm->n];
        uint8_t rnode[prm->n];
        xmss_node(prm, sk_seed, i * 2,     z - 1, pk_seed, adrs, lnode);
        xmss_node(prm, sk_seed, i * 2 + 1, z - 1, pk_seed, adrs, rnode);

        setTypeAndClear(&adrs, prm->TREE);
        setTreeHeight(&adrs, z);
        setTreeIndex(&adrs, i);

        // Concatenate lnode and rnode
        uint8_t combined[prm->n * 2];
        memcpy(combined, lnode, prm->n);
        memcpy(combined + prm->n, rnode, prm->n);

        H(prm, pk_seed, &adrs, combined, node);
    }
    memcpy(buffer, node, prm->n);
}

// algorithm 10
void xmss_sign(Parameters *prm, const uint8_t *M, const uint8_t *sk_seed, uint64_t idx, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer)
{
    uint8_t AUTH[prm->h_ * prm->n];
    for (uint32_t j = 0; j < prm->h_; j++) {
        uint32_t k = (idx >> j) ^ 1;
        xmss_node(prm, sk_seed, k, j, pk_seed, adrs, AUTH + j * prm->n);
    }

    setTypeAndClear(&adrs, prm->WOTS_HASH);
    setKeyPairAddress(&adrs, idx);
    uint8_t sig[prm->len * prm->n];
    wots_sign(prm, M, sk_seed, pk_seed, adrs, sig);

    memcpy(buffer, sig, prm->len * prm->n);
    memcpy(buffer + prm->len * prm->n, AUTH, prm->h_ * prm->n);
}

// algorithm 11
void xmss_pkFromSig(Parameters *prm, uint64_t idx, const uint8_t *sig_xmss, const uint8_t *M, const uint8_t *pk_seed, ADRS adrs, uint8_t *buffer)
{
    uint8_t node_0[prm->n];
    uint8_t node_1[prm->n];

    setTypeAndClear(&adrs, prm->WOTS_HASH);
    setKeyPairAddress(&adrs, idx);

    uint8_t sig[prm->len * prm->n];
    uint8_t AUTH[prm->h_ * prm->n];
    memcpy(sig, sig_xmss, prm->len * prm->n);
    memcpy(AUTH, sig_xmss + prm->len * prm->n, prm->h_ * prm->n);

    wots_pkFromSig(prm, sig, M, pk_seed, adrs, node_0);
    setTypeAndClear(&adrs, prm->TREE);
    setTreeIndex(&adrs, idx);

    uint8_t combined[2 * prm->n];
    for (uint32_t k = 0; k < prm->h_; k++) {
        setTreeHeight(&adrs, k + 1);
        if (((idx >> k) & 1) == 0) {
            setTreeIndex(&adrs, getTreeIndex(&adrs) / 2);
            memcpy(combined, node_0, prm->n);
            memcpy(combined + prm->n, AUTH + k * prm->n, prm->n);
            H(prm, pk_seed, &adrs, combined, node_1);
        } else {
            setTreeIndex(&adrs, (getTreeIndex(&adrs) - 1) / 2);
            memcpy(combined, AUTH + k * prm->n, prm->n);
            memcpy(combined + prm->n, node_0, prm->n);
            H(prm, pk_seed, &adrs, combined, node_1);
        }
        memcpy(node_0, node_1, prm->n);
    }
    memcpy(buffer, node_0, prm->n);
}
