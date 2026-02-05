#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "adrs.h"
#include "xmss.h"

// algorithm 12
// Generates a hypertree signature
void ht_sign(Parameters *prm, const uint8_t *M, const uint8_t *sk_seed, const uint8_t *pk_seed, uint64_t idx_tree, uint64_t idx_leaf, uint8_t *buffer)
{
    // length of one XMSS signature
    uint32_t xmss_sig_len = (prm->len + prm->h_) * prm->n;

    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    uint8_t sig_tmp[xmss_sig_len];
    uint8_t sig_ht[xmss_sig_len * prm->d];
    xmss_sign(prm, M, sk_seed, idx_leaf, pk_seed, adrs, sig_tmp);
    memcpy(sig_ht, sig_tmp, xmss_sig_len);

    uint8_t root[prm->n];
    xmss_pkFromSig(prm, idx_leaf, sig_tmp, M, pk_seed, adrs, root);

    for (uint32_t j = 1; j < prm->d; j++) {
        idx_leaf = idx_tree & ((1 << prm->h_) - 1);
        idx_tree = idx_tree >> prm->h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);

        xmss_sign(prm, root, sk_seed, idx_leaf, pk_seed, adrs, sig_tmp);
        memcpy(sig_ht + j * xmss_sig_len, sig_tmp, xmss_sig_len);

        if (j < prm->d - 1) {
            xmss_pkFromSig(prm, idx_leaf, sig_tmp, root, pk_seed, adrs, root);
        }
    }
    memcpy(buffer, sig_ht, xmss_sig_len * prm->d);
}

// algorithm 13
// Verifies a hypertree signature
bool ht_verify(Parameters *prm, const uint8_t *M, const uint8_t *sig_ht, const uint8_t *pk_seed, uint64_t idx_tree, uint64_t idx_leaf, const uint8_t *pk_root)
{
    // length of one XMSS signature
    uint32_t xmss_sig_len = (prm->len + prm->h_) * prm->n;

    ADRS adrs;
    initADRS(&adrs);
    setTreeAddress(&adrs, idx_tree);

    uint8_t node[prm->n];
    uint8_t sig_tmp[xmss_sig_len];
    memcpy(sig_tmp, sig_ht, xmss_sig_len);
    xmss_pkFromSig(prm, idx_leaf, sig_tmp, M, pk_seed, adrs, node);

    for (uint32_t j = 1; j < prm->d; j++) {
        idx_leaf = idx_tree & ((1 << prm->h_) - 1);
        idx_tree = idx_tree >> prm->h_;
        setLayerAddress(&adrs, j);
        setTreeAddress(&adrs, idx_tree);
        memcpy(sig_tmp, sig_ht + j * xmss_sig_len, xmss_sig_len);
        xmss_pkFromSig(prm, idx_leaf, sig_tmp, node, pk_seed, adrs, node);
    }

    if (memcmp(node, pk_root, prm->n) == 0)
        return true;
    return false;
}
