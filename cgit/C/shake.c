#include <gcrypt.h>
#include "params.h"
#include "adrs.h"
#include "KeccakSpongeWidth1600.h"

void H_msg(Parameters *prm, const uint8_t *R, const uint8_t *pk_seed, const uint8_t *pk_root, const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t combined[3 * prm->n + M_len];
    memcpy(combined, R, prm->n);
    memcpy(combined + prm->n, pk_seed, prm->n);
    memcpy(combined + 2 * prm->n, pk_root, prm->n);
    memcpy(combined + 3 * prm->n, M, M_len);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->m);
}

void PRF_msg(Parameters *prm, const uint8_t *sk_prf, const uint8_t *opt_rand, const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t combined[2 * prm->n + M_len];
    memcpy(combined, sk_prf, prm->n);
    memcpy(combined + prm->n, opt_rand, prm->n);
    memcpy(combined + 2 * prm->n, M, M_len);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->n);
}

void H(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M2, uint8_t *buffer)
{
    uint8_t combined[3 * prm->n + ADRS_SIZE];
    memcpy(combined, pk_seed, prm->n);
    memcpy(combined + prm->n, adrs->adrs, ADRS_SIZE);
    memcpy(combined + prm->n + ADRS_SIZE, M2, 2 * prm->n);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->n);
}

void F(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *M1, uint8_t *buffer)
{
    uint8_t combined[2 * prm->n + ADRS_SIZE];
    memcpy(combined, pk_seed, prm->n);
    memcpy(combined + prm->n, adrs->adrs, ADRS_SIZE);
    memcpy(combined + prm->n + ADRS_SIZE, M1, prm->n);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->n);
}

void Tlen(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, uint8_t *Ml, size_t Ml_len, uint8_t *buffer)
{
    uint8_t combined[prm->n + ADRS_SIZE + Ml_len];
    memcpy(combined, pk_seed, prm->n);
    memcpy(combined + prm->n, adrs->adrs, ADRS_SIZE);
    memcpy(combined + prm->n + ADRS_SIZE, Ml, Ml_len);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->n);
}

void PRF(Parameters *prm, const uint8_t *pk_seed, const ADRS *adrs, const uint8_t *sk_seed, uint8_t *buffer)
{
    uint8_t combined[prm->n + ADRS_SIZE + prm->n];
    memcpy(combined, pk_seed, prm->n);
    memcpy(combined + prm->n, adrs->adrs, ADRS_SIZE);
    memcpy(combined + prm->n + ADRS_SIZE, sk_seed, prm->n);
    KeccakWidth1600_Sponge(1088, 512, combined, sizeof combined, 0x1F, buffer, prm->n);
}

void SHA_256(const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t *digest;
    uint32_t digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA256);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHA_512(const uint8_t *M, size_t M_len, uint8_t *buffer)
{
    uint8_t *digest;
    uint32_t digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512);

    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    digest = gcry_md_read(h, GCRY_MD_SHA512);
    memcpy(buffer, digest, digest_len);
    gcry_md_close(h);
}

void SHAKE_128(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE128, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE128, buffer, out_len);
    gcry_md_close(h);
}

void SHAKE_256(const uint8_t *M, size_t M_len, uint8_t *buffer, uint32_t out_len)
{
    gcry_md_hd_t h;
    gcry_md_open(&h, GCRY_MD_SHAKE256, GCRY_MD_FLAG_SECURE);

    gcry_md_write(h, M, M_len);

    gcry_md_extract(h, GCRY_MD_SHAKE256, buffer, out_len);
    gcry_md_close(h);
}
