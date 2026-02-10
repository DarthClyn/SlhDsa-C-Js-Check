#include <stdio.h>
#include <stdint.h>
#include <string.h>
//#include <sodium.h>

#include "adrs.h"
#include "params.h"
#include "internal.h"
#include "shake.h"
#include "external.h"

// Algorithmus 21: Generiert ein SLH-DSA Schl�sselpaar
// void slh_keygen(Parameters *prm, uint8_t *SK_seed, uint8_t *SK_prf, uint8_t *PK_seed, uint8_t *SK, uint8_t *PK)
// {
//     if (sodium_init() < 0) {
//         printf("Error initalizing sodium library\n");
//         return;
//     }

//     // check if the seed and prf values are empty
//     // if so, randomly generate them
//     uint32_t sum_sk_seed, sum_sk_prf, sum_pk_seed = 0;
//     for (uint32_t i = 0; i < prm->n; i++) {
//         sum_sk_seed |= SK_seed[i];
//         sum_sk_prf  |= SK_prf[i];
//         sum_pk_seed |= PK_seed[i];
//     }
//     if (sum_sk_seed == 0)
//         randombytes_buf(SK_seed, prm->n);
//     if (sum_sk_prf == 0)
//         randombytes_buf(SK_prf , sizeof SK_prf);
//     if (sum_pk_seed == 0)
//         randombytes_buf(PK_seed, sizeof PK_seed);

//     slh_keygen_internal(prm, SK_seed, SK_prf, PK_seed, SK, PK);
// }

// Algorithmus 22: Generiert eine reine SLH-DSA Signatur
void slh_sign(Parameters *prm, uint8_t *M, size_t M_len, const uint8_t *ctx, const size_t ctx_len, const uint8_t *SK, uint8_t *SIG, bool deterministic)
{
    if (ctx_len > MAX_CTX_LENGTH) {
        printf("Invalid context length\n");
        return;
    }

    // for deterministic varaiant, use PK_seed for addrnd
    uint8_t addrnd[prm->n];
    if (deterministic == true) {
        memcpy(addrnd, SK + 2 * prm->n, prm->n);
    }
 
    uint8_t M_prime[1 + 1 + ctx_len + M_len];
    M_prime[0] = 0;
    toByte(ctx_len, 1, M_prime + 1);

    memcpy(M_prime + 2, ctx, ctx_len);
    memcpy(M_prime + 2 + ctx_len, M, M_len);

    slh_sign_internal(prm, M_prime, sizeof M_prime, SK, addrnd, SIG);
}

// // Algorithmus 23: Generiert eine vorgehashte SLH-DSA Signatur
// void hash_slh_sign(Parameters *prm, const uint8_t *M, size_t M_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *SK, uint8_t *SIG, bool deterministic)
// {
//     if (ctx_len > MAX_CTX_LENGTH) {
//         printf("Context is longer that %d\n", MAX_CTX_LENGTH);
//         return;
//     }

//     // for deterministic varaiant, use PK_seed for addrnd
//     uint8_t addrnd[prm->n];
//     if (deterministic == true) {
//         memcpy(addrnd, SK + 2 * prm->n, prm->n);
//     }
//     else {
//         if (sodium_init() < 0) {
//             printf("Error initalizing sodium library\n");
//             return;
//         }
//         randombytes_buf(addrnd, sizeof addrnd);
//     }

//     uint8_t OID[11];
//     uint8_t PHM[64] = {0};

//     if (strcmp(PH, "SHA-256") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
//         SHA_256(M, M_len, PHM);
//     } else if (strcmp(PH, "SHA-512") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
//         SHA_512(M, M_len, PHM);
//     } else if (strcmp(PH, "SHAKE128") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B", 11);
//         SHAKE_128(M, M_len, PHM, 32);
//     } else if (strcmp(PH, "SHAKE256") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C", 11);
//         SHAKE_256(M, M_len, PHM, 64);
//     } else {
//         printf("Unsupported hash function\n");
//         printf("Valid values are 'SHA-256', 'SHA-512', 'SHAKE128', 'SHAKE256'\n");
//         return;
//     }

//     uint8_t M_prime[1 + 1 + ctx_len + 11 + sizeof PHM];
//     M_prime[0] = 1;
//     toByte(ctx_len, 1, M_prime + 1);

//     memcpy(M_prime + 2, ctx, ctx_len);
//     memcpy(M_prime + 2 + ctx_len, OID, sizeof OID);
//     memcpy(M_prime + 2 + ctx_len + sizeof OID, PHM, sizeof PHM);

//     slh_sign_internal(prm, M_prime, sizeof M_prime, SK, addrnd, SIG);
// }

// // Algorithmus 24: Verifiziert eine reine SLH-DSA Signatur
// bool slh_verify(Parameters *prm, uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, uint8_t *ctx, size_t ctx_len, const uint8_t *PK)
// {
//     if (ctx_len > MAX_CTX_LENGTH) {
//         printf("Invalid context length\n");
//         return false;
//     }
//     uint8_t M_prime[1 + 1 + ctx_len + M_len];
//     M_prime[0] = 0;
//     toByte(ctx_len, 1, M_prime + 1);

//     memcpy(M_prime + 2, ctx, ctx_len);
//     memcpy(M_prime + 2 + ctx_len, M, M_len);
//     return slh_verify_internal(prm, M_prime, sizeof M_prime, SIG, SIG_len, PK);
// }

// // Algorithmus 25: Verifiziert eine vorgehashte SLH-DSA Signatur
// bool hash_slh_verify(Parameters *prm, const uint8_t *M, size_t M_len, uint8_t *SIG, size_t SIG_len, const uint8_t *ctx, size_t ctx_len, const char *PH, const uint8_t *PK)
// {
//     if (ctx_len > MAX_CTX_LENGTH) {
//         printf("Context is longer that %d\n", MAX_CTX_LENGTH);
//         return false;
//     }

//     uint8_t OID[11];
//     uint8_t PHM[64] = {0};

//     if (strcmp(PH, "SHA-256") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", 11);
//         SHA_256(M, M_len, PHM);
//     } else if (strcmp(PH, "SHA-512") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", 11);
//         SHA_512(M, M_len, PHM);
//     } else if (strcmp(PH, "SHAKE128") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0B", 11);
//         SHAKE_128(M, M_len, PHM, 32);
//     } else if (strcmp(PH, "SHAKE256") == 0) {
//         memcpy(OID, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0C", 11);
//         SHAKE_256(M, M_len, PHM, 64);
//     } else {
//         printf("Unsupported hash function\n");
//         printf("Valid values are 'SHA-256', 'SHA-512', 'SHAKE128', 'SHAKE256'\n");
//         return false;
//     }

//     uint8_t M_prime[1 + 1 + ctx_len + 11 + sizeof PHM];
//     M_prime[0] = 1;
//     toByte(ctx_len, 1, M_prime + 1);

//     memcpy(M_prime + 2, ctx, ctx_len);
//     memcpy(M_prime + 2 + ctx_len, OID, sizeof OID);
//     memcpy(M_prime + 2 + ctx_len + sizeof OID, PHM, sizeof PHM);

//     return slh_verify_internal(prm, M_prime, sizeof M_prime, SIG, SIG_len, PK);
// }
