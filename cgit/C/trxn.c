#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "params.h"
#include "external.h"
#include <cjson/cJSON.h>

/*
  Paths (relative to executable location)

  Executable: cgit/C/trxn
  trxn.json : ../../trxn.json
  sign.json : ../../sign.json
*/

#define TRXN_JSON_PATH "../../trxn.json"
#define SIGN_JSON_PATH "../../sign.json"

/* =========================================================
    Key material is now loaded from trxn.json
    ========================================================= */

/* =========================================================
   Helpers
   ========================================================= */

static uint8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (hex_val(hex[i * 2]) << 4)
               |  hex_val(hex[i * 2 + 1]);
    }
}

static char *bytes_to_hex(const uint8_t *data, size_t len) {
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

static cJSON *load_json(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    char *buf = malloc(sz + 1);
    fread(buf, 1, sz, f);
    buf[sz] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    return json;
}

/* =========================================================
   MAIN
   ========================================================= */

int main(void) {
    printf("[C-SIGNER] Loading parameters...\n");

    Parameters prm;
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-256f");


    /* Load trxn.json */
    cJSON *trxn = load_json(TRXN_JSON_PATH);
    if (!trxn) {
        printf("ERROR: Failed to open %s\n", TRXN_JSON_PATH);
        return 1;
    }

    cJSON *msgHashItem = cJSON_GetObjectItem(trxn, "msgHash");
    if (!cJSON_IsString(msgHashItem)) {
        printf("ERROR: msgHash missing in trxn.json\n");
        cJSON_Delete(trxn);
        return 1;
    }

    cJSON *privKeyItem = cJSON_GetObjectItem(trxn, "privateKey");
    if (!cJSON_IsString(privKeyItem)) {
        printf("ERROR: privateKey missing in trxn.json\n");
        cJSON_Delete(trxn);
        return 1;
    }


    /* Decode msgHash (32 bytes) */
    uint8_t msg[32];
    hex_to_bytes(msgHashItem->valuestring, msg, 32);

    printf("[C-SIGNER] msgHash loaded\n");

    /* Decode private key */
    uint8_t SK[128];
    hex_to_bytes(privKeyItem->valuestring, SK, 128);

    /* Compute signature length */
    size_t sig_len =
        prm.n +
        (prm.k * (1 + prm.a) * prm.n) +
        ((prm.h + prm.d * prm.len) * prm.n);

    uint8_t *SIG = malloc(sig_len);
    memset(SIG, 0, sig_len);

    uint8_t ctx[0];

    printf("[C-SIGNER] Signing...\n");

    /* Sign EXACTLY like Noble */
    slh_sign(&prm, msg, 32, ctx, 0, SK, SIG, false);

    /* Build sig = SIG */
    char *sig_hex = bytes_to_hex(SIG, sig_len);

    FILE *out = fopen(SIGN_JSON_PATH, "w");
    if (!out) {
        printf("ERROR: Failed to write %s\n", SIGN_JSON_PATH);
        return 1;
    }

    fprintf(out,
        "{\n"
        "  \"sig\": \"0x%s\"\n"
        "}\n",
        sig_hex
    );

    fclose(out);

    printf("[C-SIGNER] Signature written to %s\n", SIGN_JSON_PATH);

    free(SIG);
    free(sig_hex);
    cJSON_Delete(trxn);

    return 0;
}
