#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "params.h"
#include "external.h"
#include <cjson/cJSON.h>

static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t ascii_to_hex(char c)
{
    uint32_t num = (int32_t) c;
    if (num < 58 && num > 47)
        return num - 48;
    if (num < 103 && num > 96)
        return num - 87;
    return num;
}

void writeHexToFile(const char *filename, const uint8_t *data, size_t length) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        printf("Failed to open file: %s\n", filename);
        return;
    }

    for (size_t i = 0; i < length; i++) {
        fprintf(file, "%02x", data[i]);
    }

    fclose(file);
    printf("Hex data successfully written to file: %s\n", filename);
}

size_t base64_decode(const char *input, uint8_t *output) {
    if (input == NULL || output == NULL) return 0;

    size_t input_length = strlen(input);
    size_t padding = 0;
    
    // Count padding characters
    if (input_length > 0 && input[input_length - 1] == '=') padding++;
    if (input_length > 1 && input[input_length - 2] == '=') padding++;

    // Calculate output length
    size_t output_length = (input_length * 3) / 4 - padding;
    uint8_t *buffer = output;
    
    size_t i = 0;
    size_t j = 0;
    int val = 0;
    int valb = -8;
    
    while (i < input_length) {
        char c = input[i++];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        
        if (c == '=') break; // Padding character, stop here
        
        const char *p = strchr(base64_chars, c);
        if (p == NULL) continue; // Invalid character, skip
        
        val = (val << 6) | (p - base64_chars);
        valb += 6;
        
        if (valb >= 0) {
            buffer[j++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return output_length;
}

void decode_base64_to_bytes(const char *base64_str, uint8_t *output, size_t output_size) {
    uint8_t temp_buffer[output_size * 4];
    char hex_buffer[output_size * 8];
    
    size_t temp_len = base64_decode(base64_str, temp_buffer);
    for (size_t i = 0; i < output_size && i * 2 < temp_len * 2; i++) {
        sprintf(hex_buffer + i * 2, "%02x", temp_buffer[i]);
    }

    for (size_t i = 0; i < output_size; i++) {
        output[i] = (ascii_to_hex(hex_buffer[i * 2]) << 4) | ascii_to_hex(hex_buffer[i * 2 + 1]);
    }
}

char *bytes_to_hex(const uint8_t *data, size_t len) {
    char *hex = (char *)malloc(len * 2 + 1);
    if (!hex) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

cJSON *load_json_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error opening file: %s\n", filename);
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read file content
    char *json_content = (char *)malloc(file_size + 1);
    if (!json_content) {
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(json_content, 1, file_size, file);
    json_content[bytes_read] = '\0';
    fclose(file);
    
    // Parse JSON
    cJSON *json = cJSON_Parse(json_content);
    free(json_content);
    
    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            printf("Error parsing JSON: %s\n", error_ptr);
        }
        return NULL;
    }
    
    return json;
}

int main(void)
{
    // Initialize parameter set
    Parameters prm;
    setup_parameter_set(&prm, "SLH-DSA-SHAKE-256f");
    
    // Load JSON data
    cJSON *json = load_json_file("../payload.json");
    if (!json) {
        return EXIT_FAILURE;
    }
    
    // Extract base64 encoded values from JSON
    cJSON *seed_private_key = cJSON_GetObjectItem(json, "seedPrivateKeyByteArray");
    cJSON *prf_private_key = cJSON_GetObjectItem(json, "prfPrivateKeyByteArray");
    cJSON *public_seed_private_key = cJSON_GetObjectItem(json, "publicSeedPrivateKeyByteArray");
    cJSON *expected_raw_private_key = cJSON_GetObjectItem(json, "rawPrivateKeyByteArray");
    cJSON *expected_raw_public_key = cJSON_GetObjectItem(json, "rawPublicKeyByteArray");
    cJSON *payload = cJSON_GetObjectItem(json, "payloadByteArray");
    cJSON *signature = cJSON_GetObjectItem(json, "signatureByteArray");
    
    if (!cJSON_IsString(seed_private_key) || !cJSON_IsString(prf_private_key) || 
        !cJSON_IsString(public_seed_private_key) || !cJSON_IsString(expected_raw_private_key) || 
        !cJSON_IsString(expected_raw_public_key) || !cJSON_IsString(payload) ||
        !cJSON_IsString(signature)) {
        printf("Missing or invalid JSON fields\n");
        cJSON_Delete(json);
        return EXIT_FAILURE;
    }
    
    uint8_t sk_seed[prm.n];
    uint8_t sk_prf[prm.n];
    uint8_t pk_seed[prm.n];
    uint8_t expected_SK[prm.n * 4];
    uint8_t expected_PK[prm.n * 2];
    uint8_t message[1024];
    
    // Decode sk_seed
    decode_base64_to_bytes(seed_private_key->valuestring, sk_seed, prm.n);
    // Decode sk_prf
    decode_base64_to_bytes(prf_private_key->valuestring, sk_prf, prm.n);
    // Decode pk_seed
    decode_base64_to_bytes(public_seed_private_key->valuestring, pk_seed, prm.n);
    // Decode message
    size_t message_len = base64_decode(payload->valuestring, message);
    decode_base64_to_bytes(payload->valuestring, message, message_len);

    size_t expected_sk_len = base64_decode(expected_raw_private_key->valuestring, expected_SK);
    size_t expected_pk_len = base64_decode(expected_raw_public_key->valuestring, expected_PK);
    
    // Generate key pair
    uint8_t SK[prm.n * 4];
    uint8_t PK[prm.n * 2];
    
    printf("Generating keys...\n\n");
    slh_keygen(&prm, sk_seed, sk_prf, pk_seed, SK, PK);
    
    // Convert keys to hex for display
    char *sk_hex = bytes_to_hex(SK, prm.n * 4);
    char *pk_hex = bytes_to_hex(PK, prm.n * 2);
    
    printf("Private Key (Hex): %s\n", sk_hex);
    printf("Public Key (Hex): %s\n", pk_hex);
    
    if (memcmp(SK, expected_SK, expected_sk_len) == 0) {
        printf("\nPrivate key matches expected value!\n");
    } else {
        printf("\nPrivate key does not match expected value!\n");
    }
    
    if (memcmp(PK, expected_PK, expected_pk_len) == 0) {
        printf("Public key matches expected value!\n");
    } else {
        printf("Public key does not match expected value!\n");
    }
    
    // Generate signature
    uint8_t ctx[0];
    uint32_t sig_len = prm.n + (prm.k * (1 + prm.a) * prm.n) + ((prm.h + prm.d * prm.len) * prm.n);
    uint8_t *GEN_SIG = (uint8_t *)malloc(sig_len);
    if (!GEN_SIG) {
        printf("Memory allocation failed for signature\n");
        free(pk_hex);
        free(sk_hex);
        cJSON_Delete(json);
        return EXIT_FAILURE;
    }
    memset(GEN_SIG, 0, sig_len);
    
    printf("\nSigning message...\n");
    slh_sign(&prm, message, message_len, ctx, sizeof(ctx), SK, GEN_SIG, false);
    
    printf("Verifying generated signature...\n");
    bool result = slh_verify(&prm, message, message_len, GEN_SIG, sig_len, ctx, sizeof(ctx), PK);
    printf("Generated signature verification result: %s\n", result ? "SUCCESS" : "FAILED");
    
    writeHexToFile("../generated_signature_hex.txt", GEN_SIG, sig_len);
    
    // Decode and verify the signature from JSON
    uint8_t *PAYLOAD_SIG = (uint8_t *)malloc(sig_len);
    if (!PAYLOAD_SIG) {
        printf("Memory allocation failed for JSON signature\n");
        free(GEN_SIG);
        free(pk_hex);
        free(sk_hex);
        cJSON_Delete(json);
        return EXIT_FAILURE;
    }
    
    size_t payload_sig_len = base64_decode(signature->valuestring, PAYLOAD_SIG);
    printf("\nVerifying signature from Payload...\n");
    result = slh_verify(&prm, message, message_len, PAYLOAD_SIG, payload_sig_len, ctx, sizeof(ctx), PK);
    printf("Payload signature verification result: %s\n", result ? "SUCCESS" : "FAILED");
    
    // Clean up
    free(GEN_SIG);
    free(PAYLOAD_SIG);
    free(pk_hex);
    free(sk_hex);
    cJSON_Delete(json);
    
    return EXIT_SUCCESS;
}