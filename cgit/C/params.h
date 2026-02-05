#pragma once

#include <stdint.h>

// Structure to hold parameters
typedef struct {
    uint8_t WOTS_HASH;
    uint8_t WOTS_PK;
    uint8_t TREE;
    uint8_t FORS_TREE;
    uint8_t FORS_ROOTS;
    uint8_t WOTS_PRF;
    uint8_t FORS_PRF;
    uint8_t lg_w;
    uint8_t w;
    uint8_t len2;
    uint8_t n;
    uint8_t h;
    uint8_t d;
    uint8_t h_;
    uint8_t a;
    uint8_t k;
    uint8_t m;
    uint8_t len1;
    uint8_t len;
} Parameters;

void setup_parameter_set(Parameters *prm, const char* name);
