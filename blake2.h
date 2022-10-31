// required header files
#include <stdio.h>
#include <stdint.h>

// state context for BLAKE2s-256
typedef struct
{
    uint8_t b[64]; // input buffer
    uint32_t h[8]; // chained state
    uint32_t t[2]; // total number of bytes
    size_t c;      // pointer for b[]
    size_t outlen; // digest size
} blake2s_ctx;

// function declarations

// Initialize the hashing context "ctx" with optional key "key".
// 1 <= outlen <= 32 gives the digest size in bytes.
// Secret key (also <= 32 bytes) is optional (keylen = 0).
int blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen);

// Add "inlen" bytes from "in" into the hash.
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen);

// Generate the message digest (size given in init).
// Result placed in "out".
void blake2s_final(blake2s_ctx *ctx, void *out);

// All-in-one convenience function.
// parameters: output array, key, input array
int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen);