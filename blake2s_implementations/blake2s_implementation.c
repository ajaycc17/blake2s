// include the blake2s.h file
#include "blake2_header.h"
#include <string.h>

#define toRead 64

// define the circular right rotation by 32 bits
// ((x) << (32 - (y))) is used to bring the discarded values due to shift back at the end maintaining rotation or circular shift
#define ROTR32(x, y) (((x) >> (y)) ^ ((x) << (32 - (y))))

// the function to get the little endian form of b[] in m[]
#define B2S_GET32(p)                           \
    (((uint32_t)((uint8_t *)(p))[0]) ^         \
     (((uint32_t)((uint8_t *)(p))[1]) << 8) ^  \
     (((uint32_t)((uint8_t *)(p))[2]) << 16) ^ \
     (((uint32_t)((uint8_t *)(p))[3]) << 24))

// define the core function G
#define B2S_G(a, b, c, d, x, y)         \
    {                                   \
        v[a] = v[a] + v[b] + x;         \
        v[d] = ROTR32(v[d] ^ v[a], 16); \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR32(v[b] ^ v[c], 12); \
        v[a] = v[a] + v[b] + y;         \
        v[d] = ROTR32(v[d] ^ v[a], 8);  \
        v[c] = v[c] + v[d];             \
        v[b] = ROTR32(v[b] ^ v[c], 7);  \
    }

// the constants in blake2s
// IV[i] = floor(2**w * frac(sqrt(prime(i+1)))), where prime(i) is the i:th prime number ( 2, 3, 5, 7, 11, 13, 17, 19 )
// and sqrt(x) is the square root of x.
static const uint32_t blake2s_iv[8] =
    {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

// compression function to generate hash digest
static void blake2s_compress(blake2s_ctx *ctx, int last)
{
    // permutation table (10x16)
    const uint8_t sigma[10][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

    // defining states and message blocks (16 states and 16 blocks of message for G function)
    uint32_t v[16], m[16];

    // initializing states with h values repeatedly
    int i;
    for (i = 0; i < 8; i++)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2s_iv[i];
    }

    // 13th and 14th state (index - 12th and 13th) should be XORed with the counter variables
    // low 32 bits of offset
    v[12] ^= ctx->t[0];

    // high 32 bits
    v[13] ^= ctx->t[1];

    // if last block, finalization flag (f0) is set as 1
    if (last)
    {
        v[14] = ~v[14];
    }

    // initialize m[] with b[] but in little endian form
    // m[] is 16 blocks of 32 bits and b[] is 64 blocks of 8 bits (both is of size 512 bits)
    for (i = 0; i < 16; i++)
    {
        // initialize
        m[i] = B2S_GET32(&ctx->b[4 * i]);
        // printf("%x\n", m[i]);
    }

    // ten rounds of the G core function
    for (i = 0; i < 10; i++)
    {
        B2S_G(0, 4, 8, 12, m[sigma[i][0]], m[sigma[i][1]]);
        B2S_G(1, 5, 9, 13, m[sigma[i][2]], m[sigma[i][3]]);
        B2S_G(2, 6, 10, 14, m[sigma[i][4]], m[sigma[i][5]]);
        B2S_G(3, 7, 11, 15, m[sigma[i][6]], m[sigma[i][7]]);
        B2S_G(0, 5, 10, 15, m[sigma[i][8]], m[sigma[i][9]]);
        B2S_G(1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2S_G(2, 7, 8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2S_G(3, 4, 9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

    // generate the hash digest and assign it to the h[] (chained states)
    for (i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

// Initialization function to initialize the context "ctx" with optional key "key".
int blake2s_init(blake2s_ctx *ctx, size_t outlen, const void *key, size_t keylen)
{
    // outlen cannot be 0 or more than 32 bytes as it can generate only
    // 32 bytes = 32*8 bits = 256 bits of hash digest
    // also keylen should not be greater than 32 but it can be 0 i.e. no key provided as key is optional
    // if any of the conditions is violated return -1
    if (outlen == 0 || outlen > 32 || keylen > 32)
    {
        // return -1 to show pass of illegal parameters
        return -1;
    }

    // initialize chained value of context with the constant values of (iv)
    size_t i;
    for (i = 0; i < 8; i++)
    {
        ctx->h[i] = blake2s_iv[i];
    }

    // parameter block
    // general parameters are: outlen, keylen, salt, personalization
    // XORed with 0 is left unchanged
    // hence taking the first 32 bits in little endian format:
    // 01 - maximal depth, 01 - fanout, 00 - key, 00 - digest length (in little endian) - 0x01 01 00 00
    // actually - 0x00 00 01 01
    // parameter block is of size 8 * 32bits(4bytes) = 32 bytes
    // as bitwise operations start from right first 00 is XORed with outlen and becomes 0x20(int 32) and similar for key
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->t[0] = 0; // input count low word
    ctx->t[1] = 0; // input count high word
    ctx->c = 0;    // pointer within buffer
    ctx->outlen = outlen;

    // offset the size for key and then insert 0s
    for (i = keylen; i < 64; i++)
    {
        ctx->b[i] = 0;
    }

    // if key exists i.e. keylen > 0 then,
    if (keylen > 0)
    {
        // call update function to insert the key/message
        blake2s_update(ctx, key, keylen);

        // mark buffer as full before sending the buffer for compression of the key
        ctx->c = 64;
    }

    // finally return 0 on successful completion
    return 0;
}

// update function to insert key or message and then send to compress function
void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen)
{
    size_t i;
    // until the given length insert key or message
    for (i = 0; i < inlen; i++)
    {
        // if buffer is already full
        if (ctx->c == 64)
        {
            // add counters
            ctx->t[0] += ctx->c;

            // carry overflow
            if (ctx->t[0] < ctx->c)
            {
                // high word
                ctx->t[1]++;
            }

            // compress (not last)
            blake2s_compress(ctx, 0);

            // set counter to 0
            ctx->c = 0;
        }

        // insert the message or key at the beginning of the buffer b[64 bytes]
        ctx->b[ctx->c++] = ((const uint8_t *)in)[i];
    }
}

// Generate the message digest (size given in init).
// Result placed in "out".
void blake2s_final(blake2s_ctx *ctx, void *out)
{
    // mark last block offset
    ctx->t[0] += ctx->c;

    // handle carry overflow
    if (ctx->t[0] < ctx->c)
        // high word
        ctx->t[1]++;

    // fill up with zeros till 512 bits or 64 bytes
    while (ctx->c < 64)
        ctx->b[ctx->c++] = 0;

    // final block, set falg = 1
    blake2s_compress(ctx, 1);

    // little endian convert and store the hash digest in out
    size_t i;
    for (i = 0; i < ctx->outlen; i++)
    {
        // i>>2 fetches the same byte 4 times e.g. i>>2 is 0 for i = 0 to 4 and similarly it is 7 for i = 27 to 31
        // 8*(i&3) is always 0 to 3 for any number like for i = 0 to 3 it is 0 to 3
        // and for i = 4 to 7 it is 0 to 3 similarly for all other bytes thus shifting by 0,1,2,and 3 for every 4 bytes to get the last byte
        // & 0xff gives the last byte only from the 4 bytes thus giving the little endian form
        // e.g. if h[0] = 8c5e8c50 then out[0] = 00000050, out[1] = 0000008c, out[2] = 0000005e, out[3] = 0000008c
        ((uint8_t *)out)[i] = (ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
    }
}

// simplification of all the steps i.e. invokes all other functions inside this function
int blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen)
{
    // declaration of state context instance
    blake2s_ctx ctx;

    // if the init function does not return 0 then it is not initialized successfully
    // thus terminate the process and mark the input as invalid
    if (blake2s_init(&ctx, outlen, key, keylen))
        return -1;

    // call for update function
    blake2s_update(&ctx, in, inlen);

    // call for final function
    blake2s_final(&ctx, out);
    return 0;
}

// main function: takes file input if argument is provided in command line
int main(int argc, char **argv)
{
    // output array - this will contain the final hash-digest
    // (32 bytes = 32*8 bits = 256 bits = 256/4 hex characters = 64 characters -> as 1 hex digit requires a nibble(i.e. 1/2 byte))
    uint8_t out[32];

    // take the message(in) and the key(key)
    char *key = "";

    // calculate the length of the key
    size_t key_len = strlen(key);

    // for default
    // if command line has no arguments then print default hash for "abc"
    if (argc < 2)
    {
        // take the message(in) and the key(key)
        char *message = "ajay";

        // calculate the length of message and the key
        size_t msg_len = strlen(message);

        // invoke the BLAKE2s-256 hashing function
        // void pointers cannot be dereferenced i.e. *out cannot print the value in out[0]
        // definition  = blake2s(void *out, size_t outlen, const void *key, size_t keylen, const void *in, size_t inlen)
        blake2s(out, 32, key, key_len, message, msg_len);

        // print the hash-digest in hexadecimal form
        printf("BLAKE2s-256 HASH for \"%s\": ", message);
        // since 256-bits in bytes is 32 bytes- but in little endian form
        for (int i = 0; i < 32; ++i)
        {
            // to get two characters even if the first character is "0" like "06"
            // normally if "0" is skipped in "06"
            printf("%02x", out[i]);
        }
    }

    // for file input
    // if command line argument is provided then print the hash of the file provided
    else
    {
        FILE *fp;
        int i, j, bytesread;
        uint8_t in[toRead];
        blake2s_ctx ctx;

        // until all the files are read and processed
        for (i = 1; i < argc; ++i)
        {
            // open the file in read mode
            fp = fopen(*(argv + i), "r");

            // if file not found or unable to read
            if (fp == NULL)
            {
                printf("Error: unable to open %s\n", *(argv + i));
                return 1;
            }

            // initialize the context "ctx" with key (optional)
            blake2s_init(&ctx, 32, key, key_len);

            while (1)
            {
                // read 64 bytes at a time i.e. 512 bits at a time and update the chained states accordingly
                bytesread = fread(in, 1, toRead, fp);

                // if there is some data read run the update function otherwise break
                if (bytesread)
                    blake2s_update(&ctx, in, bytesread);
                else
                    break;
            }

            // call the final function to generate the hash digest
            blake2s_final(&ctx, out);

            // print the hash digest in hexadecimal
            printf("BLAKE2s-256 HASH for \"%s\" is: ", *(argv + i));
            for (j = 0; j < 32; ++j)
            {
                printf("%02x", out[j]);
            }

            // close the file pointer
            fclose(fp);
        }
        return 0;
    }
}