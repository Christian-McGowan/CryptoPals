// C_12.c — Byte-at-a-time ECB decryption (Simple)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16
#define MAX_CT_LEN 32768

// The unknown Base64‐encoded suffix:
static const char *UNKNOWN_B64 =
    "Um9sbGluJyBpbiBteSA1LjAK"
    "V2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBv"
    "biBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNh"
    "eSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1"
    "c3QgZHJvdmVieWwK";

// Globals for the oracle
static unsigned char UNKNOWN_KEY[BLOCK_SIZE];
static unsigned char UNKNOWN_BYTES[MAX_CT_LEN];
static size_t UNKNOWN_LEN = 0;
static int ORACLE_INIT = 0;

// Map Base64 char → value
static int b64val(char c) {
    if ('A'<=c && c<='Z') return c - 'A';
    if ('a'<=c && c<='z') return c - 'a' + 26;
    if ('0'<=c && c<='9') return c - '0' + 52;
    if (c=='+') return 62;
    if (c=='/') return 63;
    return -1;
}
// Decode Base64 (ignore whitespace) into out[], return length
static size_t b64decode(const char *in, unsigned char *out) {
    int val=0, valb=-8;
    size_t idx=0;
    for(const char *p=in; *p; ++p) {
        unsigned char c = *p;
        if (isspace(c)) continue;
        int d = b64val(c);
        if (d<0) break;
        val = (val<<6)|d; valb+=6;
        if (valb>=0) {
            out[idx++] = (val>>valb)&0xFF;
            valb-=8;
        }
    }
    return idx;
}
// One‐time init: random key + decode suffix
static void init_oracle() {
    RAND_bytes(UNKNOWN_KEY, BLOCK_SIZE);
    UNKNOWN_LEN = b64decode(UNKNOWN_B64, UNKNOWN_BYTES);
    ORACLE_INIT = 1;
}

unsigned char *encryption_oracle(const unsigned char *in, int in_len, int *out_len) {
    if (!ORACLE_INIT) init_oracle();

    int pt_len = in_len + UNKNOWN_LEN;
    unsigned char *pt = malloc(pt_len);
    memcpy(pt, in, in_len);
    memcpy(pt+in_len, UNKNOWN_BYTES, UNKNOWN_LEN);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, UNKNOWN_KEY, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 1);

    unsigned char *ct = malloc(pt_len + BLOCK_SIZE);
    int len=0, ct_len=0;
    EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len); ct_len+=len;
    EVP_EncryptFinal_ex(ctx, ct+ct_len, &len);     ct_len+=len;
    EVP_CIPHER_CTX_free(ctx);
    free(pt);

    *out_len = ct_len;
    return ct;
}

// Detect the block size by observing output growth
static int detect_block_size() {
    int prev = 0;
    for (int i = 1; i <= 64; ++i) {
        int clen;
        unsigned char *c = encryption_oracle((unsigned char*)"A", i, &clen);
        free(c);
        if (i==1) prev=clen;
        else if (clen>prev) return clen-prev;
    }
    return 0;
}
// Confirm ECB by looking for repeated blocks
static int detect_ecb(int bs) {
    unsigned char *in = malloc(bs*4);
    memset(in,'A',bs*4);
    int clen; unsigned char *c = encryption_oracle(in,bs*4,&clen);
    free(in);
    int blocks = clen/bs, ecb=0;
    for(int i=0;i<blocks && !ecb;++i)
      for(int j=i+1;j<blocks;++j)
        if(!memcmp(c+i*bs,c+j*bs,bs)){ecb=1;break;}
    free(c);
    return ecb;
}

int main(void) {
    // 1) Find block size
    int bs = detect_block_size();
    printf("Block size: %d\n", bs);

    // 2) Verify ECB
    if (!detect_ecb(bs)) {
        fprintf(stderr,"Not ECB!\n");
        return 1;
    }
    printf("ECB mode confirmed\n\n");

    // 3) Byte-at-a-time recovery
    unsigned char *recovered = calloc(UNKNOWN_LEN+1,1);

    for (size_t i = 0; i < UNKNOWN_LEN; ++i) {
        int block_index = i / bs;
        int offset     = i % bs;
        int prefix_len = bs - offset - 1;
        int ct_len;
        // 3a) Get target block
        unsigned char *prefix = malloc(prefix_len);
        memset(prefix,'A',prefix_len);
        unsigned char *ct = encryption_oracle(prefix,prefix_len,&ct_len);
        unsigned char target[BLOCK_SIZE];
        memcpy(target, ct + block_index*bs, bs);
        free(ct);

        // 3b) Build dictionary
        for (int b = 0; b < 256; ++b) {
            int trial_len = prefix_len + i + 1;
            unsigned char *trial_in = malloc(trial_len);
            memset(trial_in,'A',prefix_len);
            memcpy(trial_in+prefix_len, recovered, i);
            trial_in[prefix_len + i] = (unsigned char)b;

            unsigned char *tc = encryption_oracle(trial_in, trial_len, &ct_len);
            if (!memcmp(tc + block_index*bs, target, bs)) {
                recovered[i] = (unsigned char)b;
                free(tc);
                free(trial_in);
                break;
            }
            free(tc);
            free(trial_in);
        }
        free(prefix);
    }

    printf("Recovered text:\n%s\n", recovered);
    free(recovered);
    return 0;
}
