// C_10.c — AES-128-CBC Decryption by hand (EVP for single-block ECB)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_CT_LEN 65536
#define BLOCK_SIZE 16

// Map Base64 char to value
static int b64val(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c && c <= 'z') return c - 'a' + 26;
    if ('0' <= c && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;  // padding or invalid
}

// Decode Base64 (ignore whitespace, stop at '=')
static size_t b64decode(const char *in, unsigned char *out) {
    int val = 0, valb = -8;
    size_t idx = 0;
    for (const char *p = in; *p; ++p) {
        unsigned char c = *p;
        if (isspace(c)) continue;
        int v = b64val(c);
        if (v < 0) break;
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            out[idx++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }
    return idx;
}

// XOR two blocks of length BLOCK_SIZE
static void xor_block(const unsigned char *a, const unsigned char *b, unsigned char *out) {
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

int main(void) {
    // 1) Read Base64 from file
    FILE *fp = fopen("10.txt", "r");
    if (!fp) { perror("10.txt"); return 1; }
    static char b64[MAX_CT_LEN];
    size_t blen = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t L = strcspn(line, "\r\n");
        if (blen + L < sizeof(b64)) {
            memcpy(b64 + blen, line, L);
            blen += L;
        }
    }
    b64[blen] = '\0';
    fclose(fp);

    // 2) Decode Base64 -> ciphertext
    static unsigned char ciphertext[MAX_CT_LEN];
    size_t ctLen = b64decode(b64, ciphertext);
    if (ctLen % BLOCK_SIZE != 0) {
        fprintf(stderr, "Ciphertext not a multiple of %d\n", BLOCK_SIZE);
        return 1;
    }

    // 3) Prepare key and IV
    const unsigned char keyData[BLOCK_SIZE] = "YELLOW SUBMARINE";
    unsigned char iv[BLOCK_SIZE] = {0};

    // 4) Decrypt each block with EVP-ECB, then XOR for CBC
    unsigned char plain[MAX_CT_LEN];
    unsigned char decBlock[BLOCK_SIZE];
    unsigned char xored[BLOCK_SIZE];

    for (size_t offset = 0; offset < ctLen; offset += BLOCK_SIZE) {
        // a) ECB decrypt this block
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { fprintf(stderr, "ctx new failed\n"); return 1; }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, keyData, NULL) != 1 ||
            EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        int outlen = 0;
        if (EVP_DecryptUpdate(ctx, decBlock, &outlen,
                              ciphertext + offset, BLOCK_SIZE) != 1 ||
            outlen != BLOCK_SIZE) {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        EVP_CIPHER_CTX_free(ctx);

        // b) XOR with IV (or previous ciphertext)
        xor_block(decBlock,
                  offset == 0 ? iv : ciphertext + offset - BLOCK_SIZE,
                  xored);

        // c) store plaintext
        memcpy(plain + offset, xored, BLOCK_SIZE);
    }

    // 5) Remove PKCS#7 padding
    unsigned char pad = plain[ctLen - 1];
    if (pad < 1 || pad > BLOCK_SIZE) {
        fprintf(stderr, "Invalid padding: %u\n", pad);
        return 1;
    }
    size_t ptLen = ctLen - pad;

    // 6) Output
    fwrite(plain, 1, ptLen, stdout);
    return 0;
}
