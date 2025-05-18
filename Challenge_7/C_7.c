// C_7.c — AES-128-ECB Decryption using OpenSSL EVP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_CT_LEN 65536

// Map Base64 char to value
static int b64val(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c && c <= 'z') return c - 'a' + 26;
    if ('0' <= c && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decode Base64, ignoring whitespace and padding
static size_t b64decode(const char *in, unsigned char *out) {
    int val = 0, valb = -8;
    size_t idx = 0;
    for (const char *p = in; *p; ++p) {
        unsigned char c = *p;
        if (isspace(c)) continue;
        int dv = b64val(c);
        if (dv < 0) break;  // '=' or invalid
        val = (val << 6) | dv;
        valb += 6;
        if (valb >= 0) {
            out[idx++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }
    return idx;
}

int main(void) {
    // 1) Read base64-encoded input
    FILE *fp = fopen("7.txt", "r");
    if (!fp) { perror("7.txt"); return 1; }
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
    fclose(fp);
    b64[blen] = '\0';

    // 2) Decode Base64 to ciphertext
    static unsigned char ciphertext[MAX_CT_LEN];
    size_t ctLen = b64decode(b64, ciphertext);

    // 3) Initialize OpenSSL EVP for AES-128-ECB decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        return 1;
    }

    // Key is "YELLOW SUBMARINE"
    unsigned char key[16] = "YELLOW SUBMARINE";

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) {
        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    // ECB mode does not use IV; disable padding if file is block-aligned
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // 4) Decrypt
    unsigned char *plaintext = malloc(ctLen);
    int len1 = 0, len2 = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &len1, ciphertext, (int)ctLen) != 1) {
        fprintf(stderr, "EVP_DecryptUpdate failed\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + len1, &len2) != 1) {
        fprintf(stderr, "EVP_DecryptFinal_ex failed\n");
        free(plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    // 5) Write plaintext to stdout
    fwrite(plaintext, 1, len1 + len2, stdout);
    free(plaintext);
    return 0;
}
