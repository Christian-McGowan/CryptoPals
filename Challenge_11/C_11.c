// C_11.c — ECB/CBC detection oracle

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16

unsigned char *encryption_oracle(const unsigned char *input, int in_len, 
                                 int *out_len, int *mode_used) {
    // 1) Generate random AES key
    unsigned char key[BLOCK_SIZE];
    RAND_bytes(key, BLOCK_SIZE);

    // 2) Random prefix & suffix lengths [5..10]
    int prefix_len = rand() % 6 + 5;
    int suffix_len = rand() % 6 + 5;
    int total_len  = prefix_len + in_len + suffix_len;

    // 3) Build buffer = prefix || input || suffix
    unsigned char *buf = malloc(total_len);
    RAND_bytes(buf, prefix_len);
    memcpy(buf + prefix_len, input, in_len);
    RAND_bytes(buf + prefix_len + in_len, suffix_len);

    // 4) Prepare EVP
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[BLOCK_SIZE];
    unsigned char *ciphertext = malloc(total_len + BLOCK_SIZE);
    int len, cipher_len = 0;

    if ((rand() & 1) == 0) {
        // ECB
        *mode_used = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    } else {
        // CBC
        *mode_used = 1;
        RAND_bytes(iv, BLOCK_SIZE);
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
        EVP_CIPHER_CTX_set_padding(ctx, 1);
    }

    // 5) Encrypt
    EVP_EncryptUpdate(ctx, ciphertext, &len, buf, total_len);
    cipher_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, &len);
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
    free(buf);

    *out_len = cipher_len;
    return ciphertext;
}

// detect_mode:
//   ciphertext = buffer
//   len        = ciphertext length
// Returns 0 for ECB, 1 for CBC.
int detect_mode(const unsigned char *ciphertext, int len) {
    int blocks = len / BLOCK_SIZE;
    for (int i = 0; i < blocks; ++i) {
        for (int j = i + 1; j < blocks; ++j) {
            if (memcmp(ciphertext + i*BLOCK_SIZE,
                       ciphertext + j*BLOCK_SIZE,
                       BLOCK_SIZE) == 0) {
                return 0; // ECB
            }
        }
    }
    return 1; // CBC
}

int main(void) {
    // Seed both C rand() and OpenSSL RAND
    srand((unsigned)time(NULL));
    RAND_poll();

    // Prepare 64 bytes of 'A'
    unsigned char input[64];
    memset(input, 'A', sizeof(input));

    int out_len, mode_used;
    unsigned char *ct = encryption_oracle(input, sizeof(input),
                                          &out_len, &mode_used);

    int guess = detect_mode(ct, out_len);

    printf("Oracle used:   %s\n", mode_used == 0 ? "ECB" : "CBC");
    printf("Detector guess:%s\n", guess     == 0 ? "ECB" : "CBC");

    free(ct);
    return 0;
}
