// C_6.c — Break Repeating-key XOR (fixed Base64 decode + robust keysize search)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#define MIN_KEYSIZE 2
#define MAX_KEYSIZE 40
#define MAX_CT_LEN 32768
#define TOP_N 3

// Count set bits in a byte
static int countBits(unsigned char b) {
    int cnt = 0;
    while (b) { cnt += b & 1; b >>= 1; }
    return cnt;
}

// Hamming distance between two buffers
static int hammingDistance(const unsigned char *a, const unsigned char *b, size_t len) {
    int d = 0;
    for (size_t i = 0; i < len; ++i) d += countBits(a[i] ^ b[i]);
    return d;
}

// Map Base64 char to value
static int base64Value(char c) {
    if ('A' <= c && c <= 'Z') return c - 'A';
    if ('a' <= c && c <= 'z') return c - 'a' + 26;
    if ('0' <= c && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; // for padding '=' or invalid
}

// Decode Base64, ignoring whitespace and handling '=' padding.
// Returns number of bytes written to out.
static size_t base64Decode(const char *in, unsigned char *out) {
    int val = 0, valb = -8;
    size_t idx = 0;
    for (const char *p = in; *p; ++p) {
        unsigned char c = *p;
        if (isspace(c)) continue;
        int v = base64Value(c);
        if (v == -1) break;        // hit '=' or invalid, stop
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            out[idx++] = (val >> valb) & 0xFF;
            valb -= 8;
        }
    }
    return idx;
}

// Simple English scoring
static double scoreEnglish(const unsigned char *buf, size_t len) {
    double score = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = tolower(buf[i]);
        if (c == ' ') score += 13;
        else if (c == 'e') score += 12;
        else if (c == 't') score += 11;
        else if (c == 'a') score += 10;
        else if (c == 'o') score +=  9;
        else if (c == 'i') score +=  8;
        else if (c == 'n') score +=  7;
        else if (c == 's') score +=  6;
        else if (c == 'h') score +=  5;
        else if (c == 'r') score +=  4;
        else if (isalpha(c)) score += 2;
        else if (isprint(c)) score += 0.5;
        else score -= 5;
    }
    return score;
}

// Find the best single-byte XOR key for a block
static unsigned char findBestSingleByteKey(const unsigned char *block, size_t len) {
    double bestScore = -1e9;
    unsigned char bestKey = 0;
    unsigned char trial[MAX_CT_LEN];
    for (int k = 0; k < 256; ++k) {
        for (size_t i = 0; i < len; ++i) trial[i] = block[i] ^ (unsigned char)k;
        double sc = scoreEnglish(trial, len);
        if (sc > bestScore) bestScore = sc, bestKey = k;
    }
    return bestKey;
}

int main(void) {
    // 1) Read base64 file, stripping newlines
    FILE *fp = fopen("6.txt", "r");
    if (!fp) { perror("Could not open 6.txt"); return 1; }
    static char b64[MAX_CT_LEN];
    size_t b64len = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        size_t L = strcspn(line, "\r\n");
        if (b64len + L < sizeof(b64)) {
            memcpy(b64 + b64len, line, L);
            b64len += L;
        }
    }
    b64[b64len] = '\0';
    fclose(fp);

    // 2) Decode Base64
    static unsigned char ciphertext[MAX_CT_LEN];
    size_t ctLen = base64Decode(b64, ciphertext);

    // 3) Guess top‐3 key sizes by normalized Hamming distance
    double bestNorms[TOP_N] = {1e9,1e9,1e9};
    int    bestSizes[TOP_N] = {0,0,0};

    for (int ks = MIN_KEYSIZE; ks <= MAX_KEYSIZE; ++ks) {
        if ((size_t)(4*ks) >= ctLen) break;
        int total = 0;
        for (int b = 0; b < 4; ++b) {
            total += hammingDistance(
                ciphertext + b*ks,
                ciphertext + (b+1)*ks,
                ks
            );
        }
        double norm = (double)total / (4 * ks);
        for (int pos = 0; pos < TOP_N; ++pos) {
            if (norm < bestNorms[pos]) {
                for (int j = TOP_N-1; j > pos; --j) {
                    bestNorms[j] = bestNorms[j-1];
                    bestSizes[j] = bestSizes[j-1];
                }
                bestNorms[pos] = norm;
                bestSizes[pos] = ks;
                break;
            }
        }
    }

    // 4) For each candidate keysize, break key and score full plaintext
    double bestPlainScore = -1e9;
    int    bestKeySize   = 0;
    unsigned char bestKey[MAX_KEYSIZE];
    static unsigned char bestPlain[MAX_CT_LEN+1];

    for (int c = 0; c < TOP_N; ++c) {
        int ks = bestSizes[c];
        if (!ks) continue;

        unsigned char key[MAX_KEYSIZE];
        // transpose blocks
        for (int i = 0; i < ks; ++i) {
            unsigned char block[MAX_CT_LEN];
            size_t bl = 0;
            for (size_t j = i; j < ctLen; j += ks) {
                block[bl++] = ciphertext[j];
            }
            key[i] = findBestSingleByteKey(block, bl);
        }

        // decrypt full text
        static unsigned char plain[MAX_CT_LEN+1];
        for (size_t i = 0; i < ctLen; ++i) {
            plain[i] = ciphertext[i] ^ key[i % ks];
        }
        plain[ctLen] = '\0';

        double sc = scoreEnglish(plain, ctLen);
        if (sc > bestPlainScore) {
            bestPlainScore  = sc;
            bestKeySize     = ks;
            memcpy(bestKey, key, ks);
            memcpy(bestPlain, plain, ctLen+1);
        }
    }

    // 5) Print results
    printf("Best keysize: %d\n", bestKeySize);
    printf("Key: ");
    for (int i = 0; i < bestKeySize; ++i) putchar(bestKey[i]);
    printf("\n\nDecrypted message:\n%s\n", bestPlain);

    return 0;
}
