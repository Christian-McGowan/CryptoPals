#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

unsigned char hexCharToByte(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return 0;
}

void hexToBytes(const char *hex, unsigned char *bytes, size_t *outLen) {
    size_t len = strlen(hex);
    *outLen = len / 2;
    for (size_t i = 0; i < len; i += 2) {
        bytes[i / 2] = (hexCharToByte(hex[i]) << 4) | hexCharToByte(hex[i + 1]);
    }
}

// Basic frequency scoring for English letters and space
double scoreEnglish(const unsigned char *buf, size_t len) {
    double score = 0.0;
    for (size_t i = 0; i < len; ++i) {
        char c = tolower(buf[i]);
        if (c == ' ') score += 13;
        else if (c == 'e') score += 12;
        else if (c == 't') score += 11;
        else if (c == 'a') score += 10;
        else if (c == 'o') score += 9;
        else if (c == 'i') score += 8;
        else if (c == 'n') score += 7;
        else if (c == 's') score += 6;
        else if (c == 'h') score += 5;
        else if (c == 'r') score += 4;
        else if (isalpha(c)) score += 2;
        else if (isprint(c)) score += 0.5;
        else score -= 5;
    }
    return score;
}

int main() {
    const char *hexInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    size_t len;
    double bestScore = -1e9;
    unsigned char bestKey = 0;

    hexToBytes(hexInput, ciphertext, &len);

    for (int k = 0; k < 256; ++k) {
        for (size_t i = 0; i < len; ++i) {
            decrypted[i] = ciphertext[i] ^ (unsigned char)k;
        }
        double score = scoreEnglish(decrypted, len);
        if (score > bestScore) {
            bestScore = score;
            bestKey = (unsigned char)k;
        }
    }

    printf("Best key: 0x%02x ('%c')\nDecrypted text:\n", bestKey, isprint(bestKey) ? bestKey : '?');
    for (size_t i = 0; i < len; ++i) {
        putchar(ciphertext[i] ^ bestKey);
    }
    putchar('\n');
    return 0;
}
