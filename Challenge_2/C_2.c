#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

void bytesToHex(const unsigned char *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(hex + (i * 2), "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

int main() {
    const char *hex1 = "1c0111001f010100061a024b53535009181c";
    const char *hex2 = "686974207468652062756c6c277320657965";

    unsigned char bytes1[64], bytes2[64], result[64];
    char resultHex[129];
    size_t len1, len2;

    hexToBytes(hex1, bytes1, &len1);
    hexToBytes(hex2, bytes2, &len2);

    if (len1 != len2) {
        printf("Error: Input lengths don't match.\n");
        return 1;
    }

    for (size_t i = 0; i < len1; ++i) {
        result[i] = bytes1[i] ^ bytes2[i];
    }

    bytesToHex(result, len1, resultHex);
    printf("%s\n", resultHex);

    return 0;
}
