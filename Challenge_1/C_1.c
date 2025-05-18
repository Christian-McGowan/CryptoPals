#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>  // <-- Needed for uint32_t

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

const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64Encode(const unsigned char *in, size_t len, char *out) {
    int i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? in[i++] : 0;
        uint32_t octet_b = i < len ? in[i++] : 0;
        uint32_t octet_c = i < len ? in[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
}

int main() {
    const char *hexInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    unsigned char bytes[256];
    char b64[512];
    size_t byteLen;

    hexToBytes(hexInput, bytes, &byteLen);
    base64Encode(bytes, byteLen, b64);

    printf("%s\n", b64);
    return 0;
}
