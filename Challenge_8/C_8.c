// C_8.c — Detect AES in ECB Mode

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Convert a hex character to its 0–15 value
static unsigned char hexCharToByte(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return 0;
}

// Decode hex string (no “0x”, even-length) into bytes; returns byte length
static size_t hexToBytes(const char *hex, unsigned char *out) {
    size_t len = strlen(hex);
    size_t outLen = len/2;
    for (size_t i = 0; i < outLen; ++i) {
        out[i] = (hexCharToByte(hex[2*i]) << 4)
               |  hexCharToByte(hex[2*i+1]);
    }
    return outLen;
}

// Return 1 if any 16-byte block repeats in data[0..len)
static int containsRepeatedBlock(const unsigned char *data, size_t len) {
    size_t blocks = len / 16;
    for (size_t i = 0; i < blocks; ++i) {
        for (size_t j = i+1; j < blocks; ++j) {
            if (memcmp(data + i*16, data + j*16, 16) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

int main(void) {
    FILE *fp = fopen("8.txt", "r");
    if (!fp) {
        perror("Could not open 8.txt");
        return 1;
    }

    char line[1024];
    unsigned char buffer[1024];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        // strip newline
        line[strcspn(line, "\r\n")] = '\0';

        size_t byteLen = hexToBytes(line, buffer);
        if (byteLen % 16 != 0) continue;  // skip non‐aligned lines

        if (containsRepeatedBlock(buffer, byteLen)) {
            printf("ECB detected in line:\n%s\n", line);
            found = 1;
            break;
        }
    }
    fclose(fp);

    if (!found) {
        printf("No ECB‐encrypted line detected.\n");
    }
    return 0;
}
