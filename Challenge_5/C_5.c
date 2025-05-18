#include <stdio.h>
#include <string.h>
#include <stdint.h>

void repeatingKeyXOR(const char *plaintext, const char *key, char *outputHex) {
    size_t ptLen = strlen(plaintext);
    size_t keyLen = strlen(key);

    for (size_t i = 0; i < ptLen; ++i) {
        uint8_t xored = plaintext[i] ^ key[i % keyLen];
        sprintf(outputHex + (i * 2), "%02x", xored);
    }
    outputHex[ptLen * 2] = '\0';
}

int main() {
    const char *text =
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal";

    const char *key = "ICE";
    char hexOut[4096];

    repeatingKeyXOR(text, key, hexOut);
    printf("%s\n", hexOut);

    return 0;
}
