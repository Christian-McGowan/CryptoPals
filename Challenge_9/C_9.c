// C_9.c — PKCS#7 Padding

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void pkcs7_pad(const unsigned char *in, size_t in_len,
               size_t block, unsigned char **out, size_t *out_len) {
    size_t pad = block - (in_len % block);
    if (pad == 0) pad = block;
    *out_len = in_len + pad;
    *out = malloc(*out_len);
    memcpy(*out, in, in_len);
    memset(*out + in_len, (unsigned char)pad, pad);
}

// Print buffer as hex
void print_hex(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int main(void) {
    const unsigned char *plaintext = (unsigned char *)
        "YELLOW SUBMARINE";
    size_t pt_len = strlen((char*)plaintext);
    size_t block_size = 20;

    unsigned char *padded = NULL;
    size_t padded_len = 0;
    pkcs7_pad(plaintext, pt_len, block_size, &padded, &padded_len);

    // Output as hex
    print_hex(padded, padded_len);

    free(padded);
    return 0;
}
