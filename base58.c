#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "RIPEMD160.h"
#include "base58.h"

extern void reverse_array(unsigned char *src, unsigned char *dest, int len);
 
int is_hex(const char *s)
{
    int i;
    for (i = 0; i < 64; i++)
        if (!isxdigit(s[i])) return 0;
    return 1;
}
 
void str_to_byte(const char *src, unsigned char *dst, int n)
{
    while (n--) sscanf(src + n * 2, "%2hhx", dst + n);
}
 
char *base58(unsigned char *s, unsigned char out[35])
{
    int c, i, n;
    static const char *tmpl =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (out)
    {
        out[n = 34] = 0;
        while (n--)
        {
            for(c = i = 0; i < 25; i++)
            {
                c = c * 256 + s[i];
                s[i] = c / 58;
                c %= 58;
            }
            out[n] = tmpl[c];
        }
    }
    return out;
}

void bitcoin_ripemd160_to_address(const uint8_t ripemd160[20], uint8_t output[25])
{
    uint8_t hash1[32];
    output[0] = 0;
    memcpy(&output[1], ripemd160, 20);
    compute_sha256(output, 21, hash1);
    compute_sha256(hash1, 32, hash1);
    output[21] = hash1[0];
    output[22] = hash1[1];
    output[23] = hash1[2];
    output[24] = hash1[3];
}

void bitcoin_ripemd160_to_ascii(const uint8_t ripemd160[20], unsigned char output[35])
{
    uint8_t tmp[25];
    bitcoin_ripemd160_to_address(ripemd160, tmp);
    base58(tmp, output);
}

// The 65 bytes long ECDSA public key; first byte will always be 0x4 followed by two 32 byte components
int bitcoin_public_key_to_address(const uint8_t input[65], uint8_t output[25])
{
    int ret = -1;
    if (input[0] == 0x04)
    {
        uint8_t hash1[32];
        compute_sha256((unsigned char *)input, 65, hash1);
        output[0] = 0;
        computeRIPEMD160(hash1, 32, &output[1]);
        compute_sha256(output, 21, hash1);
        compute_sha256(hash1, 32, hash1);
        output[21] = hash1[0];
        output[22] = hash1[1];
        output[23] = hash1[2];
        output[24] = hash1[3];
        ret = 0;
    }
    return ret;
}

int bitcoin_public_key_to_ascii(const uint8_t input[65], unsigned char output[35])
{
    uint8_t tmp[25];
    int ret = bitcoin_public_key_to_address(input, tmp);
    if (ret == 0)
    {
        base58(tmp, output);
    }
    return ret;
}
