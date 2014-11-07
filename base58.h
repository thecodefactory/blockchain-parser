#ifndef __BASE58_H__
#define __BASE58_H__

int bitcoin_public_key_to_address(const uint8_t input[65], uint8_t output[25]);
int bitcoin_public_key_to_ascii(const uint8_t input[65], unsigned char *output);

#endif /* __BASE58_H__ */
