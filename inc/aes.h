#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define BLOCK_SIZE 16

#define KEY_SIZE_128 16
#define KEY_SIZE_192 24
#define KEY_SIZE_256 32

#define ROUNDS_128 10
#define ROUNDS_192 12
#define ROUNDS_256 14

void generate_key(uint8_t *buffer, const size_t len_in_bytes);
void fwrite_key(FILE *f, const uint8_t *const buffer, const size_t len_in_bytes);
size_t fread_key(FILE *f, uint8_t *buffer);

void encrypt(const uint8_t plain_block[16], uint8_t encrypted_block[16],
             uint8_t round_keys[][16], const size_t rounds);
void decrypt(const uint8_t encrypted_block[16], uint8_t plain_block[16],
             uint8_t round_keys[][16], const size_t rounds);

void key_expansion_128(const uint8_t key[16], uint8_t round_keys[11][16]);
void key_expansion_192(const uint8_t key[24], uint8_t round_keys[13][16]);
void key_expansion_256(const uint8_t key[32], uint8_t round_keys[15][16]);

void xor_block(uint8_t *block, uint8_t *key, uint8_t *result, const size_t size);

#endif // _AES_H_
