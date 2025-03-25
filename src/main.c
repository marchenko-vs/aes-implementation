#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

#include "aes.h"

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        printf("Error: program requires at least 3 parameters.\n");
        return -1;
    }

    uint8_t key[KEY_SIZE_256] = {0};
    uint8_t iv[16] = {0};
    size_t len = 0;
    
    uint8_t key_buffer[15][16];

    size_t key_len = KEY_SIZE_128; // in bytes, 16 by default
    size_t rounds = ROUNDS_128; // by default

    if (strcmp(argv[1], "-e") == 0)
    {
        srand(time(NULL));

        if (argc == 5)
        {
            if (strcmp(argv[4], "128") == 0)
            {
                key_len = KEY_SIZE_128;
                rounds = ROUNDS_128;
            }
            else if (strcmp(argv[4], "192") == 0)
            {
                key_len = KEY_SIZE_192;
                rounds = ROUNDS_192;
            }
            else if (strcmp(argv[4], "256") == 0)
            {
                key_len = KEY_SIZE_256;
                rounds = ROUNDS_256;
            }
            else
            {
                printf("Error: incorrect length of the key.\n");
                return -2;
            }
        }

        FILE *f_key = fopen("key.bin", "wb");
        generate_key(key, key_len);
        fwrite_key(f_key, key, key_len);
        fclose(f_key);
        
        FILE *f_iv = fopen("iv.bin", "wb");
        generate_key(iv, 16);
        fwrite_key(f_iv, iv, 16);
        fclose(f_iv);

        if (key_len == KEY_SIZE_128)
        {
            key_expansion_128(key, key_buffer);
        }
        else if (key_len == KEY_SIZE_192)
        {
            key_expansion_192(key, key_buffer);
        }
        else if (key_len == KEY_SIZE_256)
        {
            key_expansion_256(key, key_buffer);
        }
        else
        {
            printf("Error: incorrect length of the key.\n");
            return -2;
        }

        uint8_t plain_block[BLOCK_SIZE] = {0};
        uint8_t encrypted_block[BLOCK_SIZE] = {0};
        uint8_t xored_block[BLOCK_SIZE] = {0};

        FILE *f_in = fopen(argv[2], "rb");
        FILE *f_out = fopen(argv[3], "wb");
        
        while ((len = fread(plain_block, sizeof(uint8_t), BLOCK_SIZE, f_in)))
        {
            xor_block(plain_block, iv, xored_block, BLOCK_SIZE);
            encrypt(xored_block, encrypted_block, key_buffer, rounds);
            
            fwrite(encrypted_block, sizeof(uint8_t), BLOCK_SIZE, f_out);

            xor_block(plain_block, encrypted_block, iv, BLOCK_SIZE);
            memset(plain_block, 0, BLOCK_SIZE);
        }

        fclose(f_out);
        fclose(f_in);
    }
    else if (strcmp(argv[1], "-d") == 0)
    {
        FILE *f_key = fopen("key.bin", "rb");
        key_len = fread_key(f_key, key);
        fclose(f_key);
        
        FILE *f_iv = fopen("iv.bin", "rb");
        fread_key(f_iv, iv);
        fclose(f_iv);

        if (key_len == 16)
        {
            key_expansion_128(key, key_buffer);
        }
        else if (key_len == KEY_SIZE_192)
        {
            key_expansion_192(key, key_buffer);
            rounds = ROUNDS_192;
        }
        else if (key_len == KEY_SIZE_256)
        {
            key_expansion_256(key, key_buffer);
            rounds = ROUNDS_256;
        }
        else
        {
            printf("Error: incorrect length of the key.\n");
            return -2;
        }

        uint8_t encrypted_block[BLOCK_SIZE] = {0};
        uint8_t decrypted_block[BLOCK_SIZE] = {0};
        uint8_t xored_block[BLOCK_SIZE] = {0};

        FILE *f_in = fopen(argv[2], "rb");
        FILE *f_out = fopen(argv[3], "wb");
        
        while ((len = fread(encrypted_block, sizeof(uint8_t), BLOCK_SIZE, f_in)))
        {
            decrypt(encrypted_block, decrypted_block, key_buffer, rounds);
            xor_block(decrypted_block, iv, xored_block, BLOCK_SIZE);
            fwrite(xored_block, sizeof(uint8_t), BLOCK_SIZE, f_out);

            xor_block(encrypted_block, xored_block, iv, BLOCK_SIZE);
            memset(encrypted_block, 0, BLOCK_SIZE);
        }

        fclose(f_out);
        fclose(f_in);
    }
    else
    {
        printf("Error: incorrect option.\n");
        return -3;
    }

    return 0;
}
