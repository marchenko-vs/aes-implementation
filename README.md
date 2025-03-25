# AES implementation

## Implementation of Advanced Encryption Standard with PCBC mode in C

You can download **aes.c** and **aes.h** files and use them in your projects for 
encrypting and decrypting data.

## How to use

```console
$ make
$ ./app.exe -e [origin_file] [encrypted_file]
$ ./app.exe -d [encrypted_file] [decrypted_file]
$ make clean
```

This way 128-bit keys will be used. If you want to use 192- and 256- keys
execute the program the following way:

```console
$ ./app.exe -e [origin_file] [encrypted_file] 192
$ ./app.exe -e [origin_file] [encrypted_file] 256
```

You can encrypt and decrypt any files you want.
It doesn't matter if it's just a simple text or a 2-hour movie.
But if an input file is big enough, you will have to wait patiently.

## Description

Basically, the program consists of the following stages.
1. Generating 128-, 192- or 256-bit key and initialization vector using random generator.
2. Saving the key and the initialization vector in files.
3. Generating round keys.
4. Encrypting 128-bit block using round keys.

## Useful links

[An explanation of PCBC mode](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC))
