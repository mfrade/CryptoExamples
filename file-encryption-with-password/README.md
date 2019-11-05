# File encryption with password
Encrypt and decrypt a large file and protect it with a user inserted password.
Based on the code available on [Libsodium documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream).

## Description

This example program will:
1. ask the user for a password and then encrypt the file `/tmp/bigfile.dat` and save the result to `/tmp/encrypted.dat`
2. ask the user for a password to decrypt the file `/tmp/bigfile.dat` to `/tmp/decrypted.dat`. If the password is incorrect, the decryption will fail.

To generate a random file do (change the `count` and/or `bs` values to increase file size):
`dd if=/dev/urandom of=/tmp/bigfile.dat bs=4M count=16`

The function `sodium_malloc()` is used to allocate and protect the memory to store the clear text password. 
To read the user input `readpassphrase()` is used to guarantee that the password is not displayed on the terminal. 

To encrypt the file, a *key* and *salt* values must be generated. The *salt* is a random value created with `randombytes_buf()` that is also stored inside the file (it's required to decrypt the file). The *salt* value doesn't need to be secret. Its function is to ensure that, even if the user encrypts the same file with the same password, the encrypted file will be different. The *key* is then generated with `crypto_pwhash()` based on the user provided password and the random *salt*. Once the *key* and *salt* values are created, the memory location that stores the password is cleared with `sodium_free()`. Finally, the file is encrypted with the `crypto_secretstream_xchacha20poly1305_push()` function inside a loop.


## Compile and run

Depends on:
- `libsodium-dev`
- `libbsd-dev`

On ubuntu do:
`sudo apt install libsodium-dev libbsd-dev`

To disable debug info, comment out `-D SHOW_DEBUG` on the `Makefile`

To compile:
`make`

To run:
`./file-encryption`


