# File encryption with password
Encrypt and decrypt a large file and protect it with a user inserted password. Authenticated encryption is used to guarantee the authenticity of the file contents.

This program will ask the user for a password and then encrypt/decrypt the source file and save the result to target file.

The function `sodium_malloc()` is used to allocate and protect the memory to store the clear text password. 
To read the user input `readpassphrase()` is used to guarantee that the password is not displayed on the terminal. 

To encrypt the file, a *key* and *salt* values must be generated. The *salt* is a random value created with `randombytes_buf()` that is also stored inside the file (it's required to decrypt the file). The *salt* value doesn't need to be secret, its function is to ensure that, even if the user encrypts the same file with the same password, the encrypted file will be different. The *key* is then generated with `crypto_pwhash()` based on the user provided password and the random *salt*. Once the *key* and *salt* values are created, the memory location that stores the password is cleared with `sodium_free()` to minimize the possibility of the password being captured in RAM. Finally, the file is encrypted with the `crypto_secretstream_xchacha20poly1305_push()` function inside a loop.


## Credits
This program is based on code available on [Libsodium documentation](https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream).


## Compile and run

Depends on:
- `libsodium-dev` for the encryption algorithms
- `libbsd-dev` to read passwords from the terminal
- `gengetopt` to parse the command line arguments

On ubuntu do:
```
sudo apt install libsodium-dev libbsd-dev gengetopt
```

To disable debug info, comment out `-D SHOW_DEBUG` on the `Makefile`

To compile:
`make`

To run:
1. Create a test file `/tmp/bigfile.dat`, for example (change the `count` and/or `bs` values to increase file size):
```
dd if=/dev/urandom of=/tmp/bigfile.dat bs=4M count=16
```
2. `./file-encryption` [-e|d] -s source_file -t target_file


## Questions
1. What happens if an incorrect password is used to decrypt the file?

2. What was the *salt* value used to encrypt the file? Use an *hex viewer* to answer (eg. bless).

3. Encrypt the same file multiple times with the **same** password and check the hash values of:
    - `/tmp/bigfile.dat`
    - `/tmp/encrypted.dat`
    - `/tmp/decrypted.dat`

    Use the `sha256sum /tmp/*.dat` command.
    Is the hash value of `/tmp/encrypted.dat` always the same?

4. With an hex editor (eg. bless) change only one byte of the `/tmp/encrypted.dat` file. Are you able to decrypt the edited file?
