#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <bsd/readpassphrase.h>  // sudo apt install libbsd-dev 

#include "debug.h"

#define CHUNK_SIZE 4096
#define PASS_SIZE 1024

// generate a random file:
// dd if=/dev/urandom of=/tmp/bigfile.dat bs=4M count=16

static int
encrypt(const char *target_file, const char *source_file, const char *password)
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    
    FILE          *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    
    randombytes_buf(salt, sizeof salt);
    
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, 
            crypto_pwhash_ALG_DEFAULT) != 0) {
        
        /* out of memory */
         ERROR(1, "crypto_pwhash");
    }
    
    // free the clear text password as soon as possible!
    sodium_free((void *)password);
    
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    
    fwrite(salt, 1, sizeof salt, fp_t);
    fwrite(header, 1, sizeof header, fp_t);
    
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen, NULL, 0, tag);
        
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
        
    } while (! eof);
    
    fclose(fp_t);
    fclose(fp_s);
    
    return 0;
}

static int
decrypt(const char *target_file, const char *source_file, const char *password)
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    
    FILE          *fp_t, *fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    
    fread(salt, 1, sizeof salt, fp_s);
    fread(header, 1, sizeof header, fp_s);
    
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, 
            crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, 
            crypto_pwhash_ALG_DEFAULT) != 0) {
        
        /* out of memory */
         ERROR(1, "crypto_pwhash");
    }
    
    // free the clear text password as soon as possible!
    sodium_free((void *)password);
    
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t) out_len, fp_t);
    } while (! eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int
main(void)
{
    char *password_enc, *password_dec;

    if (sodium_init() != 0) {
        ERROR(1, "Sodium init");
    }
    
    
    password_enc = sodium_malloc(PASS_SIZE + 1);
    if (!password_enc) {
         ERROR(1, "Memory error");
    }
    
    password_dec = sodium_malloc(PASS_SIZE + 1);
    if (!password_dec) {
        ERROR(1, "Memory error");
    }
    
    
    
    if (readpassphrase("Pass phrase to encrypt: ", password_enc, PASS_SIZE, RPP_REQUIRE_TTY) == NULL){
        ERROR(1, "Unable to read passphrase");
    }
    
#ifdef SHOW_DEBUG    
    DEBUG("Pass phrase to encrypt: \'%s\'\n", password_enc);
#endif
            
    
    //     crypto_secretstream_xchacha20poly1305_keygen(key);
    //     problem: How to reproduce the key?
    //     this option seems very good for key encapsulation mechanism
    
    if (encrypt("/tmp/encrypted.dat", "/tmp/bigfile.dat", password_enc) != 0) {
        ERROR(1, "Not able to encrypt");
    }
    
//     sprintf(wrong_password, "%s%s", password, "?");
    if (readpassphrase("Pass phrase to decrypt: ", password_dec, PASS_SIZE, RPP_REQUIRE_TTY) == NULL){
        ERROR(1, "Unable to read passphrase");
    }
    
    
#ifdef SHOW_DEBUG
    DEBUG("Pass phrase to decrypt: \'%s\'\n", password_dec);
#endif
    
    if (decrypt("/tmp/decrypted.dat", "/tmp/encrypted.dat", password_dec) != 0) {
        ERROR(1, "Not able to decrypt. Wrong password?");
    }
    
    
    return 0;
}
