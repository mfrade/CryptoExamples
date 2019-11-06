#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sodium.h>
#include <bsd/readpassphrase.h>

#include "debug.h"
#include "cmdline.h"

#define CHUNK_SIZE 4096
#define PASS_SIZE 1024

static int encrypt(FILE *fp_s, FILE *fp_t, const char *password){
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    
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
        
        if (fwrite(buf_out, 1, (size_t) out_len, fp_t)==0 && !eof){
            ERROR(1, "Writing to file");
        }
        
    } while (! eof);
    
    
    return 0;
}

static int
decrypt(FILE *fp_s, FILE *fp_t, const char *password)
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    
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
        return ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
                                                       buf_in, rlen, NULL, 0) != 0) {
            return ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            return ret; /* premature end (end of file reached before the end of the stream) */
        }
        
        if (fwrite(buf_out, 1, (size_t) out_len, fp_t)==0 && !eof){
            ERROR(1, "Writing to file");
        }
    } while (! eof);

    /* every thing is ok*/
    ret = 0;
    return ret;
}

int main(int argc, char **argv)
{
    struct gengetopt_args_info args_info;
    char *password, *source_file, *target_file;
    FILE *f_source, *f_target;
    enum {MODE_NONE, MODE_ENCRYPT, MODE_DECRYPT} mode = MODE_NONE;
    

    /*
     * parse command line arguments
     */
    if (cmdline_parser(argc, argv, &args_info) != 0) {
        ERROR(1, "cmdline_parser");
    }
    
    source_file=args_info.source_arg;
    target_file=args_info.target_arg;
    
    if(args_info.encrypt_given)
        mode = MODE_ENCRYPT;
    if(args_info.decrypt_given)
        mode = MODE_DECRYPT;
    
    /*
     * prepare files
     */
    
    f_source = fopen(source_file, "rb");
    if(f_source == NULL){
        ERROR(1, "Open file \'%s\'", source_file);
    }
    
    f_target = fopen(target_file, "wb");
    if(f_target == NULL){
        ERROR(1, "Open file \'%s\'", target_file);
    }
    
    
    /*
     * initialize libsodium
     */
    if (sodium_init() != 0) {
        ERROR(1, "Sodium init");
    }
    
    password = sodium_malloc(PASS_SIZE + 1);
    if (!password) {
         ERROR(1, "Memory error");
    }
    if (readpassphrase("Pass phrase to encrypt: ", password, PASS_SIZE, RPP_REQUIRE_TTY) == NULL){
        ERROR(1, "Unable to read passphrase");
    }
    
#ifdef SHOW_DEBUG    
    DEBUG("Pass phrase to encrypt: \'%s\'\n", password);
#endif
            
    
    //     crypto_secretstream_xchacha20poly1305_keygen(key);
    //     this option is good for key encapsulation mechanism where there's no need to store the salt
    
    
    /*
     * encrypt or decrypt
     */
    switch (mode) {
        case MODE_ENCRYPT:
            if (encrypt(f_source, f_target, password) != 0) {
                ERROR(1, "Not able to encrypt");
            }
            break;
        case MODE_DECRYPT:
            if (decrypt(f_source, f_target, password) != 0) {
                ERROR(1, "Not able to decrypt. Wrong password?");
            }
            break;
        default:
            ERROR(1, "Operation unknown");
        }

    fclose(f_source);
    fclose(f_target);
    return 0;
}
