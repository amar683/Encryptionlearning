#define _POSIX_C_SOURCE 200809L
#include <sodium.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

//any tempering with header fileds will make authentication fails during decryption
#define MAGIC "SBOX"
#define VERSION 1
#define SALT_LEN 16
#define NONCE_LEN crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG_LEN crypto_aead_xchacha20poly1305_ietf_ABYTES
#define KEY_LEN crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define FILE_ID_LEN 16
#define HEADER_LEN (4+1+SALT_LEN+NONCE_LEN+FILE_ID_LEN)//which is 61

/// @brief Print an error message to stderr and exit(1).
/// @param msg error message
static void die(const char *msg){
    //stderr is error stream used for error reporting 
    fprint(stderr,"%s\n",msg);
    exist(1);
}

/// @brief Overwrite the memory region p with zeros (via libsodium sodium_memzero or equivalent) and free it.
/// @param p unsigned char *
/// @param n length of that
static void secure_free(void *p,size_t n){
    if(p){
        sodium_memzero(p,n);
        free(p);
    }
}

/// @brief Open a file, determine its size (via fseek/ftell), allocate a buffer, and read the whole file into memory.
/// @param path path of the file
/// @param out 
/// @param outlen 
/// @return  if success will return 0 
static int read_file(const char *path, unsigned char **out,size_t *outlen){
    FILE *f = fopen(path, "rb");
    if(!f)return -1;

    if(fseek(f,0,SEEK_END)!=0){
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if(sz<0){
        fclose(f);
        return -1;
    }
    rewind(f);
    *out = malloc((size_t)sz);
    if(!*out){
        fclose(f);
        return -1;
    }
    if(fread(*out, 1, (size_t)sz,f)!= (size_t)sz){
        fclose(f);
        free(*out);
        return -1;
    }
    fclose(f);
    *outlen = (size_t)sz;
    return 0;

}

/// @brief Open path for writing (wb) and write the buffer completely.
static int write_file(const char *path, const unsigned char *bug, size_t len){
    FILE *f= fopen(path, "wb");
    if(!f)return -1;
    if(fwrite(bug,1,len, f)!=len){
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}


static void derive_key_from_password(const char *pwd, const unsigned char *salt, unsigned char *key){
    const unsigned long long opslimit = crypto_pwhash_OPSLIMIT_MODERATE;
    const size_t memlimit = crypto_pwhash_MEMLIMIT_MODERATE;
    if(crypto_pwhash(key,KEY_LEN, pwd, strlen(pwd),salt,opslimit,memlimit,crypto_pwhash_ALG_ARGON2ID13)!=0){
        die("crypto_pwhash failed (not enough memory?");
    }
}

static void encrypt_file(const char *inpath, const char *outpath){
    unsigned char *plaintext = NULL;
    size_t pt_len = 0;
    if(read_file(inpath, &plaintext, &pt_len)!=0)die("read input failed");

    //get password
    char pwd[512];
    fprintf(stderr,"enter password: ");
    if(!fgets(pwd,sizeof pwd, stdin)){
        secure_free(plaintext,pt_len);
        die("no password");
    }
    pwd[strcspn(pwd,"\n")]=0;

    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], file_id[FILE_ID_LEN];
    randombytes_buf(salt,sizeof salt);
    randombytes_buf(nonce,sizeof nonce);
    randombytes_buf(file_id,sizeof file_id);

    unsigned char key[KEY_LEN];
    derive_key_from_password(pwd,salt,key);
    sodium_memzero(pwd,sizeof pwd);

    unsigned long long ct_len = pt_len+TAG_LEN;
    unsigned char *ct = malloc((size_t)ct_len);
    if(!ct){
        secure_free(plaintext,pt_len);
        sodium_memzero(key,sizeof key);
        die("oom");
    }

    unsigned long long actual_ct_len = 0;
    unsigned char header[HEADER_LEN];
    memset(header,0,sizeof header);
    memset(header+0, MAGIC,4 );
    header[4]= VERSION;
    memcpy(header+5,salt,SALT_LEN);
    memcpy(header+5+SALT_LEN,nonce,NONCE_LEN);
    memcpy(header+5+SALT_LEN+NONCE_LEN,file_id,FILE_ID_LEN);

    if(crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &actual_ct_len,plaintext,pt_len,header,sizeof header,NULL,nonce,key)!=0){
        secure_free(plaintext,pt_len);
        sodium_memzero(key,sizeof key);
        free(ct);
        die("encryption failed");
    }

    size_t out_total = sizeof header +(size_t)actual_ct_len;
    unsigned char *outbuf = malloc(out_total);
    if(!outbuf){
        secure_free(plaintext,pt_len);
        sodium_memzero(key,sizeof key);
        free(ct);
        die("oom");
    }
    memcpy(outbuf, header,sizeof header);
    memcpy(outbuf+sizeof header, ct,(size_t)actual_ct_len);

    if(write_file(outpath,outbuf,out_total)!=0){
        secure_free(plaintext, pt_len);
        sodium_memzero(key,sizeof key);
        free(ct);
        die("encryption failed");
    }
    printf("Encrypted %zu bytes -> %zu bytes (including header and tag)\n", pt_len, out_total);
    secure_free(plaintext, pt_len);
    sodium_memzero(key,sizeof key);
    free(ct);
    secure_free(outbuf,out_total);

}

static void decrypt_file(const char *inpath, const char *outpath){
    unsigned char *inbuf = NULL;
    size_t inlen = 0;
    if(read_file(inpath, &inbuf,&inlen)!=0)die("read input failed");
    if(inlen<HEADER_LEN +TAG_LEN ){
        free(inbuf);
        die("input too small");
    }
    if(memcmp(inbuf+0,MAGIC,4)!=0){
        free(inbuf);
        die("bad magic");
    }
    if(inbuf[4]!=VERSION){
        free(inbuf);
        die("unsupported version");
    }

    unsigned char salt[SALT_LEN], nonce[NONCE_LEN];
    memcpy(salt,inbuf+5,SALT_LEN);
    memcpy(nonce,inbuf+5+SALT_LEN,NONCE_LEN);

    char pwd[512];
    fprintf(stderr,"enter password: ");
    if(!fgets(pwd,sizeof pwd,stdin)){
        free(inbuf);
        die("no password");
    }
    pwd[strcspn(pwd,"\n")]=0;

    unsigned char key[KEY_LEN];
    derive_key_from_password(pwd,salt,key);
    sodium_memzero(pwd,sizeof pwd);

    unsigned char *ct = inbuf+ HEADER_LEN;
    size_t ct_len = inlen- HEADER_LEN;
    unsigned char *pt = malloc (ct_len);
    if(!pt){
        sodium_memzero(key,sizeof key);
        free(inbuf);
        die("oom");
    }
    unsigned long long actual_pt_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &actual_pt_len,
            NULL,
            ct, (unsigned long long)ct_len,
            inbuf, HEADER_LEN, // AAD = header
            nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        free(inbuf); free(pt);
        die("decryption failed: bad password or corrupted file");
    }

    if (write_file(outpath, pt, (size_t)actual_pt_len) != 0) {
        sodium_memzero(key, sizeof key);
        free(inbuf); free(pt);
        die("write output failed");
    }

    printf("Decrypted %llu bytes -> %zu bytes written\n", actual_pt_len, (size_t)actual_pt_len);

    sodium_memzero(key, sizeof key);
    free(inbuf); secure_free(pt, (size_t)actual_pt_len);
}

int main(int argc, char **argv){
    if(sodium_init()<0)die("sodium_init failed");
    if(argc != 4){
        fprintf(stderr,"usage: %s enc|dec infile outfile\n",argv[0]);
        return 1;
    }
    const char *cmd = argv[1], *in = argv[2], *out= argv[3];
    if(strcmp(cmd,"enc")==0)encrypt_file(in, out);
    else if(strcmp(cmd,"dec")==0)decrypt_file(in,out);
    else{
        fprintf(stderr,"unknown cmd:%s\n",cmd);
        return 1;
    }
    return 0;
}