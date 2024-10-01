#include "Encryption.h"
#include <openssl/err.h>
#include <stdlib.h>

// Error handling 
void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Base64 encoding function
char* base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char* encoded = (char*)malloc((bufferPtr->length + 1) * sizeof(char));
    memcpy(encoded, bufferPtr->data, bufferPtr->length);
    encoded[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return encoded;
}

// Base64 decoding function
unsigned char* base64_decode(const char* base64_data, size_t* out_len) {
    BIO *bio, *b64;
    int decode_len = strlen(base64_data);
    unsigned char *buffer = (unsigned char*)malloc(decode_len);

    bio = BIO_new_mem_buf(base64_data, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *out_len = BIO_read(bio, buffer, decode_len);
    buffer[*out_len] = '\0';

    BIO_free_all(bio);
    return buffer;
}

// Function to generate RSA key pair (2048-bit key size)
EVP_PKEY* generate_rsa_key() {
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    EVP_PKEY *pkey = EVP_PKEY_new();

    if (!BN_set_word(bn, RSA_F4)) {
        handle_errors();
    }

    // Generate a 2048-bit RSA key
    if (!RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL)) {
        handle_errors();
    }

    EVP_PKEY_assign_RSA(pkey, rsa);
    BN_free(bn);
    return pkey;
}

// Function to sign message using RSA-PSS
int sign_message(EVP_PKEY *private_key, const unsigned char *message, size_t message_len, unsigned char *signature) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    EVP_PKEY_CTX *pctx;
    if (1 != EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, private_key))
        handle_errors();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING))
        handle_errors();

    if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32))
        handle_errors();

    if (1 != EVP_DigestSignUpdate(mdctx, message, message_len))
        handle_errors();

    size_t signature_len = SIGNATURE_SIZE;
    if (1 != EVP_DigestSignFinal(mdctx, signature, &signature_len))
        handle_errors();

    if (signature_len != SIGNATURE_SIZE) {
        fprintf(stderr, "Unexpected signature size: %zu\n", signature_len);
        handle_errors();
    }

    EVP_MD_CTX_free(mdctx);
    return 1;
}

// AES encryption function (GCM mode)
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handle_errors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
        handle_errors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_errors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handle_errors();

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// RSA encryption of AES key
int rsa_encrypt(EVP_PKEY *public_key, const unsigned char *aes_key, size_t aes_key_len, unsigned char **encrypted_key, size_t *encrypted_key_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) handle_errors();

    if (1 != EVP_PKEY_encrypt_init(ctx)) handle_errors();

    if (1 != EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
        handle_errors();

    if (1 != EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()))  // Set OAEP to use SHA-256
        handle_errors();

    if (1 != EVP_PKEY_encrypt(ctx, NULL, encrypted_key_len, aes_key, aes_key_len))
        handle_errors();

    *encrypted_key = (unsigned char*)malloc(*encrypted_key_len);
    if (!*encrypted_key) handle_errors();

    if (1 != EVP_PKEY_encrypt(ctx, *encrypted_key, encrypted_key_len, aes_key, aes_key_len))
        handle_errors();

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Function to verify a message signature
int verify_signature(EVP_PKEY *public_key, const unsigned char *message, size_t message_len, const unsigned char *signature) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    EVP_PKEY_CTX *pctx;
    if (1 != EVP_DigestVerifyInit(mdctx, &pctx, EVP_sha256(), NULL, public_key))
        handle_errors();

    // Set the RSA-PSS padding and salt length for verification
    if (1 != EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING))
        handle_errors();

    if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 32))
        handle_errors();

    if (1 != EVP_DigestVerifyUpdate(mdctx, message, message_len))
        handle_errors();

    int result = EVP_DigestVerifyFinal(mdctx, signature, SIGNATURE_SIZE);
    EVP_MD_CTX_free(mdctx);

    return result == 1;
}
