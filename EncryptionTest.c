/*
CONTRIBUTORS:
Group 37
Alex Rowe
Darcy Lisk
Michael Marzinotto
Ben Middleton
*/

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdio.h>

// Helper function to print OpenSSL errors
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

// Function to sign a message using RSA-PSS
int sign_message(EVP_PKEY *private_key, const unsigned char *message, size_t message_len, unsigned char **signature, size_t *signature_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handle_errors();

    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    if (1 != EVP_DigestSignUpdate(mdctx, message, message_len))
        handle_errors();

    if (1 != EVP_DigestSignFinal(mdctx, NULL, signature_len))
        handle_errors();

    *signature = (unsigned char*)malloc(*signature_len);
    if (!*signature) handle_errors();

    if (1 != EVP_DigestSignFinal(mdctx, *signature, signature_len))
        handle_errors();

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

    if (1 != EVP_PKEY_encrypt(ctx, NULL, encrypted_key_len, aes_key, aes_key_len))
        handle_errors();

    *encrypted_key = (unsigned char*)malloc(*encrypted_key_len);
    if (!*encrypted_key) handle_errors();

    if (1 != EVP_PKEY_encrypt(ctx, *encrypted_key, encrypted_key_len, aes_key, aes_key_len))
        handle_errors();

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

int main() {
    // Generate RSA keys (for simplicity, this example uses small keys)
    EVP_PKEY *rsa_key = EVP_PKEY_new();
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(rsa_key, rsa);

    // Example message
    const char *message = "Hello, this is a secret message!";
    size_t message_len = strlen(message);

    // Sign the message
    unsigned char *signature = NULL;
    size_t signature_len;
    sign_message(rsa_key, (unsigned char*)message, message_len, &signature, &signature_len);

    // Encrypt the message using AES-GCM
    unsigned char aes_key[16] = {0}; // Use a random key
    unsigned char iv[16] = {0}; // Use a random IV
    unsigned char ciphertext[128] = {0};
    unsigned char tag[16] = {0};

    int ciphertext_len = aes_encrypt((unsigned char*)message, message_len, aes_key, iv, ciphertext, tag);

    // Encrypt the AES key with RSA
    unsigned char *encrypted_key = NULL;
    size_t encrypted_key_len;
    rsa_encrypt(rsa_key, aes_key, sizeof(aes_key), &encrypted_key, &encrypted_key_len);

    // Base64 encode the signature, ciphertext, and encrypted AES key
    char *b64_signature = base64_encode(signature, signature_len);
    char *b64_ciphertext = base64_encode(ciphertext, ciphertext_len);
    char *b64_encrypted_key = base64_encode(encrypted_key, encrypted_key_len);

    // Output the results (for testing purposes)
    printf("Signature: %s\n", b64_signature);
    printf("Ciphertext: %s\n", b64_ciphertext);
    printf("Encrypted AES Key: %s\n", b64_encrypted_key);

    // Free allocated memory
    free(signature);
    free(b64_signature);
    free(b64_ciphertext);
    free(b64_encrypted_key);

    EVP_PKEY_free(rsa_key);
    return 0;
}
