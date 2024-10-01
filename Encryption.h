#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string.h>
#include <stdio.h>

// Define the RSA key size (2048 bits = 256 bytes)
#define RSA_KEY_SIZE 2048
#define SIGNATURE_SIZE (RSA_KEY_SIZE / 8)  // 256 bytes for 2048-bit key

// Error handling 
void handle_errors();

// Base64 encoding function
char* base64_encode(const unsigned char* buffer, size_t length);

// Base64 decoding function
unsigned char* base64_decode(const char* base64_data, size_t* out_len);

// Function to sign message using RSA-PSS
int sign_message(EVP_PKEY *private_key, const unsigned char *message, size_t message_len, unsigned char *signature);

// AES encryption function (GCM mode)
int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);

// RSA encryption of AES key
int rsa_encrypt(EVP_PKEY *public_key, const unsigned char *aes_key, size_t aes_key_len, unsigned char **encrypted_key, size_t *encrypted_key_len);

// Function to verify message signature
int verify_signature(EVP_PKEY *public_key, const unsigned char *message, size_t message_len, const unsigned char *signature);

// Function to generate RSA key pair (2048-bit key size)
EVP_PKEY* generate_rsa_key();

#endif
