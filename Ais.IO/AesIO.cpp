#include "pch.h"
#include "AesIO.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>

// Handle Errors
void handleErrors() {
    std::cerr << "An error occurred during key/iv generation" << std::endl;
    ERR_print_errors_fp(stderr);
    exit(1);
}

int GenerateKey(unsigned char* key, size_t keyLength) {
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        std::cerr << "Invalid key length. Use 128, 192, or 256 bits." << std::endl;
        return -1;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < keyLength; ++i) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
    return 0;
}

int GenerateIV(unsigned char* iv, size_t ivLength) {
    if (ivLength != 16) {
        std::cerr << "Invalid IV length. Use 128 bits." << std::endl;
        return -1;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < ivLength; ++i) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    return 0;
}

int GenerateKeyFromInput(const char* input, unsigned char* key, size_t keyLength) {
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        std::cerr << "Invalid key length. Use 128, 192, or 256 bits." << std::endl;
        return -1;
    }
    size_t inputLength = strlen(input);
    memset(key, 0, keyLength);
    memcpy(key, input, inputLength > keyLength ? keyLength : inputLength);
    return 0;
}

int GenerateIVFromInput(const char* input, unsigned char* iv, size_t ivLength) {
    if (ivLength != 16) {
        std::cerr << "Invalid IV length. Use 128 bits." << std::endl;
        return -1;
    }
    size_t inputLength = strlen(input);
    memset(iv, 0, ivLength);
    memcpy(iv, input, inputLength > ivLength ? ivLength : inputLength);
    return 0;
}

int AesCtrEncrypt(AES_CTR_ENCRYPT* encryption) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, encryption->KEY, encryption->IV)) {
        handleErrors();
    }

    int len;
    int ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, encryption->PLAIN_TEXT_LENGTH)) {
        handleErrors();
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len)) {
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesCtrDecrypt(AES_CTR_DECRYPT* decryption) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, decryption->KEY, decryption->IV)) {
        handleErrors();
    }

    int len;
    int plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, decryption->CIPHER_TEXT_LENGTH)) {
        handleErrors();
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len)) {
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}