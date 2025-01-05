#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define SYMMETRYIO_API __declspec(dllexport)
#else
#define SYMMETRYIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <ctime>
#include <cstring>
#include <random>

enum SEGMENT_SIZE_OPTION {
    SEGMENT_NULL = 0,
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_64_BIT = 64,
    SEGMENT_128_BIT = 128,
};

enum SYMMETRY_CRYPTER {
    SYMMETRY_NULL       = 0,
    SYMMETRY_AES_CTR    = 1,
    SYMMETRY_AES_CBC    = 2,
    SYMMETRY_AES_CFB    = 3,
    SYMMETRY_AES_OFB    = 4,
    SYMMETRY_AES_ECB    = 5,
    SYMMETRY_AES_GCM    = 6,
    SYMMETRY_AES_CCM    = 7,
    SYMMETRY_AES_XTS    = 8,
    SYMMETRY_AES_OCB    = 9,
    SYMMETRY_AES_WRAP   = 10,
    SYMMETRY_DES_CBC    = 11,
    SYMMETRY_DES_CFB    = 12,
    SYMMETRY_DES_OFB    = 13,
    SYMMETRY_DES_ECB    = 14,
    SYMMETRY_DES_WRAP   = 15,
};

int handleErrors_symmetry(std::string message, EVP_CIPHER_CTX* ctx);
int handleErrors_symmetry(std::string message, EVP_MD_CTX* ctx);
const EVP_CIPHER* GetSymmetryCrypter(SYMMETRY_CRYPTER crypter, int size, SEGMENT_SIZE_OPTION segment);
EXT SYMMETRYIO_API int Generate(unsigned char* content, size_t length);
EXT SYMMETRYIO_API int Import(const unsigned char* input, size_t inputLength, unsigned char* output, size_t outputLength);