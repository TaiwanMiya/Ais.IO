#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define ASYMMETRICIO_API __declspec(dllexport)
#else
#define ASYMMETRICIO_API
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
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_64_BIT = 64,
    SEGMENT_128_BIT = 128,
};

int handleErrors(std::string message, EVP_CIPHER_CTX* ctx);
EXT ASYMMETRICIO_API int Generate(unsigned char* content, size_t length);
EXT ASYMMETRICIO_API int Import(const unsigned char* input, size_t inputLength, unsigned char* output, size_t outputLength);