#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define RSAIO_API __declspec(dllexport)
#else
#define RSAIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <string>
#include "AsymmetricIO.h"

struct RSA_PARAMETERS {
    const size_t KEY_SIZE;
    unsigned char* MODULUS;
    size_t MODULUS_LENGTH;
    unsigned char* PUBLIC_EXPONENT;
    size_t PUBLIC_EXPONENT_LENGTH;
    unsigned char* PRIVATE_EXPONENT;
    size_t PRIVATE_EXPONENT_LENGTH;
    unsigned char* FACTOR1;
    size_t FACTOR1_LENGTH;
    unsigned char* FACTOR2;
    size_t FACTOR2_LENGTH;
    unsigned char* EXPONENT1;
    size_t EXPONENT1_LENGTH;
    unsigned char* EXPONENT2;
    size_t EXPONENT2_LENGTH;
    unsigned char* COEFFICIENT;
    size_t COEFFICIENT_LENGTH;
};

struct RSA_KEY_PAIR {
    const size_t KEY_SIZE;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

EXT RSAIO_API int GenerateRsaParameters(RSA_PARAMETERS* params);
EXT RSAIO_API int RsaGenerate(RSA_KEY_PAIR* generate);