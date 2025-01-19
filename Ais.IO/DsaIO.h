#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define DSAIO_API __declspec(dllexport)
#else
#define RSAIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <string>
#include "AsymmetricIO.h"
#include "SymmetryIO.h"
#include "HashIO.h"

struct DSA_PARAMETERS {
    const size_t KEY_LENGTH;
    unsigned char* Y; // 公鑰 y
    unsigned char* X; // 私鑰 x
    unsigned char* P; // 素數 p
    unsigned char* Q; // 素數 q
    unsigned char* G; // 生成元 g
    size_t Y_LENGTH;  // 公鑰 y 長度
    size_t X_LENGTH;  // 私鑰 x 長度
    size_t P_LENGTH;  // 素數 p 長度
    size_t Q_LENGTH;  // 素數 q 長度
    size_t G_LENGTH;  // 生成元 g 長度
};

EXT DSAIO_API int DsaGetParametersLength(DSA_PARAMETERS* params);
EXT DSAIO_API int DsaGenerateParameters(DSA_PARAMETERS* params);
