#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define DSAIO_API __declspec(dllexport)
#else
#define DSAIO_API
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
    unsigned char* Y;
    unsigned char* X;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* G;
    size_t Y_LENGTH;
    size_t X_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t G_LENGTH;
};

struct DSA_KEY_PAIR {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct DSA_EXPORT {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* Y;
    unsigned char* X;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* G;
    size_t Y_LENGTH;
    size_t X_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t G_LENGTH;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct DSA_EXTRACT_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT PUBLIC_KEY_FORMAT;
    const ASYMMETRIC_KEY_FORMAT PRIVATE_KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct DSA_EXTRACT_PARAMETERS_KEYS {
    const ASYMMETRIC_KEY_FORMAT PARAMETERS_FORMAT;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PARAMETERS;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PARAMETERS_LENGTH;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct DSA_EXTRACT_KEYS_PARAMETERS {
    const ASYMMETRIC_KEY_FORMAT PARAMETERS_FORMAT;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PARAMETERS;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PARAMETERS_LENGTH;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct DSA_CHECK_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    size_t PUBLIC_KEY_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct DSA_CHECK_PRIVATE_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct DSA_CHECK_PARAMETERS {
    const ASYMMETRIC_KEY_FORMAT PARAM_FORMAT;
    const unsigned char* PARAMETERS;
    size_t PARAMETERS_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct DSA_PEM_LOCK {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct DSA_PEM_UNLOCK {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct DSA_SIGNED {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    const unsigned char* DATA;
    unsigned char* SIGNATURE;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    size_t DATA_LENGTH;
    size_t SIGNATURE_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
};

struct DSA_VERIFY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* DATA;
    const unsigned char* SIGNATURE;
    size_t PUBLIC_KEY_LENGTH;
    size_t DATA_LENGTH;
    size_t SIGNATURE_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
    bool IS_VALID;
};

EXT DSAIO_API int DsaGetParametersLength(DSA_PARAMETERS* params);
EXT DSAIO_API int DsaGetKeyLength(DSA_KEY_PAIR* params);
EXT DSAIO_API int DsaGenerateParameters(DSA_PARAMETERS* params);
EXT DSAIO_API int DsaGenerateKeys(DSA_KEY_PAIR* generate);
EXT DSAIO_API int DsaExportParameters(DSA_EXPORT* params);
EXT DSAIO_API int DsaExportKeys(DSA_EXPORT* params);
EXT DSAIO_API int DsaExtractPublicKey(DSA_EXTRACT_PUBLIC_KEY* params);
EXT DSAIO_API int DsaExtractParametersByKeys(DSA_EXTRACT_PARAMETERS_KEYS* params);
EXT DSAIO_API int DsaExtractKeysByParameters(DSA_EXTRACT_KEYS_PARAMETERS* params);
EXT DSAIO_API int DsaCheckPublicKey(DSA_CHECK_PUBLIC_KEY* check);
EXT DSAIO_API int DsaCheckPrivateKey(DSA_CHECK_PRIVATE_KEY* check);
EXT DSAIO_API int DsaCheckParameters(DSA_CHECK_PARAMETERS* check);
EXT DSAIO_API int DsaPemLock(DSA_PEM_LOCK* pem);
EXT DSAIO_API int DsaPemUnlock(DSA_PEM_UNLOCK* pem);
EXT DSAIO_API int DsaSigned(DSA_SIGNED* sign);
EXT DSAIO_API int DsaVerify(DSA_VERIFY* verify);
