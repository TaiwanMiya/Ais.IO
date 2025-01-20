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

struct RSA_PARAMETERS {
    const size_t KEY_LENGTH;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
};

struct RSA_KEY_PAIR {
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

struct RSA_PKCS8_KEY {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct RSA_PKCS10_CSR {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT CSR_FORMAT;
    unsigned char* CSR;
    size_t CSR_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
    const unsigned char* COUNTRY;
    const unsigned char* ORGANIZETION;
    const unsigned char* ORGANIZETION_UNIT;
    const unsigned char* COMMON_NAME;
};

struct RSA_PKCS12_CERTIFICATE_KEY {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* CERTIFICATE;
    unsigned char* PRIVATE_KEY;
    size_t CERTIFICATE_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
    const HASH_TYPE HASH_ALGORITHM;
    const char* PKCS12_NAME;
    const char* PKCS12_PASSWORD;
    const unsigned char* COUNTRY;
    const unsigned char* ORGANIZETION;
    const unsigned char* ORGANIZETION_UNIT;
    const unsigned char* COMMON_NAME;
    const unsigned long VALIDITY_DAYS;
};

struct RSA_EXPORT {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct RSA_EXTRACT_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT PUBLIC_KEY_FORMAT;
    const ASYMMETRIC_KEY_FORMAT PRIVATE_KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct RSA_CHECK_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    size_t PUBLIC_KEY_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_PRIVATE_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_CSR {
    const ASYMMETRIC_KEY_FORMAT CSR_FORMAT;
    const unsigned char* CSR;
    size_t CSR_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_CERTIFICATE {
    const ASYMMETRIC_KEY_FORMAT CERTIFICATE_FORMAT;
    const ASYMMETRIC_KEY_FORMAT PRIVATE_KEY_FORMAT;
    const unsigned char* CERTIFICATE;
    const unsigned char* PRIVATE_KEY;
    size_t CERTIFICATE_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const char* PKCS12_PASSWORD;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_ENCRYPT {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t PUBLIC_KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct RSA_DECRYPT {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct RSA_SIGNED {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    const unsigned char* DATA;
    unsigned char* SIGNATURE;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    size_t DATA_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
};

struct RSA_VERIFY {
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

EXT RSAIO_API int RsaGetParametersLength(RSA_PARAMETERS* params);
EXT RSAIO_API int RsaGetKeyLength(RSA_KEY_PAIR* params);
EXT RSAIO_API int RsaGenerateParameters(RSA_PARAMETERS* params);
EXT RSAIO_API int RsaGenerateKeys(RSA_KEY_PAIR* generate);
EXT RSAIO_API int RsaGeneratePKCS8(RSA_PKCS8_KEY* generate);
EXT RSAIO_API int RsaGeneratePKCS10(RSA_PKCS10_CSR* generate);
EXT RSAIO_API int RsaGeneratePKCS12(RSA_PKCS12_CERTIFICATE_KEY* generate);
EXT RSAIO_API int RsaExportParameters(RSA_EXPORT* params);
EXT RSAIO_API int RsaExportKeys(RSA_EXPORT* params);
EXT RSAIO_API int RsaExtractPublicKey(RSA_EXTRACT_PUBLIC_KEY* params);
EXT RSAIO_API int RsaCheckPublicKey(RSA_CHECK_PUBLIC_KEY* check);
EXT RSAIO_API int RsaCheckPrivateKey(RSA_CHECK_PRIVATE_KEY* check);
EXT RSAIO_API int RsaCheckCSR(RSA_CHECK_CSR* check);
EXT RSAIO_API int RsaCheckCertificate(RSA_CHECK_CERTIFICATE* check);
EXT RSAIO_API int RsaEncryption(RSA_ENCRYPT* encrypt);
EXT RSAIO_API int RsaDecryption(RSA_DECRYPT* decrypt);
EXT RSAIO_API int RsaSigned(RSA_SIGNED* sign);
EXT RSAIO_API int RsaVerify(RSA_VERIFY* verify);