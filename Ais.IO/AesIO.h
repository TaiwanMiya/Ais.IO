#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define AESIO_API __declspec(dllexport)
#else
#define AESIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <string>
#include "SymmetryIO.h"

struct AES_CTR_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    const long long COUNTER;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CTR_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    long long COUNTER;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_CBC_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CBC_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_CFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_OFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_OFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_ECB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_ECB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_GCM_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_GCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_CCM_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_CCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_XTS_ENCRYPT {
    const unsigned char* KEY1;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    const unsigned char* KEY2;
    const unsigned char* TWEAK;
    size_t KEY1_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t KEY2_LENGTH;
};

struct AES_XTS_DECRYPT {
    const unsigned char* KEY1;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* KEY2;
    const unsigned char* TWEAK;
    size_t KEY1_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t KEY2_LENGTH;
};

struct AES_OCB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_OCB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_WRAP_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* KEK;
    unsigned char* WRAP_KEY;
    size_t KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t WRAP_KEY_LENGTH;
};

struct AES_WRAP_DECRYPT {
    const unsigned char* WRAP_KEY;
    const unsigned char* KEK;
    unsigned char* KEY;
    size_t WRAP_KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t KEY_LENGTH;
};

EXT AESIO_API int AesCtrEncrypt(AES_CTR_ENCRYPT* encryption);
EXT AESIO_API int AesCtrDecrypt(AES_CTR_DECRYPT* decryption);
EXT AESIO_API int AesCbcEncrypt(AES_CBC_ENCRYPT* encryption);
EXT AESIO_API int AesCbcDecrypt(AES_CBC_DECRYPT* decryption);
EXT AESIO_API int AesCfbEncrypt(AES_CFB_ENCRYPT* encryption);
EXT AESIO_API int AesCfbDecrypt(AES_CFB_DECRYPT* decryption);
EXT AESIO_API int AesOfbEncrypt(AES_OFB_ENCRYPT* encryption);
EXT AESIO_API int AesOfbDecrypt(AES_OFB_DECRYPT* decryption);
EXT AESIO_API int AesEcbEncrypt(AES_ECB_ENCRYPT* encryption);
EXT AESIO_API int AesEcbDecrypt(AES_ECB_DECRYPT* decryption);
EXT AESIO_API int AesGcmEncrypt(AES_GCM_ENCRYPT* encryption);
EXT AESIO_API int AesGcmDecrypt(AES_GCM_DECRYPT* decryption);
EXT AESIO_API int AesCcmEncrypt(AES_CCM_ENCRYPT* encryption);
EXT AESIO_API int AesCcmDecrypt(AES_CCM_DECRYPT* decryption);
EXT AESIO_API int AesXtsEncrypt(AES_XTS_ENCRYPT* encryption);
EXT AESIO_API int AesXtsDecrypt(AES_XTS_DECRYPT* decryption);
EXT AESIO_API int AesOcbEncrypt(AES_OCB_ENCRYPT* encryption);
EXT AESIO_API int AesOcbDecrypt(AES_OCB_DECRYPT* decryption);
EXT AESIO_API int AesWrapEncrypt(AES_WRAP_ENCRYPT* encryption);
EXT AESIO_API int AesWrapDecrypt(AES_WRAP_DECRYPT* decryption);
