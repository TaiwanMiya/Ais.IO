#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define DESIO_API __declspec(dllexport)
#else
#define DESIO_API
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

struct DES_CBC_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_CBC_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_CFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_CFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_OFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_OFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_ECB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_ECB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_WRAP_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* KEK;
    unsigned char* WRAP_KEY;
    size_t KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t WRAP_KEY_LENGTH;
};

struct DES_WRAP_DECRYPT {
    const unsigned char* WRAP_KEY;
    const unsigned char* KEK;
    unsigned char* KEY;
    size_t WRAP_KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t KEY_LENGTH;
};

EXT DESIO_API int DesCbcEncrypt(DES_CBC_ENCRYPT* encryption);
EXT DESIO_API int DesCbcDecrypt(DES_CBC_DECRYPT* decryption);
EXT DESIO_API int DesCfbEncrypt(DES_CFB_ENCRYPT* encryption);
EXT DESIO_API int DesCfbDecrypt(DES_CFB_DECRYPT* decryption);
EXT DESIO_API int DesOfbEncrypt(DES_OFB_ENCRYPT* encryption);
EXT DESIO_API int DesOfbDecrypt(DES_OFB_DECRYPT* decryption);
EXT DESIO_API int DesEcbEncrypt(DES_ECB_ENCRYPT* encryption);
EXT DESIO_API int DesEcbDecrypt(DES_ECB_DECRYPT* decryption);
EXT DESIO_API int DesWrapEncrypt(DES_WRAP_ENCRYPT* encryption);
EXT DESIO_API int DesWrapDecrypt(DES_WRAP_DECRYPT* decryption);