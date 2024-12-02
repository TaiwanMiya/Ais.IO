#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define AESIO_API __declspec(dllimport)
#else
#define AESIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

struct AES_CTR_ENCRYPT {
    const unsigned char* PLAIN_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t PLAIN_TEXT_LENGTH;
    unsigned char* CIPHER_TEXT;
    const long long COUNTER;
};

struct AES_CTR_DECRYPT {
    const unsigned char* CIPHER_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t CIPHER_TEXT_LENGTH;
    unsigned char* PLAIN_TEXT;
    const long long COUNTER;
};

struct AES_CBC_ENCRYPT {
    const unsigned char* PLAIN_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t PLAIN_TEXT_LENGTH;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
};

struct AES_CBC_DECRYPT {
    const unsigned char* CIPHER_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t CIPHER_TEXT_LENGTH;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
};

// Generate a random key with specified length (128, 192, 256 bits)
EXT AESIO_API int GenerateKey(unsigned char* key, size_t keyLength);
// Generate a random IV with length 128 bits
EXT AESIO_API int GenerateIV(unsigned char* iv, size_t ivLength);
// Generate a key with specified length using input data
EXT AESIO_API int GenerateKeyFromInput(const unsigned char* input, size_t inputLength, unsigned char* key, size_t keyLength);
// Generate an IV with specified length using input data
EXT AESIO_API int GenerateIVFromInput(const unsigned char* input, size_t inputLength, unsigned char* iv, size_t ivLength);


EXT AESIO_API int AesCtrEncrypt(AES_CTR_ENCRYPT* encryption);
EXT AESIO_API int AesCtrDecrypt(AES_CTR_DECRYPT* decryption);
EXT AESIO_API int AesCbcEncrypt(AES_CBC_ENCRYPT* encryption);
EXT AESIO_API int AesCbcDecrypt(AES_CBC_DECRYPT* decryption);