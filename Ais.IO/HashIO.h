#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define HASHIO_API __declspec(dllexport)
#else
#define HASHIO_API
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

enum SALT_SEQUENCE {
	SALT_NULL	= 0,
	SALT_FIRST	= 1 << 0,
	SALT_LAST	= 1 << 1,
    SALT_MIDDLE = 1 << 2,
};

enum HASH_TYPE {
    HASH_NULL           = 0,
	HASH_MD5            = 1,
    HASH_MD5_SHA1       = 2,
    HASH_SHA1           = 3,
    HASH_SHA2_224       = 4,
    HASH_SHA2_256       = 5,
    HASH_SHA2_384       = 6,
    HASH_SHA2_512       = 7,
    HASH_SHA2_512_224   = 8,
    HASH_SHA2_512_256   = 9,
    HASH_SHA3_224       = 10,
    HASH_SHA3_256       = 11,
    HASH_SHA3_384       = 12,
    HASH_SHA3_512       = 13,
    HASH_SHA3_KE_128    = 14,
    HASH_SHA3_KE_256    = 15,
    HASH_BLAKE2S_256    = 16,
    HASH_BLAKE2B_512    = 17,
    HASH_SM3            = 18,
    HASH_RIPEMD160      = 19,
};

struct HASH_STRUCTURE {
	const unsigned char* INPUT;
	const unsigned char* SALT;
	unsigned char* OUTPUT;
	HASH_TYPE TYPE;
	SALT_SEQUENCE SEQUENCE;
	size_t INPUT_LENGTH;
	size_t SALT_LENGTH;
	size_t OUTPUT_LENGTH;
};

const EVP_MD* GetHashCrypter(HASH_TYPE type);
EXT HASHIO_API int Hash(HASH_STRUCTURE* hash);
EXT HASHIO_API int GetHashLength(HASH_TYPE type);