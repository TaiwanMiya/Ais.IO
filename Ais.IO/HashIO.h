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
#include "AsymmetricIO.h"

enum SALT_SEQUENCE {
	SALT_NULL = 0,
	SALT_FIRST = 1,
	SALT_LAST = 2,
};

struct HASH_MD5 {
	const unsigned char* INPUT;
	const unsigned char* SALT;
	unsigned char* OUTPUT;
	SALT_SEQUENCE SEQUENCE;
	size_t INPUT_LENGTH;
	size_t SALT_LENGTH;
};

EXT HASHIO_API int HashMd5(HASH_MD5* hash);