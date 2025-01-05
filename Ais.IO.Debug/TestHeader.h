#pragma once

#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef _WIN32
#define LOAD_LIBRARY(Lib) LoadLibraryA(Lib)
#define GET_PROC_ADDRESS(Lib, name) GetProcAddress(Lib, name)
#define UNLOAD_LIBRARY(Lib) FreeLibrary(Lib)
HMODULE Lib = LOAD_LIBRARY("Ais.IO.dll");
#else
#define LOAD_LIBRARY(Lib) dlopen(Lib, RTLD_LAZY)
#define GET_PROC_ADDRESS(Lib, name) dlsym(Lib, name)
#define UNLOAD_LIBRARY(Lib) dlclose(Lib)
void* Lib = LOAD_LIBRARY("./Ais.IO.so");
#endif

#ifdef _WIN32
#include <windows.h>
#include <vector>

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        return;
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
#endif

enum SYMMETRY_CRYPTER {
    SYMMETRY_NULL = 0,
    SYMMETRY_AES_CTR = 1,
    SYMMETRY_AES_CBC = 2,
    SYMMETRY_AES_CFB = 3,
    SYMMETRY_AES_OFB = 4,
    SYMMETRY_AES_ECB = 5,
    SYMMETRY_AES_GCM = 6,
    SYMMETRY_AES_CCM = 7,
    SYMMETRY_AES_XTS = 8,
    SYMMETRY_AES_OCB = 9,
    SYMMETRY_AES_WRAP = 10,
    SYMMETRY_DES_CBC = 11,
    SYMMETRY_DES_CFB = 12,
    SYMMETRY_DES_OFB = 13,
    SYMMETRY_DES_ECB = 14,
    SYMMETRY_DES_WRAP = 15,
};

enum SEGMENT_SIZE_OPTION {
    SEGMENT_NULL = 0,
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_64_BIT = 64,
    SEGMENT_128_BIT = 128,
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

#pragma region EncoderIO
typedef int (*Base16Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base16Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base32Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base64Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base85Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Decode)(const char*, const size_t, unsigned char*, const size_t);

Base16Encode Base16Encode_Func = (Base16Encode)GET_PROC_ADDRESS(Lib, "Base16Encode");
Base16Decode Base16Decode_Func = (Base16Decode)GET_PROC_ADDRESS(Lib, "Base16Decode");
Base32Encode Base32Encode_Func = (Base32Encode)GET_PROC_ADDRESS(Lib, "Base32Encode");
Base32Decode Base32Decode_Func = (Base32Decode)GET_PROC_ADDRESS(Lib, "Base32Decode");
Base64Encode Base64Encode_Func = (Base64Encode)GET_PROC_ADDRESS(Lib, "Base64Encode");
Base64Decode Base64Decode_Func = (Base64Decode)GET_PROC_ADDRESS(Lib, "Base64Decode");
Base85Encode Base85Encode_Func = (Base85Encode)GET_PROC_ADDRESS(Lib, "Base85Encode");
Base85Decode Base85Decode_Func = (Base85Decode)GET_PROC_ADDRESS(Lib, "Base85Decode");
#pragma endregion