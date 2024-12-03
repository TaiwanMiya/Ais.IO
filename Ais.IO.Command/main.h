#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <vector>
#include <string>
#include <cstdlib>
#include <iomanip>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <iostream>

enum SEGMENT_SIZE_OPTION {
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_128_BIT = 128,
};

struct AES_CTR_ENCRYPT {
    const unsigned char* PLAIN_TEXT;
    const unsigned char* KEY;
    size_t PLAIN_TEXT_LENGTH;
    unsigned char* CIPHER_TEXT;
    const long long COUNTER;
};

struct AES_CTR_DECRYPT {
    const unsigned char* CIPHER_TEXT;
    const unsigned char* KEY;
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

struct AES_CFB_ENCRYPT {
    const unsigned char* PLAIN_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t PLAIN_TEXT_LENGTH;
    unsigned char* CIPHER_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
};

struct AES_CFB_DECRYPT {
    const unsigned char* CIPHER_TEXT;
    const unsigned char* KEY;
    const unsigned char* IV;
    size_t CIPHER_TEXT_LENGTH;
    unsigned char* PLAIN_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
};

// Define function pointer types for all APIs
#pragma region BinaryIO
typedef uint64_t(*NextLength)(void*);
#pragma endregion

#pragma region BinaryReaderIO
typedef void* (*CreateBinaryReader)(const char*);
typedef void (*DestroyBinaryReader)(void*);
typedef uint64_t(*GetReaderPosition)(void*);
typedef uint64_t(*GetReaderLength)(void*);

typedef bool (*ReadBoolean)(void*);
typedef unsigned char (*ReadByte)(void*);
typedef signed char (*ReadSByte)(void*);
typedef short (*ReadShort)(void*);
typedef unsigned short (*ReadUShort)(void*);
typedef int (*ReadInt)(void*);
typedef unsigned int (*ReadUInt)(void*);
typedef long long (*ReadLong)(void*);
typedef unsigned long long (*ReadULong)(void*);
typedef float (*ReadFloat)(void*);
typedef double (*ReadDouble)(void*);
typedef void (*ReadBytes)(void*, char*, uint64_t);
typedef void (*ReadString)(void*, char*, uint64_t);
#pragma endregion

#pragma region BinaryWriterIO
typedef void* (*CreateBinaryWriter)(const char*);
typedef void (*DestroyBinaryWriter)(void*);
typedef uint64_t(*GetWriterPosition)(void*);
typedef uint64_t(*GetWriterLength)(void*);

typedef void (*WriteBoolean)(void*, bool);
typedef void (*WriteByte)(void*, unsigned char);
typedef void (*WriteSByte)(void*, signed char);
typedef void (*WriteShort)(void*, short);
typedef void (*WriteUShort)(void*, unsigned short);
typedef void (*WriteInt)(void*, int);
typedef void (*WriteUInt)(void*, unsigned int);
typedef void (*WriteLong)(void*, long long);
typedef void (*WriteULong)(void*, unsigned long long);
typedef void (*WriteFloat)(void*, float);
typedef void (*WriteDouble)(void*, double);
typedef void (*WriteBytes)(void*, const char*);
typedef void (*WriteString)(void*, const char*);
#pragma endregion

#pragma region EncoderIO
typedef int (*Base16Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base16Decode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Decode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Decode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Decode)(const unsigned char*, const size_t, char*, const size_t);
#pragma endregion

#pragma region AesIO
typedef int (*GenerateKey)(unsigned char*, size_t);
typedef int (*GenerateIV)(unsigned char*, size_t);
typedef int (*GenerateKeyFromInput)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*GenerateIVFromInput)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*AesCtrEncrypt)(AES_CTR_ENCRYPT*);
typedef int (*AesCtrDecrypt)(AES_CTR_DECRYPT*);
typedef int (*AesCbcEncrypt)(AES_CBC_ENCRYPT*);
typedef int (*AesCbcDecrypt)(AES_CBC_DECRYPT*);
typedef int (*AesCfbEncrypt)(AES_CFB_ENCRYPT*);
typedef int (*AesCfbDecrypt)(AES_CFB_DECRYPT*);
#pragma endregion
