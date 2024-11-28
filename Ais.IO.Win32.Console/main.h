#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <cstdint>

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
typedef int (*Base16Encode)(const char*, char*, int);
typedef int (*Base16Decode)(const char*, char*, int);
typedef int (*Base32Encode)(const char*, char*, int);
typedef int (*Base32Decode)(const char*, char*, int);
typedef int (*Base64Encode)(const char*, char*, int);
typedef int (*Base64Decode)(const char*, char*, int);
typedef int (*Base85Encode)(const char*, char*, int);
typedef int (*Base85Decode)(const char*, char*, int);
#pragma endregion
