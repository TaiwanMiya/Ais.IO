#pragma once
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <typeinfo>
#include <stdint.h>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define BINARYIO_API __declspec(dllexport)
#else
#define BINARYIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

EXT BINARYIO_API void* CreateBinaryReader(const char* filePath);
EXT BINARYIO_API void DestroyBinaryReader(void* reader);
EXT BINARYIO_API uint64_t GetReaderPosition(void* reader);
EXT BINARYIO_API uint64_t GetReaderLength(void* reader);

EXT BINARYIO_API bool ReadBoolean(void* reader, int64_t position = -1);
EXT BINARYIO_API unsigned char ReadByte(void* reader, int64_t position = -1);
EXT BINARYIO_API signed char ReadSByte(void* reader, int64_t position = -1);
EXT BINARYIO_API short ReadShort(void* reader, int64_t position = -1);
EXT BINARYIO_API unsigned short ReadUShort(void* reader, int64_t position = -1);
EXT BINARYIO_API int ReadInt(void* reader, int64_t position = -1);
EXT BINARYIO_API unsigned int ReadUInt(void* reader, int64_t position = -1);
EXT BINARYIO_API long long ReadLong(void* reader, int64_t position = -1);
EXT BINARYIO_API unsigned long long ReadULong(void* reader, int64_t position = -1);
EXT BINARYIO_API float ReadFloat(void* reader, int64_t position = -1);
EXT BINARYIO_API double ReadDouble(void* reader, int64_t position = -1);
EXT BINARYIO_API void ReadBytes(void* reader, unsigned char* buffer, uint64_t bufferSize, int64_t position = -1);
EXT BINARYIO_API void ReadString(void* reader, char* buffer, uint64_t bufferSize, int64_t position = -1);