#pragma once
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
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

EXT BINARYIO_API void* CreateBinaryWriter(const char* filePath);
EXT BINARYIO_API void DestroyBinaryWriter(void* writer);
EXT BINARYIO_API uint64_t GetWriterPosition(void* writer);
EXT BINARYIO_API uint64_t GetWriterLength(void* writer);

EXT BINARYIO_API void WriteBoolean(void* writer, bool value);
EXT BINARYIO_API void WriteByte(void* writer, unsigned char value);
EXT BINARYIO_API void WriteSByte(void* writer, signed char value);
EXT BINARYIO_API void WriteShort(void* writer, short value);
EXT BINARYIO_API void WriteUShort(void* writer, unsigned short value);
EXT BINARYIO_API void WriteInt(void* writer, int value);
EXT BINARYIO_API void WriteUInt(void* writer, unsigned int value);
EXT BINARYIO_API void WriteLong(void* writer, long long value);
EXT BINARYIO_API void WriteULong(void* writer, unsigned long long value);
EXT BINARYIO_API void WriteFloat(void* writer, float value);
EXT BINARYIO_API void WriteDouble(void* writer, double value);
EXT BINARYIO_API void WriteBytes(void* writer, const unsigned char* bytes, uint64_t length);
EXT BINARYIO_API void WriteString(void* writer, const char* value);