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

EXT BINARYIO_API void* CreateBinaryInserter(const char* filePath);
EXT BINARYIO_API void DestroyBinaryInserter(void* inserter);
EXT BINARYIO_API uint64_t GetInserterPosition(void* inserter);
EXT BINARYIO_API uint64_t GetInserterLength(void* inserter);

EXT BINARYIO_API void InsertBoolean(void* inserter, bool value, uint64_t position);
EXT BINARYIO_API void InsertByte(void* inserter, unsigned char value, uint64_t position);
EXT BINARYIO_API void InsertSByte(void* inserter, signed char value, uint64_t position);
EXT BINARYIO_API void InsertShort(void* inserter, short value, uint64_t position);
EXT BINARYIO_API void InsertUShort(void* inserter, unsigned short value, uint64_t position);
EXT BINARYIO_API void InsertInt(void* inserter, int value, uint64_t position);
EXT BINARYIO_API void InsertUInt(void* inserter, unsigned int value, uint64_t position);
EXT BINARYIO_API void InsertLong(void* inserter, long long value, uint64_t position);
EXT BINARYIO_API void InsertULong(void* inserter, unsigned long long value, uint64_t position);
EXT BINARYIO_API void InsertFloat(void* inserter, float value, uint64_t position);
EXT BINARYIO_API void InsertDouble(void* inserter, double value, uint64_t position);
EXT BINARYIO_API void InsertBytes(void* inserter, const unsigned char* bytes, uint64_t length, uint64_t position);
EXT BINARYIO_API void InsertString(void* inserter, const char* value, uint64_t position);