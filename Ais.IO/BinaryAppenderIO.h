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

EXT BINARYIO_API void* CreateBinaryAppender(const char* filePath);
EXT BINARYIO_API void DestroyBinaryAppender(void* appender);
EXT BINARYIO_API uint64_t GetAppenderPosition(void* appender);
EXT BINARYIO_API uint64_t GetAppenderLength(void* appender);

EXT BINARYIO_API void AppendBoolean(void* appender, bool value);
EXT BINARYIO_API void AppendByte(void* appender, unsigned char value);
EXT BINARYIO_API void AppendSByte(void* appender, signed char value);
EXT BINARYIO_API void AppendShort(void* appender, short value);
EXT BINARYIO_API void AppendUShort(void* appender, unsigned short value);
EXT BINARYIO_API void AppendInt(void* appender, int value);
EXT BINARYIO_API void AppendUInt(void* appender, unsigned int value);
EXT BINARYIO_API void AppendLong(void* appender, long long value);
EXT BINARYIO_API void AppendULong(void* appender, unsigned long long value);
EXT BINARYIO_API void AppendFloat(void* appender, float value);
EXT BINARYIO_API void AppendDouble(void* appender, double value);
EXT BINARYIO_API void AppendBytes(void* appender, const unsigned char* bytes, uint64_t length);
EXT BINARYIO_API void AppendString(void* appender, const char* value);