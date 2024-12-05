#pragma once
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <filesystem>
#include <set>
#include <assert.h>
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

enum BINARYIO_TYPE : unsigned char {
	TYPE_NULL = 0,
	TYPE_BOOLEAN = 1,
	TYPE_BYTE = 2,
	TYPE_SBYTE = 3,
	TYPE_SHORT = 4,
	TYPE_USHORT = 5,
	TYPE_INT = 6,
	TYPE_UINT = 7,
	TYPE_LONG = 8,
	TYPE_ULONG = 9,
	TYPE_FLOAT = 10,
	TYPE_DOUBLE = 11,
	TYPE_BYTES = 12,
	TYPE_STRING = 13,
};

#pragma pack(push, 1)
struct BINARYIO_INDICES {
	uint64_t POSITION;      // 數據塊的起始位置
	BINARYIO_TYPE TYPE;     // 數據塊類型
	uint64_t LENGTH;        // 數據塊長度
};
#pragma pack(pop)

EXT BINARYIO_API uint64_t NextLength(void* reader);
EXT BINARYIO_API BINARYIO_TYPE ReadType(void* reader);
EXT BINARYIO_API BINARYIO_INDICES* GetAllIndices(void* reader, uint64_t* count);
EXT BINARYIO_API void RemoveIndex(void* reader, const char* filePath, BINARYIO_INDICES* index);
EXT BINARYIO_API void FreeIndexArray(BINARYIO_INDICES* indices);