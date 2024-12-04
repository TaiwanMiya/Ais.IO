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

enum BINARYIO_TYPE : unsigned char {
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

EXT BINARYIO_API uint64_t NextLength(void* reader);
EXT BINARYIO_API BINARYIO_TYPE ReadType(void* reader);
