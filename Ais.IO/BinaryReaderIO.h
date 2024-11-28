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
#define BINARYIO_API __declspec(dllimport)
#else
#define BINARYIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

EXT {

	BINARYIO_API void* CreateBinaryReader(const char* filePath);
	BINARYIO_API void DestroyBinaryReader(void* reader);
	BINARYIO_API uint64_t GetReaderPosition(void* reader);
	BINARYIO_API uint64_t GetReaderLength(void* reader);

	BINARYIO_API bool ReadBoolean(void* reader);
	BINARYIO_API unsigned char ReadByte(void* reader);
	BINARYIO_API signed char ReadSByte(void* reader);
	BINARYIO_API short ReadShort(void* reader);
	BINARYIO_API unsigned short ReadUShort(void* reader);
	BINARYIO_API int ReadInt(void* reader);
	BINARYIO_API unsigned int ReadUInt(void* reader);
	BINARYIO_API long long ReadLong(void* reader);
	BINARYIO_API unsigned long long ReadULong(void* reader);
	BINARYIO_API float ReadFloat(void* reader);
	BINARYIO_API double ReadDouble(void* reader);
	BINARYIO_API void ReadBytes(void* reader, char* buffer, uint64_t bufferSize);
	BINARYIO_API void ReadString(void* reader, char* buffer, uint64_t bufferSize);

}