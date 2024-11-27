#pragma once

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

	BINARYIO_API void* CreateBinaryWriter(const char* filePath);
	BINARYIO_API void DestroyBinaryWriter(void* writer);
	BINARYIO_API uint64_t GetWriterPosition(void* writer);
	BINARYIO_API uint64_t GetWriterLength(void* writer);

	BINARYIO_API void WriteBoolean(void* writer, bool value);
	BINARYIO_API void WriteByte(void* writer, unsigned char value);
	BINARYIO_API void WriteSByte(void* writer, signed char value);
	BINARYIO_API void WriteShort(void* writer, short value);
	BINARYIO_API void WriteUShort(void* writer, unsigned short value);
	BINARYIO_API void WriteInt(void* writer, int value);
	BINARYIO_API void WriteUInt(void* writer, unsigned int value);
	BINARYIO_API void WriteLong(void* writer, long long value);
	BINARYIO_API void WriteULong(void* writer, unsigned long long value);
	BINARYIO_API void WriteFloat(void* writer, float value);
	BINARYIO_API void WriteDouble(void* writer, double value);
	BINARYIO_API void WriteBytes(void* writer, const char* bytes);
	BINARYIO_API void WriteString(void* writer, const char* value);

}