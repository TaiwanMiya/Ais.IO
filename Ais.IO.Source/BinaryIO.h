#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#define BINARYIO_API __declspec(dllimport)
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

EXT {

	BINARYIO_API void* CreateBinaryReader(const char* filePath);
	BINARYIO_API void DestroyBinaryReader(void* reader);
	BINARYIO_API size_t GetReaderPosition(void* reader);
	BINARYIO_API size_t GetReaderLength(void* reader);

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
	BINARYIO_API void ReadBytes(void* reader, char* buffer, size_t length);
	BINARYIO_API void ReadString(void* reader, char* buffer, int bufferSize);

	BINARYIO_API void* CreateBinaryWriter(const char* filePath);
	BINARYIO_API void DestroyBinaryWriter(void* writer);
	BINARYIO_API size_t GetWriterPosition(void* writer);
	BINARYIO_API size_t GetWriterLength(void* writer);

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
	BINARYIO_API void WriteBytes(void* writer, const char* bytes, size_t length);
	BINARYIO_API void WriteString(void* writer, const char* value);

}
