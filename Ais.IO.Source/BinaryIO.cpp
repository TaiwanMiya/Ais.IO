#include "pch.h"
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include "BinaryIO.h"

#define BINARYIO_EXPORTS

#ifndef WRITE_CAST 
#define WRITE_CAST reinterpret_cast<const char*>
#endif // !WRITE_CAST

#ifndef READ_CAST
#define READ_CAST reinterpret_cast<char*>
#endif // !READ_CAST

#ifndef STATIC_CAST
#define STATIC_CAST static_cast
#endif // !STATIC_CAST

// BinaryReader Class
class BinaryReader {
public:
    BinaryReader(const std::string& filePath) {
        InputStream.open(filePath, std::ios::binary);
        if (!InputStream.is_open())
            throw std::runtime_error("Unable to open file for reading.");
    }

    ~BinaryReader() {
        if (InputStream.is_open())
            InputStream.close();
    }

    size_t GetPosition() {
        if (!InputStream.is_open()) {
            throw std::runtime_error("Input stream is not open.");
        }
        return STATIC_CAST<size_t>(InputStream.tellg());
    }

    size_t GetLength() {
        if (!InputStream.is_open()) {
            throw std::runtime_error("Input stream is not open.");
        }
        std::streampos currentPos = InputStream.tellg();
        InputStream.seekg(0, std::ios::end);
        size_t length = STATIC_CAST<size_t>(InputStream.tellg());
        InputStream.seekg(currentPos, std::ios::beg);
        return length;
    }

    bool ReadBoolean() {
        bool value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned char ReadByte() {
        unsigned char value;
        InputStream.read(reinterpret_cast<char*>(&value), sizeof(value));
        return value;
    }

    signed char ReadSByte() {
        signed char value;
        InputStream.read(reinterpret_cast<char*>(&value), sizeof(value));
        return value;
    }

    short ReadShort() {
        short value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned short ReadUShort() {
        unsigned short value;
        InputStream.read(reinterpret_cast<char*>(&value), sizeof(value));
        return value;
    }

    int ReadInt() {
        int value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned int ReadUInt() {
        unsigned int value;
        InputStream.read(reinterpret_cast<char*>(&value), sizeof(value));
        return value;
    }

    long long ReadLong() {
        long long value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned long long ReadULong() {
        unsigned long long value;
        InputStream.read(reinterpret_cast<char*>(&value), sizeof(value));
        return value;
    }

    float ReadFloat() {
        float value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    double ReadDouble() {
        double value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    void ReadBytes(char* buffer, size_t length) {
        size_t storedLength;
        InputStream.read(READ_CAST(&storedLength), sizeof(storedLength));
        if (storedLength > length) {
            throw std::runtime_error("Buffer too small to read bytes.");
        }
        InputStream.read(buffer, storedLength);
    }

    std::string ReadString() {
        size_t length;
        InputStream.read(READ_CAST(&length), sizeof(length));

        std::string value(length, '\0');
        InputStream.read(&value[0], length);
        return value;
    }

private:
    std::ifstream InputStream;
};

// BinaryWriter Class
class BinaryWriter {
public:
    BinaryWriter(const std::string& filePath) {
        OutputStream.open(filePath, std::ios::binary);
        if (!OutputStream.is_open())
            throw std::runtime_error("Unable to open file for writing.");
    }

    ~BinaryWriter() {
        if (OutputStream.is_open())
            OutputStream.close();
    }

    size_t GetPosition() {
        if (!OutputStream.is_open())
            throw std::runtime_error("Output stream is not open.");
        return STATIC_CAST<size_t>(OutputStream.tellp());
    }

    size_t GetLength() {
        if (!OutputStream.is_open())
            throw std::runtime_error("Output stream is not open.");
        std::streampos currentPos = OutputStream.tellp();
        OutputStream.seekp(0, std::ios::end);
        size_t length = STATIC_CAST<size_t>(OutputStream.tellp());
        OutputStream.seekp(currentPos, std::ios::beg);
        return length;
    }

    void WriteBoolean(bool value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteByte(unsigned char value) {
        OutputStream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    void WriteSByte(signed char value) {
        OutputStream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    void WriteShort(short value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteUShort(unsigned short value) {
        OutputStream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    void WriteInt(int value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteUInt(unsigned int value) {
        OutputStream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    void WriteLong(long long value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteULong(unsigned long long value) {
        OutputStream.write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    void WriteFloat(float value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteDouble(double value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteBytes(const char* bytes, size_t length) {
        OutputStream.write(WRITE_CAST(&length), sizeof(length));
        OutputStream.write(bytes, length);
    }

    void WriteString(const std::string& value) {
        size_t length = value.length();
        OutputStream.write(WRITE_CAST(&length), sizeof(length));
        OutputStream.write(value.data(), length);
    }

private:
    std::ofstream OutputStream;
};

/* Reader Interface */

void* CreateBinaryReader(const char* filePath) {
    try {
        return new BinaryReader(filePath);
    }
    catch (...) {
        return nullptr;
    }
}

void DestroyBinaryReader(void* reader) {
    delete STATIC_CAST<BinaryReader*>(reader);
}

size_t GetReaderPosition(void* reader) {
    return static_cast<BinaryReader*>(reader)->GetPosition();
}

size_t GetReaderLength(void* reader) {
    return static_cast<BinaryReader*>(reader)->GetLength();
}

bool ReadBoolean(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadBoolean();
}

unsigned char ReadByte(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadByte();
}

signed char ReadSByte(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadSByte();
}

short ReadShort(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadShort();
}

unsigned short ReadUShort(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadUShort();
}

int ReadInt(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadInt();
}

unsigned int ReadUInt(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadUInt();
}

long long ReadLong(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadLong();
}

unsigned long long ReadULong(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadULong();
}

float ReadFloat(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadFloat();
}

double ReadDouble(void* reader) {
    return STATIC_CAST<BinaryReader*>(reader)->ReadDouble();
}

void ReadBytes(void* reader, char* buffer, size_t length) {
    STATIC_CAST<BinaryReader*>(reader)->ReadBytes(buffer, length);
}

void ReadString(void* reader, char* buffer, int bufferSize) {
    std::string result = STATIC_CAST<BinaryReader*>(reader)->ReadString();
    strncpy_s(buffer, bufferSize, result.c_str(), _TRUNCATE);
    buffer[bufferSize - 1] = '\0';
}

/* Writer Interface */

void* CreateBinaryWriter(const char* filePath) {
    try {
        return new BinaryWriter(filePath);
    }
    catch (...) {
        return nullptr;
    }
}

void DestroyBinaryWriter(void* writer) {
    delete STATIC_CAST<BinaryWriter*>(writer);
}

size_t GetWriterPosition(void* writer) {
    return static_cast<BinaryWriter*>(writer)->GetPosition();
}

size_t GetWriterLength(void* writer) {
    return static_cast<BinaryWriter*>(writer)->GetLength();
}

void WriteBoolean(void* writer, bool value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteBoolean(value);
}

void WriteByte(void* writer, unsigned char value) {
    static_cast<BinaryWriter*>(writer)->WriteByte(value);
}

void WriteSByte(void* writer, signed char value) {
    static_cast<BinaryWriter*>(writer)->WriteSByte(value);
}

void WriteShort(void* writer, short value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteShort(value);
}

void WriteUShort(void* writer, unsigned short value) {
    static_cast<BinaryWriter*>(writer)->WriteUShort(value);
}

void WriteInt(void* writer, int value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteInt(value);
}

void WriteUInt(void* writer, unsigned int value) {
    static_cast<BinaryWriter*>(writer)->WriteUInt(value);
}

void WriteLong(void* writer, long long value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteLong(value);
}

void WriteULong(void* writer, unsigned long long value) {
    static_cast<BinaryWriter*>(writer)->WriteULong(value);
}

void WriteFloat(void* writer, float value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteFloat(value);
}

void WriteDouble(void* writer, double value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteDouble(value);
}

void WriteBytes(void* writer, const char* bytes, size_t length) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteBytes(bytes, length);
}

void WriteString(void* writer, const char* value) {
    STATIC_CAST<BinaryWriter*>(writer)->WriteString(std::string(value));
}