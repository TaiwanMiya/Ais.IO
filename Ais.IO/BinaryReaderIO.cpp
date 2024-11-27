#include "pch.h"
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include "BinaryReaderIO.h"

#ifndef READ_CAST
#define READ_CAST reinterpret_cast<char*>
#endif // !READ_CAST

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

    uint64_t GetPosition() {
        if (!InputStream.is_open())
            throw std::runtime_error("Input stream is not open.");
        return static_cast<uint64_t>(InputStream.tellg());
    }

    uint64_t GetLength() {
        if (!InputStream.is_open())
            throw std::runtime_error("Input stream is not open.");
        std::streampos currentPos = InputStream.tellg();
        InputStream.seekg(0, std::ios::end);
        std::streampos endPos = InputStream.tellg();
        InputStream.seekg(currentPos, std::ios::beg);
        return static_cast<uint64_t>(endPos);
    }

    bool ReadBoolean() {
        bool value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned char ReadByte() {
        unsigned char value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    signed char ReadSByte() {
        signed char value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    short ReadShort() {
        short value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned short ReadUShort() {
        unsigned short value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    int ReadInt() {
        int value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned int ReadUInt() {
        unsigned int value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    long long ReadLong() {
        long long value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned long long ReadULong() {
        unsigned long long value;
        InputStream.read(READ_CAST(&value), sizeof(value));
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

    void ReadBytes(char* buffer, uint64_t bufferSize) {
        uint64_t storedLength;
        InputStream.read(READ_CAST(&storedLength), sizeof(storedLength));
        if (storedLength > bufferSize)
            throw std::runtime_error("Buffer size is too small for the data.");
        InputStream.read(buffer, storedLength);
    }

    std::string ReadString() {
        uint64_t length;
        InputStream.read(READ_CAST(&length), sizeof(length));
        if (InputStream.fail())
            throw std::runtime_error("Failed to read string length.");

        std::string value(length, '\0');
        InputStream.read(&value[0], length);
        if (InputStream.fail())
            throw std::runtime_error("Failed to read string content.");
        return value;
    }

private:
    std::ifstream InputStream;
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
    delete static_cast<BinaryReader*>(reader);
}

uint64_t GetReaderPosition(void* reader) {
    return static_cast<BinaryReader*>(reader)->GetPosition();
}

uint64_t GetReaderLength(void* reader) {
    return static_cast<BinaryReader*>(reader)->GetLength();
}

bool ReadBoolean(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadBoolean();
}

unsigned char ReadByte(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadByte();
}

signed char ReadSByte(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadSByte();
}

short ReadShort(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadShort();
}

unsigned short ReadUShort(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadUShort();
}

int ReadInt(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadInt();
}

unsigned int ReadUInt(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadUInt();
}

long long ReadLong(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadLong();
}

unsigned long long ReadULong(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadULong();
}

float ReadFloat(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadFloat();
}

double ReadDouble(void* reader) {
    return static_cast<BinaryReader*>(reader)->ReadDouble();
}

void ReadBytes(void* reader, char* buffer, uint64_t bufferSize) {
    if (!buffer || bufferSize == 0)
        throw std::invalid_argument("Buffer is null or size is zero.");
    static_cast<BinaryReader*>(reader)->ReadBytes(buffer, bufferSize);
}

void ReadString(void* reader, char* buffer, uint64_t bufferSize) {
    if (!buffer || bufferSize == 0)
        throw std::invalid_argument("Buffer is null or size is zero.");
    std::string result = static_cast<BinaryReader*>(reader)->ReadString();
#ifdef _WIN32
    strncpy_s(buffer, bufferSize, result.c_str(), _TRUNCATE);
#else
    strncpy(buffer, result.c_str(), bufferSize - 1);
#endif
    buffer[bufferSize - 1] = '\0';
}