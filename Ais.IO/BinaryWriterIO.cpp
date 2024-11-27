#include "pch.h"
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include "BinaryWriterIO.h"

#ifndef WRITE_CAST 
#define WRITE_CAST reinterpret_cast<const char*>
#endif // !WRITE_CAST

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

    uint64_t GetPosition() {
        if (!OutputStream.is_open())
            throw std::runtime_error("Output stream is not open.");
        return static_cast<uint64_t>(OutputStream.tellp());
    }

    uint64_t GetLength() {
        if (!OutputStream.is_open())
            throw std::runtime_error("Output stream is not open.");
        std::streampos currentPos = OutputStream.tellp();
        OutputStream.seekp(0, std::ios::end);
        std::streampos endPos = OutputStream.tellp();
        OutputStream.seekp(currentPos, std::ios::beg);
        return static_cast<uint64_t>(endPos);
    }

    void WriteBoolean(bool value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteByte(unsigned char value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteSByte(signed char value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteShort(short value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteUShort(unsigned short value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteInt(int value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteUInt(unsigned int value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteLong(long long value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteULong(unsigned long long value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteFloat(float value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteDouble(double value) {
        OutputStream.write(WRITE_CAST(&value), sizeof(value));
    }

    void WriteBytes(const char* bytes) {
        uint64_t length = strlen(bytes);
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
    delete static_cast<BinaryWriter*>(writer);
}

uint64_t GetWriterPosition(void* writer) {
    return static_cast<BinaryWriter*>(writer)->GetPosition();
}

uint64_t GetWriterLength(void* writer) {
    return static_cast<BinaryWriter*>(writer)->GetLength();
}

void WriteBoolean(void* writer, bool value) {
    static_cast<BinaryWriter*>(writer)->WriteBoolean(value);
}

void WriteByte(void* writer, unsigned char value) {
    static_cast<BinaryWriter*>(writer)->WriteByte(value);
}

void WriteSByte(void* writer, signed char value) {
    static_cast<BinaryWriter*>(writer)->WriteSByte(value);
}

void WriteShort(void* writer, short value) {
    static_cast<BinaryWriter*>(writer)->WriteShort(value);
}

void WriteUShort(void* writer, unsigned short value) {
    static_cast<BinaryWriter*>(writer)->WriteUShort(value);
}

void WriteInt(void* writer, int value) {
    static_cast<BinaryWriter*>(writer)->WriteInt(value);
}

void WriteUInt(void* writer, unsigned int value) {
    static_cast<BinaryWriter*>(writer)->WriteUInt(value);
}

void WriteLong(void* writer, long long value) {
    static_cast<BinaryWriter*>(writer)->WriteLong(value);
}

void WriteULong(void* writer, unsigned long long value) {
    static_cast<BinaryWriter*>(writer)->WriteULong(value);
}

void WriteFloat(void* writer, float value) {
    static_cast<BinaryWriter*>(writer)->WriteFloat(value);
}

void WriteDouble(void* writer, double value) {
    static_cast<BinaryWriter*>(writer)->WriteDouble(value);
}

void WriteBytes(void* writer, const char* bytes) {
    static_cast<BinaryWriter*>(writer)->WriteBytes(bytes);
}

void WriteString(void* writer, const char* value) {
    static_cast<BinaryWriter*>(writer)->WriteString(std::string(value));
}