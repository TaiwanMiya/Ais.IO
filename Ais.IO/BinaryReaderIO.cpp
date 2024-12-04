#include "pch.h"
#include "BinaryReaderIO.h"
#include "BinaryIO.h"

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
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_BOOLEAN)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        bool value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned char ReadByte() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_BYTE)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        unsigned char value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    signed char ReadSByte() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_SBYTE)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        signed char value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    short ReadShort() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_SHORT)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        short value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned short ReadUShort() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_USHORT)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        unsigned short value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    int ReadInt() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_INT)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        int value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned int ReadUInt() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_UINT)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        unsigned int value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    long long ReadLong() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_LONG)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        long long value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    unsigned long long ReadULong() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_ULONG)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        unsigned long long value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    float ReadFloat() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_FLOAT)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        float value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    double ReadDouble() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_DOUBLE)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        double value;
        InputStream.read(READ_CAST(&value), sizeof(value));
        return value;
    }

    void ReadBytes(unsigned char* buffer, uint64_t bufferSize) {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_BYTES)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
        uint64_t length;
        InputStream.read(READ_CAST(&length), sizeof(length));
        if (length > bufferSize)
            throw std::runtime_error("Buffer size is too small for the data.");
        InputStream.read(READ_CAST(buffer), length);
    }

    std::string ReadString() {
        BINARYIO_TYPE type = ReadType();
        if (type != BINARYIO_TYPE::TYPE_STRING)
            std::cerr << "Tip: The types are inconsistent, the correct type is " << typeid(type).name() << std::endl;
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

    BINARYIO_TYPE ReadType() {
        unsigned char typeCode;
        InputStream.read(READ_CAST(&typeCode), sizeof(typeCode));
        BINARYIO_TYPE type = static_cast<BINARYIO_TYPE>(typeCode);
        return type;
    }
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

void ReadBytes(void* reader, unsigned char* buffer, uint64_t bufferSize) {
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