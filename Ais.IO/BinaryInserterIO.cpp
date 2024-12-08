#include "pch.h"
#include "BinaryInserterIO.h"
#include "BinaryIO.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#ifndef INSERT_CAST 
#define INSERT_CAST reinterpret_cast<const char*>
#endif // !INSERT_CAST

class BinaryInserter {
public:
    BinaryInserter(const std::string& filePath) {
        Stream.open(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!Stream.is_open()) {
            Stream.open(filePath, std::ios::out | std::ios::binary);
            Stream.close();
            Stream.open(filePath, std::ios::in | std::ios::out | std::ios::binary);
        }
    }

    ~BinaryInserter() {
        if (Stream.is_open())
            Stream.close();
    }

    uint64_t GetPosition() {
        if (!Stream.is_open())
            throw std::runtime_error("Stream is not open.");
        return static_cast<uint64_t>(Stream.tellp());
    }

    uint64_t GetLength() {
        if (!Stream.is_open())
            throw std::runtime_error("Stream is not open.");
        std::streampos currentPos = Stream.tellp();
        Stream.seekp(0, std::ios::end);
        std::streampos endPos = Stream.tellp();
        Stream.seekp(currentPos, std::ios::beg);
        return static_cast<uint64_t>(endPos);
    }

    void InsertBoolean(bool value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_BOOLEAN);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }

    void InsertByte(unsigned char value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_BYTE);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }

    void InsertSByte(signed char value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_SBYTE);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }

    void InsertShort(short value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_SHORT);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }

    void InsertUShort(unsigned short value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_USHORT);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertInt(int value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_INT);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertUInt(unsigned int value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_UINT);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertLong(long long value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_LONG);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertULong(unsigned long long value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_ULONG);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertFloat(float value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_FLOAT);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertDouble(double value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_DOUBLE);
        Stream.write(INSERT_CAST(&value), sizeof(value));
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertBytes(const unsigned char* bytes, uint64_t length, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_BYTES);
        Stream.write(INSERT_CAST(&length), sizeof(length));
        Stream.write(INSERT_CAST(bytes), length);
        Stream.write(buffer.data(), buffer.size());
    }
    
    void InsertString(const std::string& value, uint64_t position) {
        std::vector<char> buffer = StartInsert(position);
        InsertType(BINARYIO_TYPE::TYPE_STRING);
        uint64_t length = value.length() + 1;
        Stream.write(INSERT_CAST(&length), sizeof(length));
        Stream.write(value.data(), length);
        Stream.write(buffer.data(), buffer.size());
    }

private:
    std::fstream Stream;

    void InsertType(BINARYIO_TYPE type) {
        Stream.write(INSERT_CAST(&type), sizeof(type));
    }

    std::vector<char> StartInsert(uint64_t position, size_t chunkSize = 1024) {
        Stream.seekg(position, std::ios::beg);

        std::vector<char> buffer;
        std::vector<char> temp(chunkSize);

        while (Stream.read(temp.data(), temp.size())) {
            buffer.insert(buffer.end(), temp.begin(), temp.begin() + Stream.gcount());
        }

        if (Stream.gcount() > 0) {
            buffer.insert(buffer.end(), temp.begin(), temp.begin() + Stream.gcount());
        }

        Stream.clear();
        Stream.seekp(position, std::ios::beg);

        return buffer;
    }
};

void* CreateBinaryInserter(const char* filePath) {
    try {
        return new BinaryInserter(filePath);
    }
    catch (...) {
        return nullptr;
    }
}

void DestroyBinaryInserter(void* inserter) {
    delete static_cast<BinaryInserter*>(inserter);
}

uint64_t GetInserterPosition(void* inserter) {
    return static_cast<BinaryInserter*>(inserter)->GetPosition();
}

uint64_t GetInserterLength(void* inserter) {
    return static_cast<BinaryInserter*>(inserter)->GetLength();
}

void InsertBoolean(void* inserter, bool value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertBoolean(value, position);
}

void InsertByte(void* inserter, unsigned char value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertByte(value, position);
}

void InsertSByte(void* inserter, signed char value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertSByte(value, position);
}

void InsertShort(void* inserter, short value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertShort(value, position);
}

void InsertUShort(void* inserter, unsigned short value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertUShort(value, position);
}

void InsertInt(void* inserter, int value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertInt(value, position);
}

void InsertUInt(void* inserter, unsigned int value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertUInt(value, position);
}

void InsertLong(void* inserter, long long value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertLong(value, position);
}

void InsertULong(void* inserter, unsigned long long value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertULong(value, position);
}

void InsertFloat(void* inserter, float value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertFloat(value, position);
}

void InsertDouble(void* inserter, double value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertDouble(value, position);
}

void InsertBytes(void* inserter, const unsigned char* bytes, uint64_t length, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertBytes(bytes, length, position);
}

void InsertString(void* inserter, const char* value, uint64_t position) {
    static_cast<BinaryInserter*>(inserter)->InsertString(value, position);
}
