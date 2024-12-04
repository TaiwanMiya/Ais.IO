#include "pch.h"
#include "BinaryIO.h"

#ifndef WRITE_CAST 
#define WRITE_CAST reinterpret_cast<const char*>
#endif // !WRITE_CAST

#ifndef READ_CAST
#define READ_CAST reinterpret_cast<char*>
#endif // !READ_CAST

// BinaryIO Class
class BinaryIO {
public:
    BinaryIO (const std::string& filePath) {
        InputStream.open(filePath, std::ios::binary);
        if (!InputStream.is_open())
            throw std::runtime_error("Unable to open file for reading.");
    }

    uint64_t NextLength() {
        if (!InputStream.is_open())
            throw std::runtime_error("Input stream is not open.");
        std::streampos currentPos = InputStream.tellg();

        BINARYIO_TYPE type = this->ReadType(true);
        if (type != BINARYIO_TYPE::TYPE_BYTES && type != BINARYIO_TYPE::TYPE_STRING)
            return 0;

        if (currentPos == std::streampos(-1))
            throw std::runtime_error("Failed to get current position.");
        uint64_t length;
        InputStream.read(READ_CAST(&length), sizeof(length));
        if (InputStream.fail())
            throw std::runtime_error("Failed to read length.");
        InputStream.seekg(currentPos, std::ios::beg);
        if (InputStream.fail())
            throw std::runtime_error("Failed to restore position.");
        return length;
    }

    BINARYIO_TYPE ReadType(bool unchangePosition) {
        if (!InputStream.is_open())
            throw std::runtime_error("Input stream is not open.");

        std::streampos currentPos = unchangePosition
            ? std::streampos(-1)
            : InputStream.tellg();
        unsigned char typeCode;
        InputStream.read(READ_CAST(&typeCode), sizeof(typeCode));
        if (currentPos != std::streampos(-1))
            InputStream.seekg(currentPos, std::ios::beg);
        return static_cast<BINARYIO_TYPE>(typeCode);
    }

private:
    std::ifstream InputStream;
};

/* Get Next Length */

uint64_t NextLength(void* reader) {
    return static_cast<BinaryIO*>(reader)->NextLength();
}

BINARYIO_TYPE ReadType(void* reader) {
    return static_cast<BinaryIO*>(reader)->ReadType(false);
}