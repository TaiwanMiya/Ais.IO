#include "pch.h"
#include <fstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <iostream>
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

private:
    std::ifstream InputStream;
};

/* Get Next Length */

uint64_t NextLength(void* reader) {
    return static_cast<BinaryIO*>(reader)->NextLength();
}