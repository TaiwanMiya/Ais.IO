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

// BinaryIO Class
class BinaryIO {
public:
    size_t NextLength() {
        if (!InputStream.is_open()) {
            throw std::runtime_error("Input stream is not open.");
        }
        std::streampos currentPos = InputStream.tellg();
        size_t length;
        InputStream.read(READ_CAST(&length), sizeof(length));
        InputStream.seekg(currentPos, std::ios::beg);
        if (InputStream.fail()) {
            throw std::runtime_error("Failed to read length.");
        }
        return length;
    }

private:
    std::ifstream InputStream;
};

/* Get Next Length */

size_t NextLength(void* reader) {
    return static_cast<BinaryIO*>(reader)->NextLength();
}