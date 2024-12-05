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
        InputStream.open(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!InputStream.is_open())
            throw std::runtime_error("Unable to open file for reading & writing.");
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

    BINARYIO_INDICES* GetAllIndices(uint64_t* count) {
        *count = 0;
        InputStream.seekg(std::streampos(0), std::ios::beg);

        std::vector<BINARYIO_INDICES> indices;
        uint64_t position = 0;

        while (true) {
            BINARYIO_INDICES index;
            InputStream.read(reinterpret_cast<char*>(&index.TYPE), sizeof(index.TYPE));
            if (InputStream.eof() || InputStream.fail())
                break;

            switch (index.TYPE) {
                case BINARYIO_TYPE::TYPE_BOOLEAN:
                case BINARYIO_TYPE::TYPE_BYTE:
                case BINARYIO_TYPE::TYPE_SBYTE: {
                    index.POSITION = position;
                    index.LENGTH = 1;
                    position += sizeof(index.TYPE) + index.LENGTH;
                    InputStream.seekg(index.LENGTH, std::ios::cur);
                    break;
                }
                case BINARYIO_TYPE::TYPE_SHORT:
                case BINARYIO_TYPE::TYPE_USHORT: {
                    index.POSITION = position;
                    index.LENGTH = 2;
                    position += sizeof(index.TYPE) + index.LENGTH;
                    InputStream.seekg(index.LENGTH, std::ios::cur);
                    break;
                }
                case BINARYIO_TYPE::TYPE_INT:
                case BINARYIO_TYPE::TYPE_UINT:
                case BINARYIO_TYPE::TYPE_FLOAT: {
                    index.POSITION = position;
                    index.LENGTH = 4;
                    position += sizeof(index.TYPE) + index.LENGTH;
                    InputStream.seekg(index.LENGTH, std::ios::cur);
                    break;
                }
                case BINARYIO_TYPE::TYPE_LONG:
                case BINARYIO_TYPE::TYPE_ULONG:
                case BINARYIO_TYPE::TYPE_DOUBLE: {
                    index.POSITION = position;
                    index.LENGTH = 8;
                    position += sizeof(index.TYPE) + index.LENGTH;
                    InputStream.seekg(index.LENGTH, std::ios::cur);
                    break;
                }
                case BINARYIO_TYPE::TYPE_BYTES:
                case BINARYIO_TYPE::TYPE_STRING: {
                    index.POSITION = position;
                    InputStream.read(READ_CAST(&index.LENGTH), sizeof(index.LENGTH));
                    if (InputStream.fail()) {
                        std::cerr << "Error: Failed to read length for type " << static_cast<int>(index.TYPE) << std::endl;
                        return nullptr;
                    }
                    position += sizeof(index.TYPE) + sizeof(index.LENGTH) + index.LENGTH;
                    InputStream.seekg(index.LENGTH, std::ios::cur);
                    break;
                }
            }
            indices.push_back(index);
        }

        InputStream.close();

        *count = indices.size();
        BINARYIO_INDICES* result = static_cast<BINARYIO_INDICES*>(malloc(indices.size() * sizeof(BINARYIO_INDICES)));
        std::memcpy(result, indices.data(), indices.size() * sizeof(BINARYIO_INDICES));
        return result;
    }

    void RemoveIndex(const std::string& filePath, BINARYIO_INDICES* index) {
        std::fstream file(filePath, std::ios::in | std::ios::out | std::ios::binary);
        if (!file.is_open())
            throw std::runtime_error("Unable to open file for remove operation.");

        if (index->TYPE == BINARYIO_TYPE::TYPE_BYTES || index->TYPE == BINARYIO_TYPE::TYPE_STRING)
            file.seekg(index->POSITION + index->LENGTH + sizeof(index->TYPE) + sizeof(index->LENGTH), std::ios::beg);
        else
            file.seekg(index->POSITION + index->LENGTH + sizeof(index->TYPE), std::ios::beg);
        std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        file.seekp(index->POSITION, std::ios::beg);

        file.write(buffer.data(), buffer.size());

        file.close();
        std::filesystem::resize_file(filePath, index->POSITION + buffer.size());
    }

    BINARYIO_TYPE ReadType(bool unchangePosition) {
        if (!InputStream.is_open()) {
            std::cerr << "Input stream is not open." << std::endl;
            return BINARYIO_TYPE::TYPE_NULL;
        }

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
    std::ofstream OutputStream;
};

/* Get Next Length */

uint64_t NextLength(void* reader) {
    return static_cast<BinaryIO*>(reader)->NextLength();
}

BINARYIO_TYPE ReadType(void* reader) {
    return static_cast<BinaryIO*>(reader)->ReadType(false);
}

BINARYIO_INDICES* GetAllIndices(void* reader, uint64_t* count) {
    return static_cast<BinaryIO*>(reader)->GetAllIndices(count);
}

void RemoveIndex(void* reader, const char* filePath, BINARYIO_INDICES* index) {
    static_cast<BinaryIO*>(reader)->RemoveIndex(filePath, index);
}

void FreeIndexArray(BINARYIO_INDICES* indices) {
    free(indices);
}