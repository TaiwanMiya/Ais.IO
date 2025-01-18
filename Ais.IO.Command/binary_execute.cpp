#include "binary_execute.h"
#include "output_colors.h"
#include "cryptography_libary.h"

std::string binary_execute::GetTypeName(BINARYIO_TYPE type) {
    switch (type) {
    case BINARYIO_TYPE::TYPE_BOOLEAN:
        return std::string("Boolean");
    case BINARYIO_TYPE::TYPE_BYTE:
        return std::string("Byte");
    case BINARYIO_TYPE::TYPE_SBYTE:
        return std::string("SByte");
    case BINARYIO_TYPE::TYPE_SHORT:
        return std::string("Short");
    case BINARYIO_TYPE::TYPE_USHORT:
        return std::string("UShort");
    case BINARYIO_TYPE::TYPE_INT:
        return std::string("Int");
    case BINARYIO_TYPE::TYPE_UINT:
        return std::string("UInt");
    case BINARYIO_TYPE::TYPE_LONG:
        return std::string("Long");
    case BINARYIO_TYPE::TYPE_ULONG:
        return std::string("ULong");
    case BINARYIO_TYPE::TYPE_FLOAT:
        return std::string("Float");
    case BINARYIO_TYPE::TYPE_DOUBLE:
        return std::string("Double");
    case BINARYIO_TYPE::TYPE_BYTES:
        return std::string("Bytes");
    case BINARYIO_TYPE::TYPE_STRING:
        return std::string("String");
    default:
        return std::string("Null");
    }
}

void binary_execute::ReadToType(void* reader, BINARYIO_TYPE type, uint64_t& count, std::string& message, CRYPT_OPTIONS bytes_option) {
    switch (type) {
    case BINARYIO_TYPE::TYPE_BOOLEAN: {
        bool value = ((ReadBoolean)ReadFunctions.at("-bool"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("Boolean: ") + Ask(value ? "true" : "false") + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_BYTE: {
        unsigned char value = ((ReadByte)ReadFunctions.at("-byte"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("Byte: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_SBYTE: {
        signed char value = ((ReadSByte)ReadFunctions.at("-sbyte"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("SByte: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_SHORT: {
        short value = ((ReadShort)ReadFunctions.at("-short"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("Short: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_USHORT: {
        unsigned short value = ((ReadUShort)ReadFunctions.at("-ushort"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("UShort: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_INT: {
        int value = ((ReadInt)ReadFunctions.at("-int"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("Int: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_UINT: {
        unsigned int value = ((ReadUInt)ReadFunctions.at("-uint"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("UInt: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_LONG: {
        long long value = ((ReadLong)ReadFunctions.at("-long"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("Long: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_ULONG: {
        unsigned long long value = ((ReadULong)ReadFunctions.at("-ulong"))(reader, -1);
        message += Hint(std::to_string(count)) + ". " + Hint("ULong: ") + Ask(std::to_string(value)) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_FLOAT: {
        float value = ((ReadFloat)ReadFunctions.at("-float"))(reader, -1);
        std::ostringstream oss;
        oss.precision(8);
        oss << std::defaultfloat << value;
        message += Hint(std::to_string(count)) + ". " + Hint("Float: ") + Ask(oss.str()) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_DOUBLE: {
        double value = ((ReadDouble)ReadFunctions.at("-double"))(reader, -1);
        std::ostringstream oss;
        oss.precision(16);
        oss << std::defaultfloat << value;
        message += Hint(std::to_string(count)) + ". " + Hint("Double: ") + Ask(oss.str()) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_BYTES: {
        uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
        std::vector<unsigned char> buffer(length);
        std::string result;
        ((ReadBytes)ReadFunctions.at("-bytes"))(reader, buffer.data(), length, -1);
        cryptography_libary::ValueEncode(bytes_option, buffer, result);
        message += Hint(std::to_string(count)) + ". " + Hint("Bytes: ") + Ask(result) + "\n";
        break;
    }
    case BINARYIO_TYPE::TYPE_STRING: {
        uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
        std::vector<char> buffer(length + 1, '\0');
        ((ReadString)ReadFunctions.at("-string"))(reader, buffer.data(), length + 1, -1);
        buffer[length] = '\0';
        message += Hint(std::to_string(count)) + ". " + Hint("String: ") + Ask(buffer.data()) + "\n";
        break;
    }
    }
    count++;
}

void binary_execute::GetIndexes(void* reader) {
    uint64_t count = 0;
    BINARYIO_INDICES* indices = ((GetAllIndices)ReadFunctions.at("-indexes"))(reader, &count);
    if (indices == nullptr) {
        std::cerr << Error("Error: Failed to get indexes from the file.") << std::endl;
        return;
    }

    std::string message = "";
    for (uint64_t i = 0; i < count; ++i)
        message += Hint(std::to_string(i)) + ". " + Ask(GetTypeName(indices[i].TYPE)) + " = " + Hint("Position:") + Ask(std::to_string(indices[i].POSITION)) + ", " + Hint("Length:") + Ask(std::to_string(indices[i].LENGTH)) + "\n";
    free(indices);
    std::cout << message << std::endl;
}

void binary_execute::ExecuteRead(void* reader, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option) {
    uint64_t count = 0;
    std::string message = "";
    for (const auto& cmd : commands) {
        try {
            if (ReadFunctions.find(cmd.type) == ReadFunctions.end()) {
                std::cerr << Warn("Unsupported type: ") << Ask(cmd.type) << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                bool value = ((ReadBoolean)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("Boolean: ") + Ask(value ? "true" : "false") + "\n";
            }
            else if (cmd.type == "-byte") {
                unsigned char value = ((ReadByte)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("Byte: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-sbyte") {
                signed char value = ((ReadSByte)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("SByte: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-short") {
                short value = ((ReadShort)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("Short: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-ushort") {
                unsigned short value = ((ReadUShort)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("UShort: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-int") {
                int value = ((ReadInt)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("Int: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-uint") {
                unsigned int value = ((ReadUInt)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("UInt: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-long") {
                long long value = ((ReadLong)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("Long: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-ulong") {
                unsigned long long value = ((ReadULong)ReadFunctions.at(cmd.type))(reader, -1);
                message += Hint(std::to_string(count)) + ". " + Hint("ULong: ") + Ask(std::to_string(value)) + "\n";
            }
            else if (cmd.type == "-float") {
                float value = ((ReadFloat)ReadFunctions.at(cmd.type))(reader, -1);
                std::ostringstream oss;
                oss.precision(8);
                oss << std::defaultfloat << value;
                message += Hint(std::to_string(count)) + ". " + Hint("Float: ") + Ask(oss.str()) + "\n";
            }
            else if (cmd.type == "-double") {
                double value = ((ReadDouble)ReadFunctions.at(cmd.type))(reader, -1);
                std::ostringstream oss;
                oss.precision(16);
                oss << std::defaultfloat << value;
                message += Hint(std::to_string(count)) + ". " + Hint("Double: ") + Ask(oss.str()) + "\n";
            }
            else if (cmd.type == "-bytes") {
                uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
                std::vector<unsigned char> buffer(length);
                std::string result;
                ((ReadBytes)ReadFunctions.at(cmd.type))(reader, buffer.data(), length, -1);
                cryptography_libary::ValueEncode(bytes_option, buffer, result);
                message += Hint(std::to_string(count)) + ". " + Hint("Bytes: ") + Ask(result) + "\n";
            }
            else if (cmd.type == "-string") {
                uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
                std::vector<char> buffer(length + 1, '\0');
                ((ReadString)ReadFunctions.at(cmd.type))(reader, buffer.data(), length + 1, -1);
                buffer[length] = '\0';
                message += Hint(std::to_string(count)) + ". " + Hint("String: ") + Ask(buffer.data()) + "\n";
            }
            count++;
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
    std::cout << message << std::endl;
}

void binary_execute::ExecuteWrite(void* writer, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option) {
    for (const auto& cmd : commands) {
        try {
            if (WriteFunctions.find(cmd.type) == WriteFunctions.end()) {
                std::cerr << Warn("Unsupported type: ") << Ask(cmd.type) << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                ((WriteBoolean)WriteFunctions.at(cmd.type))(writer, cmd.value == "true");
            }
            else if (cmd.type == "-byte") {
                ((WriteByte)WriteFunctions.at(cmd.type))(writer, static_cast<unsigned char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-sbyte") {
                ((WriteSByte)WriteFunctions.at(cmd.type))(writer, static_cast<signed char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-short") {
                ((WriteShort)WriteFunctions.at(cmd.type))(writer, static_cast<short>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-ushort") {
                ((WriteUShort)WriteFunctions.at(cmd.type))(writer, static_cast<unsigned short>(std::stoul(cmd.value)));
            }
            else if (cmd.type == "-int") {
                ((WriteInt)WriteFunctions.at(cmd.type))(writer, std::stoi(cmd.value));
            }
            else if (cmd.type == "-uint") {
                ((WriteUInt)WriteFunctions.at(cmd.type))(writer, std::stoul(cmd.value));
            }
            else if (cmd.type == "-long") {
                ((WriteLong)WriteFunctions.at(cmd.type))(writer, std::stoll(cmd.value));
            }
            else if (cmd.type == "-ulong") {
                ((WriteULong)WriteFunctions.at(cmd.type))(writer, std::stoull(cmd.value));
            }
            else if (cmd.type == "-float") {
                ((WriteFloat)WriteFunctions.at(cmd.type))(writer, std::stof(cmd.value));
            }
            else if (cmd.type == "-double") {
                ((WriteDouble)WriteFunctions.at(cmd.type))(writer, std::stod(cmd.value));
            }
            else if (cmd.type == "-string") {
                ((WriteString)WriteFunctions.at(cmd.type))(writer, cmd.value.c_str());
            }
            else if (cmd.type == "-bytes") {
                std::vector<unsigned char> result;
                cryptography_libary::ValueDecode(bytes_option, cmd.value, result);
                ((WriteBytes)WriteFunctions.at(cmd.type))(writer, result.data(), result.size());
            }
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
}

void binary_execute::ExecuteAppend(void* appender, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option) {
    for (const auto& cmd : commands) {
        try {
            if (AppendFunctions.find(cmd.type) == AppendFunctions.end()) {
                std::cerr << Warn("Unsupported type: ") << Ask(cmd.type) << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                ((AppendBoolean)AppendFunctions.at(cmd.type))(appender, cmd.value == "true");
            }
            else if (cmd.type == "-byte") {
                ((AppendByte)AppendFunctions.at(cmd.type))(appender, static_cast<unsigned char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-sbyte") {
                ((AppendSByte)AppendFunctions.at(cmd.type))(appender, static_cast<signed char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-short") {
                ((AppendShort)AppendFunctions.at(cmd.type))(appender, static_cast<short>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-ushort") {
                ((AppendUShort)AppendFunctions.at(cmd.type))(appender, static_cast<unsigned short>(std::stoul(cmd.value)));
            }
            else if (cmd.type == "-int") {
                ((AppendInt)AppendFunctions.at(cmd.type))(appender, std::stoi(cmd.value));
            }
            else if (cmd.type == "-uint") {
                ((AppendUInt)AppendFunctions.at(cmd.type))(appender, std::stoul(cmd.value));
            }
            else if (cmd.type == "-long") {
                ((AppendLong)AppendFunctions.at(cmd.type))(appender, std::stoll(cmd.value));
            }
            else if (cmd.type == "-ulong") {
                ((AppendULong)AppendFunctions.at(cmd.type))(appender, std::stoull(cmd.value));
            }
            else if (cmd.type == "-float") {
                ((AppendFloat)AppendFunctions.at(cmd.type))(appender, std::stof(cmd.value));
            }
            else if (cmd.type == "-double") {
                ((AppendDouble)AppendFunctions.at(cmd.type))(appender, std::stod(cmd.value));
            }
            else if (cmd.type == "-string") {
                ((AppendString)AppendFunctions.at(cmd.type))(appender, cmd.value.c_str());
            }
            else if (cmd.type == "-bytes") {
                std::vector<unsigned char> result;
                cryptography_libary::ValueDecode(bytes_option, cmd.value, result);
                ((AppendBytes)AppendFunctions.at(cmd.type))(appender, result.data(), result.size());
            }
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
}

void binary_execute::ExecuteInsert(void* inserter, const std::vector<Command>& commands, CRYPT_OPTIONS bytes_option) {
    for (const auto& cmd : commands) {
        try {
            if (InsertFunctions.find(cmd.type) == InsertFunctions.end()) {
                std::cerr << Warn("Unsupported type: ") << Ask(cmd.type) << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                ((InsertBoolean)InsertFunctions.at(cmd.type))(inserter, cmd.value == "true", cmd.position);
            }
            else if (cmd.type == "-byte") {
                ((InsertByte)InsertFunctions.at(cmd.type))(inserter, static_cast<unsigned char>(std::stoi(cmd.value)), cmd.position);
            }
            else if (cmd.type == "-sbyte") {
                ((InsertSByte)InsertFunctions.at(cmd.type))(inserter, static_cast<signed char>(std::stoi(cmd.value)), cmd.position);
            }
            else if (cmd.type == "-short") {
                ((InsertShort)InsertFunctions.at(cmd.type))(inserter, static_cast<short>(std::stoi(cmd.value)), cmd.position);
            }
            else if (cmd.type == "-ushort") {
                ((InsertUShort)InsertFunctions.at(cmd.type))(inserter, static_cast<unsigned short>(std::stoul(cmd.value)), cmd.position);
            }
            else if (cmd.type == "-int") {
                ((InsertInt)InsertFunctions.at(cmd.type))(inserter, std::stoi(cmd.value), cmd.position);
            }
            else if (cmd.type == "-uint") {
                ((InsertUInt)InsertFunctions.at(cmd.type))(inserter, std::stoul(cmd.value), cmd.position);
            }
            else if (cmd.type == "-long") {
                ((InsertLong)InsertFunctions.at(cmd.type))(inserter, std::stoll(cmd.value), cmd.position);
            }
            else if (cmd.type == "-ulong") {
                ((InsertULong)InsertFunctions.at(cmd.type))(inserter, std::stoull(cmd.value), cmd.position);
            }
            else if (cmd.type == "-float") {
                ((InsertFloat)InsertFunctions.at(cmd.type))(inserter, std::stof(cmd.value), cmd.position);
            }
            else if (cmd.type == "-double") {
                ((InsertDouble)InsertFunctions.at(cmd.type))(inserter, std::stod(cmd.value), cmd.position);
            }
            else if (cmd.type == "-string") {
                ((InsertString)InsertFunctions.at(cmd.type))(inserter, cmd.value.c_str(), cmd.position);
            }
            else if (cmd.type == "-bytes") {
                std::vector<unsigned char> result;
                cryptography_libary::ValueDecode(bytes_option, cmd.value, result);
                ((InsertBytes)InsertFunctions.at(cmd.type))(inserter, result.data(), result.size(), cmd.position);
            }
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
}

void binary_execute::ExecuteRemove(void* remover, const std::string filePath, const std::vector<Command>& commands) {
    for (const auto& cmd : commands) {
        try {
            BINARYIO_INDICES* index = new BINARYIO_INDICES;
            if (cmd.type == "-bool")
                index->TYPE = BINARYIO_TYPE::TYPE_BOOLEAN;
            else if (cmd.type == "-byte")
                index->TYPE = BINARYIO_TYPE::TYPE_BYTE;
            else if (cmd.type == "-sbyte")
                index->TYPE = BINARYIO_TYPE::TYPE_SBYTE;
            else if (cmd.type == "-short")
                index->TYPE = BINARYIO_TYPE::TYPE_SHORT;
            else if (cmd.type == "-ushort")
                index->TYPE = BINARYIO_TYPE::TYPE_USHORT;
            else if (cmd.type == "-int")
                index->TYPE = BINARYIO_TYPE::TYPE_INT;
            else if (cmd.type == "-uint")
                index->TYPE = BINARYIO_TYPE::TYPE_UINT;
            else if (cmd.type == "-long")
                index->TYPE = BINARYIO_TYPE::TYPE_LONG;
            else if (cmd.type == "-ulong")
                index->TYPE = BINARYIO_TYPE::TYPE_ULONG;
            else if (cmd.type == "-float")
                index->TYPE = BINARYIO_TYPE::TYPE_FLOAT;
            else if (cmd.type == "-double")
                index->TYPE = BINARYIO_TYPE::TYPE_DOUBLE;
            else if (cmd.type == "-bytes")
                index->TYPE = BINARYIO_TYPE::TYPE_BYTES;
            else if (cmd.type == "-string")
                index->TYPE = BINARYIO_TYPE::TYPE_STRING;
            else
                continue;
            index->POSITION = cmd.position;
            index->LENGTH = cmd.length;
            ((RemoveIndex)ReadFunctions.at("-remove"))(remover, filePath.c_str(), index);
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
}

void binary_execute::ExecuteRemoveIndex(void* reader, void* remover, const std::string filePath, const std::vector<Command>& commands) {
    uint64_t count = 0;
    BINARYIO_INDICES* indices = ((GetAllIndices)ReadFunctions.at("-indexes"))(reader, &count);
    for (const auto& cmd : commands) {
        try {
            uint64_t indexCount = std::stoull(cmd.value);
            if (indexCount >= count)
                continue;
            BINARYIO_INDICES* index = &indices[indexCount];
            ((RemoveIndex)ReadFunctions.at("-remove"))(remover, filePath.c_str(), index);
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
    free(indices);
}

void binary_execute::ExecuteReadIndex(void* reader, void* index_reader, const std::string filePath, const std::vector<Command>& commands, std::string& message, CRYPT_OPTIONS bytes_option) {
    uint64_t count = 0;
    uint64_t index_count = 0;
    BINARYIO_INDICES* indices = ((GetAllIndices)ReadFunctions.at("-indexes"))(index_reader, &index_count);
    for (const auto& cmd : commands) {
        try {
            uint64_t indexCount = std::stoull(cmd.value);
            if (indexCount >= index_count)
                continue;
            BINARYIO_INDICES* index = &indices[indexCount];
            int64_t position = index->POSITION;
            uint64_t length = index->LENGTH;

            switch (index->TYPE)
            {
            case BINARYIO_TYPE::TYPE_BOOLEAN: {
                bool value = ((ReadBoolean)ReadFunctions.at("-bool"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Boolean: ") + Ask(value ? "true" : "false") + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_BYTE: {
                unsigned char value = ((ReadByte)ReadFunctions.at("-byte"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Byte: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_SBYTE: {
                signed char value = ((ReadSByte)ReadFunctions.at("-sbyte"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("SByte: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_SHORT: {
                short value = ((ReadShort)ReadFunctions.at("-short"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Short: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_USHORT: {
                unsigned short value = ((ReadUShort)ReadFunctions.at("-ushort"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("UShort: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_INT: {
                int value = ((ReadInt)ReadFunctions.at("-int"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Int: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_UINT: {
                unsigned int value = ((ReadUInt)ReadFunctions.at("-uint"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("UInt: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_LONG: {
                long long value = ((ReadLong)ReadFunctions.at("-long"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Long: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_ULONG: {
                unsigned long long value = ((ReadULong)ReadFunctions.at("-ulong"))(reader, position);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("ULong: ") + Ask(std::to_string(value)) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_FLOAT: {
                float value = ((ReadFloat)ReadFunctions.at("-float"))(reader, position);
                std::ostringstream oss{};
                oss.precision(8);
                oss << std::defaultfloat << value;
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Float: ") + Ask(oss.str()) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_DOUBLE: {
                double value = ((ReadDouble)ReadFunctions.at("-double"))(reader, position);
                std::ostringstream oss{};
                oss.precision(16);
                oss << std::defaultfloat << value;
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Double: ") + Ask(oss.str()) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_BYTES: {
                std::vector<unsigned char> bytes_buffer(length);
                std::string result;
                ((ReadBytes)ReadFunctions.at("-bytes"))(reader, bytes_buffer.data(), length, position);
                cryptography_libary::ValueEncode(bytes_option, bytes_buffer, result);
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("Bytes: ") + Ask(result) + "\n";
                break;
            }
            case BINARYIO_TYPE::TYPE_STRING: {
                std::vector<char> string_buffer(length + 1, '\0');
                ((ReadString)ReadFunctions.at("-string"))(reader, string_buffer.data(), length + 1, position);
                string_buffer[length] = '\0';
                message += Hint(std::to_string(count)) + ". " + Info("[" + std::to_string(indexCount) + "] ") + Hint("String: ") + Ask(string_buffer.data()) + "\n";
                break;
            }
            default:
                break;
            }
            count++;
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << Error("Runtime error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << Error("Out of range error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << Error("Memory allocation error while reading type ") << Ask(cmd.type)
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << Error("Unknown error occurred while reading type ") << Ask(cmd.type) << std::endl;
        }
    }
}