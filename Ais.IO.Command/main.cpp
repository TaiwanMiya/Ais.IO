#include "main.h"
#include "StringCase.h"
#include <locale.h>

#ifdef _WIN32
#define LOAD_LIBRARY(lib) LoadLibraryA(lib)
#define GET_PROC_ADDRESS(lib, name) GetProcAddress(lib, name)
#define UNLOAD_LIBRARY(lib) FreeLibrary(lib)
#else
#define LOAD_LIBRARY(lib) dlopen(lib, RTLD_LAZY)
#define GET_PROC_ADDRESS(lib, name) dlsym(lib, name)
#define UNLOAD_LIBRARY(lib) dlclose(lib)
#endif

struct Command {
    std::string type;
    std::string value;
};

void ShowUsage() {
    std::cout << "Usage:\n";
    std::cout << "  --write <path> [--type] <value> ...\n";
    std::cout << "  --read <path> [--type] ...\n";
    std::cout << "  --base16 [-encode | -decode] <value>\n";
    std::cout << "  --base32 [-encode | -decode] <value>\n";
    std::cout << "  --base64 [-encode | -decode] <value>\n";
    std::cout << "  --base85 [-encode | -decode] <value>\n";
    std::cout << "Supported types:\n";
    std::cout << "  -bool, -byte, -sbyte, -short, -ushort, -int, -uint, -long, -ulong, -float, -double, -bytes, -string\n";
}

bool ParseArguments(int argc, char* argv[], std::string& mode, std::string& filePath, std::vector<Command>& commands) {
    if (argc < 3) {
        return false;
    }

    std::unordered_set<std::string> validMode = {
        "--write", "--read", "--read-all", "--base16", "--base32", "--base64", "--base85"
    };

    std::unordered_set<std::string> validOptions = {
        "-bool", "-byte", "-sbyte", "-short", "-ushort", "-int", "-uint",
        "-long", "-ulong", "-float", "-double", "-bytes", "-string"
    };

    std::unordered_set<std::string> encodeDecodeOptions = {
        "-encode", "-decode"
    };

    mode = argv[1];
    if (!validMode.count(mode))
        return false;

    if (mode == "--write" || mode == "--read") {
        if (argc < 4)
            return false;
        filePath = argv[2];

        Command cmd;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (validOptions.count(arg)) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = arg;
            }
            else {
                if (cmd.type.empty()) {
                    std::cerr << "Value without type: " << arg << "\n";
                    return false;
                }
                cmd.value = arg;
            }
        }

        if (!cmd.type.empty())
            commands.push_back(cmd);
    }
    else if (mode == "--read-all") {
        if (argc < 3)
            return false;
        filePath = argv[2];
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        if (argc != 4)
            return false;
        std::string operation = argv[2];
        if (!encodeDecodeOptions.count(operation)) {
            std::cerr << "Invalid operation: " << operation << "\n";
            return false;
        }
        Command cmd;
        cmd.type = operation;
        cmd.value = argv[3];
        commands.push_back(cmd);
    }
    return true;
}

void ExecuteWrite(void* writer, const std::vector<Command>& commands,
    const std::unordered_map<std::string, void*>& writeFunctions) {
    for (const auto& cmd : commands) {
        try {
            if (writeFunctions.find(cmd.type) == writeFunctions.end()) {
                std::cerr << "Unsupported type: " << cmd.type << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                ((WriteBoolean)writeFunctions.at(cmd.type))(writer, cmd.value == "true");
            }
            else if (cmd.type == "-byte") {
                ((WriteByte)writeFunctions.at(cmd.type))(writer, static_cast<unsigned char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-sbyte") {
                ((WriteSByte)writeFunctions.at(cmd.type))(writer, static_cast<signed char>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-short") {
                ((WriteShort)writeFunctions.at(cmd.type))(writer, static_cast<short>(std::stoi(cmd.value)));
            }
            else if (cmd.type == "-ushort") {
                ((WriteUShort)writeFunctions.at(cmd.type))(writer, static_cast<unsigned short>(std::stoul(cmd.value)));
            }
            else if (cmd.type == "-int") {
                ((WriteInt)writeFunctions.at(cmd.type))(writer, std::stoi(cmd.value));
            }
            else if (cmd.type == "-uint") {
                ((WriteUInt)writeFunctions.at(cmd.type))(writer, std::stoul(cmd.value));
            }
            else if (cmd.type == "-long") {
                ((WriteLong)writeFunctions.at(cmd.type))(writer, std::stoll(cmd.value));
            }
            else if (cmd.type == "-ulong") {
                ((WriteULong)writeFunctions.at(cmd.type))(writer, std::stoull(cmd.value));
            }
            else if (cmd.type == "-float") {
                ((WriteFloat)writeFunctions.at(cmd.type))(writer, std::stof(cmd.value));
            }
            else if (cmd.type == "-double") {
                ((WriteDouble)writeFunctions.at(cmd.type))(writer, std::stod(cmd.value));
            }
            else if (cmd.type == "-string") {
                ((WriteString)writeFunctions.at(cmd.type))(writer, cmd.value.c_str());
            }
            else if (cmd.type == "-bytes") {
                const unsigned char* data = reinterpret_cast<const unsigned char*>(cmd.value.data());
                uint64_t length = static_cast<uint64_t>(cmd.value.size());
                ((WriteBytes)writeFunctions.at(cmd.type))(writer, data, length);
            }
        }
        catch (const std::invalid_argument& e) {
            // Value conversion errors
            std::cerr << "Error writing type " << cmd.type
                << ": invalid argument '" << cmd.value << "' (" << e.what() << ")" << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << "Error writing type " << cmd.type
                << ": value out of range '" << cmd.value << "' (" << e.what() << ")" << std::endl;
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << "Error writing type " << cmd.type
                << ": runtime error (" << e.what() << ")" << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << "Unknown error occurred while writing type " << cmd.type
                << " with value '" << cmd.value << "'" << std::endl;
        }
    }
}

void ExecuteRead(void* reader, const std::vector<Command>& commands,
    const std::unordered_map<std::string, void*>& readFunctions) {
    for (const auto& cmd : commands) {
        try {
            if (readFunctions.find(cmd.type) == readFunctions.end()) {
                std::cerr << "Unsupported type: " << cmd.type << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                bool value = ((ReadBoolean)readFunctions.at(cmd.type))(reader);
                std::cout << "Boolean: " << (value ? "true" : "false") << std::endl;
            }
            else if (cmd.type == "-byte") {
                unsigned char value = ((ReadByte)readFunctions.at(cmd.type))(reader);
                std::cout << "Byte: " << static_cast<int>(value) << std::endl;
            }
            else if (cmd.type == "-sbyte") {
                signed char value = ((ReadSByte)readFunctions.at(cmd.type))(reader);
                std::cout << "SByte: " << static_cast<int>(value) << std::endl;
            }
            else if (cmd.type == "-short") {
                short value = ((ReadShort)readFunctions.at(cmd.type))(reader);
                std::cout << "Short: " << value << std::endl;
            }
            else if (cmd.type == "-ushort") {
                unsigned short value = ((ReadUShort)readFunctions.at(cmd.type))(reader);
                std::cout << "UShort: " << value << std::endl;
            }
            else if (cmd.type == "-int") {
                int value = ((ReadInt)readFunctions.at(cmd.type))(reader);
                std::cout << "Int: " << value << std::endl;
            }
            else if (cmd.type == "-uint") {
                unsigned int value = ((ReadUInt)readFunctions.at(cmd.type))(reader);
                std::cout << "UInt: " << value << std::endl;
            }
            else if (cmd.type == "-long") {
                long long value = ((ReadLong)readFunctions.at(cmd.type))(reader);
                std::cout << "Long: " << value << std::endl;
            }
            else if (cmd.type == "-ulong") {
                unsigned long long value = ((ReadULong)readFunctions.at(cmd.type))(reader);
                std::cout << "ULong: " << value << std::endl;
            }
            else if (cmd.type == "-float") {
                float value = ((ReadFloat)readFunctions.at(cmd.type))(reader);
                std::cout << "Float: " << std::setprecision(8) << std::defaultfloat << value << std::endl;
            }
            else if (cmd.type == "-double") {
                double value = ((ReadDouble)readFunctions.at(cmd.type))(reader);
                std::cout << "Double: " << std::setprecision(16) << std::defaultfloat << value << std::endl;
            }
            else if (cmd.type == "-bytes") {
                uint64_t length = ((NextLength)readFunctions.at("-next-length"))(reader);
                std::vector<unsigned char> buffer(length);
                ((ReadBytes)readFunctions.at(cmd.type))(reader, buffer.data(), length);
                std::cout << "Bytes: " << std::string(buffer.begin(), buffer.end()) << std::endl;
            }
            else if (cmd.type == "-string") {
                uint64_t length = ((NextLength)readFunctions.at("-next-length"))(reader);
                std::vector<char> buffer(length + 1, '\0');
                ((ReadString)readFunctions.at(cmd.type))(reader, buffer.data(), length + 1);
                buffer[length] = '\0';
                std::cout << "String: " << buffer.data() << std::endl;
            }
        }
        catch (const std::runtime_error& e) {
            // Runtime errors
            std::cerr << "Runtime error while reading type " << cmd.type
                << ": " << e.what() << std::endl;
        }
        catch (const std::out_of_range& e) {
            // Value out of range errors
            std::cerr << "Out of range error while reading type " << cmd.type
                << ": " << e.what() << std::endl;
        }
        catch (const std::bad_alloc& e) {
            // Memory allocation failed
            std::cerr << "Memory allocation error while reading type " << cmd.type
                << ": " << e.what() << std::endl;
        }
        catch (...) {
            // Other unknown errors
            std::cerr << "Unknown error occurred while reading type " << cmd.type << std::endl;
        }
    }
}

void ReadToType(void* reader, BINARYIO_TYPE type) {
    switch (type) {
        case BINARYIO_TYPE::TYPE_BOOLEAN: {
            bool value = ((ReadBoolean)ReadFunctions.at("-bool"))(reader);
            std::cout << "Boolean: " << (value ? "true" : "false") << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_BYTE: {
            unsigned char value = ((ReadByte)ReadFunctions.at("-byte"))(reader);
            std::cout << "Byte: " << static_cast<int>(value) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_SBYTE: {
            signed char value = ((ReadSByte)ReadFunctions.at("-sbyte"))(reader);
            std::cout << "SByte: " << static_cast<int>(value) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_SHORT: {
            short value = ((ReadShort)ReadFunctions.at("-short"))(reader);
            std::cout << "Short: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_USHORT: {
            unsigned short value = ((ReadUShort)ReadFunctions.at("-ushort"))(reader);
            std::cout << "UShort: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_INT: {
            int value = ((ReadInt)ReadFunctions.at("-int"))(reader);
            std::cout << "Int: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_UINT: {
            unsigned int value = ((ReadUInt)ReadFunctions.at("-uint"))(reader);
            std::cout << "UInt: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_LONG: {
            long long value = ((ReadLong)ReadFunctions.at("-long"))(reader);
            std::cout << "Long: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_ULONG: {
            unsigned long long value = ((ReadULong)ReadFunctions.at("-ulong"))(reader);
            std::cout << "ULong: " << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_FLOAT: {
            float value = ((ReadFloat)ReadFunctions.at("-float"))(reader);
            std::cout << "Float: " << std::setprecision(8) << std::defaultfloat << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_DOUBLE: {
            double value = ((ReadDouble)ReadFunctions.at("-double"))(reader);
            std::cout << "Double: " << std::setprecision(16) << std::defaultfloat << value << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_BYTES: {
            uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
            std::vector<unsigned char> buffer(length);
            ((ReadBytes)ReadFunctions.at("-bytes"))(reader, buffer.data(), length);
            std::cout << "Bytes: " << std::string(buffer.begin(), buffer.end()) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_STRING: {
            uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
            std::vector<char> buffer(length + 1, '\0');
            ((ReadString)ReadFunctions.at("-string"))(reader, buffer.data(), length + 1);
            buffer[length] = '\0';
            std::cout << "String: " << buffer.data() << std::endl;
            break;
        }
    }
}

void ExecuteEncoder(const std::string mode, const Command& cmd, const std::unordered_map<std::string, void*>& encodeFunctions) {
    size_t inputLength = cmd.value.size();
    size_t outputLength;
    if (mode == "--base16") {
        outputLength = inputLength * 2 + 1;
    }
    else if (mode == "--base32") {
        outputLength = ((inputLength + 4) / 5) * 8 + 1;
    }
    else if (mode == "--base64") {
        outputLength = ((inputLength + 2) / 3) * 4 + 1;
    }
    else if (mode == "--base85") {
        outputLength = ((inputLength + 3) / 4) * 5 + 1;
    }
    else {
        std::cerr << "Wrong Pattern: " << mode << "\n";
        return;
    }
    std::vector<char> outputBuffer(outputLength, '\0');
    int resultCode = -4;
    std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
    std::string displayMode = mode.substr(2);
    std::string displayType = cmd.type.substr(1);
    ToLetter(displayMode);
    ToLetter(displayType);
    const unsigned char* value = reinterpret_cast<unsigned char*>(const_cast<char*>(cmd.value.c_str()));
    if (encodeType == "-base16-encode")
        resultCode = ((Base16Encode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base32-encode")
        resultCode = ((Base32Encode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base64-encode")
        resultCode = ((Base64Encode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base85-encode")
        resultCode = ((Base85Encode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base16-decode")
        resultCode = ((Base16Decode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base32-decode")
        resultCode = ((Base32Decode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base64-decode")
        resultCode = ((Base64Decode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base85-decode")
        resultCode = ((Base85Decode)encodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (resultCode < 0)
        std::cerr << "Failed to process " << cmd.type << " for " << mode << "\nCode: " << resultCode << "\n";
    else
        std::cout << "<" << displayMode << " " << displayType << ">\n" << outputBuffer.data() << "\nInput Length: [" << inputLength << "]\nOutput Length: [" << resultCode << "]\n";
}

int main(int argc, char* argv[]) {
    std::string mode;
    std::string filePath;
    std::vector<Command> commands;
    if (!ParseArguments(argc, argv, mode, filePath, commands)) {
        ShowUsage();
        return 1;
    }

#if _WIN32
    HMODULE lib = LOAD_LIBRARY("Ais.IO.dll");
#else
    void* lib = LOAD_LIBRARY("./Ais.IO.so");
#endif

    if (!lib) {
        std::cerr << "Failed to load Ais.IO library\n";
        return 1;
    }

    // Load function pointers (example: Load WriteBoolean, WriteInt, etc.)

    WriteFunctions["-bool"] = GET_PROC_ADDRESS(lib, "WriteBoolean");
    WriteFunctions["-byte"] = GET_PROC_ADDRESS(lib, "WriteByte");
    WriteFunctions["-sbyte"] = GET_PROC_ADDRESS(lib, "WriteSByte");
    WriteFunctions["-short"] = GET_PROC_ADDRESS(lib, "WriteShort");
    WriteFunctions["-ushort"] = GET_PROC_ADDRESS(lib, "WriteUShort");
    WriteFunctions["-int"] = GET_PROC_ADDRESS(lib, "WriteInt");
    WriteFunctions["-uint"] = GET_PROC_ADDRESS(lib, "WriteUInt");
    WriteFunctions["-long"] = GET_PROC_ADDRESS(lib, "WriteLong");
    WriteFunctions["-ulong"] = GET_PROC_ADDRESS(lib, "WriteULong");
    WriteFunctions["-float"] = GET_PROC_ADDRESS(lib, "WriteFloat");
    WriteFunctions["-double"] = GET_PROC_ADDRESS(lib, "WriteDouble");
    WriteFunctions["-bytes"] = GET_PROC_ADDRESS(lib, "WriteBytes");
    WriteFunctions["-string"] = GET_PROC_ADDRESS(lib, "WriteString");

    ReadFunctions["-bool"] = GET_PROC_ADDRESS(lib, "ReadBoolean");
    ReadFunctions["-byte"] = GET_PROC_ADDRESS(lib, "ReadByte");
    ReadFunctions["-sbyte"] = GET_PROC_ADDRESS(lib, "ReadSByte");
    ReadFunctions["-short"] = GET_PROC_ADDRESS(lib, "ReadShort");
    ReadFunctions["-ushort"] = GET_PROC_ADDRESS(lib, "ReadUShort");
    ReadFunctions["-int"] = GET_PROC_ADDRESS(lib, "ReadInt");
    ReadFunctions["-uint"] = GET_PROC_ADDRESS(lib, "ReadUInt");
    ReadFunctions["-long"] = GET_PROC_ADDRESS(lib, "ReadLong");
    ReadFunctions["-ulong"] = GET_PROC_ADDRESS(lib, "ReadULong");
    ReadFunctions["-float"] = GET_PROC_ADDRESS(lib, "ReadFloat");
    ReadFunctions["-double"] = GET_PROC_ADDRESS(lib, "ReadDouble");
    ReadFunctions["-bytes"] = GET_PROC_ADDRESS(lib, "ReadBytes");
    ReadFunctions["-string"] = GET_PROC_ADDRESS(lib, "ReadString");
    ReadFunctions["-next-length"] = GET_PROC_ADDRESS(lib, "NextLength");

    EncodeFunctions["-base16-encode"] = GET_PROC_ADDRESS(lib, "Base16Encode");
    EncodeFunctions["-base16-decode"] = GET_PROC_ADDRESS(lib, "Base16Decode");
    EncodeFunctions["-base32-encode"] = GET_PROC_ADDRESS(lib, "Base32Encode");
    EncodeFunctions["-base32-decode"] = GET_PROC_ADDRESS(lib, "Base32Decode");
    EncodeFunctions["-base64-encode"] = GET_PROC_ADDRESS(lib, "Base64Encode");
    EncodeFunctions["-base64-decode"] = GET_PROC_ADDRESS(lib, "Base64Decode");
    EncodeFunctions["-base85-encode"] = GET_PROC_ADDRESS(lib, "Base85Encode");
    EncodeFunctions["-base85-decode"] = GET_PROC_ADDRESS(lib, "Base85Decode");

    AesFunctions["-generate-key"] = GET_PROC_ADDRESS(lib, "GenerateKey");
    AesFunctions["-generate-iv"] = GET_PROC_ADDRESS(lib, "GenerateIV");
    AesFunctions["-import-key"] = GET_PROC_ADDRESS(lib, "GenerateKeyFromInput");
    AesFunctions["-import-iv"] = GET_PROC_ADDRESS(lib, "GenerateIVFromInput");
    AesFunctions["-aes-ctr-encrypt"] = GET_PROC_ADDRESS(lib, "AesCtrEncrypt");
    AesFunctions["-aes-ctr-decrypt"] = GET_PROC_ADDRESS(lib, "AesCtrDecrypt");
    AesFunctions["-aes-ctr-encrypt"] = GET_PROC_ADDRESS(lib, "AesCbcEncrypt");
    AesFunctions["-aes-ctr-decrypt"] = GET_PROC_ADDRESS(lib, "AesCbcDecrypt");
    AesFunctions["-aes-ctr-encrypt"] = GET_PROC_ADDRESS(lib, "AesCfbEncrypt");
    AesFunctions["-aes-ctr-decrypt"] = GET_PROC_ADDRESS(lib, "AesCfbDecrypt");
    //aesFunctions[""] = GET_PROC_ADDRESS(lib, "");

    if (mode == "--write") {
        void* writer = ((CreateBinaryWriter)GET_PROC_ADDRESS(lib, "CreateBinaryWriter"))(filePath.c_str());
        if (!writer) {
            std::cerr << "Failed to create binary writer for file: " << filePath << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }

        ExecuteWrite(writer, commands, WriteFunctions);
        ((DestroyBinaryWriter)GET_PROC_ADDRESS(lib, "DestroyBinaryWriter"))(writer);

    }
    else if (mode == "--read") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << "Failed to create binary reader for file: " << filePath << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }

        ExecuteRead(reader, commands, ReadFunctions);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
    }
    else if (mode == "--read-all") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << "Failed to create binary reader for file: " << filePath << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }

        while (((GetReaderPosition)GET_PROC_ADDRESS(lib, "GetReaderPosition"))(reader) < ((GetReaderLength)GET_PROC_ADDRESS(lib, "GetReaderLength"))(reader)) {
            BINARYIO_TYPE type = ((ReadType)GET_PROC_ADDRESS(lib, "ReadType"))(reader);
            ReadToType(reader, type);
        }
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        const Command& cmd = commands[0];
        std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
        if (commands.empty()) {
            std::cerr << "No encoding or decoding command provided.\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        if (EncodeFunctions.find(encodeType) == EncodeFunctions.end()) {
            std::cerr << "Unsupported encode/decode operation: " << cmd.type << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteEncoder(mode, cmd, EncodeFunctions);
    }

    UNLOAD_LIBRARY(lib);
    return 0;
}
