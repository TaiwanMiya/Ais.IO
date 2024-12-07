#include "main.h"
#include "StringCase.h"
#include "output_colors.h"
#include <locale.h>
#include <algorithm>

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
    uint64_t position{};
    uint64_t length{};
};

void ShowUsage() {
    std::cout << Any("                                                                                            ", TERMINAL_STYLE::STYLE_FLASHING, 30) << std::endl;
    std::cout << Any("               AAA                 iiii                        IIIIIIIIII     OOOOOOOOO     ", TERMINAL_STYLE::STYLE_FLASHING, 31) << std::endl;
    std::cout << Any("              A:::A               i::::i                       I::::::::I   OO:::::::::OO   ", TERMINAL_STYLE::STYLE_FLASHING, 32) << std::endl;
    std::cout << Any("             A:::::A               iiii                        I::::::::I OO:::::::::::::OO ", TERMINAL_STYLE::STYLE_FLASHING, 33) << std::endl;
    std::cout << Any("            A:::::::A                                          II::::::IIO:::::::OOO:::::::O", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;
    std::cout << Any("           A:::::::::A           iiiiiii     ssssssssss          I::::I  O::::::O   O::::::O", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("          A:::::A:::::A          i:::::i   ss::::::::::s         I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("         A:::::A A:::::A          i::::i ss:::::::::::::s        I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 37) << std::endl;
    std::cout << Any("        A:::::A   A:::::A         i::::i s::::::ssss:::::s       I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 31) << std::endl;
    std::cout << Any("       A:::::A     A:::::A        i::::i  s:::::s  ssssss        I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 32) << std::endl;
    std::cout << Any("      A:::::AAAAAAAAA:::::A       i::::i    s::::::s             I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 33) << std::endl;
    std::cout << Any("     A:::::::::::::::::::::A      i::::i       s::::::s          I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;
    std::cout << Any("    A:::::AAAAAAAAAAAAA:::::A     i::::i ssssss   s:::::s        I::::I  O::::::O   O::::::O", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("   A:::::A             A:::::A   i::::::is:::::ssss::::::s     II::::::IIO:::::::OOO:::::::O", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("  A:::::A               A:::::A  i::::::is::::::::::::::s      I::::::::I OO:::::::::::::OO ", TERMINAL_STYLE::STYLE_FLASHING, 37) << std::endl;
    std::cout << Any(" A:::::A                 A:::::A i::::::i s:::::::::::ss       I::::::::I   OO:::::::::OO   ", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("AAAAAAA                   AAAAAAAiiiiiiii  sssssssssss         IIIIIIIIII     OOOOOOOOO     ", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("                                                                                            ", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;

    std::cout << Hint("Usage:\n");
    std::cout << Hint("  --indexes <path>\n");
    std::cout << Hint("  --read-all <path>\n");
    std::cout << Hint("  --read <path> [--type] ...\n");
    std::cout << Hint("  --write <path> [--type] <value> ...\n");
    std::cout << Hint("  --append <path> [--type] <value> ...\n");
    std::cout << Hint("  --insert <path> [--type] <value> <position> ...\n");
    std::cout << Hint("  --remove <path> [--type] <position> <length> ...\n");
    std::cout << Hint("  --base16 [-encode | -decode] <value>\n");
    std::cout << Hint("  --base32 [-encode | -decode] <value>\n");
    std::cout << Hint("  --base64 [-encode | -decode] <value>\n");
    std::cout << Hint("  --base85 [-encode | -decode] <value>\n");
    std::cout << Hint("Supported types:\n");
    std::cout << Hint("  -bool, -byte, -sbyte, -short, -ushort, -int, -uint, -long, -ulong, -float, -double, -bytes, -string\n");
}

bool ParseArguments(int argc, char* argv[], std::string& mode, std::string& filePath, std::vector<Command>& commands) {
    if (argc < 3) {
        return false;
    }

    std::unordered_set<std::string> validMode = {
        "--indexes", "--read-all", "--read", "--write", "--append", "--insert", "--remove",
        "--base16", "--base32", "--base64", "--base85"
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

    if (mode == "--read" || mode == "--write" || mode == "--append") {
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
                    std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                    return false;
                }
                cmd.value = arg;
            }
        }

        if (!cmd.type.empty())
            commands.push_back(cmd);
    }
    else if (mode == "--insert") {
        if (argc < 5)
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
            else if (IsULong(arg) && (i - 2) % 3 == 0) {
                if (cmd.type.empty()) {
                    std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                    return false;
                }
                cmd.position = std::stoull(arg);
            }
            else {
                if (cmd.type.empty()) {
                    std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                    return false;
                }
                cmd.value = arg;
            }
        }

        if (!cmd.type.empty())
            commands.push_back(cmd);

        std::sort(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
            return a.position > b.position;
        });
    }
    else if (mode == "--remove") {
        if (argc < 5)
            return false;
        filePath = argv[2];

        Command cmd;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            std::string arg2 = argv[i + 1];
            if (validOptions.count(arg)) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = arg;
            }
            else if (IsULong(arg) && IsULong(arg2)) {
                if (cmd.type.empty()) {
                    std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                    return false;
                }
                cmd.position = std::stoull(arg);
                cmd.length = std::stoull(arg2);
                i++;
            }
            else {
                std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                return false;
            }
        }

        if (!cmd.type.empty())
            commands.push_back(cmd);

        std::sort(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
            return a.position > b.position;
            });
    }
    else if (mode == "--read-all" || mode == "--indexes") {
        if (argc < 3)
            return false;
        filePath = argv[2];
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        if (argc != 4)
            return false;
        std::string operation = argv[2];
        if (!encodeDecodeOptions.count(operation)) {
            std::cerr << Error("Invalid operation: ") << Ask(operation) << "\n";
            return false;
        }
        Command cmd;
        cmd.type = operation;
        cmd.value = argv[3];
        commands.push_back(cmd);
    }
    return true;
}

std::string GetTypeName(BINARYIO_TYPE type) {
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

void ReadToType(void* reader, BINARYIO_TYPE type, uint64_t& count) {
    switch (type) {
        case BINARYIO_TYPE::TYPE_BOOLEAN: {
            bool value = ((ReadBoolean)ReadFunctions.at("-bool"))(reader);
            std::cout << Hint(std::to_string(count) + ". Boolean: ") << Ask(value ? "true" : "false") << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_BYTE: {
            unsigned char value = ((ReadByte)ReadFunctions.at("-byte"))(reader);
            std::cout << Hint(std::to_string(count) + ". Byte: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_SBYTE: {
            signed char value = ((ReadSByte)ReadFunctions.at("-sbyte"))(reader);
            std::cout << Hint(std::to_string(count) + ". SByte: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_SHORT: {
            short value = ((ReadShort)ReadFunctions.at("-short"))(reader);
            std::cout << Hint(std::to_string(count) + ". Short: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_USHORT: {
            unsigned short value = ((ReadUShort)ReadFunctions.at("-ushort"))(reader);
            std::cout << Hint(std::to_string(count) + ". UShort: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_INT: {
            int value = ((ReadInt)ReadFunctions.at("-int"))(reader);
            std::cout << Hint(std::to_string(count) + ". Int: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_UINT: {
            unsigned int value = ((ReadUInt)ReadFunctions.at("-uint"))(reader);
            std::cout << Hint(std::to_string(count) + ". UInt: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_LONG: {
            long long value = ((ReadLong)ReadFunctions.at("-long"))(reader);
            std::cout << Hint(std::to_string(count) + ". Long: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_ULONG: {
            unsigned long long value = ((ReadULong)ReadFunctions.at("-ulong"))(reader);
            std::cout << Hint(std::to_string(count) + ". ULong: ") << Ask(std::to_string(value)) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_FLOAT: {
            float value = ((ReadFloat)ReadFunctions.at("-float"))(reader);
            std::ostringstream oss;
            oss.precision(8);
            oss << std::defaultfloat << value;
            std::cout << Hint(std::to_string(count) + ". Float: ") << Ask(oss.str()) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_DOUBLE: {
            double value = ((ReadDouble)ReadFunctions.at("-double"))(reader);
            std::ostringstream oss;
            oss.precision(16);
            oss << std::defaultfloat << value;
            std::cout << Hint(std::to_string(count) + ". Double: ") << Ask(oss.str()) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_BYTES: {
            uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
            std::vector<unsigned char> buffer(length);
            ((ReadBytes)ReadFunctions.at("-bytes"))(reader, buffer.data(), length);
            std::cout << Hint(std::to_string(count) + ". Bytes: ") << Ask(std::string(buffer.begin(), buffer.end())) << std::endl;
            break;
        }
        case BINARYIO_TYPE::TYPE_STRING: {
            uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
            std::vector<char> buffer(length + 1, '\0');
            ((ReadString)ReadFunctions.at("-string"))(reader, buffer.data(), length + 1);
            buffer[length] = '\0';
            std::cout << Hint(std::to_string(count) + ". String: ") << Ask(buffer.data()) << std::endl;
            break;
        }
    }
    count++;
}

void GetIndexes(void* reader) {
    uint64_t count = 1;
    BINARYIO_INDICES* indices = ((GetAllIndices)ReadFunctions.at("-indexes"))(reader, &count);
    if (indices == nullptr) {
        std::cerr << Error("Error: Failed to get indexes from the file.") << std::endl;
        return;
    }
    
    for (uint64_t i = 0; i < count; ++i)
        std::cout << Hint(std::to_string(i + 1)) << ". " + Ask(GetTypeName(indices[i].TYPE)) << " = " << Hint("Position:") << Ask(std::to_string(indices[i].POSITION)) << ", " << Hint("Length:") << Ask(std::to_string(indices[i].LENGTH)) << std::endl;
    free(indices);
}

void ExecuteRead(void* reader, const std::vector<Command>& commands) {
    uint64_t count = 1;
    for (const auto& cmd : commands) {
        try {
            if (ReadFunctions.find(cmd.type) == ReadFunctions.end()) {
                std::cerr << Warn("Unsupported type: ") << Ask(cmd.type) << std::endl;
                continue;
            }

            if (cmd.type == "-bool") {
                bool value = ((ReadBoolean)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". Boolean: ") << Ask(value ? "true" : "false") << std::endl;
            }
            else if (cmd.type == "-byte") {
                unsigned char value = ((ReadByte)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". Byte: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-sbyte") {
                signed char value = ((ReadSByte)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". SByte: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-short") {
                short value = ((ReadShort)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". Short: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-ushort") {
                unsigned short value = ((ReadUShort)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". UShort: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-int") {
                int value = ((ReadInt)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". Int: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-uint") {
                unsigned int value = ((ReadUInt)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". UInt: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-long") {
                long long value = ((ReadLong)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". Long: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-ulong") {
                unsigned long long value = ((ReadULong)ReadFunctions.at(cmd.type))(reader);
                std::cout << Hint(std::to_string(count) + ". ULong: ") << Ask(std::to_string(value)) << std::endl;
            }
            else if (cmd.type == "-float") {
                float value = ((ReadFloat)ReadFunctions.at(cmd.type))(reader);
                std::ostringstream oss;
                oss.precision(8);
                oss << std::defaultfloat << value;
                std::cout << Hint(std::to_string(count) + ". Float: ") << Ask(oss.str()) << std::endl;
            }
            else if (cmd.type == "-double") {
                double value = ((ReadDouble)ReadFunctions.at(cmd.type))(reader);
                std::ostringstream oss;
                oss.precision(16);
                oss << std::defaultfloat << value;
                std::cout << Hint(std::to_string(count) + ". Double: ") << Ask(oss.str()) << std::endl;
            }
            else if (cmd.type == "-bytes") {
                uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
                std::vector<unsigned char> buffer(length);
                ((ReadBytes)ReadFunctions.at(cmd.type))(reader, buffer.data(), length);
                std::cout << Hint(std::to_string(count) + ". Bytes: ") << Ask(std::string(buffer.begin(), buffer.end())) << std::endl;
            }
            else if (cmd.type == "-string") {
                uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
                std::vector<char> buffer(length + 1, '\0');
                ((ReadString)ReadFunctions.at(cmd.type))(reader, buffer.data(), length + 1);
                buffer[length] = '\0';
                std::cout << Hint(std::to_string(count) + ". String: ") << Ask(buffer.data()) << std::endl;
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

void ExecuteWrite(void* writer, const std::vector<Command>& commands) {
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
                const unsigned char* data = reinterpret_cast<const unsigned char*>(cmd.value.data());
                uint64_t length = static_cast<uint64_t>(cmd.value.size());
                ((WriteBytes)WriteFunctions.at(cmd.type))(writer, data, length);
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

void ExecuteAppend(void* appender, const std::vector<Command>& commands) {
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
                const unsigned char* data = reinterpret_cast<const unsigned char*>(cmd.value.data());
                uint64_t length = static_cast<uint64_t>(cmd.value.size());
                ((AppendBytes)AppendFunctions.at(cmd.type))(appender, data, length);
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

void ExecuteInsert(void* inserter, const std::vector<Command>& commands) {
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
                const unsigned char* data = reinterpret_cast<const unsigned char*>(cmd.value.data());
                uint64_t length = static_cast<uint64_t>(cmd.value.size());
                ((InsertBytes)InsertFunctions.at(cmd.type))(inserter, data, length, cmd.position);
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

void ExecuteRemove(void* remover, const std::string filePath, const std::vector<Command>& commands) {
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
        std::cerr << Warn("Wrong Pattern: ") << Ask(mode) << "\n";
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
        std::cerr << Error("Failed to process ") << Ask(cmd.type) << Error(" for ") << Ask(mode) << Error("\nCode: ") << Ask(std::to_string(resultCode)) << "\n";
    else
        std::cout << Hint("<" + displayMode + " " + displayType + ">\n") << Ask(outputBuffer.data()) << Hint("\nInput Length: [") << Ask(std::to_string(inputLength)) << Hint("]\nOutput Length: [") << Ask(std::to_string(resultCode)) << Hint("]\n");
    std::cout << Mark(displayMode + " " + displayType + " Action Completed!") << std::endl;
}

int main(int argc, char* argv[]) {
    std::string mode;
    std::string filePath;
    std::vector<Command> commands;

#if _WIN32
    EnableVirtualTerminalProcessing();
#endif

    if (argc == 2 && std::string(argv[1]) == "--colors") {
        ListColorTable();
        return 1;
    }

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
        std::cerr << Error("Failed to load Ais.IO library\n");
        return 1;
    }

    // Load function pointers (example: Load WriteBoolean, WriteInt, etc.)

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
    ReadFunctions["-remove"] = GET_PROC_ADDRESS(lib, "RemoveIndex");
    ReadFunctions["-indexes"] = GET_PROC_ADDRESS(lib, "GetAllIndices");

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

    AppendFunctions["-bool"] = GET_PROC_ADDRESS(lib, "AppendBoolean");
    AppendFunctions["-byte"] = GET_PROC_ADDRESS(lib, "AppendByte");
    AppendFunctions["-sbyte"] = GET_PROC_ADDRESS(lib, "AppendSByte");
    AppendFunctions["-short"] = GET_PROC_ADDRESS(lib, "AppendShort");
    AppendFunctions["-ushort"] = GET_PROC_ADDRESS(lib, "AppendUShort");
    AppendFunctions["-int"] = GET_PROC_ADDRESS(lib, "AppendInt");
    AppendFunctions["-uint"] = GET_PROC_ADDRESS(lib, "AppendUInt");
    AppendFunctions["-long"] = GET_PROC_ADDRESS(lib, "AppendLong");
    AppendFunctions["-ulong"] = GET_PROC_ADDRESS(lib, "AppendULong");
    AppendFunctions["-float"] = GET_PROC_ADDRESS(lib, "AppendFloat");
    AppendFunctions["-double"] = GET_PROC_ADDRESS(lib, "AppendDouble");
    AppendFunctions["-bytes"] = GET_PROC_ADDRESS(lib, "AppendBytes");
    AppendFunctions["-string"] = GET_PROC_ADDRESS(lib, "AppendString");

    InsertFunctions["-bool"] = GET_PROC_ADDRESS(lib, "InsertBoolean");
    InsertFunctions["-byte"] = GET_PROC_ADDRESS(lib, "InsertByte");
    InsertFunctions["-sbyte"] = GET_PROC_ADDRESS(lib, "InsertSByte");
    InsertFunctions["-short"] = GET_PROC_ADDRESS(lib, "InsertShort");
    InsertFunctions["-ushort"] = GET_PROC_ADDRESS(lib, "InsertUShort");
    InsertFunctions["-int"] = GET_PROC_ADDRESS(lib, "InsertInt");
    InsertFunctions["-uint"] = GET_PROC_ADDRESS(lib, "InsertUInt");
    InsertFunctions["-long"] = GET_PROC_ADDRESS(lib, "InsertLong");
    InsertFunctions["-ulong"] = GET_PROC_ADDRESS(lib, "InsertULong");
    InsertFunctions["-float"] = GET_PROC_ADDRESS(lib, "InsertFloat");
    InsertFunctions["-double"] = GET_PROC_ADDRESS(lib, "InsertDouble");
    InsertFunctions["-bytes"] = GET_PROC_ADDRESS(lib, "InsertBytes");
    InsertFunctions["-string"] = GET_PROC_ADDRESS(lib, "InsertString");

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

    if (mode == "--read") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteRead(reader, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Read Action Completed!") << std::endl;
    }
    else if (mode == "--write") {
        void* writer = ((CreateBinaryWriter)GET_PROC_ADDRESS(lib, "CreateBinaryWriter"))(filePath.c_str());
        if (!writer) {
            std::cerr << Error("Failed to create binary writer for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteWrite(writer, commands);
        ((DestroyBinaryWriter)GET_PROC_ADDRESS(lib, "DestroyBinaryWriter"))(writer);
        std::cout << Mark("Write Action Completed!") << std::endl;
    }
    else if (mode == "--append") {
        void* appender = ((CreateBinaryAppender)GET_PROC_ADDRESS(lib, "CreateBinaryAppender"))(filePath.c_str());
        if (!appender) {
            std::cerr << Error("Failed to create binary appender for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteAppend(appender, commands);
        ((DestroyBinaryAppender)GET_PROC_ADDRESS(lib, "DestroyBinaryAppender"))(appender);
        std::cout << Mark("Append Action Completed!") << std::endl;
    }
    else if (mode == "--insert") {
        void* inserter = ((CreateBinaryInserter)GET_PROC_ADDRESS(lib, "CreateBinaryInserter"))(filePath.c_str());
        if (!inserter) {
            std::cerr << Error("Failed to create binary inserter for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteInsert(inserter, commands);
        ((DestroyBinaryInserter)GET_PROC_ADDRESS(lib, "DestroyBinaryInserter"))(inserter);
        std::cout << Mark("Insert Action Completed!") << std::endl;
    }
    else if (mode == "--remove") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteRemove(reader, filePath, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Remove Action Completed!") << std::endl;
    }
    else if (mode == "--read-all") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        uint64_t count = 1;
        while (((GetReaderPosition)GET_PROC_ADDRESS(lib, "GetReaderPosition"))(reader) < ((GetReaderLength)GET_PROC_ADDRESS(lib, "GetReaderLength"))(reader)) {
            BINARYIO_TYPE type = ((ReadType)GET_PROC_ADDRESS(lib, "ReadType"))(reader);
            ReadToType(reader, type, count);
        }
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Read All Action Completed!") << std::endl;
    }
    else if (mode == "--indexes") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader indexes for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        GetIndexes(reader);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Indexes Action Completed!") << std::endl;
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        const Command& cmd = commands[0];
        std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
        if (commands.empty()) {
            std::cerr << "No encoding or decoding command provided.\n";
            std::cerr << Error("No encoding or decoding command provided.\n");
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        if (EncodeFunctions.find(encodeType) == EncodeFunctions.end()) {
            std::cerr << Error("Unsupported encode/decode operation: ") << Ask(cmd.type) << "\n";
            UNLOAD_LIBRARY(lib);
            return 1;
        }
        ExecuteEncoder(mode, cmd, EncodeFunctions);
    }

    UNLOAD_LIBRARY(lib);
    return 0;
}
