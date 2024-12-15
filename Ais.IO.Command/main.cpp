#include <locale.h>
#include <algorithm>
#include "main.h"
#include "string_case.h"
#include "output_colors.h"
#include "binary_execute.h"
#include "encoder_execute.h"
#include "aes_execute.h"
#include "cryptography_libary.h"

#ifdef _WIN32
#define LOAD_LIBRARY(Lib) LoadLibraryA(Lib)
#define GET_PROC_ADDRESS(Lib, name) GetProcAddress(Lib, name)
#define UNLOAD_LIBRARY(Lib) FreeLibrary(Lib)
HMODULE Lib = LOAD_LIBRARY("Ais.IO.dll");
#else
#define LOAD_LIBRARY(Lib) dlopen(Lib, RTLD_LAZY)
#define GET_PROC_ADDRESS(Lib, name) dlsym(Lib, name)
#define UNLOAD_LIBRARY(Lib) dlclose(Lib)
void* Lib = LOAD_LIBRARY("./Ais.IO.so");
#endif

std::unordered_map<std::string, void*> ReadFunctions;
std::unordered_map<std::string, void*> WriteFunctions;
std::unordered_map<std::string, void*> AppendFunctions;
std::unordered_map<std::string, void*> InsertFunctions;
std::unordered_map<std::string, void*> EncodeFunctions;
std::unordered_map<std::string, void*> AesFunctions;
std::unordered_map<std::string, void*> RandFunctions;
std::unordered_map<CRYPT_TYPE, std::string> CryptDisplay = {
    { CRYPT_TYPE::CRYPTION_NULL, "Unknown" },
    { CRYPT_TYPE::CRYPTION_ENCRYPT, "Encrypt" },
    { CRYPT_TYPE::CRYPTION_DECRYPT, "Decrypt" },
    { CRYPT_TYPE::CRYPTION_SIGNED, "Signed" },
    { CRYPT_TYPE::CRYPTION_VERIFY, "Verify" },
    { CRYPT_TYPE::CRYPTION_DERIVE, "Derive" }
};
std::unordered_map<std::string, AES_MODE> AesMode = {
    {"-ctr", AES_MODE::AES_CTR },
    {"-cbc", AES_MODE::AES_CBC },
    {"-cfb", AES_MODE::AES_CFB },
    {"-ofb", AES_MODE::AES_OFB },
    {"-ecb", AES_MODE::AES_ECB },
    {"-gcm", AES_MODE::AES_GCM },
    {"-ccm", AES_MODE::AES_CCM },
    {"-xts", AES_MODE::AES_XTS },
    {"-ocb", AES_MODE::AES_OCB },
    {"-wrap", AES_MODE::AES_WRAP },
};
std::unordered_map<AES_MODE, std::string> AesDisplay = {
    { AES_MODE::AES_CTR, "CTR" },
    { AES_MODE::AES_CBC, "CBC" },
    { AES_MODE::AES_CFB, "CFB" },
    { AES_MODE::AES_OFB, "OFB" },
    { AES_MODE::AES_ECB, "ECB" },
    { AES_MODE::AES_GCM, "GCM" },
    { AES_MODE::AES_CCM, "CCM" },
    { AES_MODE::AES_XTS, "XTS" },
    { AES_MODE::AES_OCB, "OCB" },
    { AES_MODE::AES_WRAP, "WRAP" },
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
    std::cout << Hint("  [-id | --indexes] <path>\n");
    std::cout << Hint("  [-rl | --read-all] <path>\n");
    std::cout << Hint("  [-r | --read] <path> [--type] ...\n");
    std::cout << Hint("  [-w | --write] <path> [--type] <value> ...\n");
    std::cout << Hint("  [-a | --append] <path> [--type] <value> ...\n");
    std::cout << Hint("  [-i | --insert] <path> [--type] <value> <position> ...\n");
    std::cout << Hint("  [-rm | --remove] <path> [--type] <position> <length> ...\n");
    std::cout << Hint("  [-rs | --remove-index] <path> <index> ...\n");
    std::cout << Hint("  [-b16 | --base16] [-e | -encode | -d -decode] [Null | -in | -input <path>] [Null | -out | -output <path>] <value>\n");
    std::cout << Hint("  [-b32 | --base32] [-e | -encode | -d -decode] [Null | -in | -input <path>] [Null | -out | -output <path>] <value>\n");
    std::cout << Hint("  [-b64 | --base64] [-e | -encode | -d -decode] [Null | -in | -input <path>] [Null | -out | -output <path>] <value>\n");
    std::cout << Hint("  [-b85 | --base85] [-e | -encode | -d -decode] [Null | -in | -input <path>] [Null | -out | -output <path>] <value>\n");
    std::cout << Hint("  --colors\n");
    std::cout << Hint("Supported [--type]:\n");
    std::cout << Hint("  -bool, -byte, -sbyte, -short, -ushort, -int, -uint, -long, -ulong, -float, -double, -bytes, -string\n");
}

bool ParseArguments(int argc, char* argv[], std::string& mode, std::string& filePath, std::vector<Command>& commands) {
    if (argc < 3) {
        return false;
    }

    std::unordered_set<std::string> validMode = {
        "--indexes", "--read-all", "--read", "--write", "--append", "--insert", "--remove", "--remove-index",
        "--base16", "--base32", "--base64", "--base85",
        "--generate", "--import", "--aes"
    };

    std::unordered_map<std::string, std::string> abbreviationValidMode = {
        {"-id", "--indexes"}, {"-rl", "--read-all"}, {"-r", "--read"}, {"-w", "--write"}, {"-a", "--append"}, {"-i", "--insert"}, {"-rm", "--remove"}, {"-rs", "--remove-index"},
        {"-b16", "--base16"}, {"-b32", "--base32"}, {"-b64", "--base64"}, {"-b85", "--base85"},
        {"-gen", "--generate"}, {"-imp", "--import"}, {"-aes", "--aes"}
    };

    std::unordered_set<std::string> validOptions = {
        "-bool", "-byte", "-sbyte", "-short", "-ushort", "-int", "-uint",
        "-long", "-ulong", "-float", "-double", "-bytes", "-string"
    };

    std::unordered_set<std::string> encodeDecodeOptions = {
        "-encode", "-decode"
    };

    std::unordered_map<std::string, std::string> abbreviationEncodeDecodeOptions = {
        {"-e", "-encode"}, {"-d", "-decode"}
    };

    std::unordered_set<std::string> ioOptions = {
        "-input", "-output"
    };

    std::unordered_map<std::string, std::string> abbreviationIoOptions = {
        {"-in", "-input"}, {"-out", "-output"}
    };

    mode = ToLower(argv[1]);

    if (abbreviationValidMode.count(mode)) {
        mode = abbreviationValidMode[mode];
    }

    if (!validMode.count(mode)) {
        std::cerr << Error("Invalid mode: ") << Ask(mode) << std::endl;
        return false;
    }

    if (mode == "--read" || mode == "--write" || mode == "--append") {
        if (argc < 4)
            return false;
        filePath = argv[2];

        Command cmd;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (validOptions.count(ToLower(arg))) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = ToLower(arg);
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
            if (validOptions.count(ToLower(arg))) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = ToLower(arg);
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
            if (validOptions.count(ToLower(arg))) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = ToLower(arg);
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
    else if (mode == "--remove-index") {
        if (argc < 3)
            return false;
        filePath = argv[2];
        Command cmd;
        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (IsULong(arg)) {
                cmd.value = arg;
                commands.push_back(cmd);
            }
            else {
                std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                return false;
            }
        }
        std::sort(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
            return std::stoull(a.value) > std::stoull(b.value);
        });
        auto last = std::unique(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
            return a.value == b.value;
        });
        commands.erase(last, commands.end());
    }
    else if (mode == "--read-all" || mode == "--indexes") {
        if (argc < 3)
            return false;
        filePath = argv[2];
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        if (argc < 4)
            return false;
        std::string operation = ToLower(argv[2]);
        if (abbreviationEncodeDecodeOptions.count(operation))
            operation = abbreviationEncodeDecodeOptions[operation];
        if (!encodeDecodeOptions.count(operation)) {
            std::cerr << Error("Invalid operation: ") << Ask(operation) << "\n";
            return false;
        }

        Command cmd;
        cmd.type = operation;

        for (int i = 3; i < argc; ++i) {
            std::string arg = argv[i];
            if (abbreviationIoOptions.count(arg)) {
                arg = abbreviationIoOptions[arg];
            }
            if (arg == "-input") {
                if (i + 1 >= argc) {
                    std::cerr << Error("Missing input file path after -input.\n");
                    return false;
                }
                cmd.input = argv[++i];
            }
            else if (arg == "-output") {
                if (i + 1 >= argc) {
                    std::cerr << Error("Missing output file path after -output.\n");
                    return false;
                }
                cmd.output = argv[++i];
            }
            else {
                cmd.value = arg;
            }
        }

        if (cmd.input.empty() && cmd.value.empty()) {
            std::cerr << Error("Either an input file or a value is required for encoding/decoding.\n");
            return false;
        }
        commands.push_back(cmd);
    }
    return true;
}

void LoadFunctions() {
    ReadFunctions["-bool"] = GET_PROC_ADDRESS(Lib, "ReadBoolean");
    ReadFunctions["-byte"] = GET_PROC_ADDRESS(Lib, "ReadByte");
    ReadFunctions["-sbyte"] = GET_PROC_ADDRESS(Lib, "ReadSByte");
    ReadFunctions["-short"] = GET_PROC_ADDRESS(Lib, "ReadShort");
    ReadFunctions["-ushort"] = GET_PROC_ADDRESS(Lib, "ReadUShort");
    ReadFunctions["-int"] = GET_PROC_ADDRESS(Lib, "ReadInt");
    ReadFunctions["-uint"] = GET_PROC_ADDRESS(Lib, "ReadUInt");
    ReadFunctions["-long"] = GET_PROC_ADDRESS(Lib, "ReadLong");
    ReadFunctions["-ulong"] = GET_PROC_ADDRESS(Lib, "ReadULong");
    ReadFunctions["-float"] = GET_PROC_ADDRESS(Lib, "ReadFloat");
    ReadFunctions["-double"] = GET_PROC_ADDRESS(Lib, "ReadDouble");
    ReadFunctions["-bytes"] = GET_PROC_ADDRESS(Lib, "ReadBytes");
    ReadFunctions["-string"] = GET_PROC_ADDRESS(Lib, "ReadString");

    ReadFunctions["-next-length"] = GET_PROC_ADDRESS(Lib, "NextLength");
    ReadFunctions["-remove"] = GET_PROC_ADDRESS(Lib, "RemoveIndex");
    ReadFunctions["-indexes"] = GET_PROC_ADDRESS(Lib, "GetAllIndices");

    WriteFunctions["-bool"] = GET_PROC_ADDRESS(Lib, "WriteBoolean");
    WriteFunctions["-byte"] = GET_PROC_ADDRESS(Lib, "WriteByte");
    WriteFunctions["-sbyte"] = GET_PROC_ADDRESS(Lib, "WriteSByte");
    WriteFunctions["-short"] = GET_PROC_ADDRESS(Lib, "WriteShort");
    WriteFunctions["-ushort"] = GET_PROC_ADDRESS(Lib, "WriteUShort");
    WriteFunctions["-int"] = GET_PROC_ADDRESS(Lib, "WriteInt");
    WriteFunctions["-uint"] = GET_PROC_ADDRESS(Lib, "WriteUInt");
    WriteFunctions["-long"] = GET_PROC_ADDRESS(Lib, "WriteLong");
    WriteFunctions["-ulong"] = GET_PROC_ADDRESS(Lib, "WriteULong");
    WriteFunctions["-float"] = GET_PROC_ADDRESS(Lib, "WriteFloat");
    WriteFunctions["-double"] = GET_PROC_ADDRESS(Lib, "WriteDouble");
    WriteFunctions["-bytes"] = GET_PROC_ADDRESS(Lib, "WriteBytes");
    WriteFunctions["-string"] = GET_PROC_ADDRESS(Lib, "WriteString");

    AppendFunctions["-bool"] = GET_PROC_ADDRESS(Lib, "AppendBoolean");
    AppendFunctions["-byte"] = GET_PROC_ADDRESS(Lib, "AppendByte");
    AppendFunctions["-sbyte"] = GET_PROC_ADDRESS(Lib, "AppendSByte");
    AppendFunctions["-short"] = GET_PROC_ADDRESS(Lib, "AppendShort");
    AppendFunctions["-ushort"] = GET_PROC_ADDRESS(Lib, "AppendUShort");
    AppendFunctions["-int"] = GET_PROC_ADDRESS(Lib, "AppendInt");
    AppendFunctions["-uint"] = GET_PROC_ADDRESS(Lib, "AppendUInt");
    AppendFunctions["-long"] = GET_PROC_ADDRESS(Lib, "AppendLong");
    AppendFunctions["-ulong"] = GET_PROC_ADDRESS(Lib, "AppendULong");
    AppendFunctions["-float"] = GET_PROC_ADDRESS(Lib, "AppendFloat");
    AppendFunctions["-double"] = GET_PROC_ADDRESS(Lib, "AppendDouble");
    AppendFunctions["-bytes"] = GET_PROC_ADDRESS(Lib, "AppendBytes");
    AppendFunctions["-string"] = GET_PROC_ADDRESS(Lib, "AppendString");

    InsertFunctions["-bool"] = GET_PROC_ADDRESS(Lib, "InsertBoolean");
    InsertFunctions["-byte"] = GET_PROC_ADDRESS(Lib, "InsertByte");
    InsertFunctions["-sbyte"] = GET_PROC_ADDRESS(Lib, "InsertSByte");
    InsertFunctions["-short"] = GET_PROC_ADDRESS(Lib, "InsertShort");
    InsertFunctions["-ushort"] = GET_PROC_ADDRESS(Lib, "InsertUShort");
    InsertFunctions["-int"] = GET_PROC_ADDRESS(Lib, "InsertInt");
    InsertFunctions["-uint"] = GET_PROC_ADDRESS(Lib, "InsertUInt");
    InsertFunctions["-long"] = GET_PROC_ADDRESS(Lib, "InsertLong");
    InsertFunctions["-ulong"] = GET_PROC_ADDRESS(Lib, "InsertULong");
    InsertFunctions["-float"] = GET_PROC_ADDRESS(Lib, "InsertFloat");
    InsertFunctions["-double"] = GET_PROC_ADDRESS(Lib, "InsertDouble");
    InsertFunctions["-bytes"] = GET_PROC_ADDRESS(Lib, "InsertBytes");
    InsertFunctions["-string"] = GET_PROC_ADDRESS(Lib, "InsertString");

    EncodeFunctions["-base16-encode"] = GET_PROC_ADDRESS(Lib, "Base16Encode");
    EncodeFunctions["-base16-decode"] = GET_PROC_ADDRESS(Lib, "Base16Decode");
    EncodeFunctions["-base32-encode"] = GET_PROC_ADDRESS(Lib, "Base32Encode");
    EncodeFunctions["-base32-decode"] = GET_PROC_ADDRESS(Lib, "Base32Decode");
    EncodeFunctions["-base64-encode"] = GET_PROC_ADDRESS(Lib, "Base64Encode");
    EncodeFunctions["-base64-decode"] = GET_PROC_ADDRESS(Lib, "Base64Decode");
    EncodeFunctions["-base85-encode"] = GET_PROC_ADDRESS(Lib, "Base85Encode");
    EncodeFunctions["-base85-decode"] = GET_PROC_ADDRESS(Lib, "Base85Decode");

    AesFunctions["-ctr-encrypt"] = GET_PROC_ADDRESS(Lib, "AesCtrEncrypt");
    AesFunctions["-ctr-decrypt"] = GET_PROC_ADDRESS(Lib, "AesCtrDecrypt");
    AesFunctions["-cbc-encrypt"] = GET_PROC_ADDRESS(Lib, "AesCbcEncrypt");
    AesFunctions["-cbc-decrypt"] = GET_PROC_ADDRESS(Lib, "AesCbcDecrypt");
    AesFunctions["-cfb-encrypt"] = GET_PROC_ADDRESS(Lib, "AesCfbEncrypt");
    AesFunctions["-cfb-decrypt"] = GET_PROC_ADDRESS(Lib, "AesCfbDecrypt");
    AesFunctions["-ofb-encrypt"] = GET_PROC_ADDRESS(Lib, "AesOfbEncrypt");
    AesFunctions["-ofb-decrypt"] = GET_PROC_ADDRESS(Lib, "AesOfbDecrypt");
    AesFunctions["-ecb-encrypt"] = GET_PROC_ADDRESS(Lib, "AesEcbEncrypt");
    AesFunctions["-ecb-decrypt"] = GET_PROC_ADDRESS(Lib, "AesEcbDecrypt");
    AesFunctions["-gcm-encrypt"] = GET_PROC_ADDRESS(Lib, "AesGcmEncrypt");
    AesFunctions["-gcm-decrypt"] = GET_PROC_ADDRESS(Lib, "AesGcmDecrypt");
    AesFunctions["-ccm-encrypt"] = GET_PROC_ADDRESS(Lib, "AesCcmEncrypt");
    AesFunctions["-ccm-decrypt"] = GET_PROC_ADDRESS(Lib, "AesCcmDecrypt");
    AesFunctions["-xts-encrypt"] = GET_PROC_ADDRESS(Lib, "AesXtsEncrypt");
    AesFunctions["-xts-decrypt"] = GET_PROC_ADDRESS(Lib, "AesXtsDecrypt");
    AesFunctions["-ocb-encrypt"] = GET_PROC_ADDRESS(Lib, "AesOcbEncrypt");
    AesFunctions["-ocb-decrypt"] = GET_PROC_ADDRESS(Lib, "AesOcbDecrypt");
    AesFunctions["-wrap-encrypt"] = GET_PROC_ADDRESS(Lib, "AesWrapEncrypt");
    AesFunctions["-wrap-decrypt"] = GET_PROC_ADDRESS(Lib, "AesWrapDecrypt");

    RandFunctions["-generate"] = GET_PROC_ADDRESS(Lib, "Generate");
    RandFunctions["-import"] = GET_PROC_ADDRESS(Lib, "Import");
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
        return 0;
    }

    if (!ParseArguments(argc, argv, mode, filePath, commands)) {
        ShowUsage();
        return 1;
    }

    auto timeStart = std::chrono::high_resolution_clock::now();

    if (!Lib) {
        std::cerr << Error("Failed to load Ais.IO library\n");
        return 1;
    }

    LoadFunctions();

    if (mode == "--read") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRead(reader, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Read Action Completed!") << std::endl;
    }
    else if (mode == "--write") {
        void* writer = ((CreateBinaryWriter)GET_PROC_ADDRESS(Lib, "CreateBinaryWriter"))(filePath.c_str());
        if (!writer) {
            std::cerr << Error("Failed to create binary writer for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteWrite(writer, commands);
        ((DestroyBinaryWriter)GET_PROC_ADDRESS(Lib, "DestroyBinaryWriter"))(writer);
        std::cout << Mark("Write Action Completed!") << std::endl;
    }
    else if (mode == "--append") {
        void* appender = ((CreateBinaryAppender)GET_PROC_ADDRESS(Lib, "CreateBinaryAppender"))(filePath.c_str());
        if (!appender) {
            std::cerr << Error("Failed to create binary appender for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteAppend(appender, commands);
        ((DestroyBinaryAppender)GET_PROC_ADDRESS(Lib, "DestroyBinaryAppender"))(appender);
        std::cout << Mark("Append Action Completed!") << std::endl;
    }
    else if (mode == "--insert") {
        void* inserter = ((CreateBinaryInserter)GET_PROC_ADDRESS(Lib, "CreateBinaryInserter"))(filePath.c_str());
        if (!inserter) {
            std::cerr << Error("Failed to create binary inserter for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteInsert(inserter, commands);
        ((DestroyBinaryInserter)GET_PROC_ADDRESS(Lib, "DestroyBinaryInserter"))(inserter);
        std::cout << Mark("Insert Action Completed!") << std::endl;
    }
    else if (mode == "--remove") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRemove(reader, filePath, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Remove Action Completed!") << std::endl;
    }
    else if (mode == "--remove-index") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        void* remover = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader || !remover) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRemoveIndex(reader, remover, filePath, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(remover);
        std::cout << Mark("Remove Action Completed!") << std::endl;
    }
    else if (mode == "--read-all") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        uint64_t count = 0;
        std::string message = "";
        while (((GetReaderPosition)GET_PROC_ADDRESS(Lib, "GetReaderPosition"))(reader) < ((GetReaderLength)GET_PROC_ADDRESS(Lib, "GetReaderLength"))(reader)) {
            BINARYIO_TYPE type = ((ReadType)GET_PROC_ADDRESS(Lib, "ReadType"))(reader);
            binary_execute::ReadToType(reader, type, count, message);
        }
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        std::cout << message << std::endl;
        std::cout << Mark("Read All Action Completed!") << std::endl;
    }
    else if (mode == "--indexes") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader indexes for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::GetIndexes(reader);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        std::cout << Mark("Indexes Action Completed!") << std::endl;
    }
    else if (mode == "--base16" || mode == "--base32" || mode == "--base64" || mode == "--base85") {
        Command cmd = commands[0];
        std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
        if (commands.empty()) {
            std::cerr << "No encoding or decoding command provided.\n";
            std::cerr << Error("No encoding or decoding command provided.\n");
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        if (EncodeFunctions.find(encodeType) == EncodeFunctions.end()) {
            std::cerr << Error("Unsupported encode/decode operation: ") << Ask(cmd.type) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        encoder_execute::ExecuteEncoder(mode, cmd);
    }
    else if (mode == "--aes") {
        Aes aes;
        aes_execute::ParseParameters(argc, argv, aes);
        aes_execute::AesStart(aes);
    }
    else if (mode == "--generate" || mode == "--import") {
        Rand rand;
        cryptography_libary::ParseParameters(argc, argv, rand);
        cryptography_libary::RandStart(rand);
    }

    UNLOAD_LIBRARY(Lib);
    auto timeEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> seconds = timeEnd - timeStart;
    std::ostringstream oss;
    oss.precision(16);
    oss << std::defaultfloat << seconds.count();
    std::cout << Any("Elapsed time: " + oss.str() + " Seconds", TERMINAL_STYLE::STYLE_UNDERLINE, 33) << std::endl;
    return 0;
}
