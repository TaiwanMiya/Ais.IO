#include <locale.h>
#include <algorithm>
#include "main.h"
#include "string_case.h"
#include "output_colors.h"
#include "binary_execute.h"
#include "encoder_execute.h"
#include "cryptography_libary.h"
#include "mapping_libary.h"
#include "aes_execute.h"
#include "des_execute.h"
#include "hash_execute.h"
#include "usage_libary.h"
#include "rsa_execute.h"
#include "dsa_execute.h"

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
std::unordered_map<std::string, void*> SymmetryFunctions;
std::unordered_map<std::string, void*> AesFunctions;
std::unordered_map<std::string, void*> DesFunctions;
std::unordered_map<std::string, void*> HashFunctions;
std::unordered_map<std::string, void*> DsaFunctions;
std::unordered_map<std::string, void*> RsaFunctions;
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
std::unordered_map<std::string, DES_MODE> DesMode = {
    {"-cbc", DES_MODE::DES_CBC },
    {"-cfb", DES_MODE::DES_CFB },
    {"-ofb", DES_MODE::DES_OFB },
    {"-ecb", DES_MODE::DES_ECB },
    {"-wrap", DES_MODE::DES_WRAP },
};
std::unordered_map<DES_MODE, std::string> DesDisplay = {
    { DES_MODE::DES_CBC, "CBC" },
    { DES_MODE::DES_CFB, "CFB" },
    { DES_MODE::DES_OFB, "OFB" },
    { DES_MODE::DES_ECB, "ECB" },
    { DES_MODE::DES_WRAP, "WRAP" },
};
std::unordered_map<std::string, HASH_TYPE> HashMode = {
    { "-md5", HASH_TYPE::HASH_MD5 },
    { "-md5-sha1", HASH_TYPE::HASH_MD5_SHA1 },
    { "-sha1", HASH_TYPE::HASH_SHA1 },
    { "-sha2-224", HASH_TYPE::HASH_SHA2_224 },
    { "-sha2-256", HASH_TYPE::HASH_SHA2_256 },
    { "-sha2-384", HASH_TYPE::HASH_SHA2_384 },
    { "-sha2-512", HASH_TYPE::HASH_SHA2_512 },
    { "-sha224", HASH_TYPE::HASH_SHA2_224 },
    { "-sha256", HASH_TYPE::HASH_SHA2_256 },
    { "-sha384", HASH_TYPE::HASH_SHA2_384 },
    { "-sha512", HASH_TYPE::HASH_SHA2_512 },
    { "-sha2-512-224", HASH_TYPE::HASH_SHA2_512_224 },
    { "-sha2-512-256", HASH_TYPE::HASH_SHA2_512_256 },
    { "-sha512-224", HASH_TYPE::HASH_SHA2_512_224 },
    { "-sha512-256", HASH_TYPE::HASH_SHA2_512_256 },
    { "-sha3-224", HASH_TYPE::HASH_SHA3_224 },
    { "-sha3-256", HASH_TYPE::HASH_SHA3_256 },
    { "-sha3-384", HASH_TYPE::HASH_SHA3_384 },
    { "-sha3-512", HASH_TYPE::HASH_SHA3_512 },
    { "-sha3-ke-128", HASH_TYPE::HASH_SHA3_KE_128 },
    { "-sha3-ke-256", HASH_TYPE::HASH_SHA3_KE_256 },
    { "-shake128", HASH_TYPE::HASH_SHA3_KE_128 },
    { "-shake256", HASH_TYPE::HASH_SHA3_KE_256 },
    { "-blake2s-256", HASH_TYPE::HASH_BLAKE2S_256 },
    { "-blake2b-512", HASH_TYPE::HASH_BLAKE2B_512 },
    { "-blake2s", HASH_TYPE::HASH_BLAKE2S_256 },
    { "-blake2b", HASH_TYPE::HASH_BLAKE2B_512 },
    { "-blake256", HASH_TYPE::HASH_BLAKE2S_256 },
    { "-blake512", HASH_TYPE::HASH_BLAKE2B_512 },
    { "-sm3", HASH_TYPE::HASH_SM3 },
    { "-ripemd160", HASH_TYPE::HASH_RIPEMD160 },
};
std::unordered_map<HASH_TYPE, std::string> HashDisplay = {
    { HASH_TYPE::HASH_MD5, "MD5"},
    { HASH_TYPE::HASH_MD5_SHA1, "MD5 & SHA1"},
    { HASH_TYPE::HASH_SHA1, "SHA1"},
    { HASH_TYPE::HASH_SHA2_224, "SHA2-224"},
    { HASH_TYPE::HASH_SHA2_256, "SHA2-256"},
    { HASH_TYPE::HASH_SHA2_384, "SHA2-384"},
    { HASH_TYPE::HASH_SHA2_512, "SHA2-512"},
    { HASH_TYPE::HASH_SHA2_512_224, "SHA2-512 & 224"},
    { HASH_TYPE::HASH_SHA2_512_256, "SHA2-512 & 256"},
    { HASH_TYPE::HASH_SHA3_224, "SHA3-224"},
    { HASH_TYPE::HASH_SHA3_256, "SHA3-256"},
    { HASH_TYPE::HASH_SHA3_384, "SHA3-384"},
    { HASH_TYPE::HASH_SHA3_512, "SHA3-512"},
    { HASH_TYPE::HASH_SHA3_KE_128, "SHA3-KE-128"},
    { HASH_TYPE::HASH_SHA3_KE_256, "SHA3-KE-256"},
    { HASH_TYPE::HASH_BLAKE2S_256, "BLAKE2S-256"},
    { HASH_TYPE::HASH_BLAKE2B_512, "BLAKE2B-512"},
    { HASH_TYPE::HASH_SM3, "SM3"},
    { HASH_TYPE::HASH_RIPEMD160, "RIPEMD160"},
};

void PutBaseOptions(char* argv[], std::unordered_map<std::string, std::string> abbreviationValidBytesOptions, std::string& filePath, CRYPT_OPTIONS& option) {
    std::string byte_option = ToLower(argv[2]);
    if (abbreviationValidBytesOptions.count(byte_option))
        byte_option = abbreviationValidBytesOptions[byte_option];
    if      (byte_option == "-base10")
        option = CRYPT_OPTIONS::OPTION_BASE10;
    else if (byte_option == "-base16")
        option = CRYPT_OPTIONS::OPTION_BASE16;
    else if (byte_option == "-base32")
        option = CRYPT_OPTIONS::OPTION_BASE32;
    else if (byte_option == "-base58")
        option = CRYPT_OPTIONS::OPTION_BASE58;
    else if (byte_option == "-base62")
        option = CRYPT_OPTIONS::OPTION_BASE62;
    else if (byte_option == "-base64")
        option = CRYPT_OPTIONS::OPTION_BASE64;
    else if (byte_option == "-base85")
        option = CRYPT_OPTIONS::OPTION_BASE85;
    else if (byte_option == "-base91")
        option = CRYPT_OPTIONS::OPTION_BASE91;
    else {
        option = CRYPT_OPTIONS::OPTION_TEXT;
        filePath = argv[2];
        return;
    }
    filePath = argv[3];
}

bool ParseArguments(int argc, char* argv[], std::string& mode, std::string& filePath, CRYPT_OPTIONS& option, std::vector<Command>& commands) {
    if (argc < 3) {
        return false;
    }

    std::unordered_set<std::string> validMode = {
        "--help",
        "--map",
        "--indexes", "--read-all", "--read", "--write", "--append", "--insert", "--remove", "--remove-index", "--read-index",
        "--base10", "--base16", "--base32", "--base58", "--base62", "--base64", "--base85", "--base91",
        "--generate", "--convert", "--aes", "--des", "--hash", "--dsa", "--rsa"
    };

    std::unordered_map<std::string, std::string> abbreviationValidMode = {
        {"-help", "--help"}, {"-h", "--help"},
        {"-m", "--map"},
        {"-id", "--indexes"}, {"-rl", "--read-all"}, {"-r", "--read"}, {"-w", "--write"}, {"-a", "--append"}, {"-i", "--insert"}, {"-rm", "--remove"}, {"-rs", "--remove-index"}, {"-ri", "--read-index"},
        {"-b10", "--base10"}, {"-b16", "--base16"}, {"-b32", "--base32"}, {"-b58", "--base58"}, {"-b62", "--base62"}, {"-b64", "--base64"}, {"-b85", "--base85"}, {"-b91", "--base91"},
        {"-gen", "--generate"}, {"-conv", "--convert"}, {"-aes", "--aes"}, {"-des", "--des"}, {"-hash", "--hash"}, {"-dsa", "--dsa"}, {"-rsa", "--rsa"}
    };

    std::unordered_set<std::string> validHelper = {
        "-binary", "-base", "-aes", "-des", "-hash", "-dsa", "-rsa"
    };

    std::unordered_map<std::string, std::string> abbreviationValidHelper = {
        {"-bin", "-binary"}, {"-b", "-base"}, {"-a", "-aes"}, {"-d", "-des"}, {"-h", "-hash"}, {"-ds", "-dsa"}, {"-r", "-rsa"}
    };

    std::unordered_set<std::string> validBytesOptions = {
        "-base10", "-base16", "-base32", "-base58", "-base62", "-base64", "-base85", "-base91"
    };

    std::unordered_map<std::string, std::string> abbreviationValidBytesOptions = {
        {"-b10", "-base10"}, {"-b16", "-base16"}, {"-b32", "-base32"}, {"-b58", "-base58"}, {"-b62", "-base62"}, {"-b64", "-base64"}, {"-b85", "-base85"}, {"-b91", "-base91"}
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
        "-file", "-output"
    };

    std::unordered_map<std::string, std::string> abbreviationIoOptions = {
        {"-f", "-file"}, {"-out", "-output"}
    };

    std::unordered_set<std::string> settingsOptions = {
        "-pure"
    };

    mode = ToLower(argv[1]);

    if (abbreviationValidMode.count(mode)) {
        mode = abbreviationValidMode[mode];
    }

    if (!validMode.count(mode)) {
        std::cerr << Error("Invalid mode: ") << Ask(mode) << std::endl;
        return false;
    }

    if (mode == "--help") {
        if (argc > 2) {
            std::string helper = ToLower(argv[2]);
            if (abbreviationValidHelper.count(helper)) {
                helper = abbreviationValidHelper[helper];
            }
            if (!validHelper.count(helper))
                usage_libary::ShowUsage();
            if (helper == "-binary")
                usage_libary::ShowBinaryUsage();
            if (helper == "-base")
                usage_libary::ShowBaseUsage();
            if (helper == "-aes")
                usage_libary::ShowAesUsage();
            if (helper == "-des")
                usage_libary::ShowDesUsage();
            if (helper == "-hash")
                usage_libary::ShowHashUsage();
            if (helper == "-dsa")
                usage_libary::ShowDsaUsage();
            if (helper == "-rsa")
                usage_libary::ShowRsaUsage();
            exit(0);
        }
        else {
            usage_libary::ShowUsage();
            exit(0);
        }
    }

    for (int i = 1; i < argc; ++i) {
        if (ToLower(std::string(argv[i])) == "-row") {
            IsRowData = true;
            break;
        }
    }

    if (mode == "--map") {
        if (argc < 3)
            return false;
        filePath = argv[2];
    }
    else if (mode == "--read" || mode == "--write" || mode == "--append") {
        if (argc < 4)
            return false;
        PutBaseOptions(argv, abbreviationValidBytesOptions, filePath, option);

        Command cmd;
        int start = option == CRYPT_OPTIONS::OPTION_TEXT ? 3 : 4;
        for (int i = start; i < argc; ++i) {
            std::string arg = argv[i];
            if (ToLower(arg) == "-row")
                continue;
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
        PutBaseOptions(argv, abbreviationValidBytesOptions, filePath, option);

        Command cmd;
        int start = option == CRYPT_OPTIONS::OPTION_TEXT ? 3 : 4;
        for (int i = start; i < argc; ++i) {
            std::string arg = argv[i];
            if (ToLower(arg) == "-row")
                continue;
            if (validOptions.count(ToLower(arg))) {
                if (!cmd.type.empty()) {
                    commands.push_back(cmd);
                    cmd = Command{};
                }
                cmd.type = ToLower(arg);
            }
            else if (IsULong(arg) && (i - (start - 1)) % 3 == 0) {
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
            if (ToLower(arg) == "-row" || ToLower(arg2) == "-row")
                continue;
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
    else if (mode == "--read-index" || mode == "--remove-index") {
        if (argc < 3)
            return false;
        PutBaseOptions(argv, abbreviationValidBytesOptions, filePath, option);

        Command cmd;
        int start = option == CRYPT_OPTIONS::OPTION_TEXT ? 3 : 4;
        for (int i = start; i < argc; ++i) {
            std::string arg = argv[i];
            std::replace(arg.begin(), arg.end(), ' ', '\0');
            if (ToLower(arg) == "-row")
                continue;
            if (arg.find('~') != std::string::npos) {
                size_t pos = arg.find('~');
                std::string startStr = arg.substr(0, pos);
                std::string endStr = arg.substr(pos + 1);

                if (IsULong(startStr) && IsULong(endStr)) {
                    unsigned long start = std::stoul(startStr);
                    unsigned long end = std::stoul(endStr);

                    if (start <= end) {
                        for (unsigned long val = start; val <= end; ++val) {
                            cmd.value = std::to_string(val);
                            commands.push_back(cmd);
                        }
                    }
                    else {
                        std::cerr << Error("Invalid range: ") << Ask(arg) << "\n";
                        return false;
                    }
                }
                else {
                    std::cerr << Error("Invalid range format: ") << Ask(arg) << "\n";
                    return false;
                }
            }
            else if (arg.find('*') != std::string::npos && arg.find('+') == std::string::npos) {
                size_t pos = arg.find('*');
                std::string baseStr = arg.substr(0, pos);
                std::string countStr = arg.substr(pos + 1);

                if (IsULong(baseStr) && IsULong(countStr)) {
                    unsigned long base = std::stoul(baseStr);
                    unsigned long count = std::stoul(countStr);
                    for (unsigned long i = 1; i <= count; ++i) {
                        cmd.value = std::to_string(base * i);
                        commands.push_back(cmd);
                    }
                }
                else {
                    std::cerr << Error("Invalid sequence format: ") << Ask(arg) << "\n";
                    return false;
                }
            }
            else if (arg.find('+') != std::string::npos && arg.find('*') != std::string::npos) {
                size_t plusPos = arg.find('+');
                size_t starPos = arg.find('*');

                std::string startStr = arg.substr(0, plusPos);
                std::string stepStr = arg.substr(plusPos + 1, starPos - plusPos - 1);
                std::string countStr = arg.substr(starPos + 1);

                if (IsULong(startStr) && IsULong(stepStr) && IsULong(countStr)) {
                    unsigned long start = std::stoul(startStr);
                    unsigned long step = std::stoul(stepStr);
                    unsigned long count = std::stoul(countStr);

                    for (unsigned long i = 0; i < count; ++i) {
                        cmd.value = std::to_string(start + i * step);
                        commands.push_back(cmd);
                    }
                }
                else {
                    std::cerr << Error("Invalid sequence format: ") << Ask(arg) << "\n";
                    return false;
                }
            }
            else if (IsULong(arg)) {
                cmd.value = arg;
                commands.push_back(cmd);
            }
            else {
                std::cerr << Error("Value without type: ") << Ask(arg) << "\n";
                return false;
            }
        }
        if (mode == "--read-index") {
            std::sort(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
                return std::stoull(a.value) < std::stoull(b.value);
                });
            auto last = std::unique(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
                return a.value == b.value;
                });
            commands.erase(last, commands.end());
        }
        if (mode == "--remove-index") {
            std::sort(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
                return std::stoull(a.value) > std::stoull(b.value);
                });
            auto last = std::unique(commands.begin(), commands.end(), [](const Command& a, const Command& b) {
                return a.value == b.value;
                });
            commands.erase(last, commands.end());
        }
    }
    else if (mode == "--read-all" || mode == "--indexes") {
        if (argc < 3)
            return false;
        PutBaseOptions(argv, abbreviationValidBytesOptions, filePath, option);
    }
    else if (mode == "--base10" || mode == "--base16" || mode == "--base32" || mode == "--base58" ||
             mode == "--base62" || mode == "--base64" || mode == "--base85" || mode == "--base91") {
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
            if (ToLower(arg) == "-row")
                continue;
            if (arg == "-file") {
                if (i + 1 >= argc) {
                    std::cerr << Error("Missing input file path after -file.") << std::endl;
                    return false;
                }
                cmd.input = argv[++i];
            }
            else if (arg == "-output") {
                if (i + 1 >= argc) {
                    std::cerr << Error("Missing output file path after -output.") << std::endl;
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
    ReadFunctions["-create"] = GET_PROC_ADDRESS(Lib, "CreateBinaryReader");
    ReadFunctions["-destory"] = GET_PROC_ADDRESS(Lib, "DestroyBinaryReader");
    ReadFunctions["-position"] = GET_PROC_ADDRESS(Lib, "GetReaderPosition");
    ReadFunctions["-length"] = GET_PROC_ADDRESS(Lib, "GetReaderLength");
    ReadFunctions["-type"] = GET_PROC_ADDRESS(Lib, "ReadType");
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

    WriteFunctions["-create"] = GET_PROC_ADDRESS(Lib, "CreateBinaryWriter");
    WriteFunctions["-destory"] = GET_PROC_ADDRESS(Lib, "DestroyBinaryWriter");
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

    AppendFunctions["-create"] = GET_PROC_ADDRESS(Lib, "CreateBinaryAppender");
    AppendFunctions["-destory"] = GET_PROC_ADDRESS(Lib, "DestroyBinaryAppender");
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

    InsertFunctions["-create"] = GET_PROC_ADDRESS(Lib, "CreateBinaryInserter");
    InsertFunctions["-destory"] = GET_PROC_ADDRESS(Lib, "DestroyBinaryInserter");
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

    EncodeFunctions["-base10-length"] = GET_PROC_ADDRESS(Lib, "Base10Length");
    EncodeFunctions["-base16-length"] = GET_PROC_ADDRESS(Lib, "Base16Length");
    EncodeFunctions["-base32-length"] = GET_PROC_ADDRESS(Lib, "Base32Length");
    EncodeFunctions["-base58-length"] = GET_PROC_ADDRESS(Lib, "Base58Length");
    EncodeFunctions["-base62-length"] = GET_PROC_ADDRESS(Lib, "Base62Length");
    EncodeFunctions["-base64-length"] = GET_PROC_ADDRESS(Lib, "Base64Length");
    EncodeFunctions["-base85-length"] = GET_PROC_ADDRESS(Lib, "Base85Length");
    EncodeFunctions["-base91-length"] = GET_PROC_ADDRESS(Lib, "Base91Length");
    EncodeFunctions["-base10-encode"] = GET_PROC_ADDRESS(Lib, "Base10Encode");
    EncodeFunctions["-base10-decode"] = GET_PROC_ADDRESS(Lib, "Base10Decode");
    EncodeFunctions["-base16-encode"] = GET_PROC_ADDRESS(Lib, "Base16Encode");
    EncodeFunctions["-base16-decode"] = GET_PROC_ADDRESS(Lib, "Base16Decode");
    EncodeFunctions["-base32-encode"] = GET_PROC_ADDRESS(Lib, "Base32Encode");
    EncodeFunctions["-base32-decode"] = GET_PROC_ADDRESS(Lib, "Base32Decode");
    EncodeFunctions["-base58-encode"] = GET_PROC_ADDRESS(Lib, "Base58Encode");
    EncodeFunctions["-base58-decode"] = GET_PROC_ADDRESS(Lib, "Base58Decode");
    EncodeFunctions["-base62-encode"] = GET_PROC_ADDRESS(Lib, "Base62Encode");
    EncodeFunctions["-base62-decode"] = GET_PROC_ADDRESS(Lib, "Base62Decode");
    EncodeFunctions["-base64-encode"] = GET_PROC_ADDRESS(Lib, "Base64Encode");
    EncodeFunctions["-base64-decode"] = GET_PROC_ADDRESS(Lib, "Base64Decode");
    EncodeFunctions["-base85-encode"] = GET_PROC_ADDRESS(Lib, "Base85Encode");
    EncodeFunctions["-base85-decode"] = GET_PROC_ADDRESS(Lib, "Base85Decode");
    EncodeFunctions["-base91-encode"] = GET_PROC_ADDRESS(Lib, "Base91Encode");
    EncodeFunctions["-base91-decode"] = GET_PROC_ADDRESS(Lib, "Base91Decode");

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

    DesFunctions["-cbc-encrypt"] = GET_PROC_ADDRESS(Lib, "DesCbcEncrypt");
    DesFunctions["-cbc-decrypt"] = GET_PROC_ADDRESS(Lib, "DesCbcDecrypt");
    DesFunctions["-cfb-encrypt"] = GET_PROC_ADDRESS(Lib, "DesCfbEncrypt");
    DesFunctions["-cfb-decrypt"] = GET_PROC_ADDRESS(Lib, "DesCfbDecrypt");
    DesFunctions["-ofb-encrypt"] = GET_PROC_ADDRESS(Lib, "DesOfbEncrypt");
    DesFunctions["-ofb-decrypt"] = GET_PROC_ADDRESS(Lib, "DesOfbDecrypt");
    DesFunctions["-ecb-encrypt"] = GET_PROC_ADDRESS(Lib, "DesEcbEncrypt");
    DesFunctions["-ecb-decrypt"] = GET_PROC_ADDRESS(Lib, "DesEcbDecrypt");
    DesFunctions["-wrap-encrypt"] = GET_PROC_ADDRESS(Lib, "DesWrapEncrypt");
    DesFunctions["-wrap-decrypt"] = GET_PROC_ADDRESS(Lib, "DesWrapDecrypt");

    HashFunctions["-hash"] = GET_PROC_ADDRESS(Lib, "Hash");
    HashFunctions["-hash-length"] = GET_PROC_ADDRESS(Lib, "GetHashLength");

    DsaFunctions["-param-length"] = GET_PROC_ADDRESS(Lib, "DsaGetParametersLength");
    DsaFunctions["-key-length"] = GET_PROC_ADDRESS(Lib, "DsaGetKeyLength");
    DsaFunctions["-param-gen"] = GET_PROC_ADDRESS(Lib, "DsaGenerateParameters");
    DsaFunctions["-key-gen"] = GET_PROC_ADDRESS(Lib, "DsaGenerateKeys");
    DsaFunctions["-param-export"] = GET_PROC_ADDRESS(Lib, "DsaExportParameters");
    DsaFunctions["-key-export"] = GET_PROC_ADDRESS(Lib, "DsaExportKeys");
    DsaFunctions["-key-extract-pub"] = GET_PROC_ADDRESS(Lib, "DsaExtractPublicKey");
    DsaFunctions["-key-extract-param"] = GET_PROC_ADDRESS(Lib, "DsaExtractParametersByKeys");
    DsaFunctions["-key-extract-key"] = GET_PROC_ADDRESS(Lib, "DsaExtractKeysByParameters");
    DsaFunctions["-pub-check"] = GET_PROC_ADDRESS(Lib, "DsaCheckPublicKey");
    DsaFunctions["-priv-check"] = GET_PROC_ADDRESS(Lib, "DsaCheckPrivateKey");
    DsaFunctions["-param-check"] = GET_PROC_ADDRESS(Lib, "DsaCheckParameters");
    DsaFunctions["-signed"] = GET_PROC_ADDRESS(Lib, "DsaSigned");
    DsaFunctions["-verify"] = GET_PROC_ADDRESS(Lib, "DsaVerify");

    RsaFunctions["-param-length"] = GET_PROC_ADDRESS(Lib, "RsaGetParametersLength");
    RsaFunctions["-key-length"] = GET_PROC_ADDRESS(Lib, "RsaGetKeyLength");
    RsaFunctions["-param-gen"] = GET_PROC_ADDRESS(Lib, "RsaGenerateParameters");
    RsaFunctions["-key-gen"] = GET_PROC_ADDRESS(Lib, "RsaGenerateKeys");
    RsaFunctions["-param-export"] = GET_PROC_ADDRESS(Lib, "RsaExportParameters");
    RsaFunctions["-key-export"] = GET_PROC_ADDRESS(Lib, "RsaExportKeys");
    RsaFunctions["-key-extract"] = GET_PROC_ADDRESS(Lib, "RsaExtractPublicKey");
    RsaFunctions["-pub-check"] = GET_PROC_ADDRESS(Lib, "RsaCheckPublicKey");
    RsaFunctions["-priv-check"] = GET_PROC_ADDRESS(Lib, "RsaCheckPrivateKey");
    RsaFunctions["-encrypt"] = GET_PROC_ADDRESS(Lib, "RsaEncryption");
    RsaFunctions["-decrypt"] = GET_PROC_ADDRESS(Lib, "RsaDecryption");
    RsaFunctions["-signed"] = GET_PROC_ADDRESS(Lib, "RsaSigned");
    RsaFunctions["-verify"] = GET_PROC_ADDRESS(Lib, "RsaVerify");

    SymmetryFunctions["-generate"] = GET_PROC_ADDRESS(Lib, "Generate");
    SymmetryFunctions["-convert"] = GET_PROC_ADDRESS(Lib, "Import");
}

bool FindFileInEnvPath(const std::string& filename, std::string& resolvedPath) {
#if _WIN32
    char* envPath = nullptr;
    size_t envPathSize = 0;

    if (_dupenv_s(&envPath, &envPathSize, "PATH") != 0 || envPath == nullptr) {
        std::cerr << "Environment variable PATH not found or failed to read.\n";
        return false;
    }

    std::string pathStr(envPath);
    free(envPath);

    std::stringstream pathStream(pathStr);
    std::string directory;

    while (std::getline(pathStream, directory, ';')) {
        std::filesystem::path potentialPath = std::filesystem::path(directory) / filename;
        if (std::filesystem::exists(potentialPath)) {
            resolvedPath = potentialPath.string();
            return true;
        }
    }

    return false;
#else
    const char* envPath = std::getenv("PATH");
    if (envPath == nullptr) {
        std::cerr << "Environment variable PATH not found or failed to read.\n";
        return false;
    }

    std::string pathStr(envPath);
    std::stringstream pathStream(pathStr);
    std::string directory;

    while (std::getline(pathStream, directory, ':')) {
        std::filesystem::path potentialPath = std::filesystem::path(directory) / filename;
        if (std::filesystem::exists(potentialPath)) {
            resolvedPath = potentialPath.string();
            return true;
        }
    }

    return false;
#endif
}

int main(int argc, char* argv[]) {
    std::string mode;
    std::string filePath;
    CRYPT_OPTIONS binary_bytes_option = CRYPT_OPTIONS::OPTION_TEXT;
    std::vector<Command> commands;

    CheckRedirects();

#if _WIN32
    EnableVirtualTerminalProcessing();
#endif

    if (argc == 3 && std::string(argv[1]) == "--path") {
        std::string resolvedPath = "";
        bool is_resolved = FindFileInEnvPath(argv[2], resolvedPath);
        if (is_resolved)
            std::cout << Hint("File found at: ") << Ask(resolvedPath) << std::endl;
        else
            std::cout << Error("File not found in PATH directories.") << std::endl;
        return 0;
    }

    if (argc == 2 && std::string(argv[1]) == "--colors") {
        ListColorTable();
        return 0;
    }

    if (argc >= 2 && std::string(argv[1]) == "--bar") {
        const int total = 100;
        int width = argc > 2 && IsULong(argv[2]) ? std::stoi(argv[2]) : 100;
        char strip = argc > 3 ? argv[3][0] : '=';
        bool show_current = argc > 4 && std::string(argv[4]) == "true" ? true: false;

        std::cout << "Start Progress Bar Running...\n" << std::endl;
        for (int i = 0; i <= total; ++i) {
            MoveCursorUp(1);
            ClearLine();
            std::cout << "Test:" << i << std::endl;
            ShowProgressBar(i, total, width, strip, show_current);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::cout << std::endl;
        return 0;
    }

    if (!ParseArguments(argc, argv, mode, filePath, binary_bytes_option, commands)) {
        usage_libary::ShowUsage();
        return 1;
    }

    auto timeStart = std::chrono::high_resolution_clock::now();

    if (!Lib) {
        std::cerr << Error("Failed to load Ais.IO library\n");
        return 1;
    }

    LoadFunctions();

    if (mode == "--map") {
        mapping_libary::ShowHexEditor(filePath.c_str());
    }
    else if (mode == "--read") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRead(reader, commands, binary_bytes_option);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        if (!IsRowData)
            std::cout << Mark("Read Action Completed!") << std::endl;
    }
    else if (mode == "--write") {
        void* writer = ((CreateBinaryWriter)GET_PROC_ADDRESS(Lib, "CreateBinaryWriter"))(filePath.c_str());
        if (!writer) {
            std::cerr << Error("Failed to create binary writer for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteWrite(writer, commands, binary_bytes_option);
        ((DestroyBinaryWriter)GET_PROC_ADDRESS(Lib, "DestroyBinaryWriter"))(writer);
        if (!IsRowData)
            std::cout << Mark("Write Action Completed!") << std::endl;
    }
    else if (mode == "--append") {
        void* appender = ((CreateBinaryAppender)GET_PROC_ADDRESS(Lib, "CreateBinaryAppender"))(filePath.c_str());
        if (!appender) {
            std::cerr << Error("Failed to create binary appender for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteAppend(appender, commands, binary_bytes_option);
        ((DestroyBinaryAppender)GET_PROC_ADDRESS(Lib, "DestroyBinaryAppender"))(appender);
        if (!IsRowData)
            std::cout << Mark("Append Action Completed!") << std::endl;
    }
    else if (mode == "--insert") {
        void* inserter = ((CreateBinaryInserter)GET_PROC_ADDRESS(Lib, "CreateBinaryInserter"))(filePath.c_str());
        if (!inserter) {
            std::cerr << Error("Failed to create binary inserter for file: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteInsert(inserter, commands, binary_bytes_option);
        ((DestroyBinaryInserter)GET_PROC_ADDRESS(Lib, "DestroyBinaryInserter"))(inserter);
        if (!IsRowData)
            std::cout << Mark("Insert Action Completed!") << std::endl;
    }
    else if (mode == "--remove") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRemove(reader, filePath, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        if (!IsRowData)
            std::cout << Mark("Remove Action Completed!") << std::endl;
    }
    else if (mode == "--remove-index") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        void* remover = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader || !remover) {
            std::cerr << Error("Failed to create binary reader for: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        binary_execute::ExecuteRemoveIndex(reader, remover, filePath, commands);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(remover);
        if (!IsRowData)
            std::cout << Mark("Remove Action Completed!") << std::endl;
    }
    else if (mode == "--read-all") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        uint64_t count = 0;
        std::string message = "";
        while (((GetReaderPosition)GET_PROC_ADDRESS(Lib, "GetReaderPosition"))(reader) < ((GetReaderLength)GET_PROC_ADDRESS(Lib, "GetReaderLength"))(reader)) {
            BINARYIO_TYPE type = ((ReadType)GET_PROC_ADDRESS(Lib, "ReadType"))(reader);
            binary_execute::ReadToType(reader, type, count, message, binary_bytes_option);
        }
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        message.erase(message.find_last_not_of("\n") + 1);
        std::cout << message << std::endl;
        if (!IsRowData)
            std::cout << Mark("Read All Action Completed!") << std::endl;
    }
    else if (mode == "--read-index") {
        void* reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        void* index_reader = ((CreateBinaryReader)GET_PROC_ADDRESS(Lib, "CreateBinaryReader"))(filePath.c_str());
        if (!reader) {
            std::cerr << Error("Failed to create binary reader for: ") << Ask(filePath) << "\n";
            UNLOAD_LIBRARY(Lib);
            return 1;
        }
        std::string message = "";
        binary_execute::ExecuteReadIndex(reader, index_reader, filePath, commands, message, binary_bytes_option);
        ((DestroyBinaryReader)GET_PROC_ADDRESS(Lib, "DestroyBinaryReader"))(reader);
        message.erase(message.find_last_not_of("\n") + 1);
        std::cout << message << std::endl;
        if (!IsRowData)
            std::cout << Mark("Read Action Completed!") << std::endl;
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
        if (!IsRowData)
            std::cout << Mark("Indexes Action Completed!") << std::endl;
    }
    else if (mode == "--base10" || mode == "--base16" || mode == "--base32" || mode == "--base58" ||
             mode == "--base62" || mode == "--base64" || mode == "--base85" || mode == "--base91") {
        Command cmd = commands[0];
        std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
        if (commands.empty()) {
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
    else if (mode == "--des") {
        Des des;
        des_execute::ParseParameters(argc, argv, des);
        des_execute::DesStart(des);
    }
    else if (mode == "--hash") {
        Hashes hash;
        hash_execute::ParseParameters(argc, argv, hash);
        hash_execute::HashStart(hash);
    }
    else if (mode == "--dsa") {
        Dsa dsa;
        dsa_execute::ParseParameters(argc, argv, dsa);
        dsa_execute::DsaStart(dsa);
    }
    else if (mode == "--rsa") {
        Rsa rsa;
        rsa_execute::ParseParameters(argc, argv, rsa);
        rsa_execute::RsaStart(rsa);
    }
    else if (mode == "--generate" || mode == "--convert") {
        Rand rand;
        cryptography_libary::ParseParameters(argc, argv, rand);
        cryptography_libary::RandStart(rand);
    }

    UNLOAD_LIBRARY(Lib);
    if (IsRowData)
        return 0;
    auto timeEnd = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> seconds = timeEnd - timeStart;
    std::ostringstream oss;
    oss.precision(16);
    oss << std::defaultfloat << seconds.count();
    std::cout << Any("Elapsed time: " + oss.str() + " Seconds", TERMINAL_STYLE::STYLE_UNDERLINE, 33) << std::endl;
    return 0;
}
