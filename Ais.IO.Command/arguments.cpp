#include "arguments.h"

std::unordered_set<std::string> BinaryMode = {
    "-write", "-read",
};

std::unordered_set<std::string> BinaryOptions = {
    "-bool", "-byte", "-sbyte", "-short", "-ushort", "-int", "-uint",
    "-long", "-ulong", "-float", "-double", "-bytes", "-string"
};

std::unordered_set<std::string> BaseEncodingMode = {
    "-base16", "-base32", "-base64", "-base85"
};

std::unordered_set<std::string> EncodeDecodeOptions = {
    "-encode", "-decode"
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

bool ParseArguments(int argc, char* argv[], std::vector<Command>& commands) {
    for (int i = 0; i < argc; ++i) {
        Command cmd;
        if (argc >= i + 2 && BinaryMode.count(argv[i]) && BinaryOptions.count(argv[i + 1]) && argv[i + 2] != NULL) {
            cmd.mode = argv[i];
            cmd.type = argv[i + 1];
            cmd.value = argv[i + 2];
            i += 2;
        }
        //if (argc >= i + 3)
    }
    return true;
}

bool ParseArgumentsTemp(int argc, char* argv[], std::string& mode, std::string& filePath, std::vector<Command>& commands) {
    if (argc < 3) {
        return false;
    }

    std::unordered_set<std::string> validMode = {
        "--write", "--read", "--base16", "--base32", "--base64", "--base85"
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