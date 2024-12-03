#pragma once

#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <string>
#include <vector>

struct Command {
    std::string mode;
    std::string type;
    std::string value;

    std::string path;
};

void ShowUsage();
bool ParseArguments(int argc, char* argv[], std::vector<Command>& commands);

// Binary
extern std::unordered_set<std::string> BinaryMode;
extern std::unordered_set<std::string> ValidOptions;

// BaseEncoding
extern std::unordered_set<std::string> BaseEncodingMode;
extern std::unordered_set<std::string> EncodeDecodeOptions;