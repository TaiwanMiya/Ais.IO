#pragma once
#include "main.h"
#include "output_colors.h"
#include "string_case.h"
#include <cstring>

class encoder_execute {
public:
	static void ExecuteEncoder(const std::string mode, Command& cmd);
private:
	static void SetInput(Command& cmd, size_t& size, std::vector<unsigned char>& buffer);
	static void SetOutput(Command& cmd, size_t size, std::vector<unsigned char>& buffer);
};

