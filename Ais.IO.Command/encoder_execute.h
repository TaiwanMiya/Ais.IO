#pragma once
#include "main.h"
#include "output_colors.h"
#include "string_case.h"

class encoder_execute {
public:
	static void ExecuteEncoder(const std::string mode, Command& cmd);
private:
	static void SetInput(Command& cmd, size_t& size);
	static void SetOutput(Command& cmd, size_t size);
	static size_t CalculateOutputLength(const std::string& mode, size_t inputLength);
};

