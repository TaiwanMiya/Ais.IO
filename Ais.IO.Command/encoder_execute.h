#pragma once
#include "main.h"
#include "output_colors.h"
#include "string_case.h"
#include <cstring>

class encoder_execute {
public:
	static void ExecuteEncoder(const std::string mode, Command& cmd);
	static size_t CalculateEncodeLength(const std::string& mode, size_t length);
	static size_t CalculateDecodeLength(const std::string& mode, size_t length);
	static size_t CalculateEncodeLength(const CRYPT_OPTIONS mode, size_t length);
	static size_t CalculateDecodeLength(const CRYPT_OPTIONS mode, size_t length);
private:
	static void SetInput(Command& cmd, size_t& size, std::vector<unsigned char>& buffer);
	static void SetOutput(Command& cmd, size_t size, std::vector<unsigned char>& buffer);
};

