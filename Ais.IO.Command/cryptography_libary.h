#pragma once

#include "main.h"

class cryptography_libary {
public:
	static size_t CalculateEncodeLength(const std::string& mode, size_t length);
	static size_t CalculateDecodeLength(const std::string& mode, size_t length);
	static size_t CalculateEncodeLength(const CRYPT_OPTIONS mode, size_t length);
	static size_t CalculateDecodeLength(const CRYPT_OPTIONS mode, size_t length);
	static CRYPT_OPTIONS GetOption(int& i, char* argv[]);
	static void ValueEncode(const CRYPT_OPTIONS option, std::string input, std::vector<unsigned char>& output);
	static void ValueDecode(const CRYPT_OPTIONS option, std::vector<unsigned char> input, std::string& output);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

