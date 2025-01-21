#pragma once

#include "main.h"

class asymmetric_libary {
public:
	static CRYPT_OPTIONS GetOption(ASYMMETRIC_KEY_FORMAT& format, int& i, char* argv[]);
	static void ParseAlgorithm(int& i, char* argv[], SYMMETRY_CRYPTER& crypter, int& size, SEGMENT_SIZE_OPTION& segment);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

