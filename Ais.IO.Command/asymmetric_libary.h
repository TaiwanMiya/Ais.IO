#pragma once

#include "main.h"

class asymmetric_libary {
public:
	static CRYPT_OPTIONS GetOption(ASYMMETRIC_KEY_FORMAT& format, int& i, char* argv[]);
	static void ParseAlgorithm(int& i, char* argv[], SYMMETRY_CRYPTER& crypter, int& size, SEGMENT_SIZE_OPTION& segment);
	static void GetCsrSAN(int& i, char* argv[], int argc, std::string& san);
	static void GetCsrKeyUsage(int& i, char* argv[], int argc, ASYMMETRIC_KEY_CSR_KEY_USAGE& usage);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

