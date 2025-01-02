#pragma once
#include "main.h"
#include <regex>

class rsa_execute {
public:
	static CRYPT_OPTIONS GetOption(Rsa& rsa, int& i, char* argv[]);
	static void ParseParameters(int argc, char* argv[], Rsa& rsa);
	static void RsaStart(Rsa& rsa);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static void GenerateParameters(Rsa& rsa);
	static void GenerateKeys(Rsa& rsa);
	static void ExportParamters(Rsa& rsa);
	static void ExportKeys(Rsa& rsa);
};
