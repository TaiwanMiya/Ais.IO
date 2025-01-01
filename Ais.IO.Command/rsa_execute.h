#pragma once
#include "main.h"

class rsa_execute {
public:
	static RSA_CRYPT_OPTIONS GetOption(int& i, char* argv[]);
	static void ParseParameters(int argc, char* argv[], Rsa& rsa);
	static void RsaStart(Rsa& rsa);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

