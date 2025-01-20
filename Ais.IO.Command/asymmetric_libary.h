#pragma once

#include "main.h"

class asymmetric_libary {
public:
	static CRYPT_OPTIONS GetOption(Rsa& rsa, int& i, char* argv[]);
	static CRYPT_OPTIONS GetOption(Dsa& rsa, int& i, char* argv[]);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
};

