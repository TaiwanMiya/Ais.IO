#pragma once
#include "main.h"
#include <regex>

class dsa_execute {
public:
	static void ParseParameters(int argc, char* argv[], Dsa& dsa);
	static void DsaStart(Dsa& dsa);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static void GenerateParameters(Dsa& dsa);
	static void GenerateKeys(Dsa& dsa);
};

