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
	static void ExportParamters(Dsa& dsa);
	static void ExportKeys(Dsa& dsa);
	static void ExtractPublicKey(Dsa& dsa);
	static void ExtractParametersByKeys(Dsa& dsa);
	static void ExtractKeysByParameters(Dsa& dsa);
	static void CheckPublicKey(Dsa& dsa);
	static void CheckPrivateKey(Dsa& dsa);
	static void CheckParameters(Dsa& dsa);
	static void Signed(Dsa& dsa);
	static void Verify(Dsa& dsa);
};

