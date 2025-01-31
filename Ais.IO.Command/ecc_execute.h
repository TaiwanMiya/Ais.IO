#pragma once
#include "main.h"
#include <regex>

class ecc_execute {
public:
	static void ParseParameters(int argc, char* argv[], Ecc& ecc);
	static void EccStart(Ecc& ecc);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static std::string ParseEccCurve(Ecc& ecc, bool isGetName);
	static void ListEccCurve(Ecc& ecc);
	static void GenerateParameters(Ecc& ecc);
	static void GenerateKeys(Ecc& ecc);
	static void ExportParamters(Ecc& ecc);
	static void ExportKeys(Ecc& ecc);
};
