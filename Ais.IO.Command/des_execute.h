#pragma once
#include "main.h"

class des_execute {
public:
	static void ParseParameters(int argc, char* argv[], Des& crypt);
	static void DesStart(Des& des);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static bool GetCrypt(int& i, std::string arg, char* argv[], Des& des);
	static void EndHandling(std::vector<unsigned char>& result, Des& des);
	static void CbcEncrypt(std::vector<unsigned char>& result, Des& des);
	static void CbcDecrypt(std::vector<unsigned char>& result, Des& des);
	static void CfbEncrypt(std::vector<unsigned char>& result, Des& des);
	static void CfbDecrypt(std::vector<unsigned char>& result, Des& des);
	static void OfbEncrypt(std::vector<unsigned char>& result, Des& des);
	static void OfbDecrypt(std::vector<unsigned char>& result, Des& des);
	static void EcbEncrypt(std::vector<unsigned char>& result, Des& des);
	static void EcbDecrypt(std::vector<unsigned char>& result, Des& des);
	static void WrapEncrypt(std::vector<unsigned char>& result, Des& des);
	static void WrapDecrypt(std::vector<unsigned char>& result, Des& des);
};

