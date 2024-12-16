#pragma once
#include "main.h"

class aes_execute {
public:
	static void ParseParameters(int argc, char* argv[], Aes& crypt);
	static void AesStart(Aes& aes);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static bool GetCrypt(int& i, std::string arg, char* argv[], Aes& aes);
	static void EndHandling(std::vector<unsigned char>& result, Aes& aes);
	static void CtrEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CtrDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CbcEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CbcDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CfbEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CfbDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void OfbEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void OfbDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void EcbEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void EcbDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void GcmEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void GcmDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CcmEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void CcmDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void XtsEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void XtsDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void OcbEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void OcbDecrypt(std::vector<unsigned char>& result, Aes& aes);
	static void WrapEncrypt(std::vector<unsigned char>& result, Aes& aes);
	static void WrapDecrypt(std::vector<unsigned char>& result, Aes& aes);
};

