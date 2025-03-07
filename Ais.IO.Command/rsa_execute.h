#pragma once
#include "main.h"
#include <regex>

class rsa_execute {
public:
	static void ParseParameters(int argc, char* argv[], Rsa& rsa);
	static void RsaStart(Rsa& rsa);
private:
	static constexpr size_t hash(const char* str);
	static size_t set_hash(const char* str);
	static void GenerateParameters(Rsa& rsa);
	static void GenerateKeys(Rsa& rsa);
	static void GenerateCSR(Rsa& rsa);
	static void GenerateCA(Rsa& rsa);
	static void ExportParamters(Rsa& rsa);
	static void ExportKeys(Rsa& rsa);
	static void ExtractPublicKey(Rsa& rsa);
	static void ExtractCSR(Rsa& rsa);
	static void CheckPublicKey(Rsa& rsa);
	static void CheckPrivateKey(Rsa& rsa);
	static void CheckCSR(Rsa& rsa);
	static void PemLock(Rsa& rsa);
	static void PemUnlock(Rsa& rsa);
	static void Encrypt(Rsa& rsa);
	static void Decrypt(Rsa& rsa);
	static void Signed(Rsa& rsa);
	static void Verify(Rsa& rsa);
	static void SignCertificate(Rsa& rsa);
};
