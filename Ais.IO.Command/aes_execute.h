#pragma once
#include "main.h"
#include <functional>

class aes_execute
{
public:
	static void ParseParameters(int argc, char* argv[], Aes& crypt);
	static void AesStart(Aes& aes);
private:
	static CRYPT_OPTIONS GetOption(int& i, char* argv[], Aes& crypt);
	static bool GetCrypt(int& i, std::string arg, char* argv[], Aes& crypt);
};

