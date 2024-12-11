#include "aes_execute.h"
#include "string_case.h"

constexpr size_t hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

bool GetCrypt(int& i, std::string arg, char* argv[], Aes& crypt) {
	std::string arg_crypt = ToLower(argv[i + 1]);
	switch (std::hash<std::string>{}(arg_crypt)) {
	case hash("-encrypt"):
	case hash("-e"):
		crypt.Mode = arg;
		crypt.Crypt = "-encrypt";
		i++;
		return true;
	case hash("-decrypt"):
	case hash("-d"):
		crypt.Mode = arg;
		crypt.Crypt = "-decrypt";
		i++;
		return true;
	default:
		return false;
	}
}

CRYPT_OPTIONS GetOption(int& i, char* argv[], Aes& crypt) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (std::hash<std::string>{}(arg_option)) {
	case hash("-file"):
	case hash("-f"):
		i++;
		return CRYPT_OPTIONS::OPTION_FILE;
	case hash("-base16"):
	case hash("-b16"):
		i++;
		return CRYPT_OPTIONS::OPTION_BASE16;
	case hash("-base32"):
	case hash("-b32"):
		i++;
		return CRYPT_OPTIONS::OPTION_BASE32;
	case hash("-base64"):
	case hash("-b64"):
		i++;
		return CRYPT_OPTIONS::OPTION_BASE64;
	case hash("-base85"):
	case hash("-b85"):
		i++;
		return CRYPT_OPTIONS::OPTION_BASE85;
	default:
		i++;
		return CRYPT_OPTIONS::OPTION_TEXT;
	}
}

void aes_execute::ParseParameters(int argc, char* argv[], Aes& crypt) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (std::hash<std::string>{}(arg)) {
		case hash("-ctr"):
		case hash("-cbc"):
		case hash("-cfb"):
		case hash("-ofb"):
		case hash("-ecb"):
		case hash("-gcm"):
		case hash("-ccm"):
		case hash("-xts"):
		case hash("-ocb"):
		case hash("-wrap"):
			if (!GetCrypt(i, arg, argv, crypt))
				return;
			break;
		case hash("-key"):
			crypt.key_option = GetOption(i, argv, crypt);
			if (crypt.key_option != CRYPT_OPTIONS::OPTION_TEXT) {
				crypt.Key = argv[i + 1];
				i++;
			}
			else
				crypt.Key = argv[i];
			break;
		case hash("-iv"):
			crypt.iv_option = GetOption(i, argv, crypt);
			if (crypt.iv_option != CRYPT_OPTIONS::OPTION_TEXT) {
				crypt.IV = argv[i + 1];
				i++;
			}
			else
				crypt.Key = argv[i];
			break;
		}
	}
}