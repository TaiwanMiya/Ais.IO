#include "asymmetric_libary.h"
#include "string_case.h"

constexpr size_t asymmetric_libary::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t asymmetric_libary::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

CRYPT_OPTIONS asymmetric_libary::GetOption(Rsa& rsa, int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
	case hash("-der"):
		rsa.KeyFormat = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER;
		i++;
		if (argv[i + 1] == NULL)
			return CRYPT_OPTIONS::OPTION_TEXT;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return CRYPT_OPTIONS::OPTION_FILE;
		case hash("-base10"):
		case hash("-b10"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE10;
		case hash("-base16"):
		case hash("-b16"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE16;
		case hash("-base32"):
		case hash("-b32"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE32;
		case hash("-base58"):
		case hash("-b58"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE58;
		case hash("-base62"):
		case hash("-b62"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE62;
		case hash("-base64"):
		case hash("-b64"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE64;
		case hash("-base85"):
		case hash("-b85"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE85;
		case hash("-base91"):
		case hash("-b91"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE91;
		default:
			return CRYPT_OPTIONS::OPTION_TEXT;
		}
	case hash("-pem"):
		rsa.KeyFormat = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
		i++;
		if (argv[i + 1] == NULL)
			return CRYPT_OPTIONS::OPTION_TEXT;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return CRYPT_OPTIONS::OPTION_FILE;
		default:
			return CRYPT_OPTIONS::OPTION_TEXT;
		}
	default:
		return CRYPT_OPTIONS::OPTION_TEXT;
	}
}

CRYPT_OPTIONS asymmetric_libary::GetOption(Dsa& rsa, int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
	case hash("-der"):
		rsa.KeyFormat = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER;
		i++;
		if (argv[i + 1] == NULL)
			return CRYPT_OPTIONS::OPTION_TEXT;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return CRYPT_OPTIONS::OPTION_FILE;
		case hash("-base10"):
		case hash("-b10"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE10;
		case hash("-base16"):
		case hash("-b16"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE16;
		case hash("-base32"):
		case hash("-b32"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE32;
		case hash("-base58"):
		case hash("-b58"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE58;
		case hash("-base62"):
		case hash("-b62"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE62;
		case hash("-base64"):
		case hash("-b64"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE64;
		case hash("-base85"):
		case hash("-b85"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE85;
		case hash("-base91"):
		case hash("-b91"):
			i++;
			return CRYPT_OPTIONS::OPTION_BASE91;
		default:
			return CRYPT_OPTIONS::OPTION_TEXT;
		}
	case hash("-pem"):
		rsa.KeyFormat = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
		i++;
		if (argv[i + 1] == NULL)
			return CRYPT_OPTIONS::OPTION_TEXT;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return CRYPT_OPTIONS::OPTION_FILE;
		default:
			return CRYPT_OPTIONS::OPTION_TEXT;
		}
	default:
		return CRYPT_OPTIONS::OPTION_TEXT;
	}
}