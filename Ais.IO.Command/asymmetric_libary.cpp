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

CRYPT_OPTIONS asymmetric_libary::GetOption(ASYMMETRIC_KEY_FORMAT& format, int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
	case hash("-der"):
		format = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER;
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
		format = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
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

void asymmetric_libary::ParseAlgorithm(int& i, char* argv[], SYMMETRY_CRYPTER& crypter, int& size, SEGMENT_SIZE_OPTION& segment) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (asymmetric_libary::set_hash(arg_option.c_str())) {
	case hash("-aes"):
		i++;
		if (argv[i + 1] == NULL)
			return;
		arg_option = ToLower(argv[i + 1]);
		switch (asymmetric_libary::set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-ctr"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_CTR;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-cbc"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_CBC;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-cfb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_CFB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
				switch (asymmetric_libary::set_hash(ToLower(argv[i + 1]).c_str())) {
				case hash("1"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
					i++;
					break;
				case hash("8"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
					i++;
					break;
				case hash("128"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
					i++;
					break;
				default:
					segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
					i++;
					break;
				}
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
				i++;
			}
			break;
		case hash("-ofb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_OFB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-ecb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_ECB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-gcm"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_GCM;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-ccm"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_CCM;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-xts"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_XTS;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-ocb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_OCB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		case hash("-wrap"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_AES_WRAP;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 256;
			else {
				size = 256;
				i++;
			}
			break;
		default:break;
		}
		break;
	case hash("-des"):
		i++;
		switch (asymmetric_libary::set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-cbc"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_DES_CBC;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 192;
			else {
				size = 192;
				i++;
			}
			break;
		case hash("-cfb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_DES_CFB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
				switch (asymmetric_libary::set_hash(ToLower(argv[i + 1]).c_str())) {
				case hash("1"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
					i++;
					break;
				case hash("8"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
					i++;
					break;
				case hash("128"):
					segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
					i++;
					break;
				default:
					segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
					i++;
					break;
				}
			}
			else if (argv[i + 1] == NULL)
				size = 192;
			else {
				size = 192;
				i++;
			}
			break;
		case hash("-ofb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_DES_OFB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 192;
			else {
				size = 192;
				i++;
			}
			break;
		case hash("-ecb"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_DES_ECB;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 192;
			else {
				size = 192;
				i++;
			}
			break;
		case hash("-wrap"):
			crypter = SYMMETRY_CRYPTER::SYMMETRY_DES_WRAP;
			i++;
			if (IsULong(argv[i + 1])) {
				size = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				size = 192;
			else {
				size = 192;
				i++;
			}
			break;
		default:break;
		}
		break;
	default:break;
	}
}