#include "asymmetric_libary.h"
#include "string_case.h"
#include "cryptography_libary.h"
#include "output_colors.h"

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

void asymmetric_libary::GetCsrSAN(int& i, char* argv[], int argc, std::string& san) {
	for (i; i + 1< argc; ++i) {
		CRYPT_OPTIONS option = CRYPT_OPTIONS::OPTION_TEXT;
		bool isValid = false;
		std::vector<unsigned char> output;
		std::string arg_option = ToLower(argv[i + 1]);
		switch (asymmetric_libary::set_hash(arg_option.c_str())) {
		case hash("-dns"):
			i++;
			option = cryptography_libary::GetOption(i, argv);
			cryptography_libary::ValueDecode(option, std::string(argv[i + 1]), output);
			output.push_back('\0');
			isValid = ((IsValidDNS)CheckValidFunctions.at("-dns"))(reinterpret_cast<const char*>(output.data()));
			san += "DNS:";
			break;
		case hash("-ip"):
			i++;
			option = cryptography_libary::GetOption(i, argv);
			cryptography_libary::ValueDecode(option, std::string(argv[i + 1]), output);
			output.push_back('\0');
			isValid = ((IsValidIPv4)CheckValidFunctions.at("-ipv4"))(reinterpret_cast<const char*>(output.data())) ||
					  ((IsValidIPv6)CheckValidFunctions.at("-ipv6"))(reinterpret_cast<const char*>(output.data()));
			san += "IP:";
			break;
		case hash("-mail"):
		case hash("-email"):
			i++;
			option = cryptography_libary::GetOption(i, argv);
			cryptography_libary::ValueDecode(option, std::string(argv[i + 1]), output);
			output.push_back('\0');
			isValid = ((IsValidEmail)CheckValidFunctions.at("-email"))(reinterpret_cast<const char*>(output.data()));
			san += "email:";
			break;
		case hash("-uri"):
		case hash("-url"):
			i++;
			option = cryptography_libary::GetOption(i, argv);
			cryptography_libary::ValueDecode(option, std::string(argv[i + 1]), output);
			output.push_back('\0');
			isValid = ((IsValidURI)CheckValidFunctions.at("-uri"))(reinterpret_cast<const char*>(output.data()));
			san += "URI:";
			break;
		default:isValid = false;
		}
		if (isValid) {
			san += reinterpret_cast<const char*>(output.data());
			san += ",";
		}
		else
			break;
	}
	if (!san.empty() && san.back() == ',')
		san.pop_back();
}

void asymmetric_libary::GetCsrKeyUsage(int& i, char* argv[], int argc, ASYMMETRIC_KEY_CSR_KEY_USAGE& usage) {
	for (i; i + 1 < argc; ++i) {
		std::string arg_option = ToLower(argv[i + 1]);
		switch (asymmetric_libary::set_hash(arg_option.c_str())) {
		case hash("-ds"):
		case hash("-digital-signature"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DIGITAL_SIGNATURE);
			break;
		case hash("-ke"):
		case hash("-key-encipherment"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_ENCIPHERMENT);
			break;
		case hash("-de"):
		case hash("-data-encipherment"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DATA_ENCIPHERMENT);
			break;
		case hash("-ka"):
		case hash("-key-agreement"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_AGREEMENT);
			break;
		case hash("-kc"):
		case hash("-key-cert-sign"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CERT_SIGN);
			break;
		case hash("-cs"):
		case hash("-crl-sign"):
			usage = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(usage | ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CRL_SIGN);
			break;
		default:return;
		}
	}
}

void asymmetric_libary::PrintCsrSAN(std::string san) {
	if (!IsRowData)
		std::cout << Hint("<RSA CSR Subject Alternative Name (SAN)>") << std::endl;
	std::string tab = IsRowData ? "" : "\t";
	std::string mark_symbol = IsRowData ? ":" : " -> ";
	std::stringstream ss(san);
	std::string token;
	while (std::getline(ss, token, ',')) {
		size_t pos = token.find(':');
		if (pos != std::string::npos) {
			std::string first = token.substr(0, pos);
			std::string second = token.substr(pos + 1);
			std::cout << tab << Mark(first) << mark_symbol << Ask(second) << std::endl;
		}
		else
			std::cout << tab << Ask(token) << std::endl;
	}
}

void asymmetric_libary::PrintCsrKeyUsage(ASYMMETRIC_KEY_CSR_KEY_USAGE usage) {
	if (!IsRowData)
		std::cout << Hint("<RSA CSR Key Usage (KU)>") << std::endl;
	std::string tab = IsRowData ? "" : "\t";
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DIGITAL_SIGNATURE)
		std::cout << tab << Info("Digital Signature") << std::endl;
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_ENCIPHERMENT)
		std::cout << tab << Info("Key Encipherment") << std::endl;
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DATA_ENCIPHERMENT)
		std::cout << tab << Info("Data Encipherment") << std::endl;
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_AGREEMENT)
		std::cout << tab << Info("Key Agreement") << std::endl;
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CERT_SIGN)
		std::cout << tab << Info("Certificate Sign") << std::endl;
	if (usage & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CRL_SIGN)
		std::cout << tab << Info("CRL Sign") << std::endl;
}
