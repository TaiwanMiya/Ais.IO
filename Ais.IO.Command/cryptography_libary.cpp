#include "cryptography_libary.h"
#include "output_colors.h"
#include "string_case.h"

constexpr size_t cryptography_libary::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t cryptography_libary::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t cryptography_libary::CalculateEncodeLength(const std::string& mode, size_t length) {
    if (mode == "--base16")
        return length * 2 + 1;
    else if (mode == "--base32")
        return ((length + 4) / 5) * 8 + 1;
    else if (mode == "--base64")
        return ((length + 2) / 3) * 4 + 1;
    else if (mode == "--base85")
        return ((length + 3) / 4) * 5 + 1;
    else
        return 0;
}

size_t cryptography_libary::CalculateDecodeLength(const std::string& mode, size_t length) {
    if (mode == "--base16")
        return length / 2;
    else if (mode == "--base32")
        return (length / 8) * 5;
    else if (mode == "--base64")
        return (length / 4) * 3;
    else if (mode == "--base85")
        return (length / 5) * 4;
    else
        return 0;
}

size_t cryptography_libary::CalculateEncodeLength(const CRYPT_OPTIONS mode, size_t length) {
    switch (mode) {
    case CRYPT_OPTIONS::OPTION_BASE16:
        return length * 2 + 1;
    case CRYPT_OPTIONS::OPTION_BASE32:
        return ((length + 4) / 5) * 8 + 1;
    case CRYPT_OPTIONS::OPTION_BASE64:
        return ((length + 2) / 3) * 4 + 1;
    case CRYPT_OPTIONS::OPTION_BASE85:
        return ((length + 3) / 4) * 5 + 1;
    default:
        return 0;
    }
}

size_t cryptography_libary::CalculateDecodeLength(const CRYPT_OPTIONS mode, size_t length) {
    switch (mode) {
    case CRYPT_OPTIONS::OPTION_BASE16:
        return length / 2;
    case CRYPT_OPTIONS::OPTION_BASE32:
        return (length / 8) * 5;
    case CRYPT_OPTIONS::OPTION_BASE64:
        return (length / 4) * 3;
    case CRYPT_OPTIONS::OPTION_BASE85:
        return (length / 5) * 4;
    default:
        return 0;
    }
}

CRYPT_OPTIONS cryptography_libary::GetOption(int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
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
		return CRYPT_OPTIONS::OPTION_TEXT;
	}
}

void cryptography_libary::ValueEncode(const CRYPT_OPTIONS option, std::string input, std::vector<unsigned char>& output) {
	size_t length;
	int resultCode;
	switch (option) {
	case CRYPT_OPTIONS::OPTION_TEXT:
		output.clear();
		output.assign(input.begin(), input.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = cryptography_libary::CalculateDecodeLength("--base16", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base16Decode)EncodeFunctions.at("-base16-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = cryptography_libary::CalculateDecodeLength("--base32", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base32Decode)EncodeFunctions.at("-base32-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = cryptography_libary::CalculateDecodeLength("--base64", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base64Decode)EncodeFunctions.at("-base64-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = cryptography_libary::CalculateDecodeLength("--base85", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base85Decode)EncodeFunctions.at("-base85-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		break;
	case CRYPT_OPTIONS::OPTION_FILE:
		std::ifstream file(input, std::ios::in | std::ios::binary | std::ios::ate);
		size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		output.clear();
		output.resize(size);
		if (!file.read(reinterpret_cast<char*>(output.data()), size)) {
			std::cerr << Error("Failed to read file: " + input) << std::endl;
			output.clear();
		}
		file.close();
		break;
	}
}

void cryptography_libary::ValueDecode(const CRYPT_OPTIONS option, std::vector<unsigned char> input, std::string& output) {
	size_t length;
	int resultCode;
	std::vector<char> result;
	switch (option) {
	case CRYPT_OPTIONS::OPTION_TEXT:
		if (!input.empty() && input.back() == '\0')
			input.pop_back();
		output.resize(input.size());
		output.assign(input.begin(), input.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = cryptography_libary::CalculateEncodeLength("--base16", input.size());
		result.resize(length);
		resultCode = ((Base16Encode)EncodeFunctions.at("-base16-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = cryptography_libary::CalculateEncodeLength("--base32", input.size());
		result.resize(length);
		resultCode = ((Base32Encode)EncodeFunctions.at("-base32-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = cryptography_libary::CalculateEncodeLength("--base64", input.size());
		result.resize(length);
		resultCode = ((Base64Encode)EncodeFunctions.at("-base64-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = cryptography_libary::CalculateEncodeLength("--base85", input.size());
		result.resize(length);
		resultCode = ((Base85Encode)EncodeFunctions.at("-base85-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_FILE:
		std::ofstream file(output, std::ios::out | std::ios::binary);
		file.write(reinterpret_cast<const char*>(input.data()), input.size());
		input.clear();
		file.close();
		output = std::filesystem::absolute(output).string();
		break;
	}
}