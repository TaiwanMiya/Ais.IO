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
	switch (set_hash(mode.c_str())) {
	case hash("--base10"):return ((Base10Length)EncodeFunctions.at("-base10-length"))(length, true);
	case hash("--base16"):return ((Base16Length)EncodeFunctions.at("-base16-length"))(length, true);
	case hash("--base32"):return ((Base32Length)EncodeFunctions.at("-base32-length"))(length, true);
	case hash("--base58"):return ((Base58Length)EncodeFunctions.at("-base58-length"))(length, true);
	case hash("--base62"):return ((Base62Length)EncodeFunctions.at("-base62-length"))(length, true);
	case hash("--base64"):return ((Base64Length)EncodeFunctions.at("-base64-length"))(length, true);
	case hash("--base85"):return ((Base85Length)EncodeFunctions.at("-base85-length"))(length, true);
	case hash("--base91"):return ((Base91Length)EncodeFunctions.at("-base91-length"))(length, true);
	default:return 0;
	}
}

size_t cryptography_libary::CalculateDecodeLength(const std::string& mode, size_t length) {
	switch (set_hash(mode.c_str())) {
	case hash("--base10"):return ((Base10Length)EncodeFunctions.at("-base10-length"))(length, false);
	case hash("--base16"):return ((Base16Length)EncodeFunctions.at("-base16-length"))(length, false);
	case hash("--base32"):return ((Base32Length)EncodeFunctions.at("-base32-length"))(length, false);
	case hash("--base58"):return ((Base58Length)EncodeFunctions.at("-base58-length"))(length, false);
	case hash("--base62"):return ((Base62Length)EncodeFunctions.at("-base62-length"))(length, false);
	case hash("--base64"):return ((Base64Length)EncodeFunctions.at("-base64-length"))(length, false);
	case hash("--base85"):return ((Base85Length)EncodeFunctions.at("-base85-length"))(length, false);
	case hash("--base91"):return ((Base91Length)EncodeFunctions.at("-base91-length"))(length, false);
	default:return 0;
	}
}

size_t cryptography_libary::CalculateEncodeLength(const CRYPT_OPTIONS mode, size_t length) {
	switch (mode) {
	case CRYPT_OPTIONS::OPTION_BASE10:return ((Base10Length)EncodeFunctions.at("-base10-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE16:return ((Base16Length)EncodeFunctions.at("-base16-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE32:return ((Base32Length)EncodeFunctions.at("-base32-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE58:return ((Base58Length)EncodeFunctions.at("-base58-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE62:return ((Base62Length)EncodeFunctions.at("-base62-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE64:return ((Base64Length)EncodeFunctions.at("-base64-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE85:return ((Base85Length)EncodeFunctions.at("-base85-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE91:return ((Base91Length)EncodeFunctions.at("-base91-length"))(length, false);
	default:return 0;
	}
}

size_t cryptography_libary::CalculateDecodeLength(const CRYPT_OPTIONS mode, size_t length) {
	switch (mode) {
	case CRYPT_OPTIONS::OPTION_BASE10:return ((Base10Length)EncodeFunctions.at("-base10-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE16:return ((Base16Length)EncodeFunctions.at("-base16-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE32:return ((Base32Length)EncodeFunctions.at("-base32-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE58:return ((Base58Length)EncodeFunctions.at("-base58-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE62:return ((Base62Length)EncodeFunctions.at("-base62-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE64:return ((Base64Length)EncodeFunctions.at("-base64-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE85:return ((Base85Length)EncodeFunctions.at("-base85-length"))(length, false);
	case CRYPT_OPTIONS::OPTION_BASE91:return ((Base91Length)EncodeFunctions.at("-base91-length"))(length, false);
	default:return 0;
	}
}

CRYPT_OPTIONS cryptography_libary::GetOption(int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
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
}

void cryptography_libary::ValueEncode(const CRYPT_OPTIONS option, std::vector<unsigned char> input, std::string& output) {
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
	case CRYPT_OPTIONS::OPTION_BASE10:
		length = cryptography_libary::CalculateEncodeLength("--base10", input.size());
		result.resize(length);
		resultCode = ((Base10Encode)EncodeFunctions.at("-base10-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base10 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = cryptography_libary::CalculateEncodeLength("--base16", input.size());
		result.resize(length);
		resultCode = ((Base16Encode)EncodeFunctions.at("-base16-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base16 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = cryptography_libary::CalculateEncodeLength("--base32", input.size());
		result.resize(length);
		resultCode = ((Base32Encode)EncodeFunctions.at("-base32-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base32 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE58:
		length = cryptography_libary::CalculateEncodeLength("--base58", input.size());
		result.resize(length);
		resultCode = ((Base58Encode)EncodeFunctions.at("-base58-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base58 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE62:
		length = cryptography_libary::CalculateEncodeLength("--base62", input.size());
		result.resize(length);
		resultCode = ((Base62Encode)EncodeFunctions.at("-base62-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base62 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = cryptography_libary::CalculateEncodeLength("--base64", input.size());
		result.resize(length);
		resultCode = ((Base64Encode)EncodeFunctions.at("-base64-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base64 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = cryptography_libary::CalculateEncodeLength("--base85", input.size());
		result.resize(length);
		resultCode = ((Base85Encode)EncodeFunctions.at("-base85-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base85 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		input.clear();
		output.assign(result.begin(), result.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE91:
		length = cryptography_libary::CalculateEncodeLength("--base91", input.size());
		result.resize(length);
		resultCode = ((Base91Encode)EncodeFunctions.at("-base91-encode"))(input.data(), input.size(), result.data(), length);
		if (resultCode > 0)
			result.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base91 Encode Error: " + error_message) << std::endl;
			output.resize(0);
		}
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

void cryptography_libary::ValueDecode(const CRYPT_OPTIONS option, std::string input, std::vector<unsigned char>& output) {
	size_t length;
	int resultCode;
	std::cout << "Length: " << std::to_string(input.size()) << "\tContent: " << input << std::endl;
	switch (option) {
	case CRYPT_OPTIONS::OPTION_TEXT:
		output.clear();
		output.assign(input.begin(), input.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE10:
		length = cryptography_libary::CalculateDecodeLength("--base10", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base10Decode)EncodeFunctions.at("-base10-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base10 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = cryptography_libary::CalculateDecodeLength("--base16", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base16Decode)EncodeFunctions.at("-base16-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base16 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = cryptography_libary::CalculateDecodeLength("--base32", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base32Decode)EncodeFunctions.at("-base32-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base32 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE58:
		length = cryptography_libary::CalculateDecodeLength("--base58", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base58Decode)EncodeFunctions.at("-base58-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base58 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE62:
		length = cryptography_libary::CalculateDecodeLength("--base62", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base62Decode)EncodeFunctions.at("-base62-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base62 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = cryptography_libary::CalculateDecodeLength("--base64", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base64Decode)EncodeFunctions.at("-base64-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base64 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = cryptography_libary::CalculateDecodeLength("--base85", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base85Decode)EncodeFunctions.at("-base85-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base85 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
		break;
	case CRYPT_OPTIONS::OPTION_BASE91:
		length = cryptography_libary::CalculateDecodeLength("--base91", input.size());
		output.clear();
		output.resize(length);
		resultCode = ((Base91Decode)EncodeFunctions.at("-base91-decode"))(input.c_str(), input.size(), output.data(), length);
		if (resultCode > 0)
			output.resize(resultCode);
		else {
			std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
			std::cerr << Error("Base91 Decode Error: " + error_message) << std::endl;
			output.resize(0);
		}
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
		while ((!output.empty() && output.back() == '\n') ||
			(!output.empty() && output.back() == '\r') ||
			(!output.empty() && output.back() == '\0')) {
			if (!output.empty() && output.back() == '\0')
				output.pop_back();
			if (!output.empty() && output.back() == '\n')
				output.pop_back();
			if (!output.empty() && output.back() == '\r')
				output.pop_back();
		}
		if (output.size() >= 2 && output[0] == 0xFF && output[1] == 0xFE)
			output.erase(output.begin(), output.begin() + 2);
		else if (output.size() >= 2 && output[0] == 0xFE && output[1] == 0xFF)
			output.erase(output.begin(), output.begin() + 2);
		else if (output.size() >= 3 && output[0] == 0xEF && output[1] == 0xBB && output[2] == 0xBF)
			output.erase(output.begin(), output.begin() + 3);
		file.close();
		break;
	}
}

std::string cryptography_libary::GetBaseErrorCode(int result_code) {
	switch (result_code) {
	case -1:return "Input or Output is Empty.";
	case -2:return "Output buffer insufficient.";
	case -3:return "The input data length is illegal during decoding.";
	case -4:return "Illegal characters occurred during decoding.";
	default:return "";
	}
}

void cryptography_libary::ParseParameters(int argc, char* argv[], Rand& rand) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case hash("--generate"):
		case hash("-gen"):
			rand.Type = RAND_TYPE::RAND_GENERATE;
			rand.rand_option = GetOption(i, argv);
			if (rand.rand_option == CRYPT_OPTIONS::OPTION_FILE) {
				rand.Output = argv[i + 1];
				i++;
			}
			if (IsULong(argv[i + 1]))
				rand.Value = argv[i + 1];
			else {
				std::cerr << Error("[Generate] Only integers of size can be entered.") << std::endl;
				return;
			}
			i++;
			break;
		case hash("--convert"):
		case hash("-conv"):
			rand.Type = RAND_TYPE::RAND_IMPORT;
			rand.rand_option = GetOption(i, argv);
			rand.Value = IsInput ? InputContent : argv[i + 1];
			break;
		case hash("-output"):
		case hash("-out"):
			rand.output_option = cryptography_libary::GetOption(i, argv);
			if (rand.output_option == CRYPT_OPTIONS::OPTION_FILE) {
				rand.Output = argv[i + 1];
				i++;
			}
			i++;
			break;
		}
		}
	return;
}

void cryptography_libary::RandStart(Rand& rand) {
	std::vector<unsigned char> result;
	std::vector<unsigned char> outputResult;
	std::string result_str = rand.Output;
	switch (rand.Type) {
	case RAND_TYPE::RAND_GENERATE:
		result.resize(std::stoull(rand.Value));
		((Generate)SymmetryFunctions.at("-generate"))(result.data(), result.size());
		ValueEncode(rand.output_option, result, result_str);
		if (!IsRowData) {
			std::cout << Hint("<Generate>") << std::endl;
			std::cout << Ask(result_str) << std::endl;
			std::cout << Hint("Data Length: [") << Ask(std::to_string(result.size())) << Hint("]") <<  std::endl;
			std::cout << Hint("Output Length: [") << Ask(std::to_string(result_str.size())) << Hint("]\n");
		}
		else
			std::cout << Ask(result_str) << std::endl;
		break;
	case RAND_TYPE::RAND_IMPORT:
		ValueDecode(rand.rand_option, rand.Value, result);
		outputResult.resize(result.size());
		((Import)SymmetryFunctions.at("-convert"))(result.data(), result.size(), outputResult.data(), outputResult.size());
		ValueEncode(rand.output_option, result, result_str);
		if (!IsRowData) {
			std::cout << Hint("<Convert>") << std::endl;
			std::cout << Ask(result_str) << std::endl;
			std::cout << Hint("Data Length: [") << Ask(std::to_string(result.size())) << Hint("]") << std::endl;
			std::cout << Hint("Input Length: [") << Ask(std::to_string(rand.Value.size())) << Hint("]") << std::endl;
			std::cout << Hint("Output Length: [") << Ask(std::to_string(result_str.size())) << Hint("]") << std::endl;
		}
		else
			std::cout << Ask(result_str) << std::endl;
		break;
	}
}