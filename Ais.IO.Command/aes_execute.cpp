#include "aes_execute.h"
#include "string_case.h"
#include "encoder_execute.h"
#include <filesystem>

constexpr size_t hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

bool aes_execute::GetCrypt(int& i, std::string arg, char* argv[], Aes& crypt) {
	std::string arg_crypt = ToLower(argv[i + 1]);
	switch (set_hash(arg_crypt.c_str())) {
	case hash("-encrypt"):
	case hash("-e"):
		crypt.Mode = AesMode[arg];
		crypt.Crypt = CRYPT_TYPE::CRYPTION_ENCRYPT;
		i++;
		return true;
	case hash("-decrypt"):
	case hash("-d"):
		crypt.Mode = AesMode[arg];
		crypt.Crypt = CRYPT_TYPE::CRYPTION_DECRYPT;
		i++;
		return true;
	default:
		return false;
	}
}

CRYPT_OPTIONS aes_execute::GetOption(int& i, char* argv[], Aes& crypt) {
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

void aes_execute::ParseParameters(int argc, char* argv[], Aes& aes) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
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
			if (!GetCrypt(i, arg, argv, aes))
				return;
			break;
		case hash("-key"):
			aes.key_option = GetOption(i, argv, aes);
			aes.Key = argv[i + 1];
			i++;
			break;
		case hash("-iv"):
			aes.iv_option = GetOption(i, argv, aes);
			aes.IV = argv[i + 1];
			i++;
			break;
		case hash("-tag"):
			aes.tag_option = GetOption(i, argv, aes);
			aes.Tag = argv[i + 1];
			i++;
			break;
		case hash("-aad"):
			aes.aad_option = GetOption(i, argv, aes);
			aes.Aad = argv[i + 1];
			i++;
			break;
		case hash("-tweak"):
			aes.tweak_option = GetOption(i, argv, aes);
			aes.Tweak = argv[i + 1];
			i++;
			break;
		case hash("-key2"):
			aes.key2_option = GetOption(i, argv, aes);
			aes.Key2 = argv[i + 1];
			i++;
			break;
		case hash("-plain-text"):
		case hash("-pt"):
			aes.plaintext_option = GetOption(i, argv, aes);
			aes.PlainText = argv[i + 1];
			i++;
			break;
		case hash("-cipher-text"):
		case hash("-ct"):
			aes.ciphertext_option = GetOption(i, argv, aes);
			aes.CipherText = argv[i + 1];
			i++;
			break;
		case hash("-output"):
		case hash("-out"):
			aes.output_option = GetOption(i, argv, aes);
			if (aes.output_option == CRYPT_OPTIONS::OPTION_FILE)
				aes.Output = argv[i + 1];
			i++;
			break;
		case hash("-counter"):
		case hash("-count"):
			if (IsULong(argv[i + 1])) {
				aes.Counter = argv[i + 1];
				i++;
			}
			break;
		}
	}
}

void GetValue(std::string arg, const CRYPT_OPTIONS option, std::vector<unsigned char>& buffer) {
	size_t length;
	switch (option) {
	case CRYPT_OPTIONS::OPTION_TEXT:
		buffer.clear();
		buffer.resize(arg.size());
		buffer.assign(arg.begin(), arg.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = encoder_execute::CalculateDecodeLength("--base16", arg.size());
		buffer.clear();
		buffer.resize(length);
		length = ((Base16Decode)EncodeFunctions.at("-base16-decode"))(arg.c_str(), arg.size(), buffer.data(), length);
		if (length > 0)
			buffer.resize(length);
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = encoder_execute::CalculateDecodeLength("--base32", arg.size());
		buffer.clear();
		buffer.resize(length);
		length = ((Base32Decode)EncodeFunctions.at("-base32-decode"))(arg.c_str(), arg.size(), buffer.data(), length);
		if (length > 0)
			buffer.resize(length);
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = encoder_execute::CalculateDecodeLength("--base64", arg.size());
		buffer.clear();
		buffer.resize(length);
		length = ((Base64Decode)EncodeFunctions.at("-base64-decode"))(arg.c_str(), arg.size(), buffer.data(), length);
		if (length > 0)
			buffer.resize(length);
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = encoder_execute::CalculateDecodeLength("--base85", arg.size());
		buffer.clear();
		buffer.resize(length);
		length = ((Base85Decode)EncodeFunctions.at("-base85-decode"))(arg.c_str(), arg.size(), buffer.data(), length);
		if (length > 0)
			buffer.resize(length);
		break;
	case CRYPT_OPTIONS::OPTION_FILE:
		std::ifstream file(arg, std::ios::in | std::ios::binary | std::ios::ate);
		size_t size = file.tellg();
		file.seekg(0, std::ios::beg);
		buffer.clear();
		buffer.resize(size);
		if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
			std::cerr << Error("Failed to read file: " + arg) << std::endl;
			buffer.clear();
		}
		file.close();
		break;
	}
}

void SetValue(std::vector<unsigned char>& buffer, std::string& result_str, const CRYPT_OPTIONS option) {
	size_t length;
	std::vector<char> result;
	switch (option) {
	case CRYPT_OPTIONS::OPTION_TEXT:
		result_str.resize(buffer.size());
		result_str.assign(buffer.begin(), buffer.end());
		break;
	case CRYPT_OPTIONS::OPTION_BASE16:
		length = encoder_execute::CalculateEncodeLength("--base16", buffer.size());
		result.resize(length);
		length = ((Base16Encode)EncodeFunctions.at("-base16-encode"))(buffer.data(), buffer.size(), result.data(), length);
		if (length > 0)
			result.resize(length);
		buffer.clear();
		result_str = result.data();
		break;
	case CRYPT_OPTIONS::OPTION_BASE32:
		length = encoder_execute::CalculateEncodeLength("--base32", buffer.size());
		result.resize(length);
		length = ((Base32Encode)EncodeFunctions.at("-base32-encode"))(buffer.data(), buffer.size(), result.data(), length);
		if (length > 0)
			result.resize(length);
		buffer.clear();
		result_str = result.data();
		break;
	case CRYPT_OPTIONS::OPTION_BASE64:
		length = encoder_execute::CalculateEncodeLength("--base64", buffer.size());
		result.resize(length);
		length = ((Base64Encode)EncodeFunctions.at("-base64-encode"))(buffer.data(), buffer.size(), result.data(), length);
		if (length > 0)
			result.resize(length);
		buffer.clear();
		result_str = result.data();
		break;
	case CRYPT_OPTIONS::OPTION_BASE85:
		length = encoder_execute::CalculateEncodeLength("--base85", buffer.size());
		result.resize(length);
		length = ((Base85Encode)EncodeFunctions.at("-base85-encode"))(buffer.data(), buffer.size(), result.data(), length);
		if (length > 0)
			result.resize(length);
		buffer.clear();
		result_str = result.data();
		break;
	case CRYPT_OPTIONS::OPTION_FILE:
		std::ofstream file(result_str, std::ios::out | std::ios::binary);
		file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
		buffer.clear();
		file.close();
		result_str = std::filesystem::absolute(result_str).string();
		break;
	}
}

void EndHandling(std::vector<unsigned char>& result, Aes& aes) {
	std::string algorithm = "AES";
	std::string mode = AesDisplay[aes.Mode];
	std::string crypt = CryptDisplay[aes.Crypt];
	std::string result_str = aes.Output;
	std::cout << Hint("<" + algorithm + " " + mode + " " + crypt + ">") << std::endl;
	SetValue(result, result_str, aes.output_option);
	std::cout << Ask(result_str) << std::endl;
}

void CtrEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	size_t plaintext_size;
	const long long counter = std::stoll(aes.Counter);
	GetValue(aes.Key, aes.key_option, key);
	GetValue(aes.PlainText, aes.plaintext_option, plaintext);
	plaintext_size = plaintext.size();
	ciphertext.resize(plaintext_size);
	AES_CTR_ENCRYPT ctrEncrypt = {
		plaintext.data(),
		key.data(),
		plaintext_size,
		ciphertext.data(),
		counter,
	};

	std::cout << "PLAIN_TEXT: " << static_cast<void*>(plaintext.data()) << std::endl;
	std::cout << "PLAIN_TEXT_LENGTH: " << plaintext_size << std::endl;
	std::cout << "KEY: " << static_cast<void*>(key.data()) << std::endl;
	std::cout << "CIPHER_TEXT: " << static_cast<void*>(ciphertext.data()) << std::endl;
	std::cout << "COUNTER: " << counter << std::endl;

	int length = ((AesCtrEncrypt)AesFunctions.at("-ctr-encrypt"))(&ctrEncrypt);
	result.resize(length);
	result.assign(ciphertext.begin(), ciphertext.end());
}

void CtrDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	GetValue(aes.Key, aes.key_option, key);
	GetValue(aes.CipherText, aes.ciphertext_option, ciphertext);
	plaintext.resize(ciphertext.size());
	AES_CTR_DECRYPT ctrDecrypt = {
			ciphertext.data(),
			key.data(),
			ciphertext.size(),
			plaintext.data(),
			std::stoll(aes.Counter),
	};
	((AesCtrDecrypt)AesFunctions.at("-ctr-decrypt"))(&ctrDecrypt);
	result = plaintext;
}

void aes_execute::AesStart(Aes& aes) {
	std::vector<unsigned char> result;
	switch (aes.Crypt) {
	case CRYPT_TYPE::CRYPTION_ENCRYPT: {
		switch (aes.Mode) {
		case AES_MODE::AES_CTR:
			CtrEncrypt(result, aes);
			break;
		case AES_MODE::AES_CBC:
			break;
		case AES_MODE::AES_CFB:
			break;
		case AES_MODE::AES_OFB:
			break;
		case AES_MODE::AES_ECB:
			break;
		default:
			break;
		}
		break;
	}
	case CRYPT_TYPE::CRYPTION_DECRYPT: {
		switch (aes.Mode) {
		case AES_MODE::AES_CTR:
			CtrDecrypt(result, aes);
			break;
		case AES_MODE::AES_CBC:
			break;
		case AES_MODE::AES_CFB:
			break;
		case AES_MODE::AES_OFB:
			break;
		case AES_MODE::AES_ECB:
			break;
		default:
			break;
		}
		break;
	}
	}
	EndHandling(result, aes);
}