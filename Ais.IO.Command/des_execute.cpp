#include "des_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"

constexpr size_t des_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t des_execute::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

bool des_execute::GetCrypt(int& i, std::string arg, char* argv[], Des& crypt) {
	std::string arg_crypt = ToLower(argv[i + 1]);
	switch (set_hash(arg_crypt.c_str())) {
	case hash("-encrypt"):
	case hash("-e"):
		crypt.Mode = DesMode[arg];
		crypt.Crypt = CRYPT_TYPE::CRYPTION_ENCRYPT;
		i++;
		return true;
	case hash("-decrypt"):
	case hash("-d"):
		crypt.Mode = DesMode[arg];
		crypt.Crypt = CRYPT_TYPE::CRYPTION_DECRYPT;
		i++;
		return true;
	default:
		return false;
	}
}

void des_execute::ParseParameters(int argc, char* argv[], Des& des) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case hash("-cbc"):
		case hash("-cfb"):
		case hash("-ofb"):
		case hash("-ecb"):
		case hash("-wrap"):
			if (!GetCrypt(i, arg, argv, des))
				return;
			break;
		case hash("-key"):
			des.key_option = cryptography_libary::GetOption(i, argv);
			des.Key = argv[i + 1];
			i++;
			break;
		case hash("-iv"):
			des.iv_option = cryptography_libary::GetOption(i, argv);
			des.IV = argv[i + 1];
			i++;
			break;
		case hash("-plain-text"):
		case hash("-pt"):
			des.plaintext_option = cryptography_libary::GetOption(i, argv);
			des.PlainText = argv[i + 1];
			i++;
			break;
		case hash("-cipher-text"):
		case hash("-ct"):
			des.ciphertext_option = cryptography_libary::GetOption(i, argv);
			des.CipherText = argv[i + 1];
			i++;
			break;
		case hash("-output"):
		case hash("-out"):
			des.output_option = cryptography_libary::GetOption(i, argv);
			if (des.output_option == CRYPT_OPTIONS::OPTION_FILE) {
				des.Output = argv[i + 1];
				i++;
			}
			i++;
			break;

		// Mode Define
		case hash("-padding"):
		case hash("-pad"):
			des.Padding = true;
			break;
		case hash("-segment"):
		case hash("-seg"):
			if (IsULong(argv[i + 1])) {
				const long long segment = std::stoll(argv[i + 1]);
				if (segment <= 1)
					des.Segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
				else if (segment > 1 && segment <= 8)
					des.Segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
				else
					des.Segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
				i++;
			}
			break;
		case hash("-kek"):
			des.kek_option = cryptography_libary::GetOption(i, argv);
			des.Kek = argv[i + 1];
			i++;
			break;
		case hash("-wrapkey"):
		case hash("-wk"):
			des.wrap_option = cryptography_libary::GetOption(i, argv);
			des.Wrap = argv[i + 1];
			i++;
			break;
		}
	}
}

void des_execute::EndHandling(std::vector<unsigned char>& result, Des& des) {
	std::string algorithm = "DES";
	std::string mode = DesDisplay[des.Mode];
	std::string crypt = CryptDisplay[des.Crypt];
	std::string result_str = des.Output;
	std::cout << Hint("<" + algorithm + " " + mode + " " + crypt + ">") << std::endl;
	cryptography_libary::ValueDecode(des.output_option, result, result_str);
	std::cout << Ask(result_str) << std::endl;
}

void des_execute::DesStart(Des& des) {
	std::vector<unsigned char> result;
	switch (des.Crypt) {
	case CRYPT_TYPE::CRYPTION_ENCRYPT: {
		switch (des.Mode) {
		case DES_MODE::DES_CBC:
			CbcEncrypt(result, des);
			break;
		case DES_MODE::DES_CFB:
			CfbEncrypt(result, des);
			break;
		case DES_MODE::DES_OFB:
			OfbEncrypt(result, des);
			break;
		case DES_MODE::DES_ECB:
			EcbEncrypt(result, des);
			break;
		case DES_MODE::DES_WRAP:
			WrapEncrypt(result, des);
			break;
		default:
			break;
		}
		break;
	}
	case CRYPT_TYPE::CRYPTION_DECRYPT: {
		switch (des.Mode) {
		case DES_MODE::DES_CBC:
			CbcDecrypt(result, des);
			break;
		case DES_MODE::DES_CFB:
			CfbDecrypt(result, des);
			break;
		case DES_MODE::DES_OFB:
			OfbDecrypt(result, des);
			break;
		case DES_MODE::DES_ECB:
			EcbDecrypt(result, des);
			break;
		case DES_MODE::DES_WRAP:
			WrapDecrypt(result, des);
			break;
		default:
			break;
		}
		break;
	}
	}
	EndHandling(result, des);
}

void des_execute::CbcEncrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.plaintext_option, des.PlainText, plaintext);
	ciphertext.resize(des.Padding ? plaintext.size() + 16 : plaintext.size());
	DES_CBC_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		des.Padding,
		key.size(),
		plaintext.size(),
	};
	int length = ((DesCbcEncrypt)DesFunctions.at("-cbc-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("DES CBC Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void des_execute::CbcDecrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.ciphertext_option, des.CipherText, ciphertext);
	plaintext.resize(des.Padding ? ciphertext.size() + 16 : ciphertext.size());
	DES_CBC_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		des.Padding,
		key.size(),
		ciphertext.size(),
	};
	int length = ((DesCbcDecrypt)DesFunctions.at("-cbc-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("DES CBC Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void des_execute::CfbEncrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.plaintext_option, des.PlainText, plaintext);
	ciphertext.resize(plaintext.size());
	DES_CFB_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		des.Segment,
		key.size(),
		plaintext.size(),
	};
	int length = ((DesCfbEncrypt)DesFunctions.at("-cfb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("DES CFB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void des_execute::CfbDecrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.ciphertext_option, des.CipherText, ciphertext);
	plaintext.resize(ciphertext.size());
	DES_CFB_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		des.Segment,
		key.size(),
		ciphertext.size(),
	};
	int length = ((DesCfbDecrypt)DesFunctions.at("-cfb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("DES CFB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void des_execute::OfbEncrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.plaintext_option, des.PlainText, plaintext);
	ciphertext.resize(plaintext.size());
	DES_OFB_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		key.size(),
		plaintext.size(),
	};
	int length = ((DesOfbEncrypt)DesFunctions.at("-ofb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("DES OFB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void des_execute::OfbDecrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.iv_option, des.IV, iv);
	cryptography_libary::ValueEncode(des.ciphertext_option, des.CipherText, ciphertext);
	plaintext.resize(ciphertext.size());
	DES_OFB_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		key.size(),
		ciphertext.size(),
	};
	int length = ((DesOfbDecrypt)DesFunctions.at("-ofb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("DES OFB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void des_execute::EcbEncrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.plaintext_option, des.PlainText, plaintext);
	ciphertext.resize(des.Padding ? plaintext.size() + 16 : plaintext.size());
	DES_ECB_ENCRYPT encryption = {
		key.data(),
		plaintext.data(),
		ciphertext.data(),
		des.Padding,
		key.size(),
		plaintext.size(),
	};
	int length = ((DesEcbEncrypt)DesFunctions.at("-ecb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("DES ECB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void des_execute::EcbDecrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.ciphertext_option, des.CipherText, ciphertext);
	plaintext.resize(des.Padding ? ciphertext.size() + 16 : ciphertext.size());
	DES_ECB_DECRYPT decryption = {
		key.data(),
		ciphertext.data(),
		plaintext.data(),
		des.Padding,
		key.size(),
		ciphertext.size(),
	};
	int length = ((DesEcbDecrypt)DesFunctions.at("-ecb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("DES ECB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void des_execute::WrapEncrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> kek;
	std::vector<unsigned char> wrap;
	cryptography_libary::ValueEncode(des.key_option, des.Key, key);
	cryptography_libary::ValueEncode(des.kek_option, des.Kek, kek);
	wrap.resize(key.size() + 16);
	DES_WRAP_ENCRYPT encryption = {
		key.data(),
		kek.data(),
		wrap.data(),
		key.size(),
		kek.size(),
		wrap.size(),
	};
	int length = ((DesWrapEncrypt)DesFunctions.at("-wrap-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("DES WRAP Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(wrap.begin(), wrap.end());
	result.resize(length);
}

void des_execute::WrapDecrypt(std::vector<unsigned char>& result, Des& des) {
	std::vector<unsigned char> wrap;
	std::vector<unsigned char> kek;
	std::vector<unsigned char> key;
	cryptography_libary::ValueEncode(des.wrap_option, des.Wrap, wrap);
	cryptography_libary::ValueEncode(des.kek_option, des.Kek, kek);
	key.resize(wrap.size() - 16);
	DES_WRAP_DECRYPT decryption = {
		wrap.data(),
		kek.data(),
		key.data(),
		wrap.size(),
		kek.size(),
		key.size(),
	};
	int length = ((DesWrapDecrypt)DesFunctions.at("-wrap-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("DES WRAP Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(key.begin(), key.end());
	result.resize(length);
}
