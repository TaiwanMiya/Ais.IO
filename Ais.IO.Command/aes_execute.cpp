#include "aes_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"

constexpr size_t aes_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t aes_execute::set_hash(const char* str) {
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
			aes.key_option = cryptography_libary::GetOption(i, argv);
			aes.Key = argv[i + 1];
			i++;
			break;
		case hash("-iv"):
			aes.iv_option = cryptography_libary::GetOption(i, argv);
			aes.IV = argv[i + 1];
			i++;
			break;
		case hash("-plain-text"):
		case hash("-pt"):
			aes.plaintext_option = cryptography_libary::GetOption(i, argv);
			aes.PlainText = argv[i + 1];
			i++;
			break;
		case hash("-cipher-text"):
		case hash("-ct"):
			aes.ciphertext_option = cryptography_libary::GetOption(i, argv);
			aes.CipherText = argv[i + 1];
			i++;
			break;
		case hash("-output"):
		case hash("-out"):
			aes.output_option = cryptography_libary::GetOption(i, argv);
			if (aes.output_option == CRYPT_OPTIONS::OPTION_FILE) {
				aes.Output = argv[i + 1];
				i++;
			}
			i++;
			break;

		// Mode Define
		case hash("-counter"):
		case hash("-count"):
			if (IsULong(argv[i + 1])) {
				aes.Counter = std::stoll(argv[i + 1]);
				i++;
			}
			break;
		case hash("-padding"):
		case hash("-pad"):
			aes.Padding = true;
			break;
		case hash("-segment"):
		case hash("-seg"):
			if (IsULong(argv[i + 1])) {
				const long long segment = std::stoll(argv[i + 1]);
				if (segment <= 1)
					aes.Segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
				else if (segment > 1 && segment <= 8)
					aes.Segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
				else
					aes.Segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
				i++;
			}
			break;
		case hash("-tag"):
			aes.tag_option = cryptography_libary::GetOption(i, argv);
			aes.Tag = argv[i + 1];
			i++;
			break;
		case hash("-aad"):
			aes.aad_option = cryptography_libary::GetOption(i, argv);
			aes.Aad = argv[i + 1];
			i++;
			break;
		case hash("-tweak"):
			aes.tweak_option = cryptography_libary::GetOption(i, argv);
			aes.Tweak = argv[i + 1];
			i++;
			break;
		case hash("-key2"):
			aes.key2_option = cryptography_libary::GetOption(i, argv);
			aes.Key2 = argv[i + 1];
			i++;
			break;
		case hash("-nonce"):
			aes.nonce_option = cryptography_libary::GetOption(i, argv);
			aes.Nonce = argv[i + 1];
			i++;
			break;
		case hash("-kek"):
			aes.kek_option = cryptography_libary::GetOption(i, argv);
			aes.Kek = argv[i + 1];
			i++;
			break;
		case hash("-wrapkey"):
		case hash("-wk"):
			aes.wrap_option = cryptography_libary::GetOption(i, argv);
			aes.Wrap = argv[i + 1];
			i++;
			break;
		}
	}
}

void aes_execute::EndHandling(std::vector<unsigned char>& result, Aes& aes) {
	std::string algorithm = "AES";
	std::string mode = AesDisplay[aes.Mode];
	std::string crypt = CryptDisplay[aes.Crypt];
	std::string result_str = aes.Output;
	std::cout << Hint("<" + algorithm + " " + mode + " " + crypt + ">") << std::endl;
	cryptography_libary::ValueDecode(aes.output_option, result, result_str);
	std::cout << Ask(result_str) << std::endl;
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
			CbcEncrypt(result, aes);
			break;
		case AES_MODE::AES_CFB:
			CfbEncrypt(result, aes);
			break;
		case AES_MODE::AES_OFB:
			OfbEncrypt(result, aes);
			break;
		case AES_MODE::AES_ECB:
			EcbEncrypt(result, aes);
			break;
		case AES_MODE::AES_GCM:
			GcmEncrypt(result, aes);
			break;
		case AES_MODE::AES_CCM:
			CcmEncrypt(result, aes);
			break;
		case AES_MODE::AES_XTS:
			XtsEncrypt(result, aes);
			break;
		case AES_MODE::AES_OCB:
			OcbEncrypt(result, aes);
			break;
		case AES_MODE::AES_WRAP:
			WrapEncrypt(result, aes);
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
			CbcDecrypt(result, aes);
			break;
		case AES_MODE::AES_CFB:
			CfbDecrypt(result, aes);
			break;
		case AES_MODE::AES_OFB:
			OfbDecrypt(result, aes);
			break;
		case AES_MODE::AES_ECB:
			EcbDecrypt(result, aes);
			break;
		case AES_MODE::AES_GCM:
			GcmDecrypt(result, aes);
			break;
		case AES_MODE::AES_CCM:
			CcmDecrypt(result, aes);
			break;
		case AES_MODE::AES_XTS:
			XtsDecrypt(result, aes);
			break;
		case AES_MODE::AES_OCB:
			OcbDecrypt(result, aes);
			break;
		case AES_MODE::AES_WRAP:
			WrapDecrypt(result, aes);
			break;
		default:
			break;
		}
		break;
	}
	}
	EndHandling(result, aes);
}

#pragma region Functionality
void aes_execute::CtrEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	ciphertext.resize(plaintext.size());
	AES_CTR_ENCRYPT encryption = {
		key.data(),
		plaintext.data(),
		ciphertext.data(),
		aes.Counter,
		key.size(),
		plaintext.size(),
	};

	int length = ((AesCtrEncrypt)AesFunctions.at("-ctr-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES CTR Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::CtrDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	plaintext.resize(ciphertext.size());
	AES_CTR_DECRYPT decryption = {
			key.data(),
			ciphertext.data(),
			plaintext.data(),
			aes.Counter,
			key.size(),
			ciphertext.size(),
	};
	int length = ((AesCtrDecrypt)AesFunctions.at("-ctr-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CTR Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::CbcEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	ciphertext.resize(aes.Padding ? plaintext.size() + 16: plaintext.size());
	AES_CBC_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		aes.Padding,
		key.size(),
		plaintext.size(),
	};
	int length = ((AesCbcEncrypt)AesFunctions.at("-cbc-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES CBC Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::CbcDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	plaintext.resize(aes.Padding ? ciphertext.size() + 16: ciphertext.size());
	AES_CBC_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		aes.Padding,
		key.size(),
		ciphertext.size(),
	};
	int length = ((AesCbcDecrypt)AesFunctions.at("-cbc-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CBC Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::CfbEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	ciphertext.resize(plaintext.size());
	AES_CFB_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		aes.Segment,
		key.size(),
		plaintext.size(),
	};
	int length = ((AesCfbEncrypt)AesFunctions.at("-cfb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES CFB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::CfbDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	plaintext.resize(ciphertext.size());
	AES_CFB_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		aes.Segment,
		key.size(),
		ciphertext.size(),
	};
	int length = ((AesCfbDecrypt)AesFunctions.at("-cfb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CFB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::OfbEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	ciphertext.resize(plaintext.size());
	AES_OFB_ENCRYPT encryption = {
		key.data(),
		iv.data(),
		plaintext.data(),
		ciphertext.data(),
		key.size(),
		plaintext.size(),
	};
	int length = ((AesOfbEncrypt)AesFunctions.at("-ofb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES OFB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::OfbDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> iv;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.iv_option, aes.IV, iv);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	plaintext.resize(ciphertext.size());
	AES_OFB_DECRYPT decryption = {
		key.data(),
		iv.data(),
		ciphertext.data(),
		plaintext.data(),
		key.size(),
		ciphertext.size(),
	};
	int length = ((AesOfbDecrypt)AesFunctions.at("-ofb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES OFB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::EcbEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	ciphertext.resize(aes.Padding ? plaintext.size() + 16 : plaintext.size());
	AES_ECB_ENCRYPT encryption = {
		key.data(),
		plaintext.data(),
		ciphertext.data(),
		aes.Padding,
		key.size(),
		plaintext.size(),
	};
	int length = ((AesEcbEncrypt)AesFunctions.at("-ecb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES ECB Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::EcbDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	plaintext.resize(aes.Padding ? ciphertext.size() + 16: ciphertext.size());
	AES_ECB_DECRYPT decryption = {
		key.data(),
		ciphertext.data(),
		plaintext.data(),
		aes.Padding,
		key.size(),
		ciphertext.size(),
	};
	int length = ((AesEcbDecrypt)AesFunctions.at("-ecb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES ECB Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::GcmEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	ciphertext.resize(plaintext.size());
	AES_GCM_ENCRYPT encryption = {
		key.data(),
		nonce.data(),
		plaintext.data(),
		ciphertext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		plaintext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
	};
	int length = ((AesGcmEncrypt)AesFunctions.at("-gcm-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES GCM Encrypt Failed.") << std::endl;
		return;
	}
	std::string verify_tag;
	cryptography_libary::ValueDecode(aes.output_option, tag, verify_tag);
	std::cout << Hint("<Aes " + AesDisplay[aes.Mode] + " Tag>") << std::endl;
	std::cout << Ask(verify_tag) << std::endl;
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::GcmDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> plaintext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
    cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
    cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
    cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
    cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	plaintext.resize(ciphertext.size());
	AES_GCM_DECRYPT decryption = {
		key.data(),
		nonce.data(),
		ciphertext.data(),
		plaintext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		ciphertext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
    };
    int length = ((AesGcmDecrypt)AesFunctions.at("-gcm-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES GCM Decrypt Failed.") << std::endl;
		return;
	}
    result.assign(plaintext.begin(), plaintext.end());
    result.resize(length);
}

void aes_execute::CcmEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	ciphertext.resize(plaintext.size());
	AES_CCM_ENCRYPT encryption = {
		key.data(),
		nonce.data(),
		plaintext.data(),
		ciphertext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		plaintext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
	};
	int length = ((AesCcmEncrypt)AesFunctions.at("-ccm-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES CCM Encrypt Failed.") << std::endl;
		return;
	}
	std::string verify_tag;
	cryptography_libary::ValueDecode(aes.output_option, tag, verify_tag);
	std::cout << Hint("<Aes " + AesDisplay[aes.Mode] + " Tag>") << std::endl;
	std::cout << Ask(verify_tag) << std::endl;
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::CcmDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	plaintext.resize(ciphertext.size());
	AES_CCM_DECRYPT decryption = {
		key.data(),
		nonce.data(),
		ciphertext.data(),
		plaintext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		ciphertext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
	};
	int length = ((AesCcmDecrypt)AesFunctions.at("-ccm-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CCM Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::XtsEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key1;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> key2;
	std::vector<unsigned char> tweak;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key1);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	cryptography_libary::ValueEncode(aes.key2_option, aes.Key2, key2);
	cryptography_libary::ValueEncode(aes.tweak_option, aes.Tweak, tweak);
	ciphertext.resize(plaintext.size());
	AES_XTS_ENCRYPT encryption = {
		key1.data(),
		plaintext.data(),
		ciphertext.data(),
		key2.data(),
		tweak.data(),
		key1.size(),
		plaintext.size(),
		key2.size(),
	};
	int length = ((AesXtsEncrypt)AesFunctions.at("-xts-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES XTS Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::XtsDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key1;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> key2;
	std::vector<unsigned char> tweak;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key1);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	cryptography_libary::ValueEncode(aes.key2_option, aes.Key2, key2);
	cryptography_libary::ValueEncode(aes.tweak_option, aes.Tweak, tweak);
	plaintext.resize(ciphertext.size());
	AES_XTS_DECRYPT decryption = {
		key1.data(),
		ciphertext.data(),
		plaintext.data(),
		key2.data(),
		tweak.data(),
		key1.size(),
		ciphertext.size(),
		key2.size(),
	};
	int length = ((AesXtsDecrypt)AesFunctions.at("-xts-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES XTS Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::OcbEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
	cryptography_libary::ValueEncode(aes.plaintext_option, aes.PlainText, plaintext);
	cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	ciphertext.resize(plaintext.size());
	AES_OCB_ENCRYPT encryption = {
		key.data(),
		nonce.data(),
		plaintext.data(),
		ciphertext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		plaintext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
	};
	int length = ((AesOcbEncrypt)AesFunctions.at("-ocb-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES OCB Encrypt Failed.") << std::endl;
		return;
	}
	std::string verify_tag;
	cryptography_libary::ValueDecode(aes.output_option, tag, verify_tag);
	std::cout << Hint("<Aes " + AesDisplay[aes.Mode] + " Tag>") << std::endl;
	std::cout << Ask(verify_tag) << std::endl;
	result.assign(ciphertext.begin(), ciphertext.end());
	result.resize(length);
}

void aes_execute::OcbDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> nonce;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> tag;
	std::vector<unsigned char> aad;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.nonce_option, aes.Nonce, nonce);
	cryptography_libary::ValueEncode(aes.ciphertext_option, aes.CipherText, ciphertext);
	cryptography_libary::ValueEncode(aes.tag_option, aes.Tag, tag);
	cryptography_libary::ValueEncode(aes.aad_option, aes.Aad, aad);
	plaintext.resize(ciphertext.size());
	AES_OCB_DECRYPT decryption = {
		key.data(),
		nonce.data(),
		ciphertext.data(),
		plaintext.data(),
		tag.data(),
		aad.data(),
		key.size(),
		ciphertext.size(),
		nonce.size(),
		tag.size(),
		aad.size(),
	};
	int length = ((AesOcbDecrypt)AesFunctions.at("-ocb-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CCM Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(plaintext.begin(), plaintext.end());
	result.resize(length);
}

void aes_execute::WrapEncrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> key;
	std::vector<unsigned char> kek;
	std::vector<unsigned char> wrap;
	cryptography_libary::ValueEncode(aes.key_option, aes.Key, key);
	cryptography_libary::ValueEncode(aes.kek_option, aes.Kek, kek);
	wrap.resize(key.size() + 8);
	AES_WRAP_ENCRYPT encryption = {
		key.data(),
		kek.data(),
		wrap.data(),
		key.size(),
		kek.size(),
		wrap.size(),
	};
	int length = ((AesWrapEncrypt)AesFunctions.at("-wrap-encrypt"))(&encryption);
	if (length < 0) {
		std::cerr << Error("AES WRAP Encrypt Failed.") << std::endl;
		return;
	}
	result.assign(wrap.begin(), wrap.end());
	result.resize(length);
}

void aes_execute::WrapDecrypt(std::vector<unsigned char>& result, Aes& aes) {
	std::vector<unsigned char> wrap;
	std::vector<unsigned char> kek;
	std::vector<unsigned char> key;
	cryptography_libary::ValueEncode(aes.wrap_option, aes.Wrap, wrap);
	cryptography_libary::ValueEncode(aes.kek_option, aes.Kek, kek);
	key.resize(wrap.size() - 8);
	AES_WRAP_DECRYPT decryption = {
		wrap.data(),
		kek.data(),
		key.data(),
		wrap.size(),
		kek.size(),
		key.size(),
	};
	int length = ((AesWrapDecrypt)AesFunctions.at("-wrap-decrypt"))(&decryption);
	if (length < 0) {
		std::cerr << Error("AES CCM Decrypt Failed.") << std::endl;
		return;
	}
	result.assign(key.begin(), key.end());
	result.resize(length);
}
#pragma endregion
