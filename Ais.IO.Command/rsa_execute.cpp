#include "rsa_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"
#include "asymmetric_libary.h"

constexpr size_t rsa_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t rsa_execute::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

void rsa_execute::ParseAlgorithm(int& i, char* argv[], Rsa& rsa) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (rsa_execute::set_hash(arg_option.c_str())) {
	case hash("-aes"):
		i++;
		if (argv[i + 1] == NULL)
			return;
		arg_option = ToLower(argv[i + 1]);
		switch (rsa_execute::set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-ctr"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_CTR;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-cbc"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_CBC;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-cfb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_CFB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
				switch (rsa_execute::set_hash(ToLower(argv[i + 1]).c_str())) {
				case hash("1"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
					i++;
					break;
				case hash("8"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
					i++;
					break;
				case hash("128"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
					i++;
					break;
				default:
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
					i++;
					break;
				}
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
				i++;
			}
			break;
		case hash("-ofb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_OFB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-ecb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_ECB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-gcm"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_GCM;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-ccm"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_CCM;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-xts"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_XTS;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-ocb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_OCB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-wrap"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_WRAP;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		default:break;
		}
		break;
	case hash("-des"):
		i++;
		switch (rsa_execute::set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-cbc"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_DES_CBC;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-cfb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_DES_CFB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
				switch (rsa_execute::set_hash(ToLower(argv[i + 1]).c_str())) {
				case hash("1"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
					i++;
					break;
				case hash("8"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_8_BIT;
					i++;
					break;
				case hash("128"):
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
					i++;
					break;
				default:
					rsa.Segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
					i++;
					break;
				}
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-ofb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_DES_OFB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-ecb"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_DES_ECB;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		case hash("-wrap"):
			rsa.Algorithm = SYMMETRY_CRYPTER::SYMMETRY_DES_WRAP;
			i++;
			if (IsULong(argv[i + 1])) {
				rsa.AlgorithmSize = std::stoi(argv[i + 1]);
				i++;
			}
			else if (argv[i + 1] == NULL)
				rsa.AlgorithmSize = 256;
			else {
				rsa.AlgorithmSize = 256;
				i++;
			}
			break;
		default:break;
		}
		break;
	default:break;
	}
}

void rsa_execute::ParseParameters(int argc, char* argv[], Rsa& rsa) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case rsa_execute::hash("-gen"):
		case rsa_execute::hash("-generate"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case rsa_execute::hash("-key"):
			case rsa_execute::hash("-keys"):
				rsa.Mode = RSA_MODE::RSA_GENERATE_KEYS;
				i++;
				if (IsULong(argv[i + 1])) {
					rsa.KeyLength = std::stoll(argv[i + 1]);
					i++;
				}
				break;
			case rsa_execute::hash("-param"):
			case rsa_execute::hash("-params"):
			case rsa_execute::hash("-paramter"):
			case rsa_execute::hash("-paramters"):
				rsa.Mode = RSA_MODE::RSA_GENERATE_PARAMS;
				i++;
				if (IsULong(argv[i + 1])) {
					rsa.KeyLength = std::stoll(argv[i + 1]);
					i++;
				}
				break;
			default:
				continue;
			}
			break;
		case rsa_execute::hash("-exp"):
		case rsa_execute::hash("-export"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case rsa_execute::hash("-key"):
			case rsa_execute::hash("-keys"):
				rsa.Mode = RSA_MODE::RSA_EXPORT_KEYS;
				i++;
				break;
			case rsa_execute::hash("-param"):
			case rsa_execute::hash("-params"):
			case rsa_execute::hash("-paramter"):
			case rsa_execute::hash("-paramters"):
				rsa.Mode = RSA_MODE::RSA_EXPORT_PARAMS;
				i++;
				break;
			default:
				continue;
			}
			break;
		case rsa_execute::hash("-ext"):
		case rsa_execute::hash("-extract"):
			rsa.Mode = RSA_MODE::RSA_EXTRACT_PUBLIC;
			break;
		case rsa_execute::hash("-chk"):
		case rsa_execute::hash("-check"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case rsa_execute::hash("-pub"):
			case rsa_execute::hash("-public"):
			case rsa_execute::hash("-public-key"):
				rsa.Mode = RSA_MODE::RSA_CHECK_PUBLIC;
				i++;
				rsa.publickey_option = asymmetric_libary::GetOption(rsa, i, argv);
				rsa.PublicKey = argv[i + 1];
				i++;
				break;
			case rsa_execute::hash("-priv"):
			case rsa_execute::hash("-private"):
			case rsa_execute::hash("-private-key"):
				rsa.Mode = RSA_MODE::RSA_CHECK_PRIVATE;
				i++;
				rsa.privatekey_option = asymmetric_libary::GetOption(rsa, i, argv);
				rsa.PrivateKey = argv[i + 1];
				i++;
				break;
			}
			break;
		case rsa_execute::hash("-en"):
		case rsa_execute::hash("-encrypt"):
			rsa.Mode = RSA_MODE::RSA_ENCRPTION;
			break;
		case rsa_execute::hash("-de"):
		case rsa_execute::hash("-decrypt"):
			rsa.Mode = RSA_MODE::RSA_DECRPTION;
			break;
		case rsa_execute::hash("-sign"):
		case rsa_execute::hash("-signed"):
			rsa.Mode = RSA_MODE::RSA_SIGNATURE;
			break;
		case rsa_execute::hash("-ver"):
		case rsa_execute::hash("-verify"):
			rsa.Mode = RSA_MODE::RSA_VERIFICATION;
			break;
		case rsa_execute::hash("-pub"):
		case rsa_execute::hash("-public"):
		case rsa_execute::hash("-public-key"):
			rsa.publickey_option = asymmetric_libary::GetOption(rsa, i, argv);
			rsa.PublicKey = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-priv"):
		case rsa_execute::hash("-private"):
		case rsa_execute::hash("-private-key"):
			rsa.privatekey_option = asymmetric_libary::GetOption(rsa, i, argv);
			rsa.PrivateKey = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-pwd"):
		case rsa_execute::hash("-pass"):
		case rsa_execute::hash("-password"):
			rsa.password_option = cryptography_libary::GetOption(i, argv);
			rsa.Password = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-sg"):
		case rsa_execute::hash("-signature"):
			rsa.signature_option = cryptography_libary::GetOption(i, argv);
			rsa.Signature = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-hash"): {
			std::string hashmode = ToLower(argv[i + 1]);
			if (HashMode.find(hashmode) != HashMode.end()) {
				rsa.Hash = HashMode[hashmode];
				i++;
			}
			break;
		}
		case rsa_execute::hash("-alg"):
		case rsa_execute::hash("-algorithm"):
			rsa_execute::ParseAlgorithm(i, argv, rsa);
			break;
		case rsa_execute::hash("-param"):
		case rsa_execute::hash("-params"):
		case rsa_execute::hash("-paramter"):
		case rsa_execute::hash("-paramters"):
			rsa.param_option = cryptography_libary::GetOption(i, argv);
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
				rsa.Params = argv[i + 1];
				i++;
			}
			break;
		case rsa_execute::hash("-n"):
		case rsa_execute::hash("-modulus"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.N = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-e"):
		case rsa_execute::hash("-public-exponent"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.E = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-d"):
		case rsa_execute::hash("-private-exponent"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.D = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-p"):
		case rsa_execute::hash("-prime1"):
		case rsa_execute::hash("-first-prime-factor"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.P = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-q"):
		case rsa_execute::hash("-prime2"):
		case rsa_execute::hash("-second-prime-factor"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.Q = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-dp"):
		case rsa_execute::hash("-exponent1"):
		case rsa_execute::hash("-first-crt-exponent"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.DP = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-dq"):
		case rsa_execute::hash("-exponent2"):
		case rsa_execute::hash("-second-crt-exponent"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.DQ = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-qi"):
		case rsa_execute::hash("-coefficient"):
		case rsa_execute::hash("-crt-coefficient"):
			if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			rsa.QI = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-pt"):
		case rsa_execute::hash("-plain-text"):
			rsa.plaintext_option = cryptography_libary::GetOption(i, argv);
			rsa.PlainText = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-ct"):
		case rsa_execute::hash("-cipher-text"):
			rsa.ciphertext_option = cryptography_libary::GetOption(i, argv);
			rsa.CipherText = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-dat"):
		case rsa_execute::hash("-data"):
			rsa.data_option = cryptography_libary::GetOption(i, argv);
			rsa.Data = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-out"):
		case rsa_execute::hash("-output"):
			if (rsa.Mode == RSA_MODE::RSA_GENERATE_KEYS || rsa.Mode == RSA_MODE::RSA_EXPORT_KEYS) {
				CRYPT_OPTIONS option = asymmetric_libary::GetOption(rsa, i, argv);
				rsa.publickey_option = option;
				rsa.privatekey_option = option;
				if (rsa.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						rsa.PublicKey = argv[i + 1];
					else
						rsa.PublicKey = rsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
				if (rsa.privatekey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-priv.der|\-priv.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						rsa.PrivateKey = argv[i + 1];
					else
						rsa.PrivateKey = rsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-priv.der"
						: std::string(argv[i + 1]) + "-priv.pem";
				}
			}
			else if (rsa.Mode == RSA_MODE::RSA_GENERATE_PARAMS || rsa.Mode == RSA_MODE::RSA_EXPORT_PARAMS) {
				rsa.param_option = cryptography_libary::GetOption(i, argv);
				if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\.param)$)");
					rsa.Params = argv[i + 1];
					i++;
				}
			}
			else if (rsa.Mode == RSA_MODE::RSA_EXTRACT_PUBLIC) {
				ASYMMETRIC_KEY_FORMAT original_format = rsa.KeyFormat;
				rsa.publickey_option = asymmetric_libary::GetOption(rsa, i, argv);
				if (rsa.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						rsa.PublicKey = argv[i + 1];
					else
						rsa.PublicKey = rsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
				rsa.ExtractKeyFormat = rsa.KeyFormat;
				rsa.KeyFormat = original_format;
			}
			else {
				rsa.output_option = cryptography_libary::GetOption(i, argv);
				if (rsa.output_option == CRYPT_OPTIONS::OPTION_FILE) {
					rsa.Output = argv[i + 1];
					i++;
				}
			}
			i++;
			break;
		}
	}
}

void rsa_execute::RsaStart(Rsa& rsa) {
	switch (rsa.Mode) {
	case RSA_MODE::RSA_GENERATE_PARAMS:
		GenerateParameters(rsa);
		break;
	case RSA_MODE::RSA_GENERATE_KEYS:
		GenerateKeys(rsa);
		break;
	case RSA_MODE::RSA_EXPORT_PARAMS:
		ExportParamters(rsa);
		break;
	case RSA_MODE::RSA_EXPORT_KEYS:
		ExportKeys(rsa);
		break;
	case RSA_MODE::RSA_CHECK_PUBLIC:
		CheckPublicKey(rsa);
		break;
	case RSA_MODE::RSA_CHECK_PRIVATE:
		CheckPrivateKey(rsa);
		break;
	case RSA_MODE::RSA_EXTRACT_PUBLIC:
		ExtractPublicKey(rsa);
		break;
	case RSA_MODE::RSA_ENCRPTION:
		Encrypt(rsa);
		break;
	case RSA_MODE::RSA_DECRPTION:
		Decrypt(rsa);
		break;
	case RSA_MODE::RSA_SIGNATURE:
		Signed(rsa);
			break;
	case RSA_MODE::RSA_VERIFICATION:
		Verify(rsa);
		break;
	}
}

void rsa_execute::GenerateParameters(Rsa& rsa) {
	RSA_PARAMETERS paramters = {
		rsa.KeyLength,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	};
	((RsaGetParametersLength)RsaFunctions.at("-param-length"))(&paramters);
	paramters.N = new unsigned char[paramters.N_LENGTH];
	paramters.E = new unsigned char[paramters.E_LENGTH];
	paramters.D = new unsigned char[paramters.D_LENGTH];
	paramters.P = new unsigned char[paramters.P_LENGTH];
	paramters.Q = new unsigned char[paramters.Q_LENGTH];
	paramters.DP = new unsigned char[paramters.DP_LENGTH];
	paramters.DQ = new unsigned char[paramters.DQ_LENGTH];
	paramters.QI = new unsigned char[paramters.QI_LENGTH];
	int result = ((RsaGenerateParameters)RsaFunctions.at("-param-gen"))(&paramters);
	std::vector<unsigned char> n, e, d, p, q, dp, dq, qi;
	std::string n_str = rsa.Params;
	std::string e_str = rsa.Params;
	std::string d_str = rsa.Params;
	std::string p_str = rsa.Params;
	std::string q_str = rsa.Params;
	std::string dp_str = rsa.Params;
	std::string dq_str = rsa.Params;
	std::string qi_str = rsa.Params;
	n.assign(paramters.N, paramters.N + paramters.N_LENGTH);
	e.assign(paramters.E, paramters.E + paramters.E_LENGTH);
	d.assign(paramters.D, paramters.D + paramters.D_LENGTH);
	p.assign(paramters.P, paramters.P + paramters.P_LENGTH);
	q.assign(paramters.Q, paramters.Q + paramters.Q_LENGTH);
	dp.assign(paramters.DP, paramters.DP + paramters.DP_LENGTH);
	dq.assign(paramters.DQ, paramters.DQ + paramters.DQ_LENGTH);
	qi.assign(paramters.QI, paramters.QI + paramters.QI_LENGTH);
	if (rsa.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(rsa.param_option, n, n_str);
		cryptography_libary::ValueEncode(rsa.param_option, e, e_str);
		cryptography_libary::ValueEncode(rsa.param_option, d, d_str);
		cryptography_libary::ValueEncode(rsa.param_option, p, p_str);
		cryptography_libary::ValueEncode(rsa.param_option, q, q_str);
		cryptography_libary::ValueEncode(rsa.param_option, dp, dp_str);
		cryptography_libary::ValueEncode(rsa.param_option, dq, dq_str);
		cryptography_libary::ValueEncode(rsa.param_option, qi, qi_str);
	}
	else {
		if (std::filesystem::exists(rsa.Params.c_str()))
			std::filesystem::remove_all(rsa.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(rsa.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendBytes)AppendFunctions["-bytes"])(appender, n.data(), n.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, e.data(), e.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, d.data(), d.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, p.data(), p.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x10);
		((AppendBytes)AppendFunctions["-bytes"])(appender, q.data(), q.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x20);
		((AppendBytes)AppendFunctions["-bytes"])(appender, dp.data(), dp.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x40);
		((AppendBytes)AppendFunctions["-bytes"])(appender, dq.data(), dq.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x80);
		((AppendBytes)AppendFunctions["-bytes"])(appender, qi.data(), qi.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		n_str = e_str = d_str = p_str = q_str = dp_str = dq_str = qi_str = std::filesystem::absolute(rsa.Params.c_str()).string();
	}
	std::cout << Hint("<RSA Paramters Generate>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(rsa.KeyLength)) << std::endl;
	std::cout << Mark("Modulus (N) [") << Ask(std::to_string(paramters.N_LENGTH)) << Mark("]:\n") << Ask(n_str) << std::endl;
	std::cout << Mark("Public Exponent (E) [") << Ask(std::to_string(paramters.E_LENGTH)) << Mark("]:\n") << Ask(e_str) << std::endl;
	std::cout << Mark("Private Exponent (D) [") << Ask(std::to_string(paramters.D_LENGTH)) << Mark("]:\n") << Ask(d_str) << std::endl;
	std::cout << Mark("First Prime Factor (P) [") << Ask(std::to_string(paramters.P_LENGTH)) << Mark("]:\n") << Ask(p_str) << std::endl;
	std::cout << Mark("Second Prime Factor (Q) [") << Ask(std::to_string(paramters.Q_LENGTH)) << Mark("]:\n") << Ask(q_str) << std::endl;
	std::cout << Mark("First CRT Exponent (DP) [") << Ask(std::to_string(paramters.DP_LENGTH)) << Mark("]:\n") << Ask(dp_str) << std::endl;
	std::cout << Mark("Second CRT Exponent (DQ) [") << Ask(std::to_string(paramters.DQ_LENGTH)) << Mark("]:\n") << Ask(dq_str) << std::endl;
	std::cout << Mark("CRT Coefficient (QI) [") << Ask(std::to_string(paramters.QI_LENGTH)) << Mark("]:\n") << Ask(qi_str) << std::endl;
}

void rsa_execute::GenerateKeys(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(rsa.KeyLength);
	privateKey.resize(rsa.KeyLength);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, password);
	if (rsa.password_option)
		password.push_back('\0');
	RSA_KEY_PAIR keypair = {
		rsa.KeyLength,
		rsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		rsa.Algorithm,
		rsa.AlgorithmSize,
		rsa.Segment
	};
	((RsaGenerateKeys)RsaFunctions.at("-key-gen"))(&keypair);
	publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
	privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

	std::string publicKey_str = rsa.PublicKey;
	std::string privateKey_str = rsa.PrivateKey;
	cryptography_libary::ValueEncode(rsa.publickey_option, publicKey, publicKey_str);
	cryptography_libary::ValueEncode(rsa.privatekey_option, privateKey, privateKey_str);
	std::cout << Hint("<RSA Keys Generate>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(rsa.KeyLength))<< std::endl;
	std::cout << Mark("Public Key:\n") << Ask(publicKey_str) << std::endl;
	std::cout << Mark("Private Key:\n") << Ask(privateKey_str) << std::endl;
}

void rsa_execute::ExportParamters(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(rsa.PublicKey.size());
	privateKey.resize(rsa.PrivateKey.size());
	cryptography_libary::ValueDecode(rsa.publickey_option, rsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, password);
	password.push_back('\0');
	RSA_KEY_PAIR keyLength = {
		0,
		rsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		rsa.Algorithm,
		rsa.AlgorithmSize,
		rsa.Segment
	};
	((RsaGetKeyLength)RsaFunctions.at("-key-length"))(&keyLength);
	RSA_PARAMETERS paramLength = {
		keyLength.KEY_LENGTH,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
	};
	((RsaGetParametersLength)RsaFunctions.at("-param-length"))(&paramLength);
	RSA_EXPORT paramters = {
		0,
		rsa.KeyFormat,
		new unsigned char[paramLength.N_LENGTH],
		new unsigned char[paramLength.E_LENGTH],
		new unsigned char[paramLength.D_LENGTH],
		new unsigned char[paramLength.P_LENGTH],
		new unsigned char[paramLength.Q_LENGTH],
		new unsigned char[paramLength.DP_LENGTH],
		new unsigned char[paramLength.DQ_LENGTH],
		new unsigned char[paramLength.QI_LENGTH],
		paramLength.N_LENGTH,
		paramLength.E_LENGTH,
		paramLength.D_LENGTH,
		paramLength.P_LENGTH,
		paramLength.Q_LENGTH,
		paramLength.DP_LENGTH,
		paramLength.DQ_LENGTH,
		paramLength.QI_LENGTH,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((RsaExportParameters)RsaFunctions.at("-param-export"))(&paramters);
	std::vector<unsigned char> n, e, d, p, q, dp, dq, qi;
	std::string n_str = rsa.Params;
	std::string e_str = rsa.Params;
	std::string d_str = rsa.Params;
	std::string p_str = rsa.Params;
	std::string q_str = rsa.Params;
	std::string dp_str = rsa.Params;
	std::string dq_str = rsa.Params;
	std::string qi_str = rsa.Params;
	n.assign(paramters.N, paramters.N + paramters.N_LENGTH);
	e.assign(paramters.E, paramters.E + paramters.E_LENGTH);
	d.assign(paramters.D, paramters.D + paramters.D_LENGTH);
	p.assign(paramters.P, paramters.P + paramters.P_LENGTH);
	q.assign(paramters.Q, paramters.Q + paramters.Q_LENGTH);
	dp.assign(paramters.DP, paramters.DP + paramters.DP_LENGTH);
	dq.assign(paramters.DQ, paramters.DQ + paramters.DQ_LENGTH);
	qi.assign(paramters.QI, paramters.QI + paramters.QI_LENGTH);
	if (rsa.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(rsa.param_option, n, n_str);
		cryptography_libary::ValueEncode(rsa.param_option, e, e_str);
		cryptography_libary::ValueEncode(rsa.param_option, d, d_str);
		cryptography_libary::ValueEncode(rsa.param_option, p, p_str);
		cryptography_libary::ValueEncode(rsa.param_option, q, q_str);
		cryptography_libary::ValueEncode(rsa.param_option, dp, dp_str);
		cryptography_libary::ValueEncode(rsa.param_option, dq, dq_str);
		cryptography_libary::ValueEncode(rsa.param_option, qi, qi_str);
	}
	else {
		if (std::filesystem::exists(rsa.Params.c_str()))
			std::filesystem::remove_all(rsa.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(rsa.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendBytes)AppendFunctions["-bytes"])(appender, n.data(), n.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, e.data(), e.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, d.data(), d.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, p.data(), p.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x10);
		((AppendBytes)AppendFunctions["-bytes"])(appender, q.data(), q.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x20);
		((AppendBytes)AppendFunctions["-bytes"])(appender, dp.data(), dp.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x40);
		((AppendBytes)AppendFunctions["-bytes"])(appender, dq.data(), dq.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x80);
		((AppendBytes)AppendFunctions["-bytes"])(appender, qi.data(), qi.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		n_str = e_str = d_str = p_str = q_str = dp_str = dq_str = qi_str = std::filesystem::absolute(rsa.Params.c_str()).string();
	}
	std::cout << Hint("<RSA Paramters Export>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(paramters.KEY_LENGTH)) << std::endl;
	std::cout << Mark("Modulus (N) [") << Ask(std::to_string(paramters.N_LENGTH)) << Mark("]:\n") << Ask(n_str) << std::endl;
	std::cout << Mark("Public Exponent (E) [") << Ask(std::to_string(paramters.E_LENGTH)) << Mark("]:\n") << Ask(e_str) << std::endl;
	std::cout << Mark("Private Exponent (D) [") << Ask(std::to_string(paramters.D_LENGTH)) << Mark("]:\n") << Ask(d_str) << std::endl;
	std::cout << Mark("First Prime Factor (P) [") << Ask(std::to_string(paramters.P_LENGTH)) << Mark("]:\n") << Ask(p_str) << std::endl;
	std::cout << Mark("Second Prime Factor (Q) [") << Ask(std::to_string(paramters.Q_LENGTH)) << Mark("]:\n") << Ask(q_str) << std::endl;
	std::cout << Mark("First CRT Exponent (DP) [") << Ask(std::to_string(paramters.DP_LENGTH)) << Mark("]:\n") << Ask(dp_str) << std::endl;
	std::cout << Mark("Second CRT Exponent (DQ) [") << Ask(std::to_string(paramters.DQ_LENGTH)) << Mark("]:\n") << Ask(dq_str) << std::endl;
	std::cout << Mark("CRT Coefficient (QI) [") << Ask(std::to_string(paramters.QI_LENGTH)) << Mark("]:\n") << Ask(qi_str) << std::endl;
}

void rsa_execute::ExportKeys(Rsa& rsa) {
	std::vector<unsigned char> n, e, d, p, q, dp, dq, qi;
	if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
		void* reader = ((CreateBinaryReader)ReadFunctions["-create"])(rsa.Params.c_str());

		while (((GetReaderPosition)ReadFunctions["-position"])(reader) < ((GetReaderLength)ReadFunctions["-length"])(reader)) {
			BINARYIO_TYPE type = ((ReadType)ReadFunctions["-type"])(reader);
			if (type == BINARYIO_TYPE::TYPE_INT) {
				int param_type = ((ReadInt)ReadFunctions.at("-int"))(reader, -1);
				uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
				switch (param_type)
				{
				case 0x01:
					n.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, n.data(), n.size(), -1);
					break;
				case 0x02:
					e.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, e.data(), e.size(), -1);
					break;
				case 0x04:
					d.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, d.data(), d.size(), -1);
					break;
				case 0x08:
					p.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, p.data(), p.size(), -1);
					break;
				case 0x10:
					q.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, q.data(), q.size(), -1);
					break;
				case 0x20:
					dp.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, dp.data(), dp.size(), -1);
					break;
				case 0x40:
					dq.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, dq.data(), dq.size(), -1);
					break;
				case 0x80:
					qi.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, qi.data(), qi.size(), -1);
					break;
				default:break;
				}
			}
		}
		((DestroyBinaryReader)ReadFunctions["-destory"])(reader);
	}
	else {
		cryptography_libary::ValueDecode(rsa.param_option, rsa.N, n);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.E, e);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.D, d);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.P, p);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.Q, q);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.DP, dp);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.DQ, dq);
		cryptography_libary::ValueDecode(rsa.param_option, rsa.QI, qi);
	}
	
	size_t keysize = n.size() * 8;
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(keysize);
	privateKey.resize(keysize);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, password);

	RSA_EXPORT paramters = {
		0,
		rsa.KeyFormat,
		n.data(),
		e.data(),
		d.data(),
		p.data(),
		q.data(),
		dp.data(),
		dq.data(),
		qi.data(),
		n.size(),
		e.size(),
		d.size(),
		p.size(),
		q.size(),
		dp.size(),
		dq.size(),
		qi.size(),
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((RsaExportKeys)RsaFunctions.at("-key-export"))(&paramters);
	publicKey.resize(paramters.PUBLIC_KEY_LENGTH);
	privateKey.resize(paramters.PRIVATE_KEY_LENGTH);
	std::cout << Hint("<RSA Keys Export>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(paramters.KEY_LENGTH)) << std::endl;
	std::string publicKey_str = rsa.PublicKey;
	std::string privateKey_str = rsa.PrivateKey;
	cryptography_libary::ValueEncode(rsa.publickey_option, publicKey, publicKey_str);
	cryptography_libary::ValueEncode(rsa.privatekey_option, privateKey, privateKey_str);
	std::cout << Mark("Public Key:\n") << Ask(publicKey_str) << std::endl;
	std::cout << Mark("Private Key:\n") << Ask(privateKey_str) << std::endl;
}

void rsa_execute::ExtractPublicKey(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, pemPass);
	pemPass.push_back('\0');

	RSA_CHECK_PRIVATE_KEY priv = {
		rsa.KeyFormat,
		privateKey.data(),
		privateKey.size(),
		pemPass.data(),
		pemPass.size(),
	};
	((RsaCheckPrivateKey)RsaFunctions.at("-priv-check"))(&priv);

	publicKey.resize(priv.KEY_LENGTH);
	
	RSA_EXTRACT_PUBLIC_KEY pub = {
		rsa.ExtractKeyFormat,
		rsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		pemPass.data(),
		publicKey.size(),
		privateKey.size(),
		pemPass.size()
	};
	((RsaExtractPublicKey)RsaFunctions.at("-key-extract"))(&pub);

	publicKey.resize(pub.PUBLIC_KEY_LENGTH);
	std::cout << Hint("<RSA Extract Public Key>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
	std::string publicKey_str = rsa.PublicKey;
	cryptography_libary::ValueEncode(rsa.publickey_option, publicKey, publicKey_str);
	std::cout << Mark("Public Key:\n") << Ask(publicKey_str) << std::endl;
}

void rsa_execute::CheckPublicKey(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	cryptography_libary::ValueDecode(rsa.publickey_option, rsa.PublicKey, publicKey);
	RSA_CHECK_PUBLIC_KEY pub = {
		rsa.KeyFormat,
		publicKey.data(),
		publicKey.size()
	};
	((RsaCheckPublicKey)RsaFunctions.at("-pub-check"))(&pub);
	std::cout << Hint("<RSA Public Key Check>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(pub.KEY_LENGTH)) << std::endl;
	if (pub.IS_KEY_OK)
		std::cout << Hint("Rsa Public Key Check Success.") << std::endl;
	else
		std::cout << Error("Rsa Public Key Check Falture.") << std::endl;
}

void rsa_execute::CheckPrivateKey(Rsa& rsa) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, pemPass);
	RSA_CHECK_PRIVATE_KEY priv = {
		rsa.KeyFormat,
		privateKey.data(),
		privateKey.size(),
		pemPass.data(),
		pemPass.size(),
	};
	((RsaCheckPrivateKey)RsaFunctions.at("-priv-check"))(&priv);
	std::cout << Hint("<RSA Private Key Check>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
	if (priv.IS_KEY_OK)
		std::cout << Hint("Rsa Private Key Check Success.") << std::endl;
	else
		std::cout << Error("Rsa Private Key Check Falture.") << std::endl;
}

void rsa_execute::Encrypt(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> plaintext;
	std::vector<unsigned char> ciphertext;
	cryptography_libary::ValueDecode(rsa.publickey_option, rsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(rsa.plaintext_option, rsa.PlainText, plaintext);

	RSA_CHECK_PUBLIC_KEY pub = {
		rsa.KeyFormat,
		publicKey.data(),
		publicKey.size()
	};
	((RsaCheckPublicKey)RsaFunctions.at("-pub-check"))(&pub);
	if (pub.IS_KEY_OK)
		ciphertext.resize(pub.KEY_LENGTH);
	else {
		std::cout << Hint("<RSA Encrypt>") << std::endl;
		std::cout << Error("Rsa get public key failed.") << std::endl;
	}

	RSA_ENCRYPT encrypt = {
		rsa.KeyFormat,
		publicKey.data(),
		plaintext.data(),
		ciphertext.data(),
		publicKey.size(),
		plaintext.size()
	};
	int result_size = ((RsaEncryption)RsaFunctions.at("-encrypt"))(&encrypt);
	if (result_size != -1) {
		ciphertext.resize(result_size);
		std::cout << Hint("<RSA Encrypt>") << std::endl;
		cryptography_libary::ValueEncode(rsa.output_option, ciphertext, rsa.Output);
		std::cout << Ask(rsa.Output) << std::endl;
	}
	else {
		std::cout << Hint("<RSA Encrypt>") << std::endl;
		std::cout << Error("Rsa encryption failed.") << std::endl;
	}
}

void rsa_execute::Decrypt(Rsa& rsa) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	std::vector<unsigned char> ciphertext;
	std::vector<unsigned char> plaintext;
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, pemPass);
	cryptography_libary::ValueDecode(rsa.ciphertext_option, rsa.CipherText, ciphertext);

	RSA_CHECK_PRIVATE_KEY priv = {
		rsa.KeyFormat,
		privateKey.data(),
		privateKey.size(),
		pemPass.data(),
		pemPass.size(),
	};
	((RsaCheckPrivateKey)RsaFunctions.at("-priv-check"))(&priv);
	if (priv.IS_KEY_OK)
		plaintext.resize(priv.KEY_LENGTH);
	else {
		std::cout << Hint("<RSA Encrypt>") << std::endl;
		std::cout << Error("Rsa get private key failed.") << std::endl;
	}

	RSA_DECRYPT decrypt = {
		rsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		ciphertext.data(),
		plaintext.data(),
		privateKey.size(),
		pemPass.size(),
		ciphertext.size()
	};
	int result_size = ((RsaDecryption)RsaFunctions.at("-decrypt"))(&decrypt);
	if (result_size != -1) {
		plaintext.resize(result_size);
		std::cout << Hint("<RSA Decrypt>") << std::endl;
		cryptography_libary::ValueEncode(rsa.output_option, plaintext, rsa.Output);
		std::cout << Ask(rsa.Output) << std::endl;
	}
	else {
		std::cout << Hint("<RSA Decrypt>") << std::endl;
		std::cout << Error("Rsa decryption failed.") << std::endl;
	}
}

void rsa_execute::Signed(Rsa& rsa) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(rsa.password_option, rsa.Password, pemPass);
	cryptography_libary::ValueDecode(rsa.data_option, rsa.Data, data);

	RSA_CHECK_PRIVATE_KEY priv = {
		rsa.KeyFormat,
		privateKey.data(),
		privateKey.size(),
		pemPass.data(),
		pemPass.size(),
	};
	((RsaCheckPrivateKey)RsaFunctions.at("-priv-check"))(&priv);
	if (priv.IS_KEY_OK)
		signature.resize(priv.KEY_LENGTH);
	else {
		std::cout << Hint("<RSA Encrypt>") << std::endl;
		std::cout << Error("Rsa get private key failed.") << std::endl;
	}

	RSA_SIGNED sign = {
		rsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		data.data(),
		signature.data(),
		privateKey.size(),
		pemPass.size(),
		data.size(),
		rsa.Hash
	};
	int result_size = ((RsaSigned)RsaFunctions.at("-signed"))(&sign);
	if (result_size != -1) {
		signature.resize(result_size);
		std::cout << Hint("<RSA Signed>") << std::endl;
		cryptography_libary::ValueEncode(rsa.output_option, signature, rsa.Output);
		std::cout << Ask(rsa.Output) << std::endl;
	}
	else {
		std::cout << Hint("<RSA Signed>") << std::endl;
		std::cout << Error("Rsa sign failed.") << std::endl;
	}
}

void rsa_execute::Verify(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(rsa.publickey_option, rsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(rsa.data_option, rsa.Data, data);
	cryptography_libary::ValueDecode(rsa.signature_option, rsa.Signature, signature);

	RSA_VERIFY verify = {
		rsa.KeyFormat,
		publicKey.data(),
		data.data(),
		signature.data(),
		publicKey.size(),
		data.size(),
		signature.size(),
		rsa.Hash
	};
	((RsaVerify)RsaFunctions.at("-verify"))(&verify);
	if (verify.IS_VALID) {
		std::cout << Hint("<RSA Verify>") << std::endl;
		std::cout << Ask("Verification Success!") << std::endl;
	}
	else {
		std::cout << Hint("<RSA Verify>") << std::endl;
		std::cout << Error("Verification Failure!") << std::endl;
	}
}
