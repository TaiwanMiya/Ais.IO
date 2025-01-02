#include "rsa_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"

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

CRYPT_OPTIONS rsa_execute::GetOption(Rsa& rsa, int& i, char* argv[]) {
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

void rsa_execute::ParseParameters(int argc, char* argv[], Rsa& rsa) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case rsa_execute::hash("-gen"):
		case rsa_execute::hash("-generate"):
			switch (set_hash(ToLower(argv[i + 1]).c_str()))
			{
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
			switch (set_hash(ToLower(argv[i + 1]).c_str()))
			{
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
		case rsa_execute::hash("-pub"):
		case rsa_execute::hash("-public"):
		case rsa_execute::hash("-public-key"):
			rsa.publickey_option = rsa_execute::GetOption(rsa, i, argv);
			rsa.PublicKey = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-priv"):
		case rsa_execute::hash("-private"):
		case rsa_execute::hash("-private-key"):
			rsa.privatekey_option = rsa_execute::GetOption(rsa, i, argv);
			rsa.PrivateKey = argv[i + 1];
			i++;
			break;
		case rsa_execute::hash("-param"):
		case rsa_execute::hash("-params"):
		case rsa_execute::hash("-paramter"):
		case rsa_execute::hash("-paramters"):
			rsa.param_option = rsa_execute::GetOption(rsa, i, argv);
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
		case rsa_execute::hash("-out"):
		case rsa_execute::hash("-output"):
			if (rsa.Mode == RSA_MODE::RSA_GENERATE_KEYS || rsa.Mode == RSA_MODE::RSA_EXPORT_KEYS) {
				CRYPT_OPTIONS option = rsa_execute::GetOption(rsa, i, argv);
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
	std::cout << Ask("Length:") << rsa.KeyLength << std::endl;
	std::cout << Mark("Modulus (N):\n") << Ask(n_str) << std::endl;
	std::cout << Mark("Public Exponent (E):\n") << Ask(e_str) << std::endl;
	std::cout << Mark("Private Exponent (D):\n") << Ask(d_str) << std::endl;
	std::cout << Mark("First Prime Factor (P):\n") << Ask(p_str) << std::endl;
	std::cout << Mark("Second Prime Factor (Q):\n") << Ask(q_str) << std::endl;
	std::cout << Mark("First CRT Exponent (DP):\n") << Ask(dp_str) << std::endl;
	std::cout << Mark("Second CRT Exponent (DQ):\n") << Ask(dq_str) << std::endl;
	std::cout << Mark("CRT Coefficient (QI):\n") << Ask(qi_str) << std::endl;
}

void rsa_execute::GenerateKeys(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	publicKey.resize(rsa.KeyLength);
	privateKey.resize(rsa.KeyLength);
	RSA_KEY_PAIR keypair = {
		rsa.KeyLength,
		rsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		publicKey.size(),
		privateKey.size(),
	};
	((RsaGenerateKeys)RsaFunctions.at("-key-gen"))(&keypair);
	publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
	privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

	std::string publicKey_str = rsa.PublicKey;
	std::string privateKey_str = rsa.PrivateKey;
	cryptography_libary::ValueEncode(rsa.publickey_option, publicKey, publicKey_str);
	cryptography_libary::ValueEncode(rsa.privatekey_option, privateKey, privateKey_str);
	std::cout << Hint("<RSA Keys Generate>") << std::endl;
	std::cout << Ask("Length:") << rsa.KeyLength << std::endl;
	std::cout << Mark("Public Key:\n") << Ask(publicKey_str) << std::endl;
	std::cout << Mark("Private Key:\n") << Ask(privateKey_str) << std::endl;
}

void rsa_execute::ExportParamters(Rsa& rsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	publicKey.resize(rsa.PublicKey.size());
	privateKey.resize(rsa.PrivateKey.size());
	cryptography_libary::ValueDecode(rsa.publickey_option, rsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(rsa.privatekey_option, rsa.PrivateKey, privateKey);
	RSA_KEY_PAIR keyLength = {
		0,
		rsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		publicKey.size(),
		privateKey.size(),
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
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
	};
	((RsaGetParametersLength)RsaFunctions.at("-param-length"))(&paramLength);
	EXPORT_RSA paramters = {
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
		publicKey.size(),
		privateKey.size(),
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
	std::cout << Ask("Length:") << rsa.KeyLength << std::endl;
	std::cout << Mark("Modulus (N):\n") << Ask(n_str) << std::endl;
	std::cout << Mark("Public Exponent (E):\n") << Ask(e_str) << std::endl;
	std::cout << Mark("Private Exponent (D):\n") << Ask(d_str) << std::endl;
	std::cout << Mark("First Prime Factor (P):\n") << Ask(p_str) << std::endl;
	std::cout << Mark("Second Prime Factor (Q):\n") << Ask(q_str) << std::endl;
	std::cout << Mark("First CRT Exponent (DP):\n") << Ask(dp_str) << std::endl;
	std::cout << Mark("Second CRT Exponent (DQ):\n") << Ask(dq_str) << std::endl;
	std::cout << Mark("CRT Coefficient (QI):\n") << Ask(qi_str) << std::endl;
}

void rsa_execute::ExportKeys(Rsa& rsa) {

}