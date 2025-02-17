#include "dsa_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"
#include "asymmetric_libary.h"

constexpr size_t dsa_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t dsa_execute::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

void dsa_execute::ParseParameters(int argc, char* argv[], Dsa& dsa) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case dsa_execute::hash("-gen"):
		case dsa_execute::hash("-generate"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case dsa_execute::hash("-key"):
			case dsa_execute::hash("-keys"):
				dsa.Mode = DSA_MODE::DSA_GENERATE_KEYS;
				i++;
				if (IsULong(argv[i + 1])) {
					dsa.KeyLength = std::stoll(argv[i + 1]);
					i++;
				}
				break;
			case dsa_execute::hash("-param"):
			case dsa_execute::hash("-params"):
			case dsa_execute::hash("-parameter"):
			case dsa_execute::hash("-parameters"):
				dsa.Mode = DSA_MODE::DSA_GENERATE_PARAMS;
				i++;
				if (IsULong(argv[i + 1])) {
					dsa.KeyLength = std::stoll(argv[i + 1]);
					i++;
				}
				break;
			default:
				continue;
			}
			break;
		case dsa_execute::hash("-exp"):
		case dsa_execute::hash("-export"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case dsa_execute::hash("-key"):
			case dsa_execute::hash("-keys"):
				dsa.Mode = DSA_MODE::DSA_EXPORT_KEYS;
				i++;
				break;
			case dsa_execute::hash("-param"):
			case dsa_execute::hash("-params"):
			case dsa_execute::hash("-parameter"):
			case dsa_execute::hash("-parameters"):
				dsa.Mode = DSA_MODE::DSA_EXPORT_PARAMS;
				i++;
				break;
			default:
				continue;
			}
			break;
		case dsa_execute::hash("-ext"):
		case dsa_execute::hash("-extract"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case dsa_execute::hash("-pub"):
			case dsa_execute::hash("-public"):
			case dsa_execute::hash("-public-key"):
				dsa.Mode = DSA_MODE::DSA_EXTRACT_PUBLIC;
				i++;
				break;
			case dsa_execute::hash("-key"):
			case dsa_execute::hash("-keys"):
				dsa.Mode = DSA_MODE::DSA_EXTRACT_KEYS;
				i++;
				break;
			case dsa_execute::hash("-param"):
			case dsa_execute::hash("-params"):
			case dsa_execute::hash("-parameter"):
			case dsa_execute::hash("-parameters"):
				dsa.Mode = DSA_MODE::DSA_EXTRACT_PARAMETERS;
				i++;
				break;
			default:
				dsa.Mode = DSA_MODE::DSA_EXTRACT_PUBLIC;
				break;
			}
			break;
		case dsa_execute::hash("-chk"):
		case dsa_execute::hash("-check"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case dsa_execute::hash("-pub"):
			case dsa_execute::hash("-public"):
			case dsa_execute::hash("-public-key"):
				dsa.Mode = DSA_MODE::DSA_CHECK_PUBLIC;
				i++;
				dsa.publickey_option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
				dsa.PublicKey = IsInput ? InputContent : argv[i + 1];
				if (!IsInput)
					i++;
				break;
			case dsa_execute::hash("-priv"):
			case dsa_execute::hash("-private"):
			case dsa_execute::hash("-private-key"):
				dsa.Mode = DSA_MODE::DSA_CHECK_PRIVATE;
				i++;
				dsa.privatekey_option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
				dsa.PrivateKey = IsInput ? InputContent : argv[i + 1];
				if (!IsInput)
					i++;
				break;
			case dsa_execute::hash("-param"):
			case dsa_execute::hash("-params"):
			case dsa_execute::hash("-parameter"):
			case dsa_execute::hash("-parameters"):
				dsa.Mode = DSA_MODE::DSA_CHECK_PARAMETER;
				i++;
				dsa.param_option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
				dsa.Params = IsInput ? InputContent : argv[i + 1];
				if (!IsInput)
					i++;
				break;
			}
			break;
		case dsa_execute::hash("-sign"):
		case dsa_execute::hash("-signed"):
			dsa.Mode = DSA_MODE::DSA_SIGNATURE;
			break;
		case dsa_execute::hash("-ver"):
		case dsa_execute::hash("-verify"):
			dsa.Mode = DSA_MODE::DSA_VERIFICATION;
			break;
		case dsa_execute::hash("-pub"):
		case dsa_execute::hash("-public"):
		case dsa_execute::hash("-public-key"):
			dsa.publickey_option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
			dsa.PublicKey = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-priv"):
		case dsa_execute::hash("-private"):
		case dsa_execute::hash("-private-key"):
			dsa.privatekey_option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
			dsa.PrivateKey = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-pwd"):
		case dsa_execute::hash("-pass"):
		case dsa_execute::hash("-password"):
			dsa.password_option = cryptography_libary::GetOption(i, argv);
			dsa.Password = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-sg"):
		case dsa_execute::hash("-signature"):
			dsa.signature_option = cryptography_libary::GetOption(i, argv);
			dsa.Signature = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-hash"): {
			std::string hashmode = ToLower(argv[i + 1]);
			if (HashMode.find(hashmode) != HashMode.end()) {
				dsa.Hash = HashMode[hashmode];
				i++;
			}
			break;
		}
		case dsa_execute::hash("-alg"):
		case dsa_execute::hash("-algorithm"):
			asymmetric_libary::ParseAlgorithm(i, argv, dsa.Algorithm, dsa.AlgorithmSize, dsa.Segment);
			break;
		case dsa_execute::hash("-param"):
		case dsa_execute::hash("-params"):
		case dsa_execute::hash("-parameter"):
		case dsa_execute::hash("-parameters"):
			if (dsa.Mode == DSA_MODE::DSA_EXTRACT_KEYS) {
				dsa.param_option = asymmetric_libary::GetOption(dsa.ExtractKeyFormat, i, argv);
				dsa.Params = argv[i + 1];
				i++;
			}
			else {
				dsa.param_option = cryptography_libary::GetOption(i, argv);
				if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					dsa.Params = argv[i + 1];
					i++;
				}
			}
			break;
		case dsa_execute::hash("-y"):
		case dsa_execute::hash("-public-param"):
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			dsa.Y = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-x"):
		case dsa_execute::hash("-private-param"):
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			dsa.X = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-p"):
		case dsa_execute::hash("-prime"):
		case dsa_execute::hash("-modulus"):
		case dsa_execute::hash("-prime-modulus"):
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			dsa.P = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-q"):
		case dsa_execute::hash("-subprime"):
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			dsa.Q = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-g"):
		case dsa_execute::hash("-generator"):
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			dsa.G = argv[i + 1];
			i++;
			break;
		case dsa_execute::hash("-dat"):
		case dsa_execute::hash("-data"):
			dsa.data_option = cryptography_libary::GetOption(i, argv);
			dsa.Data = IsInput ? InputContent : argv[i + 1];
			if (!IsInput)
				i++;
			break;
		case dsa_execute::hash("-out"):
		case dsa_execute::hash("-output"):
			if (dsa.Mode == DSA_MODE::DSA_GENERATE_KEYS || dsa.Mode == DSA_MODE::DSA_EXPORT_KEYS || dsa.Mode == DSA_MODE::DSA_EXTRACT_KEYS) {
				CRYPT_OPTIONS option = asymmetric_libary::GetOption(dsa.KeyFormat, i, argv);
				dsa.publickey_option = option;
				dsa.privatekey_option = option;
				if (dsa.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						dsa.PublicKey = argv[i + 1];
					else
						dsa.PublicKey = dsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
				if (dsa.privatekey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-priv.der|\-priv.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						dsa.PrivateKey = argv[i + 1];
					else
						dsa.PrivateKey = dsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-priv.der"
						: std::string(argv[i + 1]) + "-priv.pem";
				}
			}
			else if (dsa.Mode == DSA_MODE::DSA_GENERATE_PARAMS || dsa.Mode == DSA_MODE::DSA_EXPORT_PARAMS) {
				dsa.param_option = cryptography_libary::GetOption(i, argv);
				if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					dsa.Params = argv[i + 1];
					i++;
				}
			}
			else if (dsa.Mode == DSA_MODE::DSA_EXTRACT_PUBLIC) {
				dsa.publickey_option = asymmetric_libary::GetOption(dsa.ExtractKeyFormat, i, argv);
				if (dsa.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						dsa.PublicKey = argv[i + 1];
					else
						dsa.PublicKey = dsa.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
			}
			else if (dsa.Mode == DSA_MODE::DSA_EXTRACT_PARAMETERS) {
				dsa.param_option = asymmetric_libary::GetOption(dsa.ExtractKeyFormat, i, argv);
				if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-param.der|\-param.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						dsa.Params = argv[i + 1];
					else
						dsa.Params = dsa.ExtractKeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-param.der"
						: std::string(argv[i + 1]) + "-param.pem";
				}
			}
			else {
				dsa.output_option = cryptography_libary::GetOption(i, argv);
				if (dsa.output_option == CRYPT_OPTIONS::OPTION_FILE) {
					dsa.Output = argv[i + 1];
					i++;
				}
			}
			i++;
			break;
		}
	}
}

void dsa_execute::DsaStart(Dsa& dsa) {
	switch (dsa.Mode) {
	case DSA_MODE::DSA_GENERATE_PARAMS:
		GenerateParameters(dsa);
		break;
	case DSA_MODE::DSA_GENERATE_KEYS:
		GenerateKeys(dsa);
		break;
	case DSA_MODE::DSA_EXPORT_PARAMS:
		ExportParamters(dsa);
		break;
	case DSA_MODE::DSA_EXPORT_KEYS:
		ExportKeys(dsa);
		break;
	case DSA_MODE::DSA_EXTRACT_PUBLIC:
		ExtractPublicKey(dsa);
		break;
	case DSA_MODE::DSA_EXTRACT_PARAMETERS:
		ExtractParametersByKeys(dsa);
		break;
	case DSA_MODE::DSA_EXTRACT_KEYS:
		ExtractKeysByParameters(dsa);
		break;
	case DSA_MODE::DSA_CHECK_PUBLIC:
		CheckPublicKey(dsa);
		break;
	case DSA_MODE::DSA_CHECK_PRIVATE:
		CheckPrivateKey(dsa);
		break;
	case DSA_MODE::DSA_CHECK_PARAMETER:
		CheckParameters(dsa);
		break;
	case DSA_MODE::DSA_SIGNATURE:
		Signed(dsa);
		break;
	case DSA_MODE::DSA_VERIFICATION:
		Verify(dsa);
		break;
	}
}

void dsa_execute::GenerateParameters(Dsa& dsa) {
	DSA_PARAMETERS paramters = {
		dsa.KeyLength,
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
	};
	((DsaGetParametersLength)DsaFunctions.at("-param-length"))(&paramters);
	paramters.Y = new unsigned char[paramters.Y_LENGTH];
	paramters.X = new unsigned char[paramters.X_LENGTH];
	paramters.P = new unsigned char[paramters.P_LENGTH];
	paramters.Q = new unsigned char[paramters.Q_LENGTH];
	paramters.G = new unsigned char[paramters.G_LENGTH];
	int result = ((DsaGenerateParameters)DsaFunctions.at("-param-gen"))(&paramters);
	std::vector<unsigned char> y, x, p, q, g;
	std::string y_str = dsa.Params;
	std::string x_str = dsa.Params;
	std::string p_str = dsa.Params;
	std::string q_str = dsa.Params;
	std::string g_str = dsa.Params;
	y.assign(paramters.Y, paramters.Y + paramters.Y_LENGTH);
	x.assign(paramters.X, paramters.X + paramters.X_LENGTH);
	p.assign(paramters.P, paramters.P + paramters.P_LENGTH);
	q.assign(paramters.Q, paramters.Q + paramters.Q_LENGTH);
	g.assign(paramters.G, paramters.G + paramters.G_LENGTH);
	if (dsa.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(dsa.param_option, y, y_str);
		cryptography_libary::ValueEncode(dsa.param_option, x, x_str);
		cryptography_libary::ValueEncode(dsa.param_option, p, p_str);
		cryptography_libary::ValueEncode(dsa.param_option, q, q_str);
		cryptography_libary::ValueEncode(dsa.param_option, g, g_str);
	}
	else {
		if (std::filesystem::exists(dsa.Params.c_str()))
			std::filesystem::remove_all(dsa.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(dsa.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendBytes)AppendFunctions["-bytes"])(appender, y.data(), y.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, x.data(), x.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, p.data(), p.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, q.data(), q.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x10);
		((AppendBytes)AppendFunctions["-bytes"])(appender, g.data(), g.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		 y_str = x_str = p_str = q_str = g_str = std::filesystem::absolute(dsa.Params.c_str()).string();
	}
	if (!IsRowData) {
		std::cout << Hint("<DSA Parameters Generate>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(dsa.KeyLength)) << std::endl;
		std::cout << Mark("Public Key (Y) [") << Ask(std::to_string(paramters.Y_LENGTH)) << Mark("]:\n") << Ask(y_str) << std::endl;
		std::cout << Mark("Private Key (X) [") << Ask(std::to_string(paramters.X_LENGTH)) << Mark("]:\n") << Ask(x_str) << std::endl;
		std::cout << Mark("Prime Modulus (P) [") << Ask(std::to_string(paramters.P_LENGTH)) << Mark("]:\n") << Ask(p_str) << std::endl;
		std::cout << Mark("Subprime (Q) [") << Ask(std::to_string(paramters.Q_LENGTH)) << Mark("]:\n") << Ask(q_str) << std::endl;
		std::cout << Mark("Generator (G) [") << Ask(std::to_string(paramters.G_LENGTH)) << Mark("]:\n") << Ask(g_str) << std::endl;
	}
	else {
		std::cout << Ask(y_str) << std::endl;
		std::cout << Ask(x_str) << std::endl;
		std::cout << Ask(p_str) << std::endl;
		std::cout << Ask(q_str) << std::endl;
		std::cout << Ask(g_str) << std::endl;
	}
}

void dsa_execute::GenerateKeys(Dsa& dsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(dsa.KeyLength);
	privateKey.resize(dsa.KeyLength);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, password);
	if (dsa.password_option)
		password.push_back('\0');
	DSA_KEY_PAIR keypair = {
		dsa.KeyLength,
		dsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		dsa.Algorithm,
		dsa.AlgorithmSize,
		dsa.Segment
	};
	((DsaGenerateKeys)DsaFunctions.at("-key-gen"))(&keypair);
	publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
	privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

	std::string publicKey_str = dsa.PublicKey;
	std::string privateKey_str = dsa.PrivateKey;
	cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
	cryptography_libary::ValueEncode(dsa.privatekey_option, privateKey, privateKey_str);
	if (!IsRowData) {
		std::cout << Hint("<DSA Keys Generate>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(dsa.KeyLength)) << std::endl;
		std::cout << Mark("Public Key [") << Ask(std::to_string(keypair.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
		std::cout << Mark("Private Key [") << Ask(std::to_string(keypair.PRIVATE_KEY_LENGTH)) << Mark("]:\n") << Ask(privateKey_str) << std::endl;
	}
	else {
		std::cout << Ask(publicKey_str) << std::endl;
		std::cout << Ask(privateKey_str) << std::endl;
	}
}

void dsa_execute::ExportParamters(Dsa& dsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(dsa.PublicKey.size());
	privateKey.resize(dsa.PrivateKey.size());
	cryptography_libary::ValueDecode(dsa.publickey_option, dsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(dsa.privatekey_option, dsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, password);
	if (dsa.password_option)
		password.push_back('\0');
	DSA_KEY_PAIR keyLength = {
		0,
		dsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		dsa.Algorithm,
		dsa.AlgorithmSize,
		dsa.Segment
	};
	((DsaGetKeyLength)DsaFunctions.at("-key-length"))(&keyLength);
	DSA_PARAMETERS paramLength = {
		keyLength.KEY_LENGTH,
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
	};
	((DsaGetParametersLength)DsaFunctions.at("-param-length"))(&paramLength);
	DSA_EXPORT paramters = {
		0,
		dsa.KeyFormat,
		new unsigned char[paramLength.Y_LENGTH],
		new unsigned char[paramLength.X_LENGTH],
		new unsigned char[paramLength.P_LENGTH],
		new unsigned char[paramLength.Q_LENGTH],
		new unsigned char[paramLength.G_LENGTH],
		paramLength.Y_LENGTH,
		paramLength.X_LENGTH,
		paramLength.P_LENGTH,
		paramLength.Q_LENGTH,
		paramLength.G_LENGTH,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((DsaExportParameters)DsaFunctions.at("-param-export"))(&paramters);
	std::vector<unsigned char> y, x, p, q, g;
	std::string y_str = dsa.Params;
	std::string x_str = dsa.Params;
	std::string p_str = dsa.Params;
	std::string q_str = dsa.Params;
	std::string g_str = dsa.Params;
	y.assign(paramters.Y, paramters.Y + paramters.Y_LENGTH);
	x.assign(paramters.X, paramters.X + paramters.X_LENGTH);
	p.assign(paramters.P, paramters.P + paramters.P_LENGTH);
	q.assign(paramters.Q, paramters.Q + paramters.Q_LENGTH);
	g.assign(paramters.G, paramters.G + paramters.G_LENGTH);
	if (dsa.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(dsa.param_option, y, y_str);
		cryptography_libary::ValueEncode(dsa.param_option, x, x_str);
		cryptography_libary::ValueEncode(dsa.param_option, p, p_str);
		cryptography_libary::ValueEncode(dsa.param_option, q, q_str);
		cryptography_libary::ValueEncode(dsa.param_option, g, g_str);
	}
	else {
		if (std::filesystem::exists(dsa.Params.c_str()))
			std::filesystem::remove_all(dsa.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(dsa.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendBytes)AppendFunctions["-bytes"])(appender, y.data(), y.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, x.data(), x.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, p.data(), p.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, q.data(), q.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x10);
		((AppendBytes)AppendFunctions["-bytes"])(appender, g.data(), g.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		y_str = x_str = p_str = q_str = g_str = std::filesystem::absolute(dsa.Params.c_str()).string();
	}
	if (!IsRowData) {
		std::cout << Hint("<DSA Parameters Export>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(paramters.KEY_LENGTH)) << std::endl;
		std::cout << Mark("Public Key (Y) [") << Ask(std::to_string(paramters.Y_LENGTH)) << Mark("]:\n") << Ask(y_str) << std::endl;
		std::cout << Mark("Private Key (X) [") << Ask(std::to_string(paramters.X_LENGTH)) << Mark("]:\n") << Ask(x_str) << std::endl;
		std::cout << Mark("Prime Modulus (P) [") << Ask(std::to_string(paramters.P_LENGTH)) << Mark("]:\n") << Ask(p_str) << std::endl;
		std::cout << Mark("Subprime (Q) [") << Ask(std::to_string(paramters.Q_LENGTH)) << Mark("]:\n") << Ask(q_str) << std::endl;
		std::cout << Mark("Generator (G) [") << Ask(std::to_string(paramters.G_LENGTH)) << Mark("]:\n") << Ask(g_str) << std::endl;
	}
	else {
		std::cout << Ask(y_str) << std::endl;
		std::cout << Ask(x_str) << std::endl;
		std::cout << Ask(p_str) << std::endl;
		std::cout << Ask(q_str) << std::endl;
		std::cout << Ask(g_str) << std::endl;
	}
}

void dsa_execute::ExportKeys(Dsa& dsa) {
	std::vector<unsigned char> y, x, p, q, g;
	if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
		void* reader = ((CreateBinaryReader)ReadFunctions["-create"])(dsa.Params.c_str());

		while (((GetReaderPosition)ReadFunctions["-position"])(reader) < ((GetReaderLength)ReadFunctions["-length"])(reader)) {
			BINARYIO_TYPE type = ((ReadType)ReadFunctions["-type"])(reader);
			if (type == BINARYIO_TYPE::TYPE_INT) {
				int param_type = ((ReadInt)ReadFunctions.at("-int"))(reader, -1);
				uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
				switch (param_type)
				{
				case 0x01:
					y.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, y.data(), y.size(), -1);
					break;
				case 0x02:
					x.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, x.data(), x.size(), -1);
					break;
				case 0x04:
					p.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, p.data(), p.size(), -1);
					break;
				case 0x08:
					q.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, q.data(), q.size(), -1);
					break;
				case 0x10:
					g.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, g.data(), g.size(), -1);
					break;
				default:break;
				}
			}
		}
		((DestroyBinaryReader)ReadFunctions["-destory"])(reader);
	}
	else {
		cryptography_libary::ValueDecode(dsa.param_option, dsa.Y, y);
		cryptography_libary::ValueDecode(dsa.param_option, dsa.X, x);
		cryptography_libary::ValueDecode(dsa.param_option, dsa.P, p);
		cryptography_libary::ValueDecode(dsa.param_option, dsa.Q, q);
		cryptography_libary::ValueDecode(dsa.param_option, dsa.G, g);
	}

	size_t keysize = p.size() * 8;
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(keysize);
	privateKey.resize(keysize);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, password);

	DSA_EXPORT paramters = {
		0,
		dsa.KeyFormat,
		y.data(),
		x.data(),
		p.data(),
		q.data(),
		g.data(),
		y.size(),
		x.size(),
		p.size(),
		q.size(),
		g.size(),
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((DsaExportKeys)DsaFunctions.at("-key-export"))(&paramters);
	publicKey.resize(paramters.PUBLIC_KEY_LENGTH);
	privateKey.resize(paramters.PRIVATE_KEY_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<DSA Keys Export>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(paramters.KEY_LENGTH)) << std::endl;
		std::string publicKey_str = dsa.PublicKey;
		std::string privateKey_str = dsa.PrivateKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(dsa.privatekey_option, privateKey, privateKey_str);
		std::cout << Mark("Public Key [") << Ask(std::to_string(paramters.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
		std::cout << Mark("Private Key [") << Ask(std::to_string(paramters.PRIVATE_KEY_LENGTH)) << Mark("]:\n") << Ask(privateKey_str) << std::endl;
	}
	else {
		std::string publicKey_str = dsa.PublicKey;
		std::string privateKey_str = dsa.PrivateKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(dsa.privatekey_option, privateKey, privateKey_str);
		std::cout << Ask(publicKey_str) << std::endl;
		std::cout << Ask(privateKey_str) << std::endl;
	}
}

void dsa_execute::ExtractPublicKey(Dsa& dsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(dsa.privatekey_option, dsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, pemPass);
	pemPass.push_back('\0');

	DSA_CHECK_PRIVATE_KEY priv = {
		dsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((DsaCheckPrivateKey)DsaFunctions.at("-priv-check"))(&priv);

	publicKey.resize(priv.KEY_LENGTH);

	DSA_EXTRACT_PUBLIC_KEY pub = {
		dsa.ExtractKeyFormat,
		dsa.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		pemPass.data(),
		publicKey.size(),
		privateKey.size(),
		pemPass.size()
	};
	((DsaExtractPublicKey)DsaFunctions.at("-key-extract-pub"))(&pub);

	publicKey.resize(pub.PUBLIC_KEY_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<DSA Extract Public Key>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
		std::string publicKey_str = dsa.PublicKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		std::cout << Mark("Public Key [") << Ask(std::to_string(pub.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
	}
	else {
		std::string publicKey_str = dsa.PublicKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		std::cout << Ask(publicKey_str) << std::endl;
	}
}

void dsa_execute::ExtractParametersByKeys(Dsa& dsa) {
	std::vector<unsigned char> parameters;
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(dsa.publickey_option, dsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(dsa.privatekey_option, dsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, pemPass);
	pemPass.push_back('\0');

	DSA_CHECK_PRIVATE_KEY priv = {
		dsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((DsaCheckPrivateKey)DsaFunctions.at("-priv-check"))(&priv);

	parameters.resize(priv.KEY_LENGTH);

	DSA_EXTRACT_PARAMETERS_KEYS param = {
		dsa.ExtractKeyFormat,
		dsa.KeyFormat,
		parameters.data(),
		publicKey.data(),
		privateKey.data(),
		pemPass.data(),
		parameters.size(),
		publicKey.size(),
		privateKey.size(),
		pemPass.size(),
	};
	((DsaExtractParametersByKeys)DsaFunctions.at("-key-extract-param"))(&param);

	parameters.resize(param.PARAMETERS_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<DSA Extract Parameters>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
		std::string parameters_str = dsa.Params;
		cryptography_libary::ValueEncode(dsa.param_option, parameters, parameters_str);
		std::cout << Mark("Parameters [") << Ask(std::to_string(param.PARAMETERS_LENGTH)) << Mark("]:\n") << Ask(parameters_str) << std::endl;
	}
	else {
		std::string parameters_str = dsa.Params;
		cryptography_libary::ValueEncode(dsa.param_option, parameters, parameters_str);
		std::cout << Ask(parameters_str) << std::endl;
	}
}

void dsa_execute::ExtractKeysByParameters(Dsa& dsa) {
	std::vector<unsigned char> parameters;
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(dsa.param_option, dsa.Params, parameters);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, pemPass);
	if (dsa.password_option)
		pemPass.push_back('\0');

	DSA_CHECK_PARAMETERS param = {
		dsa.ExtractKeyFormat,
		parameters.data(),
		parameters.size()
	};
	((DsaCheckParameters)DsaFunctions.at("-param-check"))(&param);

	publicKey.resize(param.KEY_LENGTH);
	privateKey.resize(param.KEY_LENGTH);

	DSA_EXTRACT_KEYS_PARAMETERS keys = {
		dsa.ExtractKeyFormat,
		dsa.KeyFormat,
		parameters.data(),
		publicKey.data(),
		privateKey.data(),
		pemPass.data(),
		parameters.size(),
		publicKey.size(),
		privateKey.size(),
		pemPass.size()
	};
	((DsaExtractKeysByParameters)DsaFunctions.at("-key-extract-key"))(&keys);

	publicKey.resize(keys.PUBLIC_KEY_LENGTH);
	privateKey.resize(keys.PRIVATE_KEY_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<DSA Extract Keys>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(param.KEY_LENGTH)) << std::endl;
		std::string publicKey_str = dsa.PublicKey;
		std::string privateKey_str = dsa.PrivateKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(dsa.privatekey_option, privateKey, privateKey_str);
		std::cout << Mark("Public Key [") << Ask(std::to_string(keys.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
		std::cout << Mark("Private Key [") << Ask(std::to_string(keys.PRIVATE_KEY_LENGTH)) << Mark("]:\n") << Ask(privateKey_str) << std::endl;
	}
	else {
		std::string publicKey_str = dsa.PublicKey;
		std::string privateKey_str = dsa.PrivateKey;
		cryptography_libary::ValueEncode(dsa.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(dsa.privatekey_option, privateKey, privateKey_str);
		std::cout << Ask(publicKey_str) << std::endl;
		std::cout << Ask(privateKey_str) << std::endl;
	}
}

void dsa_execute::CheckPublicKey(Dsa& dsa) {
	std::vector<unsigned char> publicKey;
	cryptography_libary::ValueDecode(dsa.publickey_option, dsa.PublicKey, publicKey);
	DSA_CHECK_PUBLIC_KEY pub = {
		dsa.KeyFormat,
		publicKey.data(),
		publicKey.size()
	};
	((DsaCheckPublicKey)DsaFunctions.at("-pub-check"))(&pub);
	if (!IsRowData) {
		std::cout << Hint("<DSA Public Key Check>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(pub.KEY_LENGTH)) << std::endl;
	}
	else
		std::cout << Ask(std::to_string(pub.KEY_LENGTH)) << std::endl;
	if (pub.IS_KEY_OK)
		std::cout << Hint(IsRowData ? "Success" : "Dsa Public Key Check Success.") << std::endl;
	else
		std::cout << Error(IsRowData ? "Falture" : "Dsa Public Key Check Falture.") << std::endl;
}

void dsa_execute::CheckPrivateKey(Dsa& dsa) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(dsa.privatekey_option, dsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, pemPass);
	DSA_CHECK_PRIVATE_KEY priv = {
		dsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((DsaCheckPrivateKey)DsaFunctions.at("-priv-check"))(&priv);
	if (!IsRowData) {
		std::cout << Hint("<DSA Private Key Check>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
	}
	else
		std::cout << Ask(std::to_string(priv.KEY_LENGTH)) << std::endl;
	if (priv.IS_KEY_OK)
		std::cout << Hint(IsRowData ? "Success" : "Dsa Private Key Check Success.") << std::endl;
	else
		std::cout << Error(IsRowData ? "Falture" : "Dsa Private Key Check Falture.") << std::endl;
}

void dsa_execute::CheckParameters(Dsa& dsa) {
	std::vector<unsigned char> parameters;
	cryptography_libary::ValueDecode(dsa.param_option, dsa.Params, parameters);
	DSA_CHECK_PARAMETERS param = {
		dsa.KeyFormat,
		parameters.data(),
		parameters.size()
	};
	((DsaCheckParameters)DsaFunctions.at("-param-check"))(&param);
	if (!IsRowData) {
		std::cout << Hint("<DSA Parameters Check>") << std::endl;
		std::cout << Mark("Length : ") << Ask(std::to_string(param.KEY_LENGTH)) << std::endl;
	}
	else
		std::cout << Ask(std::to_string(param.KEY_LENGTH)) << std::endl;
	if (param.IS_KEY_OK)
		std::cout << Hint(IsRowData ? "Success" : "Dsa Parameters Check Success.") << std::endl;
	else
		std::cout << Error(IsRowData ? "Falture" : "Dsa Parameters Check Falture.") << std::endl;
}

void dsa_execute::Signed(Dsa& dsa) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(dsa.privatekey_option, dsa.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(dsa.password_option, dsa.Password, pemPass);
	cryptography_libary::ValueDecode(dsa.data_option, dsa.Data, data);

	DSA_CHECK_PRIVATE_KEY priv = {
		dsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((DsaCheckPrivateKey)DsaFunctions.at("-priv-check"))(&priv);
	if (priv.IS_KEY_OK)
		signature.resize(priv.KEY_LENGTH);
	else {
		if (!IsRowData)
			std::cout << Hint("<DSA Signed>") << std::endl;
		std::cout << Error("Dsa get private key failed.") << std::endl;
	}

	DSA_SIGNED sign = {
		dsa.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		data.data(),
		signature.data(),
		privateKey.size(),
		pemPass.size(),
		data.size(),
		dsa.Hash
	};
	int result_size = ((DsaSigned)DsaFunctions.at("-signed"))(&sign);
	if (result_size != -1) {
		signature.resize(sign.SIGNATURE_LENGTH);
		if (!IsRowData) {
			std::cout << Hint("<DSA Signed>") << std::endl;
			cryptography_libary::ValueEncode(dsa.output_option, signature, dsa.Output);
			std::cout << Ask(dsa.Output) << std::endl;
			std::cout << Hint("Data Length: [") << Ask(std::to_string(sign.SIGNATURE_LENGTH)) << Hint("]") << std::endl;
			std::cout << Hint("Output Length: [") << Ask(std::to_string(dsa.Output.size())) << Hint("]") << std::endl;
		}
		else {
			cryptography_libary::ValueEncode(dsa.output_option, signature, dsa.Output);
			std::cout << Ask(dsa.Output) << std::endl;
		}
	}
	else {
		if (!IsRowData)
			std::cout << Hint("<DSA Signed>") << std::endl;
		std::cout << Error("Dsa sign failed.") << std::endl;
	}
}

void dsa_execute::Verify(Dsa& dsa) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(dsa.publickey_option, dsa.PublicKey, publicKey);
	cryptography_libary::ValueDecode(dsa.data_option, dsa.Data, data);
	cryptography_libary::ValueDecode(dsa.signature_option, dsa.Signature, signature);

	DSA_VERIFY verify = {
		dsa.KeyFormat,
		publicKey.data(),
		data.data(),
		signature.data(),
		publicKey.size(),
		data.size(),
		signature.size(),
		dsa.Hash
	};
	((DsaVerify)DsaFunctions.at("-verify"))(&verify);
	if (verify.IS_VALID) {
		if (!IsRowData)
			std::cout << Hint("<DSA Verify>") << std::endl;
		std::cout << Ask(IsRowData ? "Success" : "Verification Success!") << std::endl;
	}
	else {
		if (!IsRowData)
			std::cout << Hint("<DSA Verify>") << std::endl;
		std::cout << Error(IsRowData ? "Falture" : "Verification Failure!") << std::endl;
	}
}
