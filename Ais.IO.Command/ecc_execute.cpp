#include "ecc_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"
#include "asymmetric_libary.h"

constexpr size_t ecc_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t ecc_execute::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

std::string ecc_execute::ParseEccCurve(Ecc& ecc, bool isGetName) {
	std::string curve_name = EccCurveName[ecc.Curve];
	std::string curve_info = EccCurveDisplay[ecc.Curve];
	return isGetName
		? curve_name
		: curve_info;
}

void ecc_execute::ParseParameters(int argc, char* argv[], Ecc& ecc) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case ecc_execute::hash("-list"):
			ecc.Mode = ECC_MODE::ECC_LIST_CURVE;
			break;
		case ecc_execute::hash("-gen"):
		case ecc_execute::hash("-generate"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case ecc_execute::hash("-key"):
			case ecc_execute::hash("-keys"):
				ecc.Mode = ECC_MODE::ECC_GENERATE_KEYS;
				i++;
				ecc.Curve = IsULong(argv[i + 1])
					? (ECC_CURVE)std::stoi(argv[i + 1])
					: EccCurve[ToLower(argv[i + 1])];
				i++;
				break;
			case ecc_execute::hash("-param"):
			case ecc_execute::hash("-params"):
			case ecc_execute::hash("-parameter"):
			case ecc_execute::hash("-parameters"):
				ecc.Mode = ECC_MODE::ECC_GENERATE_PARAMS;
				i++;
				ecc.Curve = IsULong(argv[i + 1])
					? (ECC_CURVE)std::stoi(argv[i + 1])
					: EccCurve[ToLower(argv[i + 1])];
				i++;
				break;
			default:
				continue;
			}
			break;
		case ecc_execute::hash("-exp"):
		case ecc_execute::hash("-export"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case ecc_execute::hash("-key"):
			case ecc_execute::hash("-keys"):
				ecc.Mode = ECC_MODE::ECC_EXPORT_KEYS;
				i++;
				break;
			case ecc_execute::hash("-param"):
			case ecc_execute::hash("-params"):
			case ecc_execute::hash("-parameter"):
			case ecc_execute::hash("-parameters"):
				ecc.Mode = ECC_MODE::ECC_EXPORT_PARAMS;
				i++;
				break;
			default:
				continue;
			}
			break;
		case ecc_execute::hash("-ext"):
		case ecc_execute::hash("-extract"):
			ecc.Mode = ECC_MODE::ECC_EXTRACT_PUBLIC;
			break;
		case ecc_execute::hash("-chk"):
		case ecc_execute::hash("-check"):
			switch (set_hash(ToLower(argv[i + 1]).c_str())) {
			case ecc_execute::hash("-pub"):
			case ecc_execute::hash("-public"):
			case ecc_execute::hash("-public-key"):
				ecc.Mode = ECC_MODE::ECC_CHECK_PUBLIC;
				i++;
				ecc.publickey_option = asymmetric_libary::GetOption(ecc.KeyFormat, i, argv);
				ecc.PublicKey = IsInput ? InputContent : argv[i + 1];
				if (!IsInput)
					i++;
				break;
			case ecc_execute::hash("-priv"):
			case ecc_execute::hash("-private"):
			case ecc_execute::hash("-private-key"):
				ecc.Mode = ECC_MODE::ECC_CHECK_PRIVATE;
				i++;
				ecc.privatekey_option = asymmetric_libary::GetOption(ecc.KeyFormat, i, argv);
				ecc.PrivateKey = IsInput ? InputContent : argv[i + 1];
				if (!IsInput)
					i++;
				break;
			}
			break;
		case ecc_execute::hash("-sign"):
		case ecc_execute::hash("-signed"):
			ecc.Mode = ECC_MODE::ECC_SIGNATURE;
			break;
		case ecc_execute::hash("-ver"):
		case ecc_execute::hash("-verify"):
			ecc.Mode = ECC_MODE::ECC_VERIFICATION;
			break;
		case ecc_execute::hash("-dv"):
		case ecc_execute::hash("-derive"):
		case ecc_execute::hash("-key-derive"):
			ecc.Mode = ECC_MODE::ECC_KEYDERIVE;
			break;
		case ecc_execute::hash("-pub"):
		case ecc_execute::hash("-public"):
		case ecc_execute::hash("-public-key"):
			ecc.publickey_option = ecc.Mode == ECC_MODE::ECC_KEYDERIVE
				? asymmetric_libary::GetOption(ecc.ExtractKeyFormat, i, argv)
				: asymmetric_libary::GetOption(ecc.KeyFormat, i, argv);
			ecc.PublicKey = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-priv"):
		case ecc_execute::hash("-private"):
		case ecc_execute::hash("-private-key"):
			ecc.privatekey_option = asymmetric_libary::GetOption(ecc.KeyFormat, i, argv);
			ecc.PrivateKey = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-pwd"):
		case ecc_execute::hash("-pass"):
		case ecc_execute::hash("-password"):
			ecc.password_option = cryptography_libary::GetOption(i, argv);
			ecc.Password = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-sg"):
		case ecc_execute::hash("-signature"):
			ecc.signature_option = cryptography_libary::GetOption(i, argv);
			ecc.Signature = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-hash"): {
			std::string hashmode = ToLower(argv[i + 1]);
			if (HashMode.find(hashmode) != HashMode.end()) {
				ecc.Hash = HashMode[hashmode];
				i++;
			}
			break;
		}
		case ecc_execute::hash("-alg"):
		case ecc_execute::hash("-algorithm"):
			asymmetric_libary::ParseAlgorithm(i, argv, ecc.Algorithm, ecc.AlgorithmSize, ecc.Segment);
			break;
		case ecc_execute::hash("-param"):
		case ecc_execute::hash("-params"):
		case ecc_execute::hash("-parameter"):
		case ecc_execute::hash("-parameters"):
			ecc.param_option = cryptography_libary::GetOption(i, argv);
			if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE) {
				ecc.Params = argv[i + 1];
				i++;
			}
			break;
		case ecc_execute::hash("-curve"):
			if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			ecc.Curve = IsULong(argv[i + 1])
				? (ECC_CURVE)std::stoi(argv[i + 1])
				: EccCurve[ToLower(argv[i + 1])];
			i++;
			break;
		case ecc_execute::hash("-x"):
		case ecc_execute::hash("-public-x"):
			if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			ecc.X = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-y"):
		case ecc_execute::hash("-public-y"):
			if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			ecc.Y = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-p"):
		case ecc_execute::hash("-private-exp"):
			if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE)
				continue;
			ecc.EXP = argv[i + 1];
			i++;
			break;
		case ecc_execute::hash("-dat"):
		case ecc_execute::hash("-data"):
			ecc.data_option = cryptography_libary::GetOption(i, argv);
			ecc.Data = IsInput ? InputContent : argv[i + 1];
			if (!IsInput)
				i++;
			break;
		case ecc_execute::hash("-out"):
		case ecc_execute::hash("-output"):
			if (ecc.Mode == ECC_MODE::ECC_GENERATE_KEYS || ecc.Mode == ECC_MODE::ECC_EXPORT_KEYS) {
				CRYPT_OPTIONS option = asymmetric_libary::GetOption(ecc.KeyFormat, i, argv);
				ecc.publickey_option = option;
				ecc.privatekey_option = option;
				if (ecc.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						ecc.PublicKey = argv[i + 1];
					else
						ecc.PublicKey = ecc.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
				if (ecc.privatekey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-priv.der|\-priv.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						ecc.PrivateKey = argv[i + 1];
					else
						ecc.PrivateKey = ecc.KeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-priv.der"
						: std::string(argv[i + 1]) + "-priv.pem";
				}
			}
			else if (ecc.Mode == ECC_MODE::ECC_GENERATE_PARAMS || ecc.Mode == ECC_MODE::ECC_EXPORT_PARAMS) {
				ecc.param_option = cryptography_libary::GetOption(i, argv);
				if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					ecc.Params = argv[i + 1];
					i++;
				}
			}
			else if (ecc.Mode == ECC_MODE::ECC_EXTRACT_PUBLIC) {
				ecc.publickey_option = asymmetric_libary::GetOption(ecc.ExtractKeyFormat, i, argv);
				if (ecc.publickey_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\-pub.der|\-pub.pem)$)");
					if (std::regex_search(argv[i + 1], pattern))
						ecc.PublicKey = argv[i + 1];
					else
						ecc.PublicKey = ecc.ExtractKeyFormat == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER
						? std::string(argv[i + 1]) + "-pub.der"
						: std::string(argv[i + 1]) + "-pub.pem";
				}
			}
			else {
				ecc.output_option = cryptography_libary::GetOption(i, argv);
				if (ecc.output_option == CRYPT_OPTIONS::OPTION_FILE) {
					ecc.Output = argv[i + 1];
					i++;
				}
			}
			i++;
			break;
		}
	}
}

void ecc_execute::EccStart(Ecc& ecc) {
	switch (ecc.Mode) {
	case ECC_MODE::ECC_LIST_CURVE:
		ListEccCurve(ecc);
		break;
	case ECC_MODE::ECC_GENERATE_PARAMS:
		GenerateParameters(ecc);
		break;
	case ECC_MODE::ECC_GENERATE_KEYS:
		GenerateKeys(ecc);
		break;
	case ECC_MODE::ECC_EXPORT_PARAMS:
		ExportParamters(ecc);
		break;
	case ECC_MODE::ECC_EXPORT_KEYS:
		ExportKeys(ecc);
		break;
	case ECC_MODE::ECC_EXTRACT_PUBLIC:
		ExtractPublicKey(ecc);
		break;
	case ECC_MODE::ECC_CHECK_PUBLIC:
		CheckPublicKey(ecc);
		break;
	case ECC_MODE::ECC_CHECK_PRIVATE:
		CheckPrivateKey(ecc);
		break;
	case ECC_MODE::ECC_SIGNATURE:
		Signed(ecc);
		break;
	case ECC_MODE::ECC_VERIFICATION:
		Verify(ecc);
		break;
	case ECC_MODE::ECC_KEYDERIVE:
		KeyDerive(ecc);
		break;
	}
}

void ecc_execute::ListEccCurve(Ecc& ecc) {
	int count = 1;
	for (const auto& pair : EccCurveDisplay) {
		std::string name = EccCurveName[pair.first];
		std::string fullString = pair.second;
		size_t pos = fullString.find(" : ");

		if (pos != std::string::npos) {
			std::string command = fullString.substr(0, pos);
			std::string description = fullString.substr(pos + 3);
			std::cout << Mark(std::to_string(count)) << ". " << Info(name) << " <" << Hint(command) << ">" << " : " << Ask(description) << std::endl;
		}
		count++;
	}
}

void ecc_execute::GenerateParameters(Ecc& ecc) {
	ECC_PARAMETERS paramters = {
		ecc.Curve,
		NULL,
		NULL,
		NULL,
		0,
		0,
		0,
	};
	int result_code = ((EccGetParametersLength)EccFunctions.at("-param-length"))(&paramters);
	if (result_code < 0) {
		paramters.X_LENGTH = 0;
		paramters.Y_LENGTH = 0;
		paramters.EXP_LENGTH = 0;
	}
	paramters.X = new unsigned char[paramters.X_LENGTH];
	paramters.Y = new unsigned char[paramters.Y_LENGTH];
	paramters.EXP = new unsigned char[paramters.EXP_LENGTH];
	result_code = ((EccGenerateParameters)EccFunctions.at("-param-gen"))(&paramters);
	if (result_code < 0) {
		paramters.Y = new unsigned char[0];
		paramters.X = new unsigned char[0];
		paramters.EXP = new unsigned char[0];
		paramters.X_LENGTH = 0;
		paramters.Y_LENGTH = 0;
		paramters.EXP_LENGTH = 0;
	}
	std::vector<unsigned char> x, y, exp;
	std::string y_str = ecc.Params;
	std::string x_str = ecc.Params;
	std::string exp_str = ecc.Params;
	y.assign(paramters.Y, paramters.Y + paramters.Y_LENGTH);
	x.assign(paramters.X, paramters.X + paramters.X_LENGTH);
	exp.assign(paramters.EXP, paramters.EXP + paramters.EXP_LENGTH);
	if (ecc.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(ecc.param_option, y, y_str);
		cryptography_libary::ValueEncode(ecc.param_option, x, x_str);
		cryptography_libary::ValueEncode(ecc.param_option, exp, exp_str);
	}
	else {
		if (std::filesystem::exists(ecc.Params.c_str()))
			std::filesystem::remove_all(ecc.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(ecc.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendInt)AppendFunctions["-int"])(appender, ecc.Curve);
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, x.data(), x.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, y.data(), y.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, exp.data(), exp.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		y_str = x_str = exp_str = std::filesystem::absolute(ecc.Params.c_str()).string();
	}
	if (!IsRowData) {
		std::cout << Hint("<ECC Parameters Generate>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
		std::cout << Mark("Private Key Coordinate (X) [") << Ask(std::to_string(paramters.X_LENGTH)) << Mark("]:\n") << Ask(x_str) << std::endl;
		std::cout << Mark("Public Key Coordinate (Y) [") << Ask(std::to_string(paramters.Y_LENGTH)) << Mark("]:\n") << Ask(y_str) << std::endl;
		std::cout << Mark("Private Exponent  (EXP) [") << Ask(std::to_string(paramters.EXP_LENGTH)) << Mark("]:\n") << Ask(exp_str) << std::endl;
	}
	else {
		std::cout << Ask(x_str) << std::endl;
		std::cout << Ask(y_str) << std::endl;
		std::cout << Ask(exp_str) << std::endl;
	}
}

void ecc_execute::GenerateKeys(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(1024);
	privateKey.resize(1024);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, password);
	if (ecc.password_option)
		password.push_back('\0');
	ECC_KEY_PAIR keypair = {
		ecc.Curve,
		ecc.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		ecc.Algorithm,
		ecc.AlgorithmSize,
		ecc.Segment
	};
	int result_code = ((EccGenerateKeys)EccFunctions.at("-key-gen"))(&keypair);
	if (result_code < 0) {
		keypair.PUBLIC_KEY_LENGTH = 0;
		keypair.PRIVATE_KEY_LENGTH = 0;
	}
	publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
	privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

	std::string publicKey_str = ecc.PublicKey;
	std::string privateKey_str = ecc.PrivateKey;
	cryptography_libary::ValueEncode(ecc.publickey_option, publicKey, publicKey_str);
	cryptography_libary::ValueEncode(ecc.privatekey_option, privateKey, privateKey_str);
	if (!IsRowData) {
		std::cout << Hint("<ECC Keys Generate>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
		std::cout << Mark("Public Key [") << Ask(std::to_string(keypair.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
		std::cout << Mark("Private Key [") << Ask(std::to_string(keypair.PRIVATE_KEY_LENGTH)) << Mark("]:\n") << Ask(privateKey_str) << std::endl;
	}
	else {
		std::cout << Ask(publicKey_str) << std::endl;
		std::cout << Ask(privateKey_str) << std::endl;
	}
}

void ecc_execute::ExportParamters(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(ecc.PublicKey.size());
	privateKey.resize(ecc.PrivateKey.size());
	cryptography_libary::ValueDecode(ecc.publickey_option, ecc.PublicKey, publicKey);
	cryptography_libary::ValueDecode(ecc.privatekey_option, ecc.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, password);
	if (ecc.password_option)
		password.push_back('\0');
	ECC_KEY_PAIR keyLength = {
		ecc.Curve,
		ecc.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size(),
		ecc.Algorithm,
		ecc.AlgorithmSize,
		ecc.Segment
	};
	((EccGetKeyLength)EccFunctions.at("-key-length"))(&keyLength);
	ecc.Curve = keyLength.CURVE_NID;
	ECC_PARAMETERS paramLength = {
		ecc.Curve,
		NULL,
		NULL,
		NULL,
		0,
		0,
		0,
	};
	((EccGetParametersLength)EccFunctions.at("-param-length"))(&paramLength);
	ECC_EXPORT paramters = {
		ecc.Curve,
		ecc.KeyFormat,
		new unsigned char[paramLength.X_LENGTH],
		new unsigned char[paramLength.Y_LENGTH],
		new unsigned char[paramLength.EXP_LENGTH],
		paramLength.X_LENGTH,
		paramLength.Y_LENGTH,
		paramLength.EXP_LENGTH,
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((EccExportParameters)EccFunctions.at("-param-export"))(&paramters);
	std::vector<unsigned char> x, y, exp;
	std::string x_str = ecc.Params;
	std::string y_str = ecc.Params;
	std::string exp_str = ecc.Params;
	x.assign(paramters.X, paramters.X + paramters.X_LENGTH);
	y.assign(paramters.Y, paramters.Y + paramters.Y_LENGTH);
	exp.assign(paramters.EXP, paramters.EXP + paramters.EXP_LENGTH);
	if (ecc.param_option != CRYPT_OPTIONS::OPTION_FILE) {
		cryptography_libary::ValueEncode(ecc.param_option, x, x_str);
		cryptography_libary::ValueEncode(ecc.param_option, y, y_str);
		cryptography_libary::ValueEncode(ecc.param_option, exp, exp_str);
	}
	else {
		if (std::filesystem::exists(ecc.Params.c_str()))
			std::filesystem::remove_all(ecc.Params.c_str());
		void* appender = ((CreateBinaryAppender)AppendFunctions["-create"])(ecc.Params.c_str());
		((AppendInt)AppendFunctions["-int"])(appender, 0x01);
		((AppendInt)AppendFunctions["-int"])(appender, ecc.Curve);
		((AppendInt)AppendFunctions["-int"])(appender, 0x02);
		((AppendBytes)AppendFunctions["-bytes"])(appender, x.data(), x.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x04);
		((AppendBytes)AppendFunctions["-bytes"])(appender, y.data(), y.size());
		((AppendInt)AppendFunctions["-int"])(appender, 0x08);
		((AppendBytes)AppendFunctions["-bytes"])(appender, exp.data(), exp.size());
		((DestroyBinaryAppender)AppendFunctions["-destory"])(appender);
		y_str = x_str = exp_str = std::filesystem::absolute(ecc.Params.c_str()).string();
	}
	if (!IsRowData) {
		std::cout << Hint("<ECC Parameters Export>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
		std::cout << Mark("Private Key Coordinate (X) [") << Ask(std::to_string(paramters.X_LENGTH)) << Mark("]:\n") << Ask(x_str) << std::endl;
		std::cout << Mark("Public Key Coordinate (Y) [") << Ask(std::to_string(paramters.Y_LENGTH)) << Mark("]:\n") << Ask(y_str) << std::endl;
		std::cout << Mark("Private Exponent  (EXP) [") << Ask(std::to_string(paramters.EXP_LENGTH)) << Mark("]:\n") << Ask(exp_str) << std::endl;
	}
	else {
		std::cout << Ask(x_str) << std::endl;
		std::cout << Ask(y_str) << std::endl;
		std::cout << Ask(exp_str) << std::endl;
	}
}

void ecc_execute::ExportKeys(Ecc& ecc) {
	std::vector<unsigned char> x, y, exp;
	if (ecc.param_option == CRYPT_OPTIONS::OPTION_FILE) {
		void* reader = ((CreateBinaryReader)ReadFunctions["-create"])(ecc.Params.c_str());

		while (((GetReaderPosition)ReadFunctions["-position"])(reader) < ((GetReaderLength)ReadFunctions["-length"])(reader)) {
			uint64_t position = ((GetReaderPosition)ReadFunctions["-position"])(reader);
			BINARYIO_TYPE type = ((ReadType)ReadFunctions["-type"])(reader);
			if (type == BINARYIO_TYPE::TYPE_INT) {
				int param_type = ((ReadInt)ReadFunctions.at("-int"))(reader, -1);
				uint64_t length = ((NextLength)ReadFunctions.at("-next-length"))(reader);
				switch (param_type)
				{
				case 0x01: {
					int value = ((ReadInt)ReadFunctions.at("-int"))(reader, position);
					position = ((GetReaderPosition)ReadFunctions["-position"])(reader);
					value = ((ReadInt)ReadFunctions.at("-int"))(reader, position);
					ecc.Curve = static_cast<ECC_CURVE>(value);
					break;
				}
				case 0x02:
					x.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, x.data(), x.size(), -1);
					break;
				case 0x04:
					y.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, y.data(), y.size(), -1);
					break;
				case 0x08:
					exp.resize(length);
					((ReadBytes)ReadFunctions.at("-bytes"))(reader, exp.data(), exp.size(), -1);
					break;
				default:break;
				}
			}
		}
		((DestroyBinaryReader)ReadFunctions["-destory"])(reader);
	}
	else {
		cryptography_libary::ValueDecode(ecc.param_option, ecc.X, x);
		cryptography_libary::ValueDecode(ecc.param_option, ecc.Y, y);
		cryptography_libary::ValueDecode(ecc.param_option, ecc.EXP, exp);
	}

	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> password;
	publicKey.resize(1024);
	privateKey.resize(1024);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, password);

	ECC_EXPORT paramters = {
		ecc.Curve,
		ecc.KeyFormat,
		x.data(),
		y.data(),
		exp.data(),
		x.size(),
		y.size(),
		exp.size(),
		publicKey.data(),
		privateKey.data(),
		password.data(),
		publicKey.size(),
		privateKey.size(),
		password.size()
	};
	((EccExportKeys)EccFunctions.at("-key-export"))(&paramters);
	publicKey.resize(paramters.PUBLIC_KEY_LENGTH);
	privateKey.resize(paramters.PRIVATE_KEY_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<ECC Keys Export>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
		std::string publicKey_str = ecc.PublicKey;
		std::string privateKey_str = ecc.PrivateKey;
		cryptography_libary::ValueEncode(ecc.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(ecc.privatekey_option, privateKey, privateKey_str);
		std::cout << Mark("Public Key [") << Ask(std::to_string(paramters.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
		std::cout << Mark("Private Key [") << Ask(std::to_string(paramters.PRIVATE_KEY_LENGTH)) << Mark("]:\n") << Ask(privateKey_str) << std::endl;
	}
	else {
		std::string publicKey_str = ecc.PublicKey;
		std::string privateKey_str = ecc.PrivateKey;
		cryptography_libary::ValueEncode(ecc.publickey_option, publicKey, publicKey_str);
		cryptography_libary::ValueEncode(ecc.privatekey_option, privateKey, privateKey_str);
		std::cout << Ask(publicKey_str) << std::endl;
		std::cout << Ask(privateKey_str) << std::endl;
	}
}

void ecc_execute::ExtractPublicKey(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(ecc.privatekey_option, ecc.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, pemPass);
	pemPass.push_back('\0');

	ECC_CHECK_PRIVATE_KEY priv = {
		ecc.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	int result_code = ((EccCheckPrivateKey)EccFunctions.at("-priv-check"))(&priv);
	ecc.Curve = priv.CURVE_NID;

	publicKey.resize(result_code < 0 ? 0 : 1024);

	ECC_EXTRACT_PUBLIC_KEY pub = {
		ecc.ExtractKeyFormat,
		ecc.KeyFormat,
		publicKey.data(),
		privateKey.data(),
		pemPass.data(),
		publicKey.size(),
		privateKey.size(),
		pemPass.size()
	};
	result_code = ((EccExtractPublicKey)EccFunctions.at("-key-extract"))(&pub);

	publicKey.resize(result_code < 0 ? 0 : pub.PUBLIC_KEY_LENGTH);
	if (!IsRowData) {
		std::cout << Hint("<ECC Extract Public Key>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
		std::string publicKey_str = ecc.PublicKey;
		cryptography_libary::ValueEncode(ecc.publickey_option, publicKey, publicKey_str);
		std::cout << Mark("Public Key [") << Ask(std::to_string(pub.PUBLIC_KEY_LENGTH)) << Mark("]:\n") << Ask(publicKey_str) << std::endl;
	}
	else {
		std::string publicKey_str = ecc.PublicKey;
		cryptography_libary::ValueEncode(ecc.publickey_option, publicKey, publicKey_str);
		std::cout << Ask(publicKey_str) << std::endl;
	}
}

void ecc_execute::CheckPublicKey(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	cryptography_libary::ValueDecode(ecc.publickey_option, ecc.PublicKey, publicKey);
	ECC_CHECK_PUBLIC_KEY pub = {
		ecc.KeyFormat,
		publicKey.data(),
		publicKey.size()
	};
	((EccCheckPublicKey)EccFunctions.at("-pub-check"))(&pub);
	ecc.Curve = pub.CURVE_NID;
	if (!IsRowData) {
		std::cout << Hint("<ECC Public Key Check>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
	}
	else
		std::cout << Ask(ParseEccCurve(ecc, true)) << std::endl;
	if (pub.IS_KEY_OK)
		std::cout << Hint(IsRowData ? "Success" : "Ecc Public Key Check Success.") << std::endl;
	else
		std::cout << Error(IsRowData ? "Falture" : "Ecc Public Key Check Falture.") << std::endl;
}

void ecc_execute::CheckPrivateKey(Ecc& ecc) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	cryptography_libary::ValueDecode(ecc.privatekey_option, ecc.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, pemPass);
	ECC_CHECK_PRIVATE_KEY priv = {
		ecc.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((EccCheckPrivateKey)EccFunctions.at("-priv-check"))(&priv);
	ecc.Curve = priv.CURVE_NID;
	if (!IsRowData) {
		std::cout << Hint("<ECC Private Key Check>") << std::endl;
		std::cout << Mark("Curve : ") << Ask(ParseEccCurve(ecc, true)) << std::endl;
		std::cout << Mark("Curve Info : ") << Ask(ParseEccCurve(ecc, false)) << std::endl;
	}
	else
		std::cout << Ask(ParseEccCurve(ecc, true)) << std::endl;
	if (priv.IS_KEY_OK)
		std::cout << Hint(IsRowData ? "Success" : "Ecc Private Key Check Success.") << std::endl;
	else
		std::cout << Error(IsRowData ? "Falture" : "Ecc Private Key Check Falture.") << std::endl;
}

void ecc_execute::Signed(Ecc& ecc) {
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(ecc.privatekey_option, ecc.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, pemPass);
	cryptography_libary::ValueDecode(ecc.data_option, ecc.Data, data);

	ECC_CHECK_PRIVATE_KEY priv = {
		ecc.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((EccCheckPrivateKey)EccFunctions.at("-priv-check"))(&priv);
	if (priv.IS_KEY_OK)
		signature.resize(1024);
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Signed>") << std::endl;
		std::cout << Error("Ecc get private key failed.") << std::endl;
	}

	ECC_SIGNED sign = {
		ecc.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		data.data(),
		signature.data(),
		privateKey.size(),
		pemPass.size(),
		data.size(),
		ecc.Hash
	};
	int result_size = ((EccSigned)EccFunctions.at("-signed"))(&sign);
	if (result_size != -1) {
		signature.resize(sign.SIGNATURE_LENGTH);
		if (!IsRowData) {
			std::cout << Hint("<ECC Signed>") << std::endl;
			cryptography_libary::ValueEncode(ecc.output_option, signature, ecc.Output);
			std::cout << Ask(ecc.Output) << std::endl;
			std::cout << Hint("Data Length: [") << Ask(std::to_string(sign.SIGNATURE_LENGTH)) << Hint("]") << std::endl;
			std::cout << Hint("Output Length: [") << Ask(std::to_string(ecc.Output.size())) << Hint("]") << std::endl;
		}
		else {
			cryptography_libary::ValueEncode(ecc.output_option, signature, ecc.Output);
			std::cout << Ask(ecc.Output) << std::endl;
		}
	}
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Signed>") << std::endl;
		std::cout << Error("Ecc sign failed.") << std::endl;
	}
}

void ecc_execute::Verify(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> data;
	std::vector<unsigned char> signature;
	cryptography_libary::ValueDecode(ecc.publickey_option, ecc.PublicKey, publicKey);
	cryptography_libary::ValueDecode(ecc.data_option, ecc.Data, data);
	cryptography_libary::ValueDecode(ecc.signature_option, ecc.Signature, signature);

	ECC_VERIFY verify = {
		ecc.KeyFormat,
		publicKey.data(),
		data.data(),
		signature.data(),
		publicKey.size(),
		data.size(),
		signature.size(),
		ecc.Hash
	};
	((EccVerify)EccFunctions.at("-verify"))(&verify);
	if (verify.IS_VALID) {
		if (!IsRowData)
			std::cout << Hint("<ECC Verify>") << std::endl;
		std::cout << Ask(IsRowData ? "Success" : "Verification Success!") << std::endl;
	}
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Verify>") << std::endl;
		std::cout << Error(IsRowData ? "Falture" : "Verification Failure!") << std::endl;
	}
}

void ecc_execute::KeyDerive(Ecc& ecc) {
	std::vector<unsigned char> publicKey;
	std::vector<unsigned char> privateKey;
	std::vector<unsigned char> pemPass;
	std::vector<unsigned char> deriveKey;
	cryptography_libary::ValueDecode(ecc.publickey_option, ecc.PublicKey, publicKey);
	cryptography_libary::ValueDecode(ecc.privatekey_option, ecc.PrivateKey, privateKey);
	cryptography_libary::ValueDecode(ecc.password_option, ecc.Password, pemPass);

	ECC_CHECK_PRIVATE_KEY priv = {
		ecc.KeyFormat,
		privateKey.data(),
		pemPass.data(),
		privateKey.size(),
		pemPass.size(),
	};
	((EccCheckPrivateKey)EccFunctions.at("-priv-check"))(&priv);
	if (priv.IS_KEY_OK)
		deriveKey.resize(1024);
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Key Derive>") << std::endl;
		std::cout << Error("Ecc get private key failed.") << std::endl;
	}

	ECC_CHECK_PUBLIC_KEY pub = {
		ecc.ExtractKeyFormat,
		publicKey.data(),
		publicKey.size()
	};
	((EccCheckPublicKey)EccFunctions.at("-pub-check"))(&pub);
	if (pub.IS_KEY_OK)
		deriveKey.resize(1024);
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Key Derive>") << std::endl;
		std::cout << Error("Ecc get public key failed.") << std::endl;
	}

	ECC_KEY_DERIVE derive = {
		ecc.KeyFormat,
		ecc.ExtractKeyFormat,
		privateKey.data(),
		pemPass.data(),
		publicKey.data(),
		deriveKey.data(),
		privateKey.size(),
		pemPass.size(),
		publicKey.size(),
		deriveKey.size(),
	};
	int result = ((EccKeyDerive)EccFunctions.at("-derive"))(&derive);
	if (result != -1) {
		deriveKey.resize(derive.DERIVED_KEY_LENGTH);
		if (!IsRowData) {
			std::cout << Hint("<ECC Key Derive>") << std::endl;
			cryptography_libary::ValueEncode(ecc.output_option, deriveKey, ecc.Output);
			std::cout << Ask(ecc.Output) << std::endl;
			std::cout << Hint("Data Length: [") << Ask(std::to_string(derive.DERIVED_KEY_LENGTH)) << Hint("]") << std::endl;
			std::cout << Hint("Output Length: [") << Ask(std::to_string(ecc.Output.size())) << Hint("]") << std::endl;
		}
		else {
			cryptography_libary::ValueEncode(ecc.output_option, deriveKey, ecc.Output);
			std::cout << Ask(ecc.Output) << std::endl;
		}
	}
	else {
		if (!IsRowData)
			std::cout << Hint("<ECC Key Derive>") << std::endl;
		std::cout << Error("Ecc key derive failed.") << std::endl;
	}
}