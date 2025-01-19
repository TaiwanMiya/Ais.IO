#include "dsa_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"

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
			case dsa_execute::hash("-paramter"):
			case dsa_execute::hash("-paramters"):
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
		case dsa_execute::hash("-param"):
		case dsa_execute::hash("-params"):
		case dsa_execute::hash("-paramter"):
		case dsa_execute::hash("-paramters"):
			dsa.param_option = cryptography_libary::GetOption(i, argv);
			if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
				dsa.Params = argv[i + 1];
				i++;
			}
			break;
		case dsa_execute::hash("-out"):
		case dsa_execute::hash("-output"):
			if (dsa.Mode == DSA_MODE::DSA_GENERATE_PARAMS) {
				dsa.param_option = cryptography_libary::GetOption(i, argv);
				if (dsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
					std::regex pattern(R"((\.param)$)");
					dsa.Params = argv[i + 1];
					i++;
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
	std::cout << Hint("<RSA Paramters Generate>") << std::endl;
	std::cout << Mark("Length : ") << Ask(std::to_string(dsa.KeyLength)) << std::endl;
	std::cout << Mark("Public Key (Y) [") << Ask(std::to_string(paramters.Y_LENGTH)) << Mark("]:\n") << Ask(y_str) << std::endl;
	std::cout << Mark("Private Key (X) [") << Ask(std::to_string(paramters.X_LENGTH)) << Mark("]:\n") << Ask(x_str) << std::endl;
	std::cout << Mark("Prime Modulus (P) [") << Ask(std::to_string(paramters.P_LENGTH)) << Mark("]:\n") << Ask(p_str) << std::endl;
	std::cout << Mark("Subprime (Q) [") << Ask(std::to_string(paramters.Q_LENGTH)) << Mark("]:\n") << Ask(q_str) << std::endl;
	std::cout << Mark("Generator (G) [") << Ask(std::to_string(paramters.G_LENGTH)) << Mark("]:\n") << Ask(g_str) << std::endl;
}

void dsa_execute::GenerateKeys(Dsa& dsa) {

}