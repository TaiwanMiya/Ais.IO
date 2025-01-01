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

RSA_CRYPT_OPTIONS rsa_execute::GetOption(int& i, char* argv[]) {
	std::string arg_option = ToLower(argv[i + 1]);
	switch (set_hash(arg_option.c_str())) {
	case hash("-der"):
		i++;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_FILE;
		case hash("-base16"):
		case hash("-b16"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_BASE16;
		case hash("-base32"):
		case hash("-b32"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_BASE32;
		case hash("-base64"):
		case hash("-b64"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_BASE64;
		case hash("-base85"):
		case hash("-b85"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_BASE85;
		default:
			return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_TEXT;
		}
	case hash("-pem"):
		i++;
		switch (set_hash(ToLower(argv[i + 1]).c_str())) {
		case hash("-file"):
		case hash("-f"):
			i++;
			return RSA_CRYPT_OPTIONS::RSA_OPTION_PEM_FILE;
		default:
			return RSA_CRYPT_OPTIONS::RSA_OPTION_PEM_TEXT;
		}
	default:
		return RSA_CRYPT_OPTIONS::RSA_OPTION_DER_TEXT;
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
			break;
		case rsa_execute::hash("-priv"):
		case rsa_execute::hash("-private"):
		case rsa_execute::hash("-private-key"):
			break;
		case rsa_execute::hash("-out"):
		case rsa_execute::hash("-output"):
			if (rsa.Mode == RSA_MODE::RSA_GENERATE_KEYS || rsa.Mode == RSA_MODE::RSA_EXPORT_KEYS) {
				rsa.publickey_option = rsa_execute::GetOption(i, argv);
				rsa.privatekey_option = rsa_execute::GetOption(i, argv);
				if (rsa.publickey_option == RSA_CRYPT_OPTIONS::RSA_OPTION_DER_FILE || rsa.publickey_option == RSA_CRYPT_OPTIONS::RSA_OPTION_PEM_FILE) {
					rsa.PublicKey = argv[i + 1];
					i++;
				}
				if (rsa.privatekey_option == RSA_CRYPT_OPTIONS::RSA_OPTION_DER_FILE || rsa.privatekey_option == RSA_CRYPT_OPTIONS::RSA_OPTION_PEM_FILE) {
					rsa.PrivateKey = argv[i + 1];
					i++;
				}
			}
			else if (rsa.Mode == RSA_MODE::RSA_GENERATE_PARAMS || rsa.Mode == RSA_MODE::RSA_EXPORT_PARAMS) {
				rsa.param_option = cryptography_libary::GetOption(i, argv);
				if (rsa.param_option == CRYPT_OPTIONS::OPTION_FILE) {
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
	std::string n_str = rsa.Params + ".n";
	std::string e_str = rsa.Params + ".e";
	std::string d_str = rsa.Params + ".d";
	std::string p_str = rsa.Params + ".p";
	std::string q_str = rsa.Params + ".q";
	std::string dp_str = rsa.Params + ".dp";
	std::string dq_str = rsa.Params + ".dq";
	std::string qi_str = rsa.Params + ".qi";
	n.assign(paramters.N, paramters.N + paramters.N_LENGTH);
	e.assign(paramters.E, paramters.E + paramters.E_LENGTH);
	d.assign(paramters.D, paramters.D + paramters.D_LENGTH);
	p.assign(paramters.P, paramters.P + paramters.P_LENGTH);
	q.assign(paramters.Q, paramters.Q + paramters.Q_LENGTH);
	dp.assign(paramters.DP, paramters.DP + paramters.DP_LENGTH);
	dq.assign(paramters.DQ, paramters.DQ + paramters.DQ_LENGTH);
	qi.assign(paramters.QI, paramters.QI + paramters.QI_LENGTH);
	cryptography_libary::ValueEncode(rsa.param_option, n, n_str);
	cryptography_libary::ValueEncode(rsa.param_option, e, e_str);
	cryptography_libary::ValueEncode(rsa.param_option, d, d_str);
	cryptography_libary::ValueEncode(rsa.param_option, p, p_str);
	cryptography_libary::ValueEncode(rsa.param_option, q, q_str);
	cryptography_libary::ValueEncode(rsa.param_option, dp, dp_str);
	cryptography_libary::ValueEncode(rsa.param_option, dq, dq_str);
	cryptography_libary::ValueEncode(rsa.param_option, qi, qi_str);
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

}