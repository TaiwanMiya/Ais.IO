#include "hash_execute.h"
#include "string_case.h"
#include "output_colors.h"
#include "cryptography_libary.h"

constexpr size_t hash_execute::hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

size_t hash_execute::set_hash(const char* str) {
	size_t hash = 0;
	while (*str)
		hash = hash * 31 + *str++;
	return hash;
}

void hash_execute::ParseParameters(int argc, char* argv[], Hashes& hash) {
	for (int i = 0; i < argc; ++i) {
		std::string arg = ToLower(argv[i]);
		switch (set_hash(arg.c_str())) {
		case hash_execute::hash("-md5"):
		case hash_execute::hash("-md5-sha1"):
		case hash_execute::hash("-sha1"):
		case hash_execute::hash("-sha2-224"):
		case hash_execute::hash("-sha2-256"):
		case hash_execute::hash("-sha2-384"):
		case hash_execute::hash("-sha2-512"):
		case hash_execute::hash("-sha224"):
		case hash_execute::hash("-sha256"):
		case hash_execute::hash("-sha384"):
		case hash_execute::hash("-sha512"):
		case hash_execute::hash("-sha2-512-224"):
		case hash_execute::hash("-sha2-512-256"):
		case hash_execute::hash("-sha512-224"):
		case hash_execute::hash("-sha512-256"):
		case hash_execute::hash("-sha3-224"):
		case hash_execute::hash("-sha3-256"):
		case hash_execute::hash("-sha3-384"):
		case hash_execute::hash("-sha3-512"):
		case hash_execute::hash("-sha3-ke-128"):
		case hash_execute::hash("-sha3-ke-256"):
		case hash_execute::hash("-shake128"):
		case hash_execute::hash("-shake256"):
		case hash_execute::hash("-blake2s-256"):
		case hash_execute::hash("-blake2b-512"):
		case hash_execute::hash("-blake2s"):
		case hash_execute::hash("-blake2b"):
		case hash_execute::hash("-blake256"):
		case hash_execute::hash("-blake512"):
		case hash_execute::hash("-sm3"):
		case hash_execute::hash("-ripemd160"):
			hash.Mode = HashMode[arg];
			hash.input_option = cryptography_libary::GetOption(i, argv);
			hash.Input = argv[i + 1];
			i++;
			break;
		case hash_execute::hash("-salt"):
			hash.salt_option = cryptography_libary::GetOption(i, argv);
			hash.Salt = argv[i + 1];
			i++;
			break;
		case hash_execute::hash("-first"):
		case hash_execute::hash("-fir"):
			hash.Sequence = static_cast<SALT_SEQUENCE>(hash.Sequence | SALT_SEQUENCE::SALT_FIRST);
			break;
		case hash_execute::hash("-last"):
		case hash_execute::hash("-las"):
			hash.Sequence = static_cast<SALT_SEQUENCE>(hash.Sequence | SALT_SEQUENCE::SALT_LAST);
			break;
		case hash_execute::hash("-middle"):
		case hash_execute::hash("-mid"):
			hash.Sequence = static_cast<SALT_SEQUENCE>(hash.Sequence | SALT_SEQUENCE::SALT_MIDDLE);
			break;
		case hash_execute::hash("-length"):
		case hash_execute::hash("-len"):
			if (IsULong(argv[i + 1])) {
				hash.Length = std::stoull(argv[i + 1]);
				i++;
			}
			break;
		case hash_execute::hash("-output"):
		case hash_execute::hash("-out"):
			hash.output_option = cryptography_libary::GetOption(i, argv);
			if (hash.output_option == CRYPT_OPTIONS::OPTION_FILE) {
				hash.Output = argv[i + 1];
				i++;
			}
			i++;
			break;
		}
	}
}

void hash_execute::HashStart(Hashes& hash) {
	std::vector<unsigned char> input;
	std::vector<unsigned char> salt;
	std::vector<unsigned char> output;
	cryptography_libary::ValueDecode(hash.input_option, hash.Input, input);
	cryptography_libary::ValueDecode(hash.salt_option, hash.Salt, salt);
	int length = (hash.Length != 0 && hash.Mode == HASH_TYPE::HASH_SHA3_KE_128) || (hash.Length != 0 && hash.Mode == HASH_TYPE::HASH_SHA3_KE_256)
		? hash.Length 
		: ((GetHashLength)HashFunctions.at("-hash-length"))(hash.Mode);
	output.resize(length);
	HASH_STRUCTURE hashes = {
		input.data(),
		salt.data(),
		output.data(),
		hash.Mode,
		hash.Sequence,
		input.size(),
		salt.size(),
		output.size(),
	};
	int result = ((Hash)HashFunctions.at("-hash"))(&hashes);
	std::string algorithm = "HASH";
	std::string mode = HashDisplay[hash.Mode];
	std::string result_str = hash.Output;
	std::cout << Hint("<" + algorithm + " " + mode + ">") << std::endl;
	if (result < 0)
		std::cerr << Error("HASH " + mode + " Encrypt Failed.") << std::endl;
	else {
		cryptography_libary::ValueEncode(hash.output_option, output, result_str);
		std::cout << Ask(result_str) << std::endl;
		std::cout << Hint("Data Length: [") << Ask(std::to_string(length)) << Hint("]") << std::endl;
		std::cout << Hint("Input Length: [") << Ask(std::to_string(input.size())) << Hint("]") << std::endl;
		std::cout << Hint("Output Length: [") << Ask(std::to_string(result_str.size())) << Hint("]") << std::endl;
	}
}
