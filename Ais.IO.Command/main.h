#pragma once

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <vector>
#include <string>
#include <cstdlib>
#include <iomanip>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <sstream>
#include <chrono>
#include <thread>
#include <fstream>
#include <cstring>
#include <filesystem>
#include <functional>
#include <cstdlib>

enum BINARYIO_TYPE : unsigned char {
    TYPE_BOOLEAN = 1,
    TYPE_BYTE = 2,
    TYPE_SBYTE = 3,
    TYPE_SHORT = 4,
    TYPE_USHORT = 5,
    TYPE_INT = 6,
    TYPE_UINT = 7,
    TYPE_LONG = 8,
    TYPE_ULONG = 9,
    TYPE_FLOAT = 10,
    TYPE_DOUBLE = 11,
    TYPE_BYTES = 12,
    TYPE_STRING = 13,
};

enum CRYPT_OPTIONS : unsigned char {
    OPTION_TEXT = 0,
    OPTION_BASE10 = 1,
    OPTION_BASE16 = 2,
    OPTION_BASE32 = 3,
    OPTION_BASE58 = 4,
    OPTION_BASE62 = 5,
    OPTION_BASE64 = 6,
    OPTION_BASE85 = 7,
    OPTION_BASE91 = 8,
    OPTION_FILE = 9,
};

enum RAND_TYPE : unsigned char {
    RAND_GENERATE = 0,
    RAND_IMPORT = 1,
};

enum CRYPT_TYPE : unsigned char {
    CRYPTION_NULL = 0,
    CRYPTION_ENCRYPT = 1,
    CRYPTION_DECRYPT = 2,
    CRYPTION_SIGNED = 3,
    CRYPTION_VERIFY = 4,
    CRYPTION_DERIVE = 5,
};

enum AES_MODE : unsigned long long {
    AES_NULL = 0,
    AES_CTR = 1,
    AES_CBC = 2,
    AES_CFB = 3,
    AES_OFB = 4,
    AES_ECB = 5,
    AES_GCM = 6,
    AES_CCM = 7,
    AES_XTS = 8,
    AES_OCB = 9,
    AES_WRAP = 10,
};

enum DES_MODE : unsigned long long {
    DES_NULL = 0,
    DES_CBC = 1,
    DES_CFB = 2,
    DES_OFB = 3,
    DES_ECB = 4,
    DES_WRAP = 5,
};

enum HASH_TYPE {
    HASH_NULL           = 0,
	HASH_MD5            = 1,
    HASH_MD5_SHA1       = 2,
    HASH_SHA1           = 3,
    HASH_SHA2_224       = 4,
    HASH_SHA2_256       = 5,
    HASH_SHA2_384       = 6,
    HASH_SHA2_512       = 7,
    HASH_SHA2_512_224   = 8,
    HASH_SHA2_512_256   = 9,
    HASH_SHA3_224       = 10,
    HASH_SHA3_256       = 11,
    HASH_SHA3_384       = 12,
    HASH_SHA3_512       = 13,
    HASH_SHA3_KE_128    = 14,
    HASH_SHA3_KE_256    = 15,
    HASH_BLAKE2S_256    = 16,
    HASH_BLAKE2B_512    = 17,
    HASH_SM3            = 18,
    HASH_RIPEMD160      = 19,
};

enum DSA_MODE : unsigned long long {
    DSA_GENERATE_PARAMS = 0,
    DSA_GENERATE_KEYS = 1,
};

enum RSA_MODE : unsigned long long {
    RSA_GENERATE_PARAMS = 0,
    RSA_GENERATE_KEYS = 1,
    RSA_EXPORT_PARAMS = 2,
    RSA_EXPORT_KEYS = 3,
    RSA_CHECK_PUBLIC = 4,
    RSA_CHECK_PRIVATE = 5,
    RSA_ENCRPTION = 6,
    RSA_DECRPTION = 7,
    RSA_SIGNATURE = 8,
    RSA_VERIFICATION = 9,
};

enum SYMMETRY_CRYPTER {
    SYMMETRY_NULL = 0,
    SYMMETRY_AES_CTR = 1,
    SYMMETRY_AES_CBC = 2,
    SYMMETRY_AES_CFB = 3,
    SYMMETRY_AES_OFB = 4,
    SYMMETRY_AES_ECB = 5,
    SYMMETRY_AES_GCM = 6,
    SYMMETRY_AES_CCM = 7,
    SYMMETRY_AES_XTS = 8,
    SYMMETRY_AES_OCB = 9,
    SYMMETRY_AES_WRAP = 10,
    SYMMETRY_DES_CBC = 11,
    SYMMETRY_DES_CFB = 12,
    SYMMETRY_DES_OFB = 13,
    SYMMETRY_DES_ECB = 14,
    SYMMETRY_DES_WRAP = 15,
};

enum SEGMENT_SIZE_OPTION {
    SEGMENT_NULL = 0,
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_64_BIT = 64,
    SEGMENT_128_BIT = 128,
};

enum SALT_SEQUENCE {
    SALT_NULL = 0,
    SALT_FIRST = 1 << 0,
    SALT_LAST = 1 << 1,
    SALT_MIDDLE = 1 << 2,
};

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

struct Command {
    std::string type;
    std::string value;
    uint64_t position{};
    uint64_t length{};
    std::string input;
    std::string output;
};

struct Rand {
    std::string Value;
    std::string Output;
    RAND_TYPE Type;
    CRYPT_OPTIONS rand_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;
};

struct Aes {
    AES_MODE Mode;
    CRYPT_TYPE Crypt = CRYPT_TYPE::CRYPTION_NULL;
    std::string Key;
    std::string IV;
    std::string PlainText;
    std::string CipherText;
    std::string Tag;
    std::string Aad;
    std::string Tweak;
    std::string Key2;
    std::string Nonce;
    std::string Kek;
    std::string Wrap;
    std::string Output;

    CRYPT_OPTIONS key_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS iv_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS plaintext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS ciphertext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS tag_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS aad_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS tweak_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS key2_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS nonce_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS kek_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS wrap_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;

    long long Counter = 0;
    bool Padding = false;
    SEGMENT_SIZE_OPTION Segment = SEGMENT_SIZE_OPTION::SEGMENT_128_BIT;
};

struct Des {
    DES_MODE Mode;
    CRYPT_TYPE Crypt = CRYPT_TYPE::CRYPTION_NULL;
    std::string Key;
    std::string IV;
    std::string PlainText;
    std::string CipherText;
    std::string Kek;
    std::string Wrap;
    std::string Output;

    CRYPT_OPTIONS key_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS iv_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS plaintext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS ciphertext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS kek_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS wrap_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;

    bool Padding = false;
    SEGMENT_SIZE_OPTION Segment = SEGMENT_SIZE_OPTION::SEGMENT_64_BIT;
};

struct Hashes {
    HASH_TYPE Mode;
    std::string Input;
    std::string Salt;
    std::string Output;
    size_t Length = 0;

    CRYPT_OPTIONS input_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS salt_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;

    SALT_SEQUENCE Sequence = SALT_SEQUENCE::SALT_NULL;
};

struct Dsa {
    DSA_MODE Mode;
    std::string Y;
    std::string X;
    std::string P;
    std::string Q;
    std::string G;
    std::string Params;
    std::string Output;
    size_t KeyLength = 0;

    CRYPT_OPTIONS param_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;
};

struct Rsa {
    RSA_MODE Mode;
    std::string N;
    std::string E;
    std::string D;
    std::string P;
    std::string Q;
    std::string DP;
    std::string DQ;
    std::string QI;
    std::string Params;
    std::string PublicKey;
    std::string PrivateKey;
    std::string Password;
    std::string PlainText;
    std::string CipherText;
    std::string Data;
    std::string Signature;
    std::string Output;
    size_t KeyLength = 0;

    CRYPT_OPTIONS param_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS publickey_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS privatekey_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS password_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS plaintext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS ciphertext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS data_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS signature_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;

    ASYMMETRIC_KEY_FORMAT KeyFormat = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
    SYMMETRY_CRYPTER Algorithm = SYMMETRY_CRYPTER::SYMMETRY_AES_CBC;
    int AlgorithmSize = 256;
    SEGMENT_SIZE_OPTION Segment = SEGMENT_SIZE_OPTION::SEGMENT_1_BIT;
    HASH_TYPE Hash = HASH_TYPE::HASH_SHA2_256;
};

#pragma pack(push, 1)
struct BINARYIO_INDICES {
    uint64_t POSITION;
    BINARYIO_TYPE TYPE;
    uint64_t LENGTH;
};
#pragma pack(pop)

struct AES_CTR_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    const long long COUNTER;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CTR_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    long long COUNTER;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_CBC_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CBC_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_CFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_CFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_OFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_OFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_ECB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct AES_ECB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct AES_GCM_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_GCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_CCM_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_CCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_XTS_ENCRYPT {
    const unsigned char* KEY1;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    const unsigned char* KEY2;
    const unsigned char* TWEAK;
    size_t KEY1_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t KEY2_LENGTH;
};

struct AES_XTS_DECRYPT {
    const unsigned char* KEY1;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* KEY2;
    const unsigned char* TWEAK;
    size_t KEY1_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t KEY2_LENGTH;
};

struct AES_OCB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_OCB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* NONCE;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* AAD;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t NONCE_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_WRAP_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* KEK;
    unsigned char* WRAP_KEY;
    size_t KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t WRAP_KEY_LENGTH;
};

struct AES_WRAP_DECRYPT {
    const unsigned char* WRAP_KEY;
    const unsigned char* KEK;
    unsigned char* KEY;
    size_t WRAP_KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t KEY_LENGTH;
};

struct DES_CBC_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_CBC_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_CFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_CFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    SEGMENT_SIZE_OPTION SEGMENT_SIZE;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_OFB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_OFB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_ECB_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct DES_ECB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    bool PKCS7_PADDING;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct DES_WRAP_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* KEK;
    unsigned char* WRAP_KEY;
    size_t KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t WRAP_KEY_LENGTH;
};

struct DES_WRAP_DECRYPT {
    const unsigned char* WRAP_KEY;
    const unsigned char* KEK;
    unsigned char* KEY;
    size_t WRAP_KEY_LENGTH;
    size_t KEK_LENGTH;
    size_t KEY_LENGTH;
};

struct HASH_STRUCTURE {
    const unsigned char* INPUT;
    const unsigned char* SALT;
    unsigned char* OUTPUT;
    HASH_TYPE TYPE;
    SALT_SEQUENCE SEQUENCE;
    size_t INPUT_LENGTH;
    size_t SALT_LENGTH;
    size_t OUTPUT_LENGTH;
};

struct DSA_PARAMETERS {
    const size_t KEY_LENGTH;
    unsigned char* Y;
    unsigned char* X;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* G;
    size_t Y_LENGTH;
    size_t X_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t G_LENGTH;
};

struct RSA_PARAMETERS {
    const size_t KEY_LENGTH;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
};

struct RSA_KEY_PAIR {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct RSA_CHECK_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    size_t PUBLIC_KEY_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_PRIVATE_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_EXPORT {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct RSA_ENCRYPT {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    size_t PUBLIC_KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
};

struct RSA_DECRYPT {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
};

struct RSA_SIGNED {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    const unsigned char* DATA;
    unsigned char* SIGNATURE;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    size_t DATA_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
};

struct RSA_VERIFY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* DATA;
    const unsigned char* SIGNATURE;
    size_t PUBLIC_KEY_LENGTH;
    size_t DATA_LENGTH;
    size_t SIGNATURE_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
    bool IS_VALID;
};

// Define function pointer types for all APIs
#pragma region BinaryIO
typedef uint64_t(*NextLength)(void*);
typedef BINARYIO_TYPE(*ReadType)(void*);
typedef BINARYIO_INDICES* (*GetAllIndices)(void*, uint64_t*);
typedef void (*RemoveIndex)(void*, const char*, BINARYIO_INDICES*);
typedef void (*FreeIndexArray)(BINARYIO_INDICES*);
#pragma endregion

#pragma region BinaryReaderIO
typedef void* (*CreateBinaryReader)(const char*);
typedef void (*DestroyBinaryReader)(void*);
typedef uint64_t(*GetReaderPosition)(void*);
typedef uint64_t(*GetReaderLength)(void*);

typedef bool (*ReadBoolean)(void*, int64_t);
typedef unsigned char (*ReadByte)(void*, int64_t);
typedef signed char (*ReadSByte)(void*, int64_t);
typedef short (*ReadShort)(void*, int64_t);
typedef unsigned short (*ReadUShort)(void*, int64_t);
typedef int (*ReadInt)(void*, int64_t);
typedef unsigned int (*ReadUInt)(void*, int64_t);
typedef long long (*ReadLong)(void*, int64_t);
typedef unsigned long long (*ReadULong)(void*, int64_t);
typedef float (*ReadFloat)(void*, int64_t);
typedef double (*ReadDouble)(void*, int64_t);
typedef void (*ReadBytes)(void*, unsigned char*, uint64_t, int64_t);
typedef void (*ReadString)(void*, char*, uint64_t, int64_t);
#pragma endregion

#pragma region BinaryWriterIO
typedef void* (*CreateBinaryWriter)(const char*);
typedef void (*DestroyBinaryWriter)(void*);
typedef uint64_t(*GetWriterPosition)(void*);
typedef uint64_t(*GetWriterLength)(void*);

typedef void (*WriteBoolean)(void*, bool);
typedef void (*WriteByte)(void*, unsigned char);
typedef void (*WriteSByte)(void*, signed char);
typedef void (*WriteShort)(void*, short);
typedef void (*WriteUShort)(void*, unsigned short);
typedef void (*WriteInt)(void*, int);
typedef void (*WriteUInt)(void*, unsigned int);
typedef void (*WriteLong)(void*, long long);
typedef void (*WriteULong)(void*, unsigned long long);
typedef void (*WriteFloat)(void*, float);
typedef void (*WriteDouble)(void*, double);
typedef void (*WriteBytes)(void*, const unsigned char*, uint64_t);
typedef void (*WriteString)(void*, const char*);
#pragma endregion

#pragma region BinaryAppenderIO
typedef void* (*CreateBinaryAppender)(const char*);
typedef void (*DestroyBinaryAppender)(void*);
typedef uint64_t(*GetAppenderPosition)(void*);
typedef uint64_t(*GetAppenderLength)(void*);

typedef void (*AppendBoolean)(void*, bool);
typedef void (*AppendByte)(void*, unsigned char);
typedef void (*AppendSByte)(void*, signed char);
typedef void (*AppendShort)(void*, short);
typedef void (*AppendUShort)(void*, unsigned short);
typedef void (*AppendInt)(void*, int);
typedef void (*AppendUInt)(void*, unsigned int);
typedef void (*AppendLong)(void*, long long);
typedef void (*AppendULong)(void*, unsigned long long);
typedef void (*AppendFloat)(void*, float);
typedef void (*AppendDouble)(void*, double);
typedef void (*AppendBytes)(void*, const unsigned char*, uint64_t);
typedef void (*AppendString)(void*, const char*);
#pragma endregion

#pragma region BinaryInserterIO
typedef void* (*CreateBinaryInserter)(const char*);
typedef void (*DestroyBinaryInserter)(void*);
typedef uint64_t (*GetInserterPosition)(void*);
typedef uint64_t (*GetInserterLength)(void*);

typedef void (*InsertBoolean)(void*, bool, uint64_t);
typedef void (*InsertByte)(void*, unsigned char, uint64_t);
typedef void (*InsertSByte)(void*, signed char, uint64_t);
typedef void (*InsertShort)(void*, short, uint64_t);
typedef void (*InsertUShort)(void*, unsigned short, uint64_t);
typedef void (*InsertInt)(void*, int, uint64_t);
typedef void (*InsertUInt)(void*, unsigned int, uint64_t);
typedef void (*InsertLong)(void*, long long, uint64_t);
typedef void (*InsertULong)(void*, unsigned long long, uint64_t);
typedef void (*InsertFloat)(void*, float, uint64_t);
typedef void (*InsertDouble)(void*, double, uint64_t);
typedef void (*InsertBytes)(void*, const unsigned char*, uint64_t, uint64_t);
typedef void (*InsertString)(void*, const char*, uint64_t);
#pragma endregion

#pragma region BaseEncoderIO
typedef size_t (*Base10Length)(const size_t, bool);
typedef size_t (*Base16Length)(const size_t, bool);
typedef size_t (*Base32Length)(const size_t, bool);
typedef size_t (*Base58Length)(const size_t, bool);
typedef size_t (*Base62Length)(const size_t, bool);
typedef size_t (*Base64Length)(const size_t, bool);
typedef size_t (*Base85Length)(const size_t, bool);
typedef size_t (*Base91Length)(const size_t, bool);

typedef int (*Base10Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base10Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base16Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base16Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base32Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base58Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base58Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base62Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base62Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base64Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base85Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base91Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base91Decode)(const char*, const size_t, unsigned char*, const size_t);
#pragma endregion

#pragma region SymmetryIO
typedef int (*Generate)(unsigned char*, size_t);
typedef int (*Import)(const unsigned char*, size_t, unsigned char*, size_t);
#pragma endregion

#pragma region AesIO
typedef int (*AesCtrEncrypt)(AES_CTR_ENCRYPT*);
typedef int (*AesCtrDecrypt)(AES_CTR_DECRYPT*);
typedef int (*AesCbcEncrypt)(AES_CBC_ENCRYPT*);
typedef int (*AesCbcDecrypt)(AES_CBC_DECRYPT*);
typedef int (*AesCfbEncrypt)(AES_CFB_ENCRYPT*);
typedef int (*AesCfbDecrypt)(AES_CFB_DECRYPT*);
typedef int (*AesOfbEncrypt)(AES_OFB_ENCRYPT*);
typedef int (*AesOfbDecrypt)(AES_OFB_DECRYPT*);
typedef int (*AesEcbEncrypt)(AES_ECB_ENCRYPT*);
typedef int (*AesEcbDecrypt)(AES_ECB_DECRYPT*);
typedef int (*AesGcmEncrypt)(AES_GCM_ENCRYPT*);
typedef int (*AesGcmDecrypt)(AES_GCM_DECRYPT*);
typedef int (*AesCcmEncrypt)(AES_CCM_ENCRYPT*);
typedef int (*AesCcmDecrypt)(AES_CCM_DECRYPT*);
typedef int (*AesXtsEncrypt)(AES_XTS_ENCRYPT*);
typedef int (*AesXtsDecrypt)(AES_XTS_DECRYPT*);
typedef int (*AesOcbEncrypt)(AES_OCB_ENCRYPT*);
typedef int (*AesOcbDecrypt)(AES_OCB_DECRYPT*);
typedef int (*AesWrapEncrypt)(AES_WRAP_ENCRYPT*);
typedef int (*AesWrapDecrypt)(AES_WRAP_DECRYPT*);
#pragma endregion

#pragma region DesIO
typedef int (*DesCbcEncrypt)(DES_CBC_ENCRYPT*);
typedef int (*DesCbcDecrypt)(DES_CBC_DECRYPT*);
typedef int (*DesCfbEncrypt)(DES_CFB_ENCRYPT*);
typedef int (*DesCfbDecrypt)(DES_CFB_DECRYPT*);
typedef int (*DesOfbEncrypt)(DES_OFB_ENCRYPT*);
typedef int (*DesOfbDecrypt)(DES_OFB_DECRYPT*);
typedef int (*DesEcbEncrypt)(DES_ECB_ENCRYPT*);
typedef int (*DesEcbDecrypt)(DES_ECB_DECRYPT*);
typedef int (*DesWrapEncrypt)(DES_WRAP_ENCRYPT*);
typedef int (*DesWrapDecrypt)(DES_WRAP_DECRYPT*);
#pragma endregion

#pragma region HashIO
typedef int (*Hash)(HASH_STRUCTURE*);
typedef int (*GetHashLength)(HASH_TYPE);
#pragma endregion

#pragma region DsaIO
typedef int (*DsaGetParametersLength)(DSA_PARAMETERS*);
typedef int (*DsaGenerateParameters)(DSA_PARAMETERS*);
#pragma endregion


#pragma region RsaIO
typedef int (*RsaGetParametersLength)(RSA_PARAMETERS*);
typedef int (*RsaGetKeyLength)(RSA_KEY_PAIR*);
typedef int (*RsaCheckPublicKey)(RSA_CHECK_PUBLIC_KEY*);
typedef int (*RsaCheckPrivateKey)(RSA_CHECK_PRIVATE_KEY*);
typedef int (*RsaGenerateParameters)(RSA_PARAMETERS*);
typedef int (*RsaGenerateKeys)(RSA_KEY_PAIR*);
typedef int (*RsaExportParameters)(RSA_EXPORT*);
typedef int (*RsaExportKeys)(RSA_EXPORT*);
typedef int (*RsaEncryption)(RSA_ENCRYPT*);
typedef int (*RsaDecryption)(RSA_DECRYPT*);
typedef int (*RsaSigned)(RSA_SIGNED*);
typedef int (*RsaVerify)(RSA_VERIFY*);
#pragma endregion

extern std::unordered_map<std::string, void*> ReadFunctions;
extern std::unordered_map<std::string, void*> WriteFunctions;
extern std::unordered_map<std::string, void*> AppendFunctions;
extern std::unordered_map<std::string, void*> InsertFunctions;
extern std::unordered_map<std::string, void*> EncodeFunctions;
extern std::unordered_map<std::string, void*> SymmetryFunctions;
extern std::unordered_map<std::string, void*> AesFunctions;
extern std::unordered_map<std::string, void*> DesFunctions;
extern std::unordered_map<std::string, void*> HashFunctions;
extern std::unordered_map<std::string, void*> DsaFunctions;
extern std::unordered_map<std::string, void*> RsaFunctions;

extern std::unordered_map<CRYPT_TYPE, std::string> CryptDisplay;
extern std::unordered_map<std::string, AES_MODE> AesMode;
extern std::unordered_map<AES_MODE, std::string> AesDisplay;
extern std::unordered_map<std::string, DES_MODE> DesMode;
extern std::unordered_map<DES_MODE, std::string> DesDisplay;
extern std::unordered_map<std::string, HASH_TYPE> HashMode;
extern std::unordered_map<HASH_TYPE, std::string> HashDisplay;