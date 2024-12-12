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

enum CRYPT_OPTIONS : unsigned char {
    OPTION_TEXT = 0,
    OPTION_BASE16 = 1,
    OPTION_BASE32 = 2,
    OPTION_BASE64 = 3,
    OPTION_BASE85 = 4,
    OPTION_FILE = 5,
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
    AES_NULL = 0x00,
    AES_CTR = 0x01 << 0,
    AES_CBC = 0x01 << 1,
    AES_CFB = 0x01 << 2,
    AES_OFB = 0x01 << 3,
    AES_ECB = 0x01 << 4,
    AES_GCM = 0x01 << 5,
    AES_CCM = 0x01 << 6,
    AES_XTS = 0x01 << 7,
    AES_OCB = 0x01 << 8,
    AES_WRAP = 0x01 << 9,
};

struct Command {
    std::string type;
    std::string value;
    uint64_t position{};
    uint64_t length{};
    std::string input;
    std::string output;
};

struct Aes {
    AES_MODE Mode;
    CRYPT_TYPE Crypt;
    std::string Key;
    std::string IV;
    std::string PlainText;
    std::string CipherText;
    std::string Tag;
    std::string Aad;
    std::string Tweak;
    std::string Key2;
    std::string Output;

    CRYPT_OPTIONS key_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS iv_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS plaintext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS ciphertext_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS tag_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS aad_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS tweak_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS key2_option = CRYPT_OPTIONS::OPTION_TEXT;
    CRYPT_OPTIONS output_option = CRYPT_OPTIONS::OPTION_TEXT;

    std::string Counter;
    std::string Segment;
};

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

#pragma pack(push, 1)
struct BINARYIO_INDICES {
    uint64_t POSITION;
    BINARYIO_TYPE TYPE;
    uint64_t LENGTH;
};
#pragma pack(pop)

enum SEGMENT_SIZE_OPTION {
    SEGMENT_1_BIT = 1,
    SEGMENT_8_BIT = 8,
    SEGMENT_128_BIT = 128,
};

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
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t IV_LENGTH;
    size_t TAG_LENGTH;
};

struct AES_GCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t IV_LENGTH;
    size_t TAG_LENGTH;
};

struct AES_CCM_ENCRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* ADDITIONAL_DATA;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t IV_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_CCM_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* ADDITIONAL_DATA;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t IV_LENGTH;
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
    const unsigned char* IV;
    const unsigned char* PLAIN_TEXT;
    unsigned char* CIPHER_TEXT;
    unsigned char* TAG;
    const unsigned char* ADDITIONAL_DATA;
    size_t KEY_LENGTH;
    size_t PLAIN_TEXT_LENGTH;
    size_t IV_LENGTH;
    size_t TAG_LENGTH;
    size_t AAD_LENGTH;
};

struct AES_OCB_DECRYPT {
    const unsigned char* KEY;
    const unsigned char* IV;
    const unsigned char* CIPHER_TEXT;
    unsigned char* PLAIN_TEXT;
    const unsigned char* TAG;
    const unsigned char* ADDITIONAL_DATA;
    size_t KEY_LENGTH;
    size_t CIPHER_TEXT_LENGTH;
    size_t IV_LENGTH;
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

typedef bool (*ReadBoolean)(void*);
typedef unsigned char (*ReadByte)(void*);
typedef signed char (*ReadSByte)(void*);
typedef short (*ReadShort)(void*);
typedef unsigned short (*ReadUShort)(void*);
typedef int (*ReadInt)(void*);
typedef unsigned int (*ReadUInt)(void*);
typedef long long (*ReadLong)(void*);
typedef unsigned long long (*ReadULong)(void*);
typedef float (*ReadFloat)(void*);
typedef double (*ReadDouble)(void*);
typedef void (*ReadBytes)(void*, unsigned char*, uint64_t);
typedef void (*ReadString)(void*, char*, uint64_t);
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

#pragma region EncoderIO
typedef int (*Base16Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base16Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base32Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base64Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base85Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Decode)(const char*, const size_t, unsigned char*, const size_t);
#pragma endregion

#pragma region AesIO
typedef int (*GenerateKey)(unsigned char*, size_t);
typedef int (*GenerateIV)(unsigned char*, size_t);
typedef int (*GenerateTag)(unsigned char*, size_t);
typedef int (*GenerateAad)(unsigned char*, size_t);
typedef int (*GenerateTweak)(unsigned char*, size_t);
typedef int (*ImportKey)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*ImportIV)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*ImportTag)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*ImportAad)(const unsigned char*, size_t, unsigned char*, size_t);
typedef int (*ImportTweak)(const unsigned char*, size_t, unsigned char*, size_t);
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

extern std::unordered_map<std::string, void*> ReadFunctions;
extern std::unordered_map<std::string, void*> WriteFunctions;
extern std::unordered_map<std::string, void*> AppendFunctions;
extern std::unordered_map<std::string, void*> InsertFunctions;
extern std::unordered_map<std::string, void*> EncodeFunctions;
extern std::unordered_map<std::string, void*> AesFunctions;

extern std::unordered_map<CRYPT_TYPE, std::string> CryptDisplay;
extern std::unordered_map<std::string, AES_MODE> AesMode;
extern std::unordered_map<AES_MODE, std::string> AesDisplay;