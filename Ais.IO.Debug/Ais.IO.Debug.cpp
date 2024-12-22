// Ais.IO.Debug.cpp : 此檔案包含 'main' 函式。程式會於該處開始執行及結束執行。
//

#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#ifdef _WIN32
#define LOAD_LIBRARY(Lib) LoadLibraryA(Lib)
#define GET_PROC_ADDRESS(Lib, name) GetProcAddress(Lib, name)
#define UNLOAD_LIBRARY(Lib) FreeLibrary(Lib)
HMODULE Lib = LOAD_LIBRARY("Ais.IO.dll");
#else
#define LOAD_LIBRARY(Lib) dlopen(Lib, RTLD_LAZY)
#define GET_PROC_ADDRESS(Lib, name) dlsym(Lib, name)
#define UNLOAD_LIBRARY(Lib) dlclose(Lib)
void* Lib = LOAD_LIBRARY("./Ais.IO.so");
#endif

#ifdef _WIN32
#include <windows.h>

void EnableVirtualTerminalProcessing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) {
        return;
    }

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) {
        return;
    }

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}
#endif

#pragma region EncoderIO
typedef int (*Base16Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base16Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base32Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base32Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base64Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base64Decode)(const char*, const size_t, unsigned char*, const size_t);
typedef int (*Base85Encode)(const unsigned char*, const size_t, char*, const size_t);
typedef int (*Base85Decode)(const char*, const size_t, unsigned char*, const size_t);

Base16Encode Base16Encode_Func = (Base16Encode)GET_PROC_ADDRESS(Lib, "Base16Encode");
Base16Decode Base16Decode_Func = (Base16Decode)GET_PROC_ADDRESS(Lib, "Base16Decode");
Base32Encode Base32Encode_Func = (Base32Encode)GET_PROC_ADDRESS(Lib, "Base32Encode");
Base32Decode Base32Decode_Func = (Base32Decode)GET_PROC_ADDRESS(Lib, "Base32Decode");
Base64Encode Base64Encode_Func = (Base64Encode)GET_PROC_ADDRESS(Lib, "Base64Encode");
Base64Decode Base64Decode_Func = (Base64Decode)GET_PROC_ADDRESS(Lib, "Base64Decode");
Base85Encode Base85Encode_Func = (Base85Encode)GET_PROC_ADDRESS(Lib, "Base85Encode");
Base85Decode Base85Decode_Func = (Base85Decode)GET_PROC_ADDRESS(Lib, "Base85Decode");
#pragma endregion

struct RSA_PARAMETERS {
    const size_t KEY_SIZE;

    unsigned char* MODULUS;
    size_t MODULUS_LENGTH;

    unsigned char* PUBLIC_EXPONENT;
    size_t PUBLIC_EXPONENT_LENGTH;

    unsigned char* PRIVATE_EXPONENT;
    size_t PRIVATE_EXPONENT_LENGTH;

    unsigned char* PRIME1;
    size_t PRIME1_LENGTH;

    unsigned char* PRIME2;
    size_t PRIME2_LENGTH;

    unsigned char* EXPONENT1;
    size_t EXPONENT1_LENGTH;

    unsigned char* EXPONENT2;
    size_t EXPONENT2_LENGTH;

    unsigned char* COEFFICIENT;
    size_t COEFFICIENT_LENGTH;
};

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

struct RSA_KEY_PAIR {
    const size_t KEY_SIZE;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

typedef int (*GenerateRsaParameters)(RSA_PARAMETERS*);
typedef int (*RsaGenerate)(RSA_KEY_PAIR*);

int main() {
#if _WIN32
	EnableVirtualTerminalProcessing();
#endif

    GenerateRsaParameters getParamters = (GenerateRsaParameters)GET_PROC_ADDRESS(Lib, "GenerateRsaParameters");

    RSA_PARAMETERS paramters = {
        2048,
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

    getParamters(&paramters);

   /* RsaGenerate generate = (RsaGenerate)GET_PROC_ADDRESS(Lib, "RsaGenerate");

    for (int i = 0; i < 1; i++) {
        RSA_KEY_PAIR keypair = {
            4096,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
            NULL,
            NULL,
            0,
            0,
        };
        generate(&keypair);

        std::cout << "PEM - [" << i << "]" << std::endl;
        std::cout << keypair.PUBLIC_KEY << std::endl;
        std::cout << keypair.PRIVATE_KEY << std::endl;
    }

    for (int i = 0; i < 1; i++) {
        RSA_KEY_PAIR keypair = {
            4096,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
            NULL,
            NULL,
            0,
            0,
        };
        generate(&keypair);

        std::cout << "DER - [" << i << "]" << std::endl;
        char* pubString = new char[keypair.PUBLIC_KEY_LENGTH * 2 + 1] {};
        char* privString = new char[keypair.PRIVATE_KEY_LENGTH * 2 + 1] {};
        Base16Encode_Func(keypair.PUBLIC_KEY, keypair.PUBLIC_KEY_LENGTH, pubString, keypair.PUBLIC_KEY_LENGTH * 2 + 1);
        Base16Encode_Func(keypair.PRIVATE_KEY, keypair.PRIVATE_KEY_LENGTH, privString, keypair.PRIVATE_KEY_LENGTH * 2 + 1);
        std::cout << pubString << std::endl;
        std::cout << privString << std::endl;
        std::cout << "" << std::endl;
    }*/
}