#pragma once


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
#include <vector>

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