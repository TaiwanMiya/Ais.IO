#pragma once
#include <string>
#if _WIN32
#include <windows.h>
#else
#include <iconv.h>
#endif
#include <cstring>
#include <cstdlib>
#include <stdexcept>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define ENCODING_API __declspec(dllimport)
#else
#define ENCODING_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#ifdef _WIN32
#define WCHAR_ENCODING "UTF-16LE"
#else
#define WCHAR_ENCODING "UTF-32LE"
#endif

EXT ENCODING_API char* ConvertToUTF8(const wchar_t* unicodeText);
EXT ENCODING_API wchar_t* ConvertToUnicode(const char* utf8Text);
EXT ENCODING_API char* ConvertToASCII(const wchar_t* unicodeText);
EXT ENCODING_API wchar_t* ConvertFromASCII(const char* asciiText);