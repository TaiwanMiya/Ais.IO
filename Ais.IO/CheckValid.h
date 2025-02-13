#pragma once
#include <regex>
#include <iostream>
#include <sstream>
#include <string>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define CHECKVAILD_API __declspec(dllexport)
#else
#define CHECKVAILD_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

EXT CHECKVAILD_API bool IsValidDNS(const char* dns);
EXT CHECKVAILD_API bool IsValidIPv4(const char* ip);
EXT CHECKVAILD_API bool IsValidIPv6(const char* ip);
EXT CHECKVAILD_API bool IsValidEmail(const char* email);
EXT CHECKVAILD_API bool IsValidURI(const char* uri);