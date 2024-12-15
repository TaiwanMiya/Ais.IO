#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define AESIO_API __declspec(dllexport)
#else
#define AESIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <iostream>
#include <ctime>
#include <cstring>
#include <random>

EXT AESIO_API int Generate(unsigned char* content, size_t length);
EXT AESIO_API int Import(const unsigned char* input, size_t inputLength, unsigned char* output, size_t outputLength);