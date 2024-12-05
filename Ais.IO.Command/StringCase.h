#pragma once
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>

#if _WIN32
#define ECL __cdecl
#else
#define ECL
#endif

void ECL ToLetter(std::string& str);
void ECL ToLower(std::string& str);
void ECL ToUpper(std::string& str);
bool ECL IsULong(const std::string& str);
