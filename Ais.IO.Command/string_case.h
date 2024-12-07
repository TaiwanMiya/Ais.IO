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

std::string ECL ToLetter(std::string str);
std::string ECL ToLower(std::string str);
std::string ECL ToUpper(std::string str);
bool ECL IsULong(const std::string& str);
