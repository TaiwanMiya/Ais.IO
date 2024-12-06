#pragma once
#include <string>
#include <iostream>

#if _WIN32
#define COLORS __cdecl
void EnableVirtualTerminalProcessing();
#else
#define COLORS
#endif

std::string Error(std::string str);
std::string Warn(std::string str);
std::string Hint(std::string str);
std::string Ask(std::string str);
std::string Mark(std::string str);