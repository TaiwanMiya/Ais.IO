
#include "StringCase.h"


void ToLetter(std::string& str) {
	if (!str.empty()) {
		str[0] = std::toupper(str[0]);
		for (size_t i = 1; i < str.length(); ++i)
			str[i] = std::tolower(str[i]);
	}
}

void ToLower(std::string& str) {
	std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
		return std::tolower(c); });
}

void ToUpper(std::string& str) {
	std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
		return std::toupper(c); });
}