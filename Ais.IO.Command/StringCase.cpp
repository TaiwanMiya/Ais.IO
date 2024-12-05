
#include "StringCase.h"
#include <cstdint>

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

bool IsULong(const std::string& str) {
    try {
        uint64_t pos;
        std::stoull(str, &pos);
        return pos == str.size();
    }
    catch (std::invalid_argument&) {
        return false;
    }
    catch (std::out_of_range&) {
        return false;
    }
}