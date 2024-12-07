
#include "string_case.h"
#include <cstdint>

std::string ToLetter(std::string str) {
    std::string result = str;
	if (!result.empty()) {
        result[0] = std::toupper(result[0]);
		for (size_t i = 1; i < result.length(); ++i)
            result[i] = std::tolower(result[i]);
	}
    return result;
}

std::string ToLower(std::string str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::tolower(c);
        });
    return result;
}

std::string ToUpper(std::string str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return std::toupper(c);
        });
    return result;
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