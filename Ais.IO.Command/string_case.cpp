
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

char* Trim(char* str) {
    if (str == nullptr) return str; // Handle null pointer

    // Remove leading spaces and newlines
    char* start = str;
    while (*start && std::isspace(static_cast<unsigned char>(*start))) {
        start++;
    }

    // If the entire string is whitespace
    if (*start == '\0') {
        *str = '\0';
        return str;
    }

    // Remove trailing spaces and newlines
    char* end = start + std::strlen(start) - 1;
    while (end > start && std::isspace(static_cast<unsigned char>(*end))) {
        end--;
    }

    // Null-terminate the string
    *(end + 1) = '\0';

    // Move the trimmed string back to the original pointer
    if (start != str) {
        std::memmove(str, start, end - start + 2); // +2 to include null-terminator
    }

    return str;
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