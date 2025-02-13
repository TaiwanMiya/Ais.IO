#include "pch.h"
#include "CheckValid.h"

bool IsValidDNS(const char* dns) {
    std::regex dns_regex(R"(^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,63}\.?$)");
    return std::regex_match(dns, dns_regex) && (strlen(dns) <= 253);
}

bool IsValidIPv4(const char* ip) {
    std::regex ipv4_regex(R"(^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$)");
    if (!std::regex_match(ip, ipv4_regex)) return false;

    std::stringstream ss(ip);
    std::string token;
    int num;

    for (int i = 0; i < 4; ++i) {
        std::getline(ss, token, '.');
        num = std::stoi(token);
        if (num < 0 || num > 255) return false;
    }
    return true;
}

bool IsValidIPv6(const char* ip) {
    std::regex ipv6_regex(R"(^(([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4}:){1,7}:|:([0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4})$)");
    return std::regex_match(ip, ipv6_regex);
}

bool IsValidEmail(const char* email) {
    std::regex email_regex(R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
    return std::regex_match(email, email_regex);
}

bool IsValidURI(const char* uri) {
    std::regex url_regex(R"(^((https?|ftp|file)://)"
        R"(([a-zA-Z0-9.-]+|\[[0-9a-fA-F:]+\])(:\d+)?(/[^\s]*)?)$)");
    return std::regex_match(uri, url_regex);
}
