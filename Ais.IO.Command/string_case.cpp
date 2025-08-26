
#include "string_case.h"
#include <cstdint>
#include <filesystem>

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

//// 依 C++ 版本與平台把 UTF-8 路徑正確轉成 std::filesystem::path
//static inline std::filesystem::path make_path_from_utf8(const std::string& utf8) {
//#if defined(_WIN32)
//#if (__cpp_lib_char8_t) || (_MSVC_LANG >= 202002L) || (__cplusplus >= 202002L)
//    // C++20：u8path 直接吃 UTF-8
//    return std::filesystem::u8path(utf8);
//#else
//    // C++17：退而求其次，用「寬字元」建構 path
//    std::wstring w;
//    // 簡易 UTF-8→UTF-16 轉換（你可換成更穩健的轉換器或 Windows API）
//    int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
//    w.resize(len ? len - 1 : 0);
//    if (len) MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, w.data(), len);
//    return std::filesystem::path(w);
//#endif
//#else
//    // Linux/macOS：原樣（路徑即 UTF-8）
//    return std::filesystem::path(utf8);
//#endif
//}

// 單一版本：固定回傳 std::filesystem::path（避免回傳型別導致多載衝突）
std::filesystem::path make_path_from_utf8(const std::string& utf8) {
#if defined(_WIN32)

#if defined(__cpp_char8_t) || defined(__cpp_lib_char8_t) || (__cplusplus >= 202002L) || (_MSVC_LANG >= 202002L)
    // C++20：將 std::string_view (char) 轉為 std::u8string，再交給 path 建構
    const auto* p = reinterpret_cast<const char8_t*>(utf8.data());
    std::u8string u8(p, p + utf8.size());
    return std::filesystem::path(u8); // OK：path(u8string) in C++20
#else
    // C++17：UTF-8 -> UTF-16（Windows 寬字元路徑）
    if (utf8.empty()) return std::filesystem::path();

    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
        static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring w;
    w.resize(wlen);
    if (wlen > 0) {
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(),
            static_cast<int>(utf8.size()), w.data(), wlen);
    }
    return std::filesystem::path(w);
#endif

#else
    // Linux/macOS：路徑即 UTF-8
    return std::filesystem::path(std::string(utf8));
#endif
}