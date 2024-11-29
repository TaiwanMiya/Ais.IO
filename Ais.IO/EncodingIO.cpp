#include "pch.h"
#include "EncodingIO.h"

#if _WIN32
char* ConvertToUTF8(const wchar_t* unicodeText) {
    if (!unicodeText)
        return nullptr;
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, unicodeText, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0)
        return nullptr;
    char* utf8Text = new char[size_needed];
    WideCharToMultiByte(CP_UTF8, 0, unicodeText, -1, utf8Text, size_needed, nullptr, nullptr);
    return utf8Text;
}

wchar_t* ConvertToUnicode(const char* utf8Text) {
    if (!utf8Text)
        return nullptr;
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8Text, -1, nullptr, 0);
    if (size_needed <= 0)
        return nullptr;
    wchar_t* unicodeText = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, utf8Text, -1, unicodeText, size_needed);
    return unicodeText;
}

char* ConvertToASCII(const wchar_t* unicodeText) {
    if (!unicodeText)
        return nullptr;
    int size_needed = WideCharToMultiByte(CP_ACP, 0, unicodeText, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0)
        return nullptr;
    char* asciiText = new char[size_needed];
    WideCharToMultiByte(CP_ACP, 0, unicodeText, -1, asciiText, size_needed, nullptr, nullptr);
    return asciiText;
}

wchar_t* ConvertFromASCII(const char* asciiText) {
    if (!asciiText)
        return nullptr;
    int size_needed = MultiByteToWideChar(CP_ACP, 0, asciiText, -1, nullptr, 0);
    if (size_needed <= 0)
        return nullptr;
    wchar_t* unicodeText = new wchar_t[size_needed];
    MultiByteToWideChar(CP_ACP, 0, asciiText, -1, unicodeText, size_needed);
    return unicodeText;
}
#else
// Helper function for iconv usage
std::string ConvertEncoding(const char* input, const char* fromEncoding, const char* toEncoding) {
    iconv_t conv = iconv_open(toEncoding, fromEncoding);
    if (conv == (iconv_t)-1) {
        throw std::runtime_error("Failed to open iconv");
    }

    size_t inSize = strlen(input);
    size_t outSize = inSize * 4; // UTF-8 can expand
    char* output = (char*)malloc(outSize);
    char* outPtr = output;

    char* inPtr = const_cast<char*>(input);
    size_t outLeft = outSize;
    size_t inLeft = inSize;

    if (iconv(conv, &inPtr, &inLeft, &outPtr, &outLeft) == (size_t)-1) {
        free(output);
        iconv_close(conv);
        throw std::runtime_error("iconv conversion failed");
    }

    std::string result(output, outSize - outLeft);
    free(output);
    iconv_close(conv);
    return result;
}

char* ConvertToUTF8(const wchar_t* unicodeText) {
    std::string utf8Str = ConvertEncoding(reinterpret_cast<const char*>(unicodeText), "WCHAR_T", "UTF-8");
    char* result = new char[utf8Str.size() + 1];
    strcpy(result, utf8Str.c_str());
    return result;
}

wchar_t* ConvertToUnicode(const char* utf8Text) {
    std::string unicodeStr = ConvertEncoding(utf8Text, "UTF-8", "WCHAR_T");
    wchar_t* result = new wchar_t[unicodeStr.size() + 1];
    std::memcpy(result, unicodeStr.c_str(), (unicodeStr.size() + 1) * sizeof(wchar_t));
    return result;
}

char* ConvertToASCII(const wchar_t* unicodeText) {
    std::string asciiStr = ConvertEncoding(reinterpret_cast<const char*>(unicodeText), "WCHAR_T", "ASCII");
    char* result = new char[asciiStr.size() + 1];
    strcpy(result, asciiStr.c_str());
    return result;
}

wchar_t* ConvertFromASCII(const char* asciiText) {
    std::string unicodeStr = ConvertEncoding(asciiText, "ASCII", "WCHAR_T");
    wchar_t* result = new wchar_t[unicodeStr.size() + 1];
    std::memcpy(result, unicodeStr.c_str(), (unicodeStr.size() + 1) * sizeof(wchar_t));
    return result;
}
#endif
