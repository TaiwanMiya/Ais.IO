#pragma once
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <stdint.h>
#include <cmath>
#include <algorithm>
#include <string>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define ENCODERIO_API __declspec(dllexport)
#else
#define ENCODERIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

static const char Base10_Chars[] =
"0123456789";

static const char Base16_Chars[] =
"0123456789ABCDEF";

static const char Base32_Chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const char Base58_Chars[] =
"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const char Base62_Chars[] =
"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static const char Base64_Chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static const char Base85_Chars[] =
"0123456789"
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"!#$%&()*+-;<=>?@^_`{|}~";

static const char Base91_Chars[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789"
"!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

// Base16 解碼表
static const int Base16_Lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 40-47 非法字符
     0,  1,  2,  3,  4,  5,  6,  7, // 48-55: '0'-'7'
     8,  9, -1, -1, -1, -1, -1, -1, // 56-63: '8'-'9'
    -1, 10, 11, 12, 13, 14, 15, -1, // 64-71: 'A'-'F'
    -1, -1, -1, -1, -1, -1, -1, -1, // 72-79 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 80-87 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 88-95 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 96-103 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 104-111 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 112-119 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 120-127 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 非法字符
};

// Base32 解碼表
static const int Base32_Lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 40-47 非法字符
    -1, -1, 26, 27, 28, 29, 30, 31, // 48-55: '2'-'7'
    -1, -1, -1, -1, -1, -1, -1, -1, // 56-63 非法字符
    -1,  0,  1,  2,  3,  4,  5,  6, // 64-71: 'A'-'H'
     7,  8,  9, 10, 11, 12, 13, 14, // 72-79: 'I'-'P'
    15, 16, 17, 18, 19, 20, 21, 22, // 80-87: 'Q'-'X'
    23, 24, 25, -1, -1, -1, -1, -1, // 88-95: 'Y'-'Z'
    -1, -1, -1, -1, -1, -1, -1, -1, // 96-103 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 104-111 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 112-119 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 120-127 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 非法字符
};

// Base64 解碼表
static const int Base64_Lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 非法字符
    -1, -1, -1, 62, -1, -1, -1, 63, // 40-47: '+','/'
    52, 53, 54, 55, 56, 57, 58, 59, // 48-55: '0'-'7'
    60, 61, -1, -1, -1, -1, -1, -1, // 56-63: '8'-'9'
    -1,  0,  1,  2,  3,  4,  5,  6, // 64-71: 'A'-'H'
     7,  8,  9, 10, 11, 12, 13, 14, // 72-79: 'I'-'P'
    15, 16, 17, 18, 19, 20, 21, 22, // 80-87: 'Q'-'X'
    23, 24, 25, -1, -1, -1, -1, -1, // 88-95: 'Y'-'Z'
    -1, 26, 27, 28, 29, 30, 31, 32, // 96-103: 'a'-'g'
    33, 34, 35, 36, 37, 38, 39, 40, // 104-111: 'h'-'o'
    41, 42, 43, 44, 45, 46, 47, 48, // 112-119: 'p'-'w'
    49, 50, 51, -1, -1, -1, -1, -1, // 120-127: 'x'-'z'
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 非法字符
};

// Base85 解碼表
static const int Base85_Lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7: 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15: 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23: 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31: 非法字符
    -1,  0, -1,  1,  2,  3,  4, -1, // 32-39: '!'-'&'
     5,  6,  7,  8, -1,  9, -1, -1, // 40-47: '('-'-'
    10, 11, 12, 13, 14, 15, 16, 17, // 48-55: '0'-'7'
    18, 19, -1, 20, 21, 22, 23, 24, // 56-63: '8'-'?'
    25, 26, 27, 28, 29, 30, 31, 32, // 64-71: '@'-'G'
    33, 34, 35, 36, 37, 38, 39, 40, // 72-79: 'H'-'O'
    41, 42, 43, 44, 45, 46, 47, 48, // 80-87: 'P'-'W'
    49, 50, 51, -1, -1, -1, 52, 53, // 88-95: 'X'-'_'
    54, 55, 56, 57, 58, 59, 60, 61, // 96-103: '`'-'g'
    62, 63, 64, 65, 66, 67, 68, 69, // 104-111: 'h'-'o'
    70, 71, 72, 73, 74, 75, 76, 77, // 112-119: 'p'-'t'
    78, 79, 80, 81, 82, 83, 84, -1, // 120-127: 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 非法字符
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 非法字符
};

static const int Base91_Lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 62, 90, 63, 64, 65, 66, -1,
    67, 68, 69, 70, 71, -1, 72, 73,
    52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 74, 75, 76, 77, 78, 79,
    80,  0,  1,  2,  3,  4,  5,  6,
     7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 81, -1, 82, 83, 84,
    85, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 86, 87, 88, 89, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};

// 取得長度
EXT ENCODERIO_API size_t Base10Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base16Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base32Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base58Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base62Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base64Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base85Length(const size_t inputSize, bool isEncode);
EXT ENCODERIO_API size_t Base91Length(const size_t inputSize, bool isEncode);

/* Base10 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入長度不合法，解碼時必須是特定長度。
-4: 非法字符出現在解碼過程中（不是 Base10 有效字符）。*/
EXT ENCODERIO_API int Base10Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base10Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base16 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入長度不合法，解碼時必須是偶數長度。
-4: 非法字符出現在解碼過程中（不是 Base16 有效字符）。*/
EXT ENCODERIO_API int Base16Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base16Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base32 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入數據長度不合法，Base32 解碼要求長度是 8 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base32 有效字符）。*/
EXT ENCODERIO_API int Base32Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base32Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base58 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入數據長度不合法，Base58 解碼要求長度是 n 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base58 有效字符）。*/
EXT ENCODERIO_API int Base58Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base58Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base62 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入數據長度不合法，Base62 解碼要求長度是 n 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base62 有效字符）。*/
EXT ENCODERIO_API int Base62Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base62Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base64 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足，無法存儲結果。
-3: 輸入數據長度不合法，Base64 解碼要求長度是 4 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base64 有效字符）。
*/
EXT ENCODERIO_API int Base64Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base64Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base85 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足，無法存儲結果。
-3: 輸入數據長度不合法，Base85 解碼要求長度是 5 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base85 有效字符）。
*/
EXT ENCODERIO_API int Base85Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base85Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);

/* Base91 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足，無法存儲結果。
-3: 輸入數據長度不合法，Base91 解碼要求長度是 n 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base91 有效字符）。
*/
EXT ENCODERIO_API int Base91Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize);
EXT ENCODERIO_API int Base91Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize);