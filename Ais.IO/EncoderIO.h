#pragma once
#include <string>
#include <vector>
#include <cstring>
#include <stdexcept>

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define BINARYIO_API __declspec(dllimport)
#else
#define BINARYIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

/* Base16 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入長度不合法，解碼時必須是偶數長度。
-4: 非法字符出現在解碼過程中（不是 Base16 有效字符）。*/
EXT BINARYIO_API int Base16Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base16Decode(const char* input, char* output, int outputSize);

/* Base32 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足。
-3: 輸入數據長度不合法，Base32 解碼要求長度是 8 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base32 有效字符）。*/
EXT BINARYIO_API int Base32Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base32Decode(const char* input, char* output, int outputSize);

/* Base64 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足，無法存儲結果。
-3: 輸入數據長度不合法，Base64 解碼要求長度是 4 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base64 有效字符）。
*/
EXT BINARYIO_API int Base64Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base64Decode(const char* input, char* output, int outputSize);

/* Base64 錯誤碼含義：

-1: 輸入或輸出指針為空。
-2: 輸出緩衝區不足，無法存儲結果。
-3: 輸入數據長度不合法，Base85 解碼要求長度是 5 的倍數。
-4: 非法字符出現在解碼過程中（不是 Base85 有效字符）。
*/
EXT BINARYIO_API int Base85Encode(const char* input, char* output, int outputSize);
EXT BINARYIO_API int Base85Decode(const char* input, char* output, int outputSize);