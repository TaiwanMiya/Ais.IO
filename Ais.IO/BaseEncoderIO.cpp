﻿#include "pch.h"
#include "BaseEncoderIO.h"
#include <iostream>

static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; // 非法字符返回 -1
}

size_t Base10Length(const size_t inputSize, bool isEncode) {
    return isEncode ? std::ceil(inputSize * std::log10(256)) + 1 : std::ceil(inputSize * std::log10(10) / std::log10(256.0));
}

size_t Base16Length(const size_t inputSize, bool isEncode) {
    return isEncode ? inputSize * 2 + 1: inputSize / 2;
}

size_t Base32Length(const size_t inputSize, bool isEncode) {
    return isEncode ? ((inputSize + 4) / 5) * 8 + 1 : (inputSize / 8) * 5;
}

size_t Base58Length(const size_t inputSize, bool isEncode) {
    return isEncode ? std::ceil((inputSize * 8) / std::log2(58)) + 1 : std::floor(inputSize * std::log2(58) / 8) + 1;
}

size_t Base62Length(const size_t inputSize, bool isEncode) {
    return isEncode ? std::ceil((inputSize * 8) / std::log2(62)) + 1 : std::floor(inputSize * std::log2(62) / 8) + 1;
}

size_t Base64Length(const size_t inputSize, bool isEncode) {
    return isEncode ? ((inputSize + 2) / 3) * 4 + 1 : (inputSize / 4) * 3;
}

size_t Base85Length(const size_t inputSize, bool isEncode) {
    return isEncode ? ((inputSize + 3) / 4) * 5 + 1 : (inputSize / 5) * 4;
}

size_t Base91Length(const size_t inputSize, bool isEncode) {
    return isEncode ? std::ceil((inputSize * 8) / std::log2(91)) + 1 : std::floor(inputSize * std::log2(91) / 8) + 1;
}

int Base10Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查，避免空指針

    // 預估結果最大長度，避免重複內存分配
    size_t maxResultSize = static_cast<size_t>(std::ceil(inputSize * std::log10(256))) + 1;
    if (outputSize < maxResultSize) return -2; // 確認輸出緩衝區大小

    // 初始化大整數，初始值為 0
    std::vector<unsigned char> bigInt(1, '0');

    // 將輸入轉換為大整數 (Base256 轉 Base10)
    for (size_t i = 0; i < inputSize; ++i) {
        int carry = static_cast<int>(input[i]); // 當前位的進位值
        // 大整數的每一位進行更新 (模擬乘法與加法)
        for (int j = bigInt.size() - 1; j >= 0; --j) {
            int value = (bigInt[j] - '0') * 256 + carry; // 將每位放大
            bigInt[j] = (value % 10) + '0';              // 更新當前位
            carry = value / 10;                         // 更新進位
        }
        // 處理剩餘的進位
        while (carry > 0) {
            bigInt.insert(bigInt.begin(), (carry % 10) + '0');
            carry /= 10;
        }
    }

    // 去掉前導零
    std::vector<unsigned char>::iterator firstNonZero = std::find_if(bigInt.begin(), bigInt.end(), [](unsigned char c) { return c != '0'; });
    if (firstNonZero == bigInt.end()) {
        // 全為零，結果應該是 "0"
        output[0] = '0';
        output[1] = '\0';
        return 1;
    }

    // 複製結果到輸出緩衝區
    size_t resultSize = std::distance(firstNonZero, bigInt.end());
    if (resultSize >= outputSize) return -2; // 確認輸出緩衝區大小足夠
    std::copy(firstNonZero, bigInt.end(), output);
    output[resultSize] = '\0'; // 添加結束符
    return static_cast<int>(resultSize); // 返回結果大小
}

int Base10Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查，避免空指針

    // 確認輸入是否為有效的十進制字符串
    if (!std::all_of(input, input + inputSize, ::isdigit)) {
        return -4; // 非法字符
    }

    // 初始化結果數據結構，預估最大輸出長度
    std::vector<unsigned char> bigInt(input, input + inputSize);

    // 反向將大整數 (Base10) 轉換為 Base256
    std::vector<unsigned char> result;
    while (!bigInt.empty() && !(bigInt.size() == 1 && bigInt[0] == '0')) {
        int carry = 0;
        for (size_t i = 0; i < bigInt.size(); ++i) {
            int value = carry * 10 + (bigInt[i] - '0');
            bigInt[i] = static_cast<unsigned char>((value / 256) + '0'); // 更新高位
            carry = value % 256;                                       // 保留餘數作為低位
        }

        // 提取最低有效字節並添加到結果
        result.push_back(static_cast<unsigned char>(carry));

        // 去掉前導零
        while (!bigInt.empty() && bigInt[0] == '0') {
            bigInt.erase(bigInt.begin());
        }
    }

    // 確認輸出緩衝區是否足夠
    if (result.size() > outputSize) return -2;

    // 反轉結果以恢復正確順序
    std::reverse(result.begin(), result.end());
    std::copy(result.begin(), result.end(), output);

    return static_cast<int>(result.size()); // 返回解碼後的字節數
}

int Base16Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查，避免空指針

    size_t inputLen = inputSize; // 獲取輸入的長度
    int requiredSize = inputLen * 2;   // 每個字節對應兩個十六進制字符

    if (outputSize <= 0 || outputSize < requiredSize + 1) // 檢查輸出緩衝區是否足夠（+1 是為了 '\0'）
        return -2;

    for (int i = 0; i < inputLen; ++i) {
        unsigned char byte = static_cast<unsigned char>(input[i]); // 獲取每個字節
        output[i * 2] = Base16_Chars[byte >> 4];      // 高四位轉換為十六進制字符
        output[i * 2 + 1] = Base16_Chars[byte & 0x0F]; // 低四位轉換為十六進制字符
    }

    output[requiredSize] = '\0'; // 添加結尾的空字符
    return requiredSize;         // 返回實際的編碼長度
}

int Base16Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查

    size_t inputLen = inputSize; // 獲取輸入的長度
    if (inputLen % 2 != 0) return -3; // Base16 的輸入長度必須是偶數

    int requiredSize = inputLen / 2; // 每兩個字符對應一個字節
    if (outputSize <= 0 || outputSize < requiredSize) return -2;

    for (int i = 0; i < inputLen; i += 2) {
        int high = HexCharToValue(input[i]);     // 轉換高位字符
        int low = HexCharToValue(input[i + 1]); // 轉換低位字符

        if (high == -1 || low == -1) return -4; // 檢查字符是否合法

        output[i / 2] = (high << 4) | low; // 合併高低位得到一個字節
    }

    return static_cast<int>(requiredSize);; // 返回解碼後的字節數
}

int Base32Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    const unsigned char* data = reinterpret_cast<const unsigned char*>(input); // 將輸入轉換為無符號字元指針，方便按位元組處理
    size_t inputLength = inputSize; // 輸入長度
    size_t outputNeeded = ((inputLength + 4) / 5) * 8; // 每 5 字節對應 8 個 Base32 字符

    if (outputSize <= 0 || outputSize < static_cast<int>(outputNeeded + 1)) // 包含結尾的 '\0'
        return -2; // 輸出緩衝區不足

    // 計算完整的 5 位元組區塊數量和尾數字節數量
    const size_t fullChunks = inputLength / 5;
    const size_t leftover = inputLength % 5;

    // 輸出字元索引初始化
    size_t outputIndex = 0;

    // 處理完整的 5 字節區塊
    for (size_t i = 0; i < fullChunks; ++i) {
        uint64_t chunk = 0; // 暫時儲存 5 位元組資料的 40 位元整數
        for (int j = 0; j < 5; ++j)
            chunk = (chunk << 8) | data[i * 5 + j]; // 將 5 位元組拼接為一個 40 位元整數

        // 擷取每 5 位元數據，對應為 Base32 字符
        for (int j = 7; j >= 0; --j)
            output[outputIndex++] = Base32_Chars[(chunk >> (j * 5)) & 0x1F];
    }

    // 處理不足 5 字節的尾數
    if (leftover > 0) {
        uint64_t chunk = 0; // 暫時儲存不足 5 位元組的數據
        for (size_t j = 0; j < leftover; ++j) {
            // 拼接剩餘的位元組
            chunk = (chunk << 8) | data[fullChunks * 5 + j];
        }
        chunk <<= (5 - leftover) * 8; // 將尾數部分左移，填滿零位，補齊到 40 位

        // 擷取有效的 Base32 字符
        for (size_t j = 0; j < leftover * 8 / 5 + 1; ++j)
            output[outputIndex++] = Base32_Chars[(chunk >> ((7 - j) * 5)) & 0x1F];

        // 填充 "="，使輸出長度是 8 的倍數
        for (size_t j = leftover * 8 / 5 + 1; j < 8; ++j)
            output[outputIndex++] = '=';
    }

    // 添加結尾的 '\0'
    output[outputIndex] = '\0';
    return static_cast<int>(outputIndex); // 返回編碼後的長度
}

int Base32Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    size_t inputLen = inputSize;
    if (inputLen % 8 != 0) return -3; // Base32 的輸入長度必須是 8 的倍數

    int requiredSize = (inputLen * 5) / 8; // 每 8 個字符對應 5 個字節
    if (outputSize <= 0 || outputSize < requiredSize) return -2; // 輸出緩衝區不足

    int i = 0, j = 0;
    uint64_t buffer = 0;   // 暫存 Base32 數據
    int bufferBits = 0;    // 暫存有效位數

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // 忽略結尾的填充符

        // 獲取字符對應的數值
        if (c < 0 || c >= 128 || Base32_Lookup[c] == -1) return -4; // 非法字符
        buffer = (buffer << 5) | Base32_Lookup[c];
        bufferBits += 5;

        // 每次從 buffer 中取出 8 位，轉換成一個字節
        while (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // 返回解碼後的字節數
}

int Base58Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1;

    // 預估最大輸出大小
    size_t maxResultSize = static_cast<size_t>(std::ceil((inputSize * 8) / std::log2(58.0))) + 1;
    if (outputSize < maxResultSize) return -3;

    // 初始化固定大小的緩衝區
    const size_t bufferSize = inputSize * 2;
    unsigned char* buffer = new unsigned char[bufferSize];
    size_t bufferLen = 0;

    // 初始化數據
    for (size_t i = 0; i < inputSize; ++i) {
        unsigned int carry = input[i];
        for (size_t j = 0; j < bufferLen; ++j) {
            carry += buffer[j] << 8; // 高位左移並加上進位
            buffer[j] = carry % 58; // 更新當前位
            carry /= 58;            // 更新進位
        }

        // 添加新的進位
        while (carry > 0) {
            buffer[bufferLen++] = carry % 58;
            carry /= 58;
        }
    }

    // 添加前導零
    size_t zeroCount = 0;
    for (size_t i = 0; i < inputSize && input[i] == 0; ++i) {
        output[zeroCount++] = Base58_Chars[0];
    }

    // 轉換結果
    for (size_t i = 0; i < bufferLen; ++i) {
        output[zeroCount + i] = Base58_Chars[buffer[bufferLen - 1 - i]];
    }

    // 添加結束符
    output[zeroCount + bufferLen] = '\0';
    return static_cast<int>(zeroCount + bufferLen);
}

int Base58Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查

    // 建立 Base58 字符查找表
    int Base58Lookup[256];
    std::fill(std::begin(Base58Lookup), std::end(Base58Lookup), -1);
    for (size_t i = 0; i < 58; ++i) {
        Base58Lookup[static_cast<unsigned char>(Base58_Chars[i])] = i;
    }

    // 初始化解碼緩衝區
    const size_t bufferSize = inputSize * 2;
    unsigned char* buffer = new unsigned char[bufferSize];
    size_t bufferLen = 0;

    // 解碼過程
    for (size_t i = 0; i < inputSize; ++i) {
        int value = Base58Lookup[static_cast<unsigned char>(input[i])];
        if (value == -1) return -4; // 非法字符

        uint64_t carry = value;
        for (size_t j = 0; j < bufferLen; ++j) {
            carry += buffer[j] * 58;
            buffer[j] = carry & 0xFF;
            carry >>= 8;
        }

        // 添加新的進位
        while (carry > 0) {
            buffer[bufferLen++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    // 處理前導零
    size_t zeroCount = 0;
    for (size_t i = 0; i < inputSize && input[i] == Base58_Chars[0]; ++i) {
        zeroCount++;
    }

    // 確認輸出緩衝區大小
    size_t resultSize = zeroCount + bufferLen;
    if (resultSize > outputSize) return -2;

    // 將結果複製到輸出緩衝區
    std::fill(output, output + zeroCount, 0);
    for (size_t i = 0; i < bufferLen; ++i) {
        output[zeroCount + i] = static_cast<unsigned char>(buffer[bufferLen - 1 - i]);
    }

    return static_cast<int>(resultSize);
}

int Base62Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1;

    // 預估最大輸出大小
    size_t maxResultSize = static_cast<size_t>(std::ceil((inputSize * 8) / std::log2(62.0))) + 1;
    if (outputSize < maxResultSize) return -3;

    // 初始化固定大小的緩衝區
    const size_t bufferSize = inputSize * 2;
    unsigned char* buffer = new unsigned char[bufferSize];
    size_t bufferLen = 0;

    // 初始化數據
    for (size_t i = 0; i < inputSize; ++i) {
        unsigned int carry = input[i];
        for (size_t j = 0; j < bufferLen; ++j) {
            carry += buffer[j] << 8; // 高位左移並加上進位
            buffer[j] = carry % 62; // 更新當前位
            carry /= 62;            // 更新進位
        }

        // 添加新的進位
        while (carry > 0) {
            buffer[bufferLen++] = carry % 62;
            carry /= 62;
        }
    }

    // 添加前導零
    size_t zeroCount = 0;
    for (size_t i = 0; i < inputSize && input[i] == 0; ++i) {
        output[zeroCount++] = Base62_Chars[0];
    }

    // 轉換結果
    for (size_t i = 0; i < bufferLen; ++i) {
        output[zeroCount + i] = Base62_Chars[buffer[bufferLen - 1 - i]];
    }

    // 添加結束符
    output[zeroCount + bufferLen] = '\0';
    return static_cast<int>(zeroCount + bufferLen);
}

int Base62Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性檢查

    // 建立 Base62 字符查找表
    int Base62Lookup[256];
    std::fill(std::begin(Base62Lookup), std::end(Base62Lookup), -1);
    for (size_t i = 0; i < 62; ++i) {
        Base62Lookup[static_cast<unsigned char>(Base62_Chars[i])] = i;
    }

    // 初始化解碼緩衝區
    const size_t bufferSize = inputSize * 2;
    unsigned char* buffer = new unsigned char[bufferSize];
    size_t bufferLen = 0;

    // 解碼過程
    for (size_t i = 0; i < inputSize; ++i) {
        int value = Base62Lookup[static_cast<unsigned char>(input[i])];
        if (value == -1) return -4; // 非法字符

        uint64_t carry = value;
        for (size_t j = 0; j < bufferLen; ++j) {
            carry += buffer[j] * 62;
            buffer[j] = carry & 0xFF;
            carry >>= 8;
        }

        // 添加新的進位
        while (carry > 0) {
            buffer[bufferLen++] = carry & 0xFF;
            carry >>= 8;
        }
    }

    // 處理前導零
    size_t zeroCount = 0;
    for (size_t i = 0; i < inputSize && input[i] == Base62_Chars[0]; ++i) {
        zeroCount++;
    }

    // 確認輸出緩衝區大小
    size_t resultSize = zeroCount + bufferLen;
    if (resultSize > outputSize) return -2;

    // 將結果複製到輸出緩衝區
    std::fill(output, output + zeroCount, 0);
    for (size_t i = 0; i < bufferLen; ++i) {
        output[zeroCount + i] = static_cast<unsigned char>(buffer[bufferLen - 1 - i]);
    }

    return static_cast<int>(resultSize);
}

int Base64Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    size_t inputLen = inputSize;
    int requiredSize = ((inputLen + 2) / 3) * 4; // 每 3 字節對應 4 個 Base64 字符

    if (outputSize <= 0 || outputSize < requiredSize) // +1 是為 '\0'
        return -2; // 輸出緩衝區不足

    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int inputIndex = 0;

    while (inputLen--) {
        char_array_3[i++] = input[inputIndex++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                output[j++] = Base64_Chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i > 0) {
        for (int k = i; k < 3; k++) {
            char_array_3[k] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (int k = 0; k < i + 1; k++) {
            output[j++] = Base64_Chars[char_array_4[k]];
        }

        while (i++ < 3) {
            output[j++] = '=';
        }
    }

    return j;  // 返回編碼後的長度
}

int Base64Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    size_t inputLen = inputSize;
    if (inputLen % 4 != 0) return -3; // Base64 的輸入長度必須是 4 的倍數

    int requiredSize = (inputLen / 4) * 3; // 每 4 個字符對應 3 個字節
    if (input[inputLen - 1] == '=') requiredSize--; // 處理 '=' 填充
    if (input[inputLen - 2] == '=') requiredSize--;

    if (outputSize <= 0 || outputSize < requiredSize) return -2; // 輸出緩衝區不足

    int i = 0, j = 0;
    uint32_t buffer = 0;   // 暫存 Base64 數據
    int bufferBits = 0;    // 暫存有效位數

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // 結尾填充符

        int value = (c >= 0 && c < 256) ? Base64_Lookup[c] : -1;
        if (value < 0) return -4; // 非法字符

        buffer = (buffer << 6) | value;
        bufferBits += 6;

        // 每次從 buffer 中提取 8 位
        if (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // 返回解碼後的字節數
}

int Base85Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    size_t inputLen = inputSize;
    int requiredSize = ((inputLen + 3) / 4) * 5; // 每 4 字節對應 5 個 Base85 字符

    if (outputSize <= 0 || outputSize < requiredSize + 1) // +1 是為 '\0'
        return -2; // 輸出緩衝區不足

    int i = 0, j = 0;
    while (i < inputLen) {
        // 將每四個字節組成一個 32 位的數據塊
        uint32_t value = 0;
        for (int k = 0; k < 4; ++k) {
            value = (value << 8) | (i < inputLen ? input[i++] : 0);
        }

        // 將 32 位數據塊轉換為 5 個 Base85 字符
        for (int k = 4; k >= 0; --k) {
            output[j + k] = Base85_Chars[value % 85];
            value /= 85;
        }
        j += 5;
    }

    output[j] = '\0'; // 添加結尾的 '\0'
    return requiredSize; // 返回編碼後的長度
}

int Base85Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    size_t inputLen = inputSize;
    if (inputLen % 5 != 0) return -3; // 輸入長度必須是 5 的倍數

    int requiredSize = (inputLen / 5) * 4; // 每 5 個字符對應 4 個字節
    if (outputSize <= 0 || outputSize < requiredSize) return -2; // 輸出緩衝區不足

    uint32_t value = 0;
    size_t i = 0, j = 0;

    while (i < inputLen) {
        value = 0;

        // 將 5 個 Base85 字元轉換為 32-bit 整數值
        for (int k = 0; k < 5; ++k) {
            const char* pos = strchr(Base85_Chars, input[i++]);
            if (!pos)
                return -4;
            value = value * 85 + (pos - Base85_Chars);
        }

        // 將 32-bit 整數值分解為最多 4 個位元組
        for (int k = 3; k >= 0; --k) {
            if (j + k < requiredSize)
                output[j + k] = static_cast<unsigned char>(value & 0xFF);
            value >>= 8;
        }
        j += 4;
    }

    while (j > 0 && output[j - 1] == '\0')
        --j;

    return j;
}

int Base91Encode(const unsigned char* input, const size_t inputSize, char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    // 計算輸出所需的大小
    size_t requiredSize = static_cast<size_t>(std::ceil((inputSize * 8) / std::log2(91.0))) + 1;
    if (outputSize < requiredSize) return -3; // 輸出緩衝區不足

    uint32_t value = 0; // 暫存值
    int bits = 0;       // 暫存的位數
    size_t outputIndex = 0;

    for (size_t i = 0; i < inputSize; ++i) {
        value |= input[i] << bits; // 添加字節到暫存值
        bits += 8;                 // 更新位數

        if (bits > 13) {
            if (outputIndex + 2 > outputSize) return -2; // 輸出緩衝區不足
            unsigned int encoded = value & 8191;
            if (encoded > 88) {
                value >>= 13;
                bits -= 13;
            }
            else {
                encoded = value & 16383;
                value >>= 14;
                bits -= 14;
            }

            int mod91 = encoded % 91;
            int div91 = encoded / 91;

            if (mod91 < 91 && div91 < 91) {
                output[outputIndex++] = Base91_Chars[mod91];
                output[outputIndex++] = Base91_Chars[div91];
            }
            else
                return -4; // 無效的數據，防止越界
        }
    }

    if (bits > 0) {
        if (outputIndex + 1 > outputSize) return -2; // 輸出緩衝區不足
        output[outputIndex++] = Base91_Chars[value % 91];
        if (bits > 7 || value > 90) {
            if (outputIndex + 1 > outputSize) return -2;
            output[outputIndex++] = Base91_Chars[value / 91];
        }
    }

    return static_cast<int>(outputIndex);
}

int Base91Decode(const char* input, const size_t inputSize, unsigned char* output, const size_t outputSize) {
    if (!input || !output) return -1; // 防禦性編程，檢查指針是否為空

    // 計算輸出所需的大小
    size_t requiredSize = static_cast<size_t>(std::floor(inputSize * std::log2(91.0) / 8));
    if (outputSize < requiredSize) return -3; // 輸出緩衝區不足

    unsigned int value = 0; // 暫存值
    long long bits = 0;       // 暫存的位數
    size_t outputIndex = 0;
    unsigned int decoded = -1;

    for (size_t i = 0; i < inputSize; ++i) {
        int index = Base91_Lookup[static_cast<unsigned char>(input[i])];
        if (index == -1) continue; // 跳過無效字符

        if (decoded == -1)
            decoded = index;
        else {
            decoded += index * 91;
            value |= decoded << bits;
            bits += (decoded & 8191) > 88 ? 13 : 14;

            // 提取字節，當 queue 中的位數超過 8 位時
            for (bool ok = true; ok; ok = (bits > 7)) {
                if (outputIndex >= outputSize) return -2; // 輸出緩衝區不足
                output[outputIndex++] = static_cast<unsigned char>(value & 0xFF); // 提取最低 8 位
                value >>= 8; // 更新 value
                bits -= 8;
            }

            decoded = -1;
        }
    }

    if (decoded != -1) {
        if (outputIndex >= outputSize) return -2; // 輸出緩衝區不足
        output[outputIndex++] = static_cast<unsigned char>(value | (decoded << bits));
    }

    return static_cast<int>(outputIndex);
}