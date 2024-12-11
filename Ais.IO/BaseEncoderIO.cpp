#include "pch.h"
#include "BaseEncoderIO.h"

static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; // 非法字符返回 -1
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
            value = (value << 8) | (i < inputLen ? static_cast<unsigned char>(input[i++]) : 0);
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

    return j;
}