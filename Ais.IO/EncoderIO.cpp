#include "pch.h"
#include "EncoderIO.h"

#include <iostream>

static const char base16_chars[] = 
    "0123456789ABCDEF";

static const char base32_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static const char base85_chars[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "!#$%&()*+-;<=>?@^_`{|}~";

// Base32 秆絏
static const int base32_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 40-47 獶猭才
    -1, -1, 26, 27, 28, 29, 30, 31, // 48-55: '2'-'7'
    -1, -1, -1, -1, -1, -1, -1, -1, // 56-63 獶猭才
    -1,  0,  1,  2,  3,  4,  5,  6, // 64-71: 'A'-'H'
     7,  8,  9, 10, 11, 12, 13, 14, // 72-79: 'I'-'P'
    15, 16, 17, 18, 19, 20, 21, 22, // 80-87: 'Q'-'X'
    23, 24, 25, -1, -1, -1, -1, -1, // 88-95: 'Y'-'Z'
    -1, -1, -1, -1, -1, -1, -1, -1, // 96-103 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 104-111 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 112-119 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 120-127 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 獶猭才
};

// Base64 秆絏
static const int base64_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 獶猭才
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
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 獶猭才
};

// Base85 秆絏
static const int base85_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7: 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15: 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23: 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31: 獶猭才
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
    78, 79, 80, 81, 82, 83, 84, -1, // 120-127: 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 獶猭才
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 獶猭才
};

static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; // 獶猭才 -1
}

int Base16Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦浪琩磷皐

    int inputLen = std::strlen(input); // 莉块
    int requiredSize = inputLen * 2;   // –竊癸莱ㄢせ秈才

    if (outputSize < requiredSize + 1) // 浪琩块絯侥跋琌ì镑+1 琌 '\0'
        return -2;

    for (int i = 0; i < inputLen; ++i) {
        unsigned char byte = static_cast<unsigned char>(input[i]); // 莉–竊
        output[i * 2] = base16_chars[byte >> 4];      // 蔼锣传せ秈才
        output[i * 2 + 1] = base16_chars[byte & 0x0F]; // 锣传せ秈才
    }

    output[requiredSize] = '\0'; // 睰挡Ю才
    return requiredSize;         // 龟悔絪絏
}

int Base16Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦浪琩

    int inputLen = std::strlen(input); // 莉块
    if (inputLen % 2 != 0) return -3; // Base16 块ゲ斗琌案计

    int requiredSize = inputLen / 2; // –ㄢ才癸莱竊
    if (outputSize < requiredSize) return -2;

    for (int i = 0; i < inputLen; i += 2) {
        int high = HexCharToValue(input[i]);     // 锣传蔼才
        int low = HexCharToValue(input[i + 1]); // 锣传才

        if (high == -1 || low == -1) return -4; // 浪琩才琌猭

        output[i / 2] = (high << 4) | low; // ㄖ蔼眔竊
    }

    return requiredSize; // 秆絏竊计
}

int Base32Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input); // 块
    int requiredSize = ((inputLen + 4) / 5) * 8; // – 5 竊癸莱 8  Base32 才

    if (outputSize < requiredSize + 1) // 挡Ю '\0'
        return -2; // 块絯侥跋ぃì

    int i = 0, j = 0;
    while (i < inputLen) {
        uint64_t buffer = 0;   // 既 5 竊计沮
        int bufferBits = 0;    // 既计沮Τ计

        // –Ω程弄 5 竊舱Θ 40  buffer
        for (int k = 0; k < 5; ++k) {
            buffer <<= 8;      // オ簿 8 
            if (i < inputLen) {
                buffer |= static_cast<unsigned char>(input[i++]);
                bufferBits += 8; // Τ计糤 8 
            }
        }

        // 盢 buffer 计沮矗Θ Base32 才
        while (bufferBits > 0) {
            output[j++] = base32_chars[(buffer >> (bufferBits - 5)) & 0x1F];
            bufferBits -= 5; // –Ω矪瞶 5 
        }
    }

    // 睰挡Ю '\0'
    output[j] = '\0';
    return requiredSize;
}

int Base32Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input);
    if (inputLen % 8 != 0) return -3; // Base32 块ゲ斗琌 8 计

    int requiredSize = (inputLen * 5) / 8; // – 8 才癸莱 5 竊
    if (outputSize < requiredSize) return -2; // 块絯侥跋ぃì

    int i = 0, j = 0;
    uint64_t buffer = 0;   // 既 Base32 计沮
    int bufferBits = 0;    // 既Τ计

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // ┛菠挡Ю恶才

        // 莉才癸莱计
        if (c < 0 || c >= 128 || base32_lookup[c] == -1) return -4; // 獶猭才
        buffer = (buffer << 5) | base32_lookup[c];
        bufferBits += 5;

        // –Ω眖 buffer い 8 锣传Θ竊
        while (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // 秆絏竊计
}

int Base64Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input);
    int requiredSize = ((inputLen + 2) / 3) * 4; // – 3 竊癸莱 4  Base64 才

    if (outputSize < requiredSize + 1) // +1 琌 '\0'
        return -2; // 块絯侥跋ぃì

    int i = 0, j = 0;
    while (i < inputLen) {
        // 盢–竊舱Θ 24 计沮遏
        unsigned char a = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char b = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char c = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        // 盢 24 计沮遏╊だ 4  Base64 才
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = (i > inputLen + 1) ? '=' : base64_chars[(triple >> 6) & 0x3F];
        output[j++] = (i > inputLen) ? '=' : base64_chars[triple & 0x3F];
    }

    output[j] = '\0'; // 睰挡Ю '\0'
    return requiredSize; // 絪絏
}

int Base64Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input);
    if (inputLen % 4 != 0) return -3; // Base64 块ゲ斗琌 4 计

    int requiredSize = (inputLen / 4) * 3; // – 4 才癸莱 3 竊
    if (input[inputLen - 1] == '=') requiredSize--; // 矪瞶 '=' 恶
    if (input[inputLen - 2] == '=') requiredSize--;

    if (outputSize < requiredSize) return -2; // 块絯侥跋ぃì

    int i = 0, j = 0;
    uint32_t buffer = 0;   // 既 Base64 计沮
    int bufferBits = 0;    // 既Τ计

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // 挡Ю恶才

        int value = (c >= 0 && c < 256) ? base64_lookup[c] : -1;
        if (value < 0) return -4; // 獶猭才

        buffer = (buffer << 6) | value;
        bufferBits += 6;

        // –Ω眖 buffer い矗 8 
        if (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // 秆絏竊计
}

int Base85Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input);
    int requiredSize = ((inputLen + 3) / 4) * 5; // – 4 竊癸莱 5  Base85 才

    if (outputSize < requiredSize + 1) // +1 琌 '\0'
        return -2; // 块絯侥跋ぃì

    int i = 0, j = 0;
    while (i < inputLen) {
        // 盢–竊舱Θ 32 计沮遏
        uint32_t value = 0;
        for (int k = 0; k < 4; ++k) {
            value = (value << 8) | (i < inputLen ? static_cast<unsigned char>(input[i++]) : 0);
        }

        // 盢 32 计沮遏锣传 5  Base85 才
        for (int k = 4; k >= 0; --k) {
            output[j + k] = base85_chars[value % 85];
            value /= 85;
        }
        j += 5;
    }

    output[j] = '\0'; // 睰挡Ю '\0'
    return requiredSize; // 絪絏
}

int Base85Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ň縨┦絪祘浪琩皐琌

    int inputLen = std::strlen(input);
    if (inputLen % 5 != 0) return -3; // 块ゲ斗琌 5 计

    int requiredSize = (inputLen / 5) * 4; // – 5 才癸莱 4 竊
    if (outputSize < requiredSize) return -2; // 块絯侥跋ぃì

    uint32_t value = 0;
    size_t i = 0, j = 0;

    while (i < inputLen) {
        value = 0;

        // 盢 5  Base85 じ锣传 32-bit 俱计
        for (int k = 0; k < 5; ++k) {
            const char* pos = strchr(base85_chars, input[i++]);
            if (!pos)
                return -4;
            value = value * 85 + (pos - base85_chars);
        }

        // 盢 32-bit 俱计だ秆程 4 じ舱
        for (int k = 3; k >= 0; --k) {
            if (j + k < requiredSize)
                output[j + k] = static_cast<uint8_t>(value & 0xFF);
            value >>= 8;
        }
        j += 4;
    }

    return j;
}