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

// Base32 �ѽX��
static const int base32_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 40-47 �D�k�r��
    -1, -1, 26, 27, 28, 29, 30, 31, // 48-55: '2'-'7'
    -1, -1, -1, -1, -1, -1, -1, -1, // 56-63 �D�k�r��
    -1,  0,  1,  2,  3,  4,  5,  6, // 64-71: 'A'-'H'
     7,  8,  9, 10, 11, 12, 13, 14, // 72-79: 'I'-'P'
    15, 16, 17, 18, 19, 20, 21, 22, // 80-87: 'Q'-'X'
    23, 24, 25, -1, -1, -1, -1, -1, // 88-95: 'Y'-'Z'
    -1, -1, -1, -1, -1, -1, -1, -1, // 96-103 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 104-111 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 112-119 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 120-127 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 �D�k�r��
};

// Base64 �ѽX��
static const int base64_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 32-39 �D�k�r��
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
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 �D�k�r��
};

// Base85 �ѽX��
static const int base85_lookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, // 0-7: �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 8-15: �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 16-23: �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 24-31: �D�k�r��
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
    78, 79, 80, 81, 82, 83, 84, -1, // 120-127: �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 128-135 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 136-143 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 144-151 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 152-159 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 160-167 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 168-175 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 176-183 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 184-191 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 192-199 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 200-207 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 208-215 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 216-223 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 224-231 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 232-239 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 240-247 �D�k�r��
    -1, -1, -1, -1, -1, -1, -1, -1, // 248-255 �D�k�r��
};

static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; // �D�k�r�Ū�^ -1
}

int Base16Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m���ˬd�A�קK�ū��w

    int inputLen = std::strlen(input); // �����J������
    int requiredSize = inputLen * 2;   // �C�Ӧr�`������ӤQ���i��r��

    if (outputSize < requiredSize + 1) // �ˬd��X�w�İϬO�_�����]+1 �O���F '\0'�^
        return -2;

    for (int i = 0; i < inputLen; ++i) {
        unsigned char byte = static_cast<unsigned char>(input[i]); // ����C�Ӧr�`
        output[i * 2] = base16_chars[byte >> 4];      // ���|���ഫ���Q���i��r��
        output[i * 2 + 1] = base16_chars[byte & 0x0F]; // �C�|���ഫ���Q���i��r��
    }

    output[requiredSize] = '\0'; // �K�[�������Ŧr��
    return requiredSize;         // ��^��ڪ��s�X����
}

int Base16Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m���ˬd

    int inputLen = std::strlen(input); // �����J������
    if (inputLen % 2 != 0) return -3; // Base16 ����J���ץ����O����

    int requiredSize = inputLen / 2; // �C��Ӧr�Ź����@�Ӧr�`
    if (outputSize < requiredSize) return -2;

    for (int i = 0; i < inputLen; i += 2) {
        int high = HexCharToValue(input[i]);     // �ഫ����r��
        int low = HexCharToValue(input[i + 1]); // �ഫ�C��r��

        if (high == -1 || low == -1) return -4; // �ˬd�r�ŬO�_�X�k

        output[i / 2] = (high << 4) | low; // �X�ְ��C��o��@�Ӧr�`
    }

    return requiredSize; // ��^�ѽX�᪺�r�`��
}

int Base32Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input); // ��J����
    int requiredSize = ((inputLen + 4) / 5) * 8; // �C 5 �r�`���� 8 �� Base32 �r��

    if (outputSize < requiredSize + 1) // �]�t������ '\0'
        return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    while (i < inputLen) {
        uint64_t buffer = 0;   // �Ȧs 5 �r�`���ƾ�
        int bufferBits = 0;    // �Ȧs�ƾڪ����Ħ��

        // �C���̦hŪ�� 5 �Ӧr�`�A�զ��@�� 40 �쪺 buffer
        for (int k = 0; k < 5; ++k) {
            buffer <<= 8;      // ���� 8 ��
            if (i < inputLen) {
                buffer |= static_cast<unsigned char>(input[i++]);
                bufferBits += 8; // ���Ħ�ƼW�[ 8 ��
            }
        }

        // �N buffer ���ƾڴ����� Base32 �r��
        while (bufferBits > 0) {
            output[j++] = base32_chars[(buffer >> (bufferBits - 5)) & 0x1F];
            bufferBits -= 5; // �C���B�z 5 ��
        }
    }

    // �K�[������ '\0'
    output[j] = '\0';
    return requiredSize;
}

int Base32Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input);
    if (inputLen % 8 != 0) return -3; // Base32 ����J���ץ����O 8 ������

    int requiredSize = (inputLen * 5) / 8; // �C 8 �Ӧr�Ź��� 5 �Ӧr�`
    if (outputSize < requiredSize) return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    uint64_t buffer = 0;   // �Ȧs Base32 �ƾ�
    int bufferBits = 0;    // �Ȧs���Ħ��

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // ������������R��

        // ����r�Ź������ƭ�
        if (c < 0 || c >= 128 || base32_lookup[c] == -1) return -4; // �D�k�r��
        buffer = (buffer << 5) | base32_lookup[c];
        bufferBits += 5;

        // �C���q buffer �����X 8 ��A�ഫ���@�Ӧr�`
        while (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // ��^�ѽX�᪺�r�`��
}

int Base64Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input);
    int requiredSize = ((inputLen + 2) / 3) * 4; // �C 3 �r�`���� 4 �� Base64 �r��

    if (outputSize < requiredSize + 1) // +1 �O�� '\0'
        return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    while (i < inputLen) {
        // �N�C�T�Ӧr�`�զ��@�� 24 �쪺�ƾڶ�
        unsigned char a = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char b = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char c = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        // �N 24 ��ƾڶ������ 4 �� Base64 �r��
        output[j++] = base64_chars[(triple >> 18) & 0x3F];
        output[j++] = base64_chars[(triple >> 12) & 0x3F];
        output[j++] = (i > inputLen + 1) ? '=' : base64_chars[(triple >> 6) & 0x3F];
        output[j++] = (i > inputLen) ? '=' : base64_chars[triple & 0x3F];
    }

    output[j] = '\0'; // �K�[������ '\0'
    return requiredSize; // ��^�s�X�᪺����
}

int Base64Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input);
    if (inputLen % 4 != 0) return -3; // Base64 ����J���ץ����O 4 ������

    int requiredSize = (inputLen / 4) * 3; // �C 4 �Ӧr�Ź��� 3 �Ӧr�`
    if (input[inputLen - 1] == '=') requiredSize--; // �B�z '=' ��R
    if (input[inputLen - 2] == '=') requiredSize--;

    if (outputSize < requiredSize) return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    uint32_t buffer = 0;   // �Ȧs Base64 �ƾ�
    int bufferBits = 0;    // �Ȧs���Ħ��

    while (i < inputLen) {
        char c = input[i++];
        if (c == '=') break; // ������R��

        int value = (c >= 0 && c < 256) ? base64_lookup[c] : -1;
        if (value < 0) return -4; // �D�k�r��

        buffer = (buffer << 6) | value;
        bufferBits += 6;

        // �C���q buffer ������ 8 ��
        if (bufferBits >= 8) {
            output[j++] = (buffer >> (bufferBits - 8)) & 0xFF;
            bufferBits -= 8;
        }
    }

    return j; // ��^�ѽX�᪺�r�`��
}

int Base85Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input);
    int requiredSize = ((inputLen + 3) / 4) * 5; // �C 4 �r�`���� 5 �� Base85 �r��

    if (outputSize < requiredSize + 1) // +1 �O�� '\0'
        return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    while (i < inputLen) {
        // �N�C�|�Ӧr�`�զ��@�� 32 �쪺�ƾڶ�
        uint32_t value = 0;
        for (int k = 0; k < 4; ++k) {
            value = (value << 8) | (i < inputLen ? static_cast<unsigned char>(input[i++]) : 0);
        }

        // �N 32 ��ƾڶ��ഫ�� 5 �� Base85 �r��
        for (int k = 4; k >= 0; --k) {
            output[j + k] = base85_chars[value % 85];
            value /= 85;
        }
        j += 5;
    }

    output[j] = '\0'; // �K�[������ '\0'
    return requiredSize; // ��^�s�X�᪺����
}

int Base85Decode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m�ʽs�{�A�ˬd���w�O�_����

    int inputLen = std::strlen(input);
    if (inputLen % 5 != 0) return -3; // ��J���ץ����O 5 ������

    int requiredSize = (inputLen / 5) * 4; // �C 5 �Ӧr�Ź��� 4 �Ӧr�`
    if (outputSize < requiredSize) return -2; // ��X�w�İϤ���

    uint32_t value = 0;
    size_t i = 0, j = 0;

    while (i < inputLen) {
        value = 0;

        // �N 5 �� Base85 �r���ഫ�� 32-bit ��ƭ�
        for (int k = 0; k < 5; ++k) {
            const char* pos = strchr(base85_chars, input[i++]);
            if (!pos)
                return -4;
            value = value * 85 + (pos - base85_chars);
        }

        // �N 32-bit ��ƭȤ��Ѭ��̦h 4 �Ӧ줸��
        for (int k = 3; k >= 0; --k) {
            if (j + k < requiredSize)
                output[j + k] = static_cast<uint8_t>(value & 0xFF);
            value >>= 8;
        }
        j += 4;
    }

    return j;
}