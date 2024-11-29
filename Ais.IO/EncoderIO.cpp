#include "pch.h"
#include "EncoderIO.h"

static int HexCharToValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1; // �D�k�r�Ū�^ -1
}

// �ˬd�O�_�O�X�k�� Base64 �r��
inline bool isBase64Char(char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

int Base16Encode(const char* input, char* output, int outputSize) {
    if (!input || !output) return -1; // ���m���ˬd�A�קK�ū��w

    int inputLen = std::strlen(input); // �����J������
    int requiredSize = inputLen * 2;   // �C�Ӧr�`������ӤQ���i��r��

    if (outputSize < requiredSize + 1) // �ˬd��X�w�İϬO�_�����]+1 �O���F '\0'�^
        return -2;

    for (int i = 0; i < inputLen; ++i) {
        unsigned char byte = static_cast<unsigned char>(input[i]); // ����C�Ӧr�`
        output[i * 2] = Base16_Chars[byte >> 4];      // ���|���ഫ���Q���i��r��
        output[i * 2 + 1] = Base16_Chars[byte & 0x0F]; // �C�|���ഫ���Q���i��r��
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

    const unsigned char* data = reinterpret_cast<const unsigned char*>(input); // �N��J�ഫ���L�Ÿ��r�����w�A��K���줸�ճB�z
    size_t inputLength = std::strlen(input); // ��J����
    size_t outputNeeded = ((inputLength + 4) / 5) * 8; // �C 5 �r�`���� 8 �� Base32 �r��

    if (outputSize < static_cast<int>(outputNeeded + 1)) // �]�t������ '\0'
        return -2; // ��X�w�İϤ���

    // �p�⧹�㪺 5 �줸�հ϶��ƶq�M���Ʀr�`�ƶq
    const size_t fullChunks = inputLength / 5;
    const size_t leftover = inputLength % 5;

    // ��X�r�����ު�l��
    size_t outputIndex = 0;

    // �B�z���㪺 5 �r�`�϶�
    for (size_t i = 0; i < fullChunks; ++i) {
        uint64_t chunk = 0; // �Ȯ��x�s 5 �줸�ո�ƪ� 40 �줸���
        for (int j = 0; j < 5; ++j)
            chunk = (chunk << 8) | data[i * 5 + j]; // �N 5 �줸�ի������@�� 40 �줸���

        // �^���C 5 �줸�ƾڡA������ Base32 �r��
        for (int j = 7; j >= 0; --j)
            output[outputIndex++] = Base32_Chars[(chunk >> (j * 5)) & 0x1F];
    }

    // �B�z���� 5 �r�`������
    if (leftover > 0) {
        uint64_t chunk = 0; // �Ȯ��x�s���� 5 �줸�ժ��ƾ�
        for (size_t j = 0; j < leftover; ++j) {
            // �����Ѿl���줸��
            chunk = (chunk << 8) | data[fullChunks * 5 + j];
        }
        chunk <<= (5 - leftover) * 8; // �N���Ƴ��������A�񺡹s��A�ɻ��� 40 ��

        // �^�����Ī� Base32 �r��
        for (size_t j = 0; j < leftover * 8 / 5 + 1; ++j)
            output[outputIndex++] = Base32_Chars[(chunk >> ((7 - j) * 5)) & 0x1F];

        // ��R "="�A�Ͽ�X���׬O 8 ������
        for (size_t j = leftover * 8 / 5 + 1; j < 8; ++j)
            output[outputIndex++] = '=';
    }

    // �K�[������ '\0'
    output[outputIndex] = '\0';
    return static_cast<int>(outputIndex); // ��^�s�X�᪺����
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
        if (c < 0 || c >= 128 || Base32_Lookup[c] == -1) return -4; // �D�k�r��
        buffer = (buffer << 5) | Base32_Lookup[c];
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

    if (outputSize < requiredSize) // +1 �O�� '\0'
        return -2; // ��X�w�İϤ���

    int i = 0, j = 0;
    while (i < inputLen) {
        // �N�C�T�Ӧr�`�զ��@�� 24 �쪺�ƾڶ�
        unsigned char a = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char b = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;
        unsigned char c = i < inputLen ? static_cast<unsigned char>(input[i++]) : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        // �N 24 ��ƾڶ������ 4 �� Base64 �r��
        output[j++] = Base64_Chars[(triple >> 18) & 0x3F];
        output[j++] = Base64_Chars[(triple >> 12) & 0x3F];
        output[j++] = (i > inputLen + 1) ? '=' : Base64_Chars[(triple >> 6) & 0x3F];
        output[j++] = (i > inputLen) ? '=' : Base64_Chars[triple & 0x3F];
    }

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

        int value = (c >= 0 && c < 256) ? Base64_Lookup[c] : -1;
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
            output[j + k] = Base85_Chars[value % 85];
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
            const char* pos = strchr(Base85_Chars, input[i++]);
            if (!pos)
                return -4;
            value = value * 85 + (pos - Base85_Chars);
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