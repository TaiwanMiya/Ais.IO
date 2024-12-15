#include "pch.h"
#include "RandIO.h"

int Generate(unsigned char* key, size_t keyLength) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < keyLength; ++i)
        key[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int Import(const unsigned char* input, size_t inputLength, unsigned char* output, size_t outputLength) {
    std::memset(output, 0, outputLength);
    std::memcpy(output, input, inputLength > outputLength ? outputLength : inputLength);
    return 0;
}