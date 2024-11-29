#include "pch.h"
#include "AesIO.h"
#include <openssl/evp.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>

// Handle Errors
void handleErrors() {
    std::cerr << "An error occurred during key/iv generation" << std::endl;
    exit(1);
}

int GenerateKey(unsigned char* key, size_t keyLength) {
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        std::cerr << "Invalid key length. Use 128, 192, or 256 bits." << std::endl;
        return -1;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < keyLength; ++i) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
    return 0;
}

int GenerateIV(unsigned char* iv, size_t ivLength) {
    if (ivLength != 16) {
        std::cerr << "Invalid IV length. Use 128 bits." << std::endl;
        return -1;
    }
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < ivLength; ++i) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    return 0;
}

int GenerateKeyFromInput(const char* input, unsigned char* key, size_t keyLength) {
    if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
        std::cerr << "Invalid key length. Use 128, 192, or 256 bits." << std::endl;
        return -1;
    }
    size_t inputLength = strlen(input);
    memset(key, 0, keyLength);
    memcpy(key, input, inputLength > keyLength ? keyLength : inputLength);
    return 0;
}

int GenerateIVFromInput(const char* input, unsigned char* iv, size_t ivLength) {
    if (ivLength != 16) {
        std::cerr << "Invalid IV length. Use 128 bits." << std::endl;
        return -1;
    }
    size_t inputLength = strlen(input);
    memset(iv, 0, ivLength);
    memcpy(iv, input, inputLength > ivLength ? ivLength : inputLength);
    return 0;
}


//int AesCtrEncrypt(const char* content, char* buffer, size_t bufferSize) {
//	return 0;
//}
//
//int AesCtrDecrypt(const char* content, char* buffer, size_t bufferSize) {
//	return 0;
//}