#include "pch.h"
#include "AesIO.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <string>

// Handle Errors
int handleErrors(std::string message, EVP_CIPHER_CTX* ctx) {
    std::cerr << "ERROR: " << message << std::endl;
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    return -1;
}

void longlong_to_bytes(long long counter, unsigned char* buffer, int buffer_size) {
    // Buffer size must be at least 8 bytes to store the counter
    if (buffer_size < 8) {
        std::cerr << "Buffer size too small" << std::endl;
        return;
    }

    // Store the counter in the buffer (little-endian order)
    for (int i = 0; i < 8; ++i) {
        buffer[i] = (unsigned char)((counter >> (i * 8)) & 0xFF);
    }
}

int GenerateKey(unsigned char* key, size_t keyLength) {
    ERR_clear_error();
    if (keyLength != 16 && keyLength != 24 && keyLength != 32)
        return handleErrors("Invalid Key length. Use 128, 192, or 256 bits.", NULL);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < keyLength; ++i)
        key[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int GenerateIV(unsigned char* iv, size_t ivLength) {
    ERR_clear_error();
    if (ivLength != 12 && ivLength != 16)
        return handleErrors("Invalid IV length. Use 96, 128 bits.", NULL);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < ivLength; ++i)
        iv[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int GenerateTag(unsigned char* tag, size_t tagLength) {
    ERR_clear_error();
    if (tagLength != 16)
        return handleErrors("Invalid Tag length. Use 128 bits.", NULL);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < tagLength; ++i)
        tag[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int GenerateAad(unsigned char* aad, size_t aadLength) {
    ERR_clear_error();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < aadLength; ++i)
        aad[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int GenerateTweak(unsigned char* tweak, size_t tweakLength) {
    ERR_clear_error();
    if (tweakLength != 16)
        return handleErrors("Invalid Tweak length. Use 128 bits.", NULL);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < tweakLength; ++i)
        tweak[i] = static_cast<unsigned char>(dis(gen));
    return 0;
}

int ImportKey(const unsigned char* input, size_t inputLength, unsigned char* key, size_t keyLength) {
    ERR_clear_error();
    if (keyLength != 16 && keyLength != 24 && keyLength != 32)
        return handleErrors("Invalid Key length. Use 128, 192, or 256 bits.", NULL);

    memset(key, 0, keyLength);
    memcpy(key, input, inputLength > keyLength ? keyLength : inputLength);
    return 0;
}

int ImportIV(const unsigned char* input, size_t inputLength, unsigned char* iv, size_t ivLength) {
    if (ivLength != 12 && ivLength != 16)
        return handleErrors("Invalid IV length. Use 96, 128 bits.", NULL);

    memset(iv, 0, ivLength);
    memcpy(iv, input, inputLength > ivLength ? ivLength : inputLength);
    return 0;
}

int ImportTag(const unsigned char* input, size_t inputLength, unsigned char* tag, size_t tagLength) {
    if (tagLength != 16)
        return handleErrors("Invalid Tag length. Use 128 bits.", NULL);

    memset(tag, 0, tagLength);
    memcpy(tag, input, inputLength > tagLength ? tagLength : inputLength);
    return 0;
}

int ImportAad(const unsigned char* input, size_t inputLength, unsigned char* aad, size_t aadLength) {
    memset(aad, 0, aadLength);
    memcpy(aad, input, inputLength > aadLength ? aadLength : inputLength);
    return 0;
}

int ImportTweak(const unsigned char* input, size_t inputLength, unsigned char* tweak, size_t tweakLength) {
    if (tweakLength != 16)
        return handleErrors("Invalid Tweak length. Use 128 bits.", NULL);
    memset(tweak, 0, tweakLength);
    memcpy(tweak, input, inputLength > tweakLength ? tweakLength : inputLength);
    return 0;
}

int AesCtrEncrypt(AES_CTR_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const int BLOCK_SIZE = 16;

    unsigned char iv_with_counter[16];
    int len, ciphertext_len = 0;

    size_t total_blocks = (encryption->PLAIN_TEXT_LENGTH + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int i = 0; i < total_blocks; ++i) {
        longlong_to_bytes(encryption->COUNTER, iv_with_counter, BLOCK_SIZE);

        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, encryption->KEY, iv_with_counter))
            return handleErrors("Initialize AES CTR encryption for the current block failed.", ctx);

        size_t current_block_size = (BLOCK_SIZE < (encryption->PLAIN_TEXT_LENGTH - (i * BLOCK_SIZE)))
                                ? BLOCK_SIZE
                                : (encryption->PLAIN_TEXT_LENGTH - (i * BLOCK_SIZE));

        if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT + ciphertext_len, &len, encryption->PLAIN_TEXT + (i * BLOCK_SIZE), static_cast<int>(current_block_size)))
            return handleErrors("Encrypt the current block failed.", ctx);
        ciphertext_len += len;
    }

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + ciphertext_len, &len))
        return handleErrors("Finalize encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesCtrDecrypt(AES_CTR_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const int BLOCK_SIZE = 16;

    unsigned char iv_with_counter[16];
    int len, plaintext_len = 0;

    size_t total_blocks = (decryption->CIPHER_TEXT_LENGTH + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int i = 0; i < total_blocks; ++i) {
        longlong_to_bytes(decryption->COUNTER, iv_with_counter, BLOCK_SIZE);

        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, decryption->KEY, iv_with_counter))
            return handleErrors("Initialize AES CTR decryption for the current block failed.", ctx);

        size_t current_block_size = (BLOCK_SIZE < (decryption->CIPHER_TEXT_LENGTH - (i * BLOCK_SIZE)))
                                ? BLOCK_SIZE
                                : (decryption->CIPHER_TEXT_LENGTH - (i * BLOCK_SIZE));

        if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT + plaintext_len, &len, decryption->CIPHER_TEXT + (i * BLOCK_SIZE), static_cast<int>(current_block_size)))
            return handleErrors("Decrypt the current block failed.", ctx);
        plaintext_len += len;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + plaintext_len, &len))
        return handleErrors("Finalize decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesCbcEncrypt(AES_CBC_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (encryption->PKCS7_PADDING == false && encryption->PLAIN_TEXT_LENGTH % 16 != 0)
        return handleErrors("PlainText block must be 16 bytes, But you give " + std::to_string(encryption->PLAIN_TEXT_LENGTH), ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES CBC encryption for the current block failed.", ctx);

    EVP_CIPHER_CTX_set_padding(ctx, encryption->PKCS7_PADDING ? 1 : 0);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, static_cast<int>(encryption->PLAIN_TEXT_LENGTH)))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesCbcDecrypt(AES_CBC_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (decryption->PKCS7_PADDING == false && decryption->CIPHER_TEXT_LENGTH % 16 != 0)
        return handleErrors("CipherText block must be 16 bytes, But you give " + std::to_string(decryption->CIPHER_TEXT_LENGTH), ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES CBC decryption for the current block failed.", ctx);

    EVP_CIPHER_CTX_set_padding(ctx, decryption->PKCS7_PADDING ? 1 : 0);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, static_cast<int>(decryption->CIPHER_TEXT_LENGTH)))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesCfbEncrypt(AES_CFB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->SEGMENT_SIZE) {
        case SEGMENT_SIZE_OPTION::SEGMENT_1_BIT:
            cipher = EVP_aes_256_cfb1();
            break;
        case SEGMENT_SIZE_OPTION::SEGMENT_8_BIT:
            cipher = EVP_aes_256_cfb8();
            break;
        case SEGMENT_SIZE_OPTION::SEGMENT_128_BIT:
            cipher = EVP_aes_256_cfb128();
            break;
        default:
            cipher = EVP_aes_256_cfb128();
            break;
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES CFB encryption failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, static_cast<int>(encryption->PLAIN_TEXT_LENGTH)))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesCfbDecrypt(AES_CFB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->SEGMENT_SIZE) {
    case SEGMENT_SIZE_OPTION::SEGMENT_1_BIT:
        cipher = EVP_aes_256_cfb1();
        break;
    case SEGMENT_SIZE_OPTION::SEGMENT_8_BIT:
        cipher = EVP_aes_256_cfb8();
        break;
    case SEGMENT_SIZE_OPTION::SEGMENT_128_BIT:
        cipher = EVP_aes_256_cfb128();
        break;
    default:
        cipher = EVP_aes_256_cfb128();
        break;
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES CFB decryption failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, static_cast<int>(decryption->CIPHER_TEXT_LENGTH)))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesOfbEncrypt(AES_OFB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES OFB encryption failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, static_cast<int>(encryption->PLAIN_TEXT_LENGTH)))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesOfbDecrypt(AES_OFB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ofb(), NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES OFB encryption failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, static_cast<int>(decryption->CIPHER_TEXT_LENGTH)))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesEcbEncrypt(AES_ECB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (encryption->PKCS7_PADDING == false && encryption->PLAIN_TEXT_LENGTH % 16 != 0)
        return handleErrors("PlainText block must be 16 bytes, But you give " + std::to_string(encryption->PLAIN_TEXT_LENGTH), ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, encryption->KEY, NULL))
        return handleErrors("Initialize AES ECB encryption for the current block failed.", ctx);

    EVP_CIPHER_CTX_set_padding(ctx, encryption->PKCS7_PADDING ? 1 : 0);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, static_cast<int>(encryption->PLAIN_TEXT_LENGTH)))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesEcbDecrypt(AES_ECB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (decryption->PKCS7_PADDING == false && decryption->CIPHER_TEXT_LENGTH % 16 != 0)
        return handleErrors("CipherText block must be 16 bytes, But you give " + std::to_string(decryption->CIPHER_TEXT_LENGTH), ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, decryption->KEY, NULL))
        return handleErrors("Initialize AES ECB decryption for the current block failed.", ctx);

    EVP_CIPHER_CTX_set_padding(ctx, decryption->PKCS7_PADDING ? 1 : 0);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, static_cast<int>(decryption->CIPHER_TEXT_LENGTH)))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesGcmEncrypt(AES_GCM_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return handleErrors("Initialize AES GCM encryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, encryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set GCM IV length.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES GCM encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, encryption->PLAIN_TEXT_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, encryption->TAG_LENGTH, encryption->TAG))
        return handleErrors("Failed to get GCM Tag length.", ctx);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesGcmDecrypt(AES_GCM_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return handleErrors("Initialize AES GCM decryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, decryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set GCM IV length.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES GCM decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, decryption->CIPHER_TEXT_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, decryption->TAG_LENGTH, (void*)decryption->TAG))
        return handleErrors("Failed to set GCM Tag length.", ctx);

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len)) {
        return handleErrors("Final decryption failed.", ctx);
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesCcmEncrypt(AES_CCM_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        return handleErrors("Initialize AES CCM encryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, encryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set CCM IV length.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, encryption->TAG_LENGTH, NULL))
        return handleErrors("Failed to set CCM Tag length.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES CCM encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, encryption->PLAIN_TEXT_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);

    if (encryption->AAD_LENGTH > 0 && 1 != EVP_EncryptUpdate(ctx, NULL, &len, encryption->ADDITIONAL_DATA, encryption->AAD_LENGTH))
        return handleErrors("Failed to set CCM ADD length and ADD data.", ctx);

    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, encryption->PLAIN_TEXT_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, encryption->TAG_LENGTH, encryption->TAG))
        return handleErrors("Failed to get CCM Tag length.", ctx);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesCcmDecrypt(AES_CCM_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL))
        return handleErrors("Initialize AES CCM decryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, decryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set CCM IV length.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, decryption->TAG_LENGTH, (void*)decryption->TAG))
        return handleErrors("Failed to set CCM Tag length.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES CCM decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, decryption->CIPHER_TEXT_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);

    if (decryption->AAD_LENGTH > 0 && 1 != EVP_DecryptUpdate(ctx, NULL, &len, decryption->ADDITIONAL_DATA, decryption->AAD_LENGTH))
        return handleErrors("Failed to set CCM ADD length and ADD data.", ctx);

    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, decryption->CIPHER_TEXT_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesXtsEncrypt(AES_XTS_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, NULL, NULL))
        return handleErrors("Initialize AES XTS encryption for the current block failed.", ctx);

    unsigned char xts_key[64];
    memcpy(xts_key, encryption->KEY1, 32);
    memcpy(xts_key + 32, encryption->KEY2, 32);

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, xts_key, encryption->TWEAK))
        return handleErrors("Initialize AES XTS encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, encryption->PLAIN_TEXT_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesXtsDecrypt(AES_XTS_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, NULL, NULL))
        return handleErrors("Initialize AES XTS decryption for the current block failed.", ctx);

    unsigned char xts_key[64];
    memcpy(xts_key, decryption->KEY1, 32);
    memcpy(xts_key + 32, decryption->KEY2, 32);

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, xts_key, decryption->TWEAK))
        return handleErrors("Initialize AES XTS decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, decryption->CIPHER_TEXT_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesOcbEncrypt(AES_OCB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ocb(), NULL, NULL, NULL))
        return handleErrors("Initialize AES OCB encryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, encryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set OCB IV length.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, encryption->TAG_LENGTH, NULL))
        return handleErrors("Failed to set OCB Tag length.", ctx);

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize AES OCB encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;
    if (encryption->AAD_LENGTH > 0 && 1 != EVP_EncryptUpdate(ctx, NULL, &len, encryption->ADDITIONAL_DATA, encryption->AAD_LENGTH))
        return handleErrors("Failed to set OCB ADD length and ADD data.", ctx);

    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, encryption->PLAIN_TEXT_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, encryption->TAG_LENGTH, encryption->TAG))
        return handleErrors("Failed to get OCM Tag length.", ctx);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesOcbDecrypt(AES_OCB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ocb(), NULL, NULL, NULL))
        return handleErrors("Initialize AES OCB decryption for the current block failed.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, decryption->IV_LENGTH, NULL))
        return handleErrors("Failed to set OCB IV length.", ctx);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, decryption->TAG_LENGTH, (void*)decryption->TAG))
        return handleErrors("Failed to set OCB Tag length.", ctx);

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize AES OCB decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;
    if (decryption->AAD_LENGTH > 0 && 1 != EVP_DecryptUpdate(ctx, NULL, &len, decryption->ADDITIONAL_DATA, decryption->AAD_LENGTH))
        return handleErrors("Failed to set OCB ADD length and ADD data.", ctx);

    if (1 != EVP_DecryptUpdate(ctx, decryption->PLAIN_TEXT, &len, decryption->CIPHER_TEXT, decryption->CIPHER_TEXT_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, decryption->TAG_LENGTH, (void*)decryption->TAG))
        return handleErrors("Failed to set OCB Tag length.", ctx);

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->PLAIN_TEXT + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

int AesWrapEncrypt(AES_WRAP_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (encryption->WRAP_KEY_LENGTH != 16 && encryption->WRAP_KEY_LENGTH != 24 && encryption->WRAP_KEY_LENGTH != 32)
        return handleErrors("Invalid wrap key length. Must be 16, 24, or 32 bytes.", ctx);

    if (encryption->PLAINTEXT_KEY_LENGTH < 16)
        return handleErrors("Invalid plaintext key length. Must be at least 16 bytes.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->WRAP_KEY_LENGTH) {
    case 16: cipher = EVP_aes_128_wrap(); break;
    case 24: cipher = EVP_aes_192_wrap(); break;
    case 32: cipher = EVP_aes_256_wrap(); break;
    default: return handleErrors("Invalid wrap key length. Must be 128, 192, or 256 bits.", ctx);
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->WRAP_KEY, NULL))
        return handleErrors("Initialize AES WRAP encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->WRAPPED_KEY, &len, encryption->PLAINTEXT_KEY, encryption->PLAINTEXT_KEY_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->WRAPPED_KEY + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    encryption->WRAPPED_KEY_LENGTH = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int AesWrapDecrypt(AES_WRAP_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (decryption->WRAP_KEY_LENGTH != 16 && decryption->WRAP_KEY_LENGTH != 24 && decryption->WRAP_KEY_LENGTH != 32)
        return handleErrors("Invalid wrap key length. Must be 128, 192, or 256 bits.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->WRAP_KEY_LENGTH) {
    case 16: cipher = EVP_aes_128_wrap(); break;
    case 24: cipher = EVP_aes_192_wrap(); break;
    case 32: cipher = EVP_aes_256_wrap(); break;
    default:return handleErrors("Invalid wrap key length. Must be 128, 192, or 256 bits.", ctx);
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->WRAP_KEY, NULL))
        return handleErrors("Initialize AES WRAP decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->UNWRAPPED_KEY, &len, decryption->WRAPPED_KEY, decryption->WRAPPED_KEY_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->UNWRAPPED_KEY + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    decryption->UNWRAPPED_KEY_LENGTH = plaintext_len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
