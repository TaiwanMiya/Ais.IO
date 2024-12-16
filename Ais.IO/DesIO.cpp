#include "pch.h"
#include "DesIO.h"
#include "AsymmetricIO.h"

int DesCbcEncrypt(DES_CBC_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_cbc(); break;
    case 24: cipher = EVP_des_ede3_cbc(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (!encryption->PKCS7_PADDING && encryption->PLAIN_TEXT_LENGTH % 8 != 0)
        return handleErrors("PlainText block must be 8 bytes, But you give " + std::to_string(encryption->PLAIN_TEXT_LENGTH), ctx);

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize DES CBC encryption for the current block failed.", ctx);
    
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

int DesCbcDecrypt(DES_CBC_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_cbc(); break;
    case 24: cipher = EVP_des_ede3_cbc(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (!decryption->PKCS7_PADDING && decryption->CIPHER_TEXT_LENGTH % 8 != 0)
        return handleErrors("CipherText block must be 8 bytes, But you give " + std::to_string(decryption->CIPHER_TEXT_LENGTH), ctx);

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize DES CBC decryption for the current block failed.", ctx);

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

int DesCfbEncrypt(DES_CFB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->KEY_LENGTH) {
    case 16:
        switch (encryption->SEGMENT_SIZE) {
        case SEGMENT_SIZE_OPTION::SEGMENT_64_BIT: cipher = EVP_des_ede_cfb64(); break;
        default:return handleErrors("Invalid segment size. Must be 64 bits.", ctx);
        }
        break;
    case 24:
        switch (encryption->SEGMENT_SIZE) {
        case SEGMENT_SIZE_OPTION::SEGMENT_1_BIT: cipher = EVP_des_ede3_cfb1(); break;
        case SEGMENT_SIZE_OPTION::SEGMENT_8_BIT: cipher = EVP_des_ede3_cfb8(); break;
        case SEGMENT_SIZE_OPTION::SEGMENT_64_BIT: cipher = EVP_des_ede3_cfb64(); break;
        default:return handleErrors("Invalid segment size. Must be 1, 8, 64 bits.", ctx);
        }
        break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize DES CFB encryption failed.", ctx);

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

int DesCfbDecrypt(DES_CFB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->KEY_LENGTH) {
    case 16:
        switch (decryption->SEGMENT_SIZE) {
        case SEGMENT_SIZE_OPTION::SEGMENT_64_BIT: cipher = EVP_des_ede_cfb64(); break;
        default:return handleErrors("Invalid segment size. Must be 64 bits.", ctx);
        }
        break;
    case 24:
        switch (decryption->SEGMENT_SIZE) {
        case SEGMENT_SIZE_OPTION::SEGMENT_1_BIT: cipher = EVP_des_ede3_cfb1(); break;
        case SEGMENT_SIZE_OPTION::SEGMENT_8_BIT: cipher = EVP_des_ede3_cfb8(); break;
        case SEGMENT_SIZE_OPTION::SEGMENT_64_BIT: cipher = EVP_des_ede3_cfb64(); break;
        default:return handleErrors("Invalid segment size. Must be 1, 8, 64 bits.", ctx);
        }
        break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize DES CFB decryption failed.", ctx);

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

int DesOfbEncrypt(DES_OFB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_ofb(); break;
    case 24: cipher = EVP_des_ede3_ofb(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEY, encryption->IV))
        return handleErrors("Initialize DES OFB encryption failed.", ctx);

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

int DesOfbDecrypt(DES_OFB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_ofb(); break;
    case 24: cipher = EVP_des_ede3_ofb(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEY, decryption->IV))
        return handleErrors("Initialize DES OFB decryption failed.", ctx);

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

int DesEcbEncrypt(DES_ECB_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;

    switch (encryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_ecb(); break;
    case 24: cipher = EVP_des_ede3_ecb(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (!encryption->PKCS7_PADDING && encryption->PLAIN_TEXT_LENGTH % 8 != 0)
        return handleErrors("PlainText block must be 8 bytes, But you give " + std::to_string(encryption->PLAIN_TEXT_LENGTH), ctx);

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEY, NULL))
        return handleErrors("Initialize DES ECB encryption for the current block failed.", ctx);

    EVP_CIPHER_CTX_set_padding(ctx, encryption->PKCS7_PADDING ? 1 : 0);

    int len = 0, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->CIPHER_TEXT, &len, encryption->PLAIN_TEXT, static_cast<int>(encryption->PLAIN_TEXT_LENGTH)))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->CIPHER_TEXT + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int DesEcbDecrypt(DES_ECB_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->KEY_LENGTH) {
    case 16: cipher = EVP_des_ede_ecb(); break;
    case 24: cipher = EVP_des_ede3_ecb(); break;
    default:return handleErrors("Invalid key length. Must be 128 or 192 bits. (16 or 24 bytes.)", ctx);
    }

    if (!decryption->PKCS7_PADDING && decryption->CIPHER_TEXT_LENGTH % 8 != 0)
        return handleErrors("CipherText block must be 16 bytes, But you give " + std::to_string(decryption->CIPHER_TEXT_LENGTH), ctx);

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEY, NULL))
        return handleErrors("Initialize DES ECB decryption for the current block failed.", ctx);

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

int DesWrapEncrypt(DES_WRAP_ENCRYPT* encryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (encryption->KEK_LENGTH != 24)
        return handleErrors("Invalid wrap key length. Must be 24 bytes.", ctx);

    if (encryption->KEY_LENGTH < 16)
        return handleErrors("Invalid plaintext key length. Must be at least 16 bytes.", ctx);

    memset(encryption->WRAP_KEY, 0, encryption->WRAP_KEY_LENGTH);

    const EVP_CIPHER* cipher = nullptr;
    switch (encryption->KEK_LENGTH) {
    case 24: cipher = EVP_des_ede3_wrap(); break;
    default: return handleErrors("Invalid wrap key length. Must be 192 bits.", ctx);
    }

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, encryption->KEK, NULL))
        return handleErrors("Initialize DES WRAP encryption for the current block failed.", ctx);

    int len, ciphertext_len = 0;
    if (1 != EVP_EncryptUpdate(ctx, encryption->WRAP_KEY, &len, encryption->KEY, encryption->KEY_LENGTH))
        return handleErrors("Encrypt the current block failed.", ctx);
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(ctx, encryption->WRAP_KEY + len, &len))
        return handleErrors("Final encryption failed.", ctx);
    ciphertext_len += len;

    encryption->WRAP_KEY_LENGTH = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int DesWrapDecrypt(DES_WRAP_DECRYPT* decryption) {
    ERR_clear_error();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return handleErrors("An error occurred during ctx generation.", ctx);

    if (decryption->KEK_LENGTH != 24)
        return handleErrors("Invalid wrap key length. Must be 24 bytes.", ctx);

    memset(decryption->KEY, 0, decryption->KEY_LENGTH);

    const EVP_CIPHER* cipher = nullptr;
    switch (decryption->KEK_LENGTH) {
    case 24: cipher = EVP_des_ede3_wrap(); break;
    default: return handleErrors("Invalid wrap key length. Must be 192 bits.", ctx);
    }

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, decryption->KEK, NULL))
        return handleErrors("Initialize DES WRAP decryption for the current block failed.", ctx);

    int len, plaintext_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, decryption->KEY, &len, decryption->WRAP_KEY, decryption->WRAP_KEY_LENGTH))
        return handleErrors("Decrypt the current block failed.", ctx);
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, decryption->KEY + len, &len))
        return handleErrors("Final decryption failed.", ctx);
    plaintext_len += len;

    decryption->KEY_LENGTH = plaintext_len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
