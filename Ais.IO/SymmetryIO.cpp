#include "pch.h"
#include "SymmetryIO.h"

int handleErrors_symmetry(std::string message, EVP_CIPHER_CTX* ctx) {
    std::cerr << "ERROR: " << message << std::endl;
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int handleErrors_symmetry(std::string message, EVP_MD_CTX* ctx) {
    std::cerr << "ERROR: " << message << std::endl;
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    return -1;
}

const EVP_CIPHER* GetSymmetryCrypter(SYMMETRY_CRYPTER crypter, int size, SEGMENT_SIZE_OPTION segment) {
    const EVP_CIPHER* cipher = NULL;
    switch (size) {
    case 16:case 128:
        switch (crypter) {
        case SYMMETRY_AES_CTR: cipher = EVP_aes_128_ctr(); break;
        case SYMMETRY_AES_CBC: cipher = EVP_aes_128_cbc(); break;
        case SYMMETRY_AES_CFB:
            switch (segment) {
            case SEGMENT_1_BIT: cipher = EVP_aes_128_cfb1(); break;
            case SEGMENT_8_BIT: cipher = EVP_aes_128_cfb8(); break;
            case SEGMENT_64_BIT: break;
            case SEGMENT_128_BIT: cipher = EVP_aes_128_cfb128(); break;
            default: break;
            }
            break;
        case SYMMETRY_AES_OFB: cipher = EVP_aes_128_ofb(); break;
        case SYMMETRY_AES_ECB: cipher = EVP_aes_128_ecb(); break;
        case SYMMETRY_AES_GCM: cipher = EVP_aes_128_gcm(); break;
        case SYMMETRY_AES_CCM: cipher = EVP_aes_128_ccm(); break;
        case SYMMETRY_AES_XTS: cipher = EVP_aes_128_xts(); break;
        case SYMMETRY_AES_OCB: cipher = EVP_aes_128_ocb(); break;
        case SYMMETRY_AES_WRAP: cipher = EVP_aes_128_wrap(); break;
        case SYMMETRY_DES_CBC: cipher = EVP_des_ede_cbc(); break;
        case SYMMETRY_DES_CFB: cipher = EVP_des_ede_cfb64(); break;
        case SYMMETRY_DES_OFB: cipher = EVP_des_ede_ofb(); break;
        case SYMMETRY_DES_ECB: cipher = EVP_des_ede_ecb(); break;
        case SYMMETRY_DES_WRAP: cipher = EVP_des_ede3_wrap(); break;
        default: break;
        }
        break;
    case 24:case 192:
        switch (crypter) {
        case SYMMETRY_AES_CTR: cipher = EVP_aes_192_ctr(); break;
        case SYMMETRY_AES_CBC: cipher = EVP_aes_192_cbc(); break;
        case SYMMETRY_AES_CFB:
            switch (segment) {
            case SEGMENT_1_BIT: cipher = EVP_aes_192_cfb1(); break;
            case SEGMENT_8_BIT: cipher = EVP_aes_192_cfb8(); break;
            case SEGMENT_64_BIT: break;
            case SEGMENT_128_BIT: cipher = EVP_aes_192_cfb128(); break;
            default: break;
            }
            break;
        case SYMMETRY_AES_OFB: cipher = EVP_aes_192_ofb(); break;
        case SYMMETRY_AES_ECB: cipher = EVP_aes_192_ecb(); break;
        case SYMMETRY_AES_GCM: cipher = EVP_aes_192_gcm(); break;
        case SYMMETRY_AES_CCM: cipher = EVP_aes_192_ccm(); break;
        case SYMMETRY_AES_XTS: break;
        case SYMMETRY_AES_OCB: cipher = EVP_aes_192_ocb(); break;
        case SYMMETRY_AES_WRAP: cipher = EVP_aes_192_wrap(); break;
        case SYMMETRY_DES_CBC: cipher = EVP_des_ede3_cbc(); break;
        case SYMMETRY_DES_CFB:
            switch (segment) {
            case SEGMENT_1_BIT: cipher = EVP_des_ede3_cfb1(); break;
            case SEGMENT_8_BIT: cipher = EVP_des_ede3_cfb8(); break;
            case SEGMENT_64_BIT: cipher = EVP_des_ede3_cfb64(); break;
            case SEGMENT_128_BIT: break;
            default: break;
            }
            break;
        case SYMMETRY_DES_OFB: cipher = EVP_des_ede3_ofb(); break;
        case SYMMETRY_DES_ECB: cipher = EVP_des_ede3_ecb(); break;
        case SYMMETRY_DES_WRAP: cipher = EVP_des_ede3_wrap(); break;
        default:
            break;
        }
        break;
    case 32:case 256: switch (crypter) {
        case SYMMETRY_AES_CTR: cipher = EVP_aes_256_ctr(); break;
        case SYMMETRY_AES_CBC: cipher = EVP_aes_256_cbc(); break;
        case SYMMETRY_AES_CFB:
            switch (segment) {
            case SEGMENT_1_BIT: cipher = EVP_aes_256_cfb1(); break;
            case SEGMENT_8_BIT: cipher = EVP_aes_256_cfb8(); break;
            case SEGMENT_64_BIT: break;
            case SEGMENT_128_BIT: cipher = EVP_aes_256_cfb128(); break;
            default: break;
            }
            break;
        case SYMMETRY_AES_OFB: cipher = EVP_aes_256_ofb(); break;
        case SYMMETRY_AES_ECB: cipher = EVP_aes_256_ecb(); break;
        case SYMMETRY_AES_GCM: cipher = EVP_aes_256_gcm(); break;
        case SYMMETRY_AES_CCM: cipher = EVP_aes_256_ccm(); break;
        case SYMMETRY_AES_XTS: cipher = EVP_aes_256_xts(); break;
        case SYMMETRY_AES_OCB: cipher = EVP_aes_256_ocb(); break;
        case SYMMETRY_AES_WRAP: cipher = EVP_aes_256_wrap(); break;
        case SYMMETRY_DES_CBC: break;
        case SYMMETRY_DES_CFB: break;
        case SYMMETRY_DES_OFB: break;
        case SYMMETRY_DES_ECB: break;
        case SYMMETRY_DES_WRAP: break;
        default: break;
        }
        break;
    default: break;
    }
    return cipher;
}

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