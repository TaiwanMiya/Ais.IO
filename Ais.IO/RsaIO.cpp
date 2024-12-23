#include "pch.h"
#include "RsaIO.h"

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1) / (y))

int GetRsaParametersLength(RSA_PARAMETERS* params) {
    params->MODULUS_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 8);
    params->PUBLIC_EXPONENT_LENGTH = 3;
    params->PRIVATE_EXPONENT_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 8);
    params->FACTOR1_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 16);
    params->FACTOR2_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 16);
    params->EXPONENT1_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 16);
    params->EXPONENT2_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 16);
    params->COEFFICIENT_LENGTH = DIV_ROUND_UP(params->KEY_SIZE, 16);
    return 0;
}

int GenerateRsaParameters(RSA_PARAMETERS* params) {
    ERR_clear_error();
    EVP_PKEY* pkey = EVP_RSA_gen(params->KEY_SIZE);
    if (!pkey)
        return handleErrors_asymmetric("RSA key generate Pair failed.", NULL);

    BIGNUM* bn = NULL;

    // 提取 Modulus (n)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn))
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL, NULL, pkey);
    params->MODULUS_LENGTH = BN_num_bytes(bn);
    params->MODULUS = new unsigned char[params->MODULUS_LENGTH];
    BN_bn2bin(bn, params->MODULUS);
    BN_free(bn);

    // 提取 Public Exponent (e)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn))
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL, NULL, pkey);
    params->PUBLIC_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PUBLIC_EXPONENT = new unsigned char[params->PUBLIC_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PUBLIC_EXPONENT);
    BN_free(bn);

    // 提取 Private Exponent (d)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bn))
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL, NULL, pkey);
    params->PRIVATE_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PRIVATE_EXPONENT = new unsigned char[params->PRIVATE_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PRIVATE_EXPONENT);
    BN_free(bn);

    // 提取 Factor1 (p)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn))
        return handleErrors_asymmetric("Get Factor1 (p) failed.", NULL, NULL, pkey);
    params->FACTOR1_LENGTH = BN_num_bytes(bn);
    params->FACTOR1 = new unsigned char[params->FACTOR1_LENGTH];
    BN_bn2bin(bn, params->FACTOR1);
    BN_free(bn);

    // 提取 Factor2 (q)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn))
        return handleErrors_asymmetric("Get Factor2 (q) failed.", NULL, NULL, pkey);
    params->FACTOR2_LENGTH = BN_num_bytes(bn);
    params->FACTOR2 = new unsigned char[params->FACTOR2_LENGTH];
    BN_bn2bin(bn, params->FACTOR2);
    BN_free(bn);

    // 提取 Exponent1 (dmp1)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &bn))
        return handleErrors_asymmetric("Get Exponent1 (dmp1) failed.", NULL, NULL, pkey);
    params->EXPONENT1_LENGTH = BN_num_bytes(bn);
    params->EXPONENT1 = new unsigned char[params->EXPONENT1_LENGTH];
    BN_bn2bin(bn, params->EXPONENT1);
    BN_free(bn);

    // 提取 Exponent2 (dmq1)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &bn))
        return handleErrors_asymmetric("Get Exponent2 (dmq1) failed.", NULL, NULL, pkey);
    params->EXPONENT2_LENGTH = BN_num_bytes(bn);
    params->EXPONENT2 = new unsigned char[params->EXPONENT2_LENGTH];
    BN_bn2bin(bn, params->EXPONENT2);
    BN_free(bn);

    // 提取 Coefficient (iqmp)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &bn))
        return handleErrors_asymmetric("Get Coefficient (iqmp) failed.", NULL, NULL, pkey);
    params->COEFFICIENT_LENGTH = BN_num_bytes(bn);
    params->COEFFICIENT = new unsigned char[params->COEFFICIENT_LENGTH];
    BN_bn2bin(bn, params->COEFFICIENT);
    BN_free(bn);

    return 0;
}

int ImportRsaParameters(RSA_PARAMETERS* params, const unsigned char* key, size_t key_length, ASYMMETRIC_KEY_FORMAT format) {
    ERR_clear_error();
    BIO* bio = BIO_new_mem_buf(key, (int)key_length);
    if (!bio) {
        return handleErrors_asymmetric("Failed to create BIO for key import.", NULL);
    }

    EVP_PKEY* pkey = nullptr;

    switch (format)
    {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (!pkey)
            return handleErrors_asymmetric("Failed to read PEM private key.", NULL, bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        pkey = d2i_PrivateKey_bio(bio, NULL);
        if (!pkey)
            return handleErrors_asymmetric("Failed to read DER private key.", NULL, bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid RSA key format.", NULL, bio, pkey);
    }

    BIO_free(bio);

    BIGNUM* bn = NULL;

    // 提取 Modulus (n)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn))
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL, NULL, pkey);
    params->MODULUS_LENGTH = BN_num_bytes(bn);
    params->MODULUS = new unsigned char[params->MODULUS_LENGTH];
    BN_bn2bin(bn, params->MODULUS);
    BN_free(bn);

    // 提取 Public Exponent (e)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn))
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL, NULL, pkey);
    params->PUBLIC_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PUBLIC_EXPONENT = new unsigned char[params->PUBLIC_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PUBLIC_EXPONENT);
    BN_free(bn);

    // 提取 Private Exponent (d)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bn))
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL, NULL, pkey);
    params->PRIVATE_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PRIVATE_EXPONENT = new unsigned char[params->PRIVATE_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PRIVATE_EXPONENT);
    BN_free(bn);

    // 提取 Factor1 (p)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn))
        return handleErrors_asymmetric("Get Factor1 (p) failed.", NULL, NULL, pkey);
    params->FACTOR1_LENGTH = BN_num_bytes(bn);
    params->FACTOR1 = new unsigned char[params->FACTOR1_LENGTH];
    BN_bn2bin(bn, params->FACTOR1);
    BN_free(bn);

    // 提取 Factor2 (q)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn))
        return handleErrors_asymmetric("Get Factor2 (q) failed.", NULL, NULL, pkey);
    params->FACTOR2_LENGTH = BN_num_bytes(bn);
    params->FACTOR2 = new unsigned char[params->FACTOR2_LENGTH];
    BN_bn2bin(bn, params->FACTOR2);
    BN_free(bn);

    // 提取 Exponent1 (dmp1)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &bn))
        return handleErrors_asymmetric("Get Exponent1 (dmp1) failed.", NULL, NULL, pkey);
    params->EXPONENT1_LENGTH = BN_num_bytes(bn);
    params->EXPONENT1 = new unsigned char[params->EXPONENT1_LENGTH];
    BN_bn2bin(bn, params->EXPONENT1);
    BN_free(bn);

    // 提取 Exponent2 (dmq1)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &bn))
        return handleErrors_asymmetric("Get Exponent2 (dmq1) failed.", NULL, NULL, pkey);
    params->EXPONENT2_LENGTH = BN_num_bytes(bn);
    params->EXPONENT2 = new unsigned char[params->EXPONENT2_LENGTH];
    BN_bn2bin(bn, params->EXPONENT2);
    BN_free(bn);

    // 提取 Coefficient (iqmp)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &bn))
        return handleErrors_asymmetric("Get Coefficient (iqmp) failed.", NULL, NULL, pkey);
    params->COEFFICIENT_LENGTH = BN_num_bytes(bn);
    params->COEFFICIENT = new unsigned char[params->COEFFICIENT_LENGTH];
    BN_bn2bin(bn, params->COEFFICIENT);
    BN_free(bn);

    EVP_PKEY_free(pkey);

    return 0;
}

int RsaGenerate(RSA_KEY_PAIR* generate) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return handleErrors_asymmetric("An error occurred during ctx generation.", ctx);

    if (1 != EVP_PKEY_keygen_init(ctx))
        return handleErrors_asymmetric("Initial RSA key generation failed.", ctx);

    if (1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, generate->KEY_SIZE))
        return handleErrors_asymmetric("Set RSA key generate bits failed.", ctx);

    EVP_PKEY* pkey = EVP_RSA_gen(generate->KEY_SIZE);

    if (!pkey)
        return handleErrors_asymmetric("RSA key generate Pair failed.", ctx);

    /*if (1 != EVP_PKEY_generate(ctx, &pkey))
        return handleErrors_asymmetric("RSA key generate Pair failed.", ctx);*/

    EVP_PKEY_CTX_free(ctx);

    RAND_poll();
    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    switch (generate->FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_PUBKEY(pub_bio, pkey))
            return handleErrors_asymmetric("Unable to write public key in PEM format to memory.", pub_bio, priv_bio, pkey);
        if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
            return handleErrors_asymmetric("Unable to write private key in PEM format to memory.", pub_bio, priv_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PUBKEY_bio(pub_bio, pkey))
            return handleErrors_asymmetric("Unable to write public key in DER format to memory.", pub_bio, priv_bio, pkey);
        if (1 != i2d_PrivateKey_bio(priv_bio, pkey))
            return handleErrors_asymmetric("Unable to write private key in DER format to memory.", pub_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    size_t pub_len = BIO_pending(pub_bio);
    size_t priv_len = BIO_pending(priv_bio);
    if (generate->PUBLIC_KEY == nullptr || generate->PRIVATE_KEY == nullptr || generate->PUBLIC_KEY_LENGTH < pub_len || generate->PRIVATE_KEY_LENGTH < priv_len) {
        generate->PUBLIC_KEY_LENGTH = pub_len;
        generate->PRIVATE_KEY_LENGTH = priv_len;

        /*BIO_free_all(pub_bio);
        BIO_free_all(priv_bio);
        EVP_PKEY_free(pkey);

        return 0;*/

        generate->PUBLIC_KEY = new unsigned char[generate->PUBLIC_KEY_LENGTH];
        generate->PRIVATE_KEY = new unsigned char[generate->PRIVATE_KEY_LENGTH];
    }

    BIO_read(pub_bio, generate->PUBLIC_KEY, pub_len);
    BIO_read(priv_bio, generate->PRIVATE_KEY, priv_len);

    generate->PUBLIC_KEY_LENGTH = pub_len;
    generate->PRIVATE_KEY_LENGTH = priv_len;

    BIO_free_all(pub_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}