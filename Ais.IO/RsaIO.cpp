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
    params->BITS_LENGTH = 8;
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

    // 提取 Bits (bits)
    bn = BN_new();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &bn))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pkey);
    params->BITS_LENGTH = BN_num_bytes(bn);
    params->BITS = new unsigned char[params->BITS_LENGTH];
    BN_bn2bin(bn, params->BITS);
    BN_free(bn);

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

int ImportRsaParametersFromKeys(IMPORT_RSA_PARAMTERS* params) {
    ERR_clear_error();
    BIO* pub_bio = BIO_new_mem_buf(params->PUBLIC_KEY, static_cast<int>(params->PUBLIC_KEY_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);

    EVP_PKEY* pub_pkey = nullptr;
    EVP_PKEY* priv_pkey = nullptr;

    switch (params->FORMAT)
    {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        pub_pkey = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
        if (!pub_pkey)
            return handleErrors_asymmetric("Failed to read PEM public key.", pub_bio, priv_bio, pub_pkey, priv_pkey);
        priv_pkey = PEM_read_bio_PrivateKey(priv_bio, NULL, NULL, NULL);
        if (!priv_pkey)
            return handleErrors_asymmetric("Failed to read PEM private key.", pub_bio, priv_bio, pub_pkey, priv_pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        pub_pkey = d2i_PUBKEY_bio(pub_bio, NULL);
        if (!pub_pkey)
            return handleErrors_asymmetric("Failed to read DER private key.", pub_bio, priv_bio, pub_pkey, priv_pkey);
        priv_pkey = d2i_PrivateKey_bio(priv_bio, NULL);
        if (!priv_pkey)
            return handleErrors_asymmetric("Failed to read DER private key.", pub_bio, priv_bio, pub_pkey, priv_pkey);
        break;
    default:return handleErrors_asymmetric("Invalid RSA key format.", pub_bio, priv_bio, pub_pkey, priv_pkey);
    }

    if (!pub_pkey || !priv_pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pub_pkey, priv_pkey);
    BIO_free(pub_bio);
    BIO_free(priv_bio);

    BIGNUM* bn = NULL;

    // 提取 Modulus (n)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(pub_pkey, OSSL_PKEY_PARAM_RSA_N, &bn))
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->MODULUS_LENGTH = BN_num_bytes(bn);
    params->MODULUS = new unsigned char[params->MODULUS_LENGTH];
    BN_bn2bin(bn, params->MODULUS);
    BN_free(bn);

    // 提取 Public Exponent (e)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(pub_pkey, OSSL_PKEY_PARAM_RSA_E, &bn))
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->PUBLIC_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PUBLIC_EXPONENT = new unsigned char[params->PUBLIC_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PUBLIC_EXPONENT);
    BN_free(bn);

    // 提取 Private Exponent (d)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_D, &bn))
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->PRIVATE_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PRIVATE_EXPONENT = new unsigned char[params->PRIVATE_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PRIVATE_EXPONENT);
    BN_free(bn);

    // 提取 Factor1 (p)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn))
        return handleErrors_asymmetric("Get Factor1 (p) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->FACTOR1_LENGTH = BN_num_bytes(bn);
    params->FACTOR1 = new unsigned char[params->FACTOR1_LENGTH];
    BN_bn2bin(bn, params->FACTOR1);
    BN_free(bn);

    // 提取 Factor2 (q)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn))
        return handleErrors_asymmetric("Get Factor2 (q) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->FACTOR2_LENGTH = BN_num_bytes(bn);
    params->FACTOR2 = new unsigned char[params->FACTOR2_LENGTH];
    BN_bn2bin(bn, params->FACTOR2);
    BN_free(bn);

    // 提取 Exponent1 (dmp1)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &bn))
        return handleErrors_asymmetric("Get Exponent1 (dmp1) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->EXPONENT1_LENGTH = BN_num_bytes(bn);
    params->EXPONENT1 = new unsigned char[params->EXPONENT1_LENGTH];
    BN_bn2bin(bn, params->EXPONENT1);
    BN_free(bn);

    // 提取 Exponent2 (dmq1)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &bn))
        return handleErrors_asymmetric("Get Exponent2 (dmq1) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->EXPONENT2_LENGTH = BN_num_bytes(bn);
    params->EXPONENT2 = new unsigned char[params->EXPONENT2_LENGTH];
    BN_bn2bin(bn, params->EXPONENT2);
    BN_free(bn);

    // 提取 Coefficient (iqmp)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &bn))
        return handleErrors_asymmetric("Get Coefficient (iqmp) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->COEFFICIENT_LENGTH = BN_num_bytes(bn);
    params->COEFFICIENT = new unsigned char[params->COEFFICIENT_LENGTH];
    BN_bn2bin(bn, params->COEFFICIENT);
    BN_free(bn);

    // 提取 Bits (bits)
    bn = NULL;
    if (1 != EVP_PKEY_get_bn_param(priv_pkey, OSSL_PKEY_PARAM_RSA_BITS, &bn))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pub_pkey, priv_pkey);
    params->BITS_LENGTH = BN_num_bytes(bn);
    params->BITS = new unsigned char[params->BITS_LENGTH];
    BN_bn2bin(bn, params->BITS);
    BN_free(bn);

    EVP_PKEY_free(pub_pkey);
    EVP_PKEY_free(priv_pkey);

    return 0;
}

int ExportRsaKeysFromParameters(EXPORT_RSA_PARAMTERS* params) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create EVP_PKEY context.", ctx);

    EVP_PKEY* pkey = NULL;
    if (1 != EVP_PKEY_fromdata_init(ctx)) {
        EVP_PKEY_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to initialize fromdata.", NULL, NULL, pkey);
    }

    OSSL_PARAM paramters[] = {
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, params->MODULUS, params->MODULUS_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, params->PUBLIC_EXPONENT, params->PUBLIC_EXPONENT_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, params->PRIVATE_EXPONENT, params->PRIVATE_EXPONENT_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, params->FACTOR1, params->FACTOR1_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, params->FACTOR2, params->FACTOR2_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, params->EXPONENT1, params->EXPONENT1_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, params->EXPONENT2, params->EXPONENT2_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, params->COEFFICIENT, params->COEFFICIENT_LENGTH),
        OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_BITS, params->BITS, params->BITS_LENGTH),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, paramters) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to generate RSA key.", NULL, NULL, pkey);
    }

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs.", pub_bio, priv_bio, pkey);

    switch (params->FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (PEM_write_bio_PUBKEY(pub_bio, pkey) <= 0 ||
            PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
            return handleErrors_asymmetric("Failed to write keys in PEM format.", pub_bio, priv_bio, pkey);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (i2d_PUBKEY_bio(pub_bio, pkey) <= 0 ||
            i2d_PrivateKey_bio(priv_bio, pkey) <= 0) {
            return handleErrors_asymmetric("Failed to write keys in DER format.", pub_bio, priv_bio, pkey);
        }
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    params->PUBLIC_KEY_LENGTH = BIO_pending(pub_bio);
    params->PRIVATE_KEY_LENGTH = BIO_pending(priv_bio);

    params->PUBLIC_KEY = new unsigned char[params->PUBLIC_KEY_LENGTH];
    params->PRIVATE_KEY = new unsigned char[params->PRIVATE_KEY_LENGTH];

    BIO_read(pub_bio, params->PUBLIC_KEY, params->PUBLIC_KEY_LENGTH);
    BIO_read(priv_bio, params->PRIVATE_KEY, params->PRIVATE_KEY_LENGTH);

    BIO_free_all(pub_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);

    return 0;
}