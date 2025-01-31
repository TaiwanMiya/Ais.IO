#include "pch.h"
#include "EccIO.h"

int EccGetParametersLength(ECC_PARAMETERS* params) {
    ERR_clear_error();

    if (params->CURVE_NID <= 0)
        params->CURVE_NID = ECC_CURVE::ECC_PRIME_256_V1;

    const EC_GROUP* group = EC_GROUP_new_by_curve_name(params->CURVE_NID);
    if (!group)
        return handleErrors_asymmetric("Invalid NID or unsupported curve.", NULL);
    int degree = EC_GROUP_get_degree(group);
    if (degree <= 0)
        return handleErrors_asymmetric("Unable to obtain the number of curve digits.", NULL);

    size_t key_length_bytes = (degree + 7) / 8;

    params->EXP_LENGTH = key_length_bytes;
    params->X_LENGTH = key_length_bytes;
    params->Y_LENGTH = key_length_bytes;

    EC_GROUP_free((EC_GROUP*)group);
    return 0;
}

int EccGetKeyLength(ECC_KEY_PAIR* params) {
    ERR_clear_error();
    RAND_poll();

    BIO* pub_bio = BIO_new_mem_buf(params->PUBLIC_KEY, static_cast<int>(params->PUBLIC_KEY_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);

    EVP_PKEY* pkey = nullptr;

    switch (params->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PUBKEY(pub_bio, &pkey, NULL, NULL);
        if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
        break;

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(pub_bio, &pkey);
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;

    default:
        return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_EC)
        return handleErrors_asymmetric("Key is not an ECC key.", pub_bio, priv_bio, pkey);

    char curve_name[128] = { 0 };
    size_t curve_name_len = sizeof(curve_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_name_len, &curve_name_len) <= 0)
        return handleErrors_asymmetric("Failed to retrieve ECC curve name.", pub_bio, priv_bio, pkey);
    int curve_nid = OBJ_sn2nid(curve_name);
    params->CURVE_NID = static_cast<ECC_CURVE>(curve_nid);

    BIO_free(pub_bio);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int EccGenerateParameters(ECC_PARAMETERS* params) {
    ERR_clear_error();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to initialize ECC gen context.", NULL);

    if (1 != EVP_PKEY_keygen_init(ctx))
        return handleErrors_asymmetric("Failed to init key gen.", ctx);

    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, params->CURVE_NID))
        return handleErrors_asymmetric("Failed to set ECC param curve.", ctx);

    EVP_PKEY* pkey = nullptr;
    if (1 != EVP_PKEY_keygen(ctx, &pkey))
        return handleErrors_asymmetric("Failed to generate ECC key.", ctx);
    EVP_PKEY_CTX_free(ctx);

    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", ctx, NULL, NULL, pkey, NULL);

    OSSL_PARAM* public_key_param = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PUB_KEY);
    OSSL_PARAM* private_key_param = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PRIV_KEY);

    BIGNUM* pub = BN_new();
    BIGNUM* exp = BN_new();

    size_t pub_len = 0;

    if (!OSSL_PARAM_get_octet_string(public_key_param, NULL, 0, &pub_len))
        return handleErrors_asymmetric("Get Public Key Coordinate parameters failed.", ctx, NULL, NULL, pkey, NULL);

    unsigned char* pub_key = new unsigned char[pub_len];
    void* pub_key_ptr = static_cast<void*>(pub_key);
    if (!OSSL_PARAM_get_octet_string(public_key_param, &pub_key_ptr, pub_len, &pub_len))
        return handleErrors_asymmetric("Get Public Key Coordinate parameters failed.", ctx, NULL, NULL, pkey, NULL);

    params->X_LENGTH = (pub_len - 1) / 2;
    params->Y_LENGTH = (pub_len - 1) / 2;

    std::memcpy(params->X, pub_key + 1, params->X_LENGTH);
    std::memcpy(params->Y, pub_key + 1 + params->X_LENGTH, params->Y_LENGTH);

    if (private_key_param && OSSL_PARAM_get_BN(private_key_param, &exp)) {
        params->EXP_LENGTH = BN_num_bytes(exp);
        BN_bn2bin(exp, params->EXP);
        BN_free(exp);
    }
    else
        return handleErrors_asymmetric("Get Private Exponent (exp) failed.", ctx, NULL, NULL, pkey, NULL);

    return 0;
};

int EccGenerateKeys(ECC_KEY_PAIR* generate) {
    ERR_clear_error();
    RAND_poll();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create EVP_PKEY context.", ctx);

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return handleErrors_asymmetric("Failed to initialize ECC key generation.", ctx);

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, generate->CURVE_NID) <= 0)
        return handleErrors_asymmetric("Failed to set ECC curve parameters.", ctx);

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        return handleErrors_asymmetric("ECC key pair generation failed.", ctx);

    EVP_PKEY_CTX_free(ctx);

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIO buffers.", pub_bio, priv_bio, pkey);

    const EVP_CIPHER* cipher = GetSymmetryCrypter(generate->PEM_CIPHER, generate->PEM_CIPHER_SIZE, generate->PEM_CIPHER_SEGMENT);

    switch (generate->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1)
            return handleErrors_asymmetric("Failed to write public key in PEM format.", pub_bio, priv_bio, pkey);

        if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
            if (PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL) != 1)
                return handleErrors_asymmetric("Failed to write private key in PEM format.", pub_bio, priv_bio, pkey);
        }
        else {
            if (PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL) != 1)
                return handleErrors_asymmetric("Failed to encrypt private key in PEM format.", pub_bio, priv_bio, pkey);
        }
        break;

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (i2d_PUBKEY_bio(pub_bio, pkey) != 1)
            return handleErrors_asymmetric("Failed to write public key in DER format.", pub_bio, priv_bio, pkey);
        if (i2d_PrivateKey_bio(priv_bio, pkey) != 1)
            return handleErrors_asymmetric("Failed to write private key in DER format.", pub_bio, priv_bio, pkey);
        break;

    default:
        return handleErrors_asymmetric("Invalid key format.", pub_bio, priv_bio, pkey);
    }

    size_t pub_len = BIO_pending(pub_bio);
    size_t priv_len = BIO_pending(priv_bio);

    if (generate->PUBLIC_KEY == nullptr || generate->PRIVATE_KEY == nullptr ||
        generate->PUBLIC_KEY_LENGTH < pub_len || generate->PRIVATE_KEY_LENGTH < priv_len) {
        generate->PUBLIC_KEY = new unsigned char[pub_len];
        generate->PRIVATE_KEY = new unsigned char[priv_len];
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

int EccExportParameters(ECC_EXPORT* params) {
    ERR_clear_error();
    RAND_poll();

    BIO* pub_bio = BIO_new_mem_buf(params->PUBLIC_KEY, static_cast<int>(params->PUBLIC_KEY_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);

    EVP_PKEY* pkey = nullptr;

    switch (params->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PUBKEY(pub_bio, &pkey, NULL, NULL);
        if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
        break;

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(pub_bio, &pkey);
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;

    default:
        return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);

    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", NULL, NULL, NULL, pkey, NULL);

    OSSL_PARAM* param_x = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PRIV_KEY);
    OSSL_PARAM* param_pub = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PUB_KEY);

    BIGNUM* x = NULL;
    size_t pub_len = 0;

    if (param_x && OSSL_PARAM_get_BN(param_x, &x)) {
        params->EXP_LENGTH = BN_num_bytes(x);
        params->EXP = new unsigned char[params->EXP_LENGTH];
        BN_bn2bin(x, params->EXP);
        BN_free(x);
    }
    else {
        handleErrors_asymmetric("Get Private Exponent (exp) failed.", NULL);
        memset(params->EXP, 0, params->EXP_LENGTH);
        params->EXP_LENGTH = 0;
    }

    if (!OSSL_PARAM_get_octet_string(param_pub, nullptr, 0, &pub_len))
        return handleErrors_asymmetric("Get Public Key Coordinate failed.", NULL, NULL, NULL, pkey, NULL);

    unsigned char* pub_key = new unsigned char[pub_len];
    void* pub_key_ptr = static_cast<void*>(pub_key);

    if (!OSSL_PARAM_get_octet_string(param_pub, &pub_key_ptr, pub_len, &pub_len))
        return handleErrors_asymmetric("Get Public Key Coordinate failed.", NULL, NULL, NULL, pkey, NULL);

    params->X_LENGTH = (pub_len - 1) / 2;
    params->Y_LENGTH = (pub_len - 1) / 2;

    params->X = new unsigned char[params->X_LENGTH];
    params->Y = new unsigned char[params->Y_LENGTH];

    std::memcpy(params->X, pub_key + 1, params->X_LENGTH);
    std::memcpy(params->Y, pub_key + 1 + params->X_LENGTH, params->Y_LENGTH);

    char curve_name[128] = { 0 };
    size_t curve_name_len = sizeof(curve_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_name_len, &curve_name_len) <= 0)
        return handleErrors_asymmetric("Failed to retrieve ECC curve name.", pub_bio, priv_bio, pkey);
    int curve_nid = OBJ_sn2nid(curve_name);
    params->CURVE_NID = static_cast<ECC_CURVE>(curve_nid);

    EVP_PKEY_free(pkey);

    return 0;
}

int EccExportKeys(ECC_EXPORT* params) {
    ERR_clear_error();

    size_t pub_key_len = 1 + params->X_LENGTH + params->Y_LENGTH;
    unsigned char* pub_key = new unsigned char[pub_key_len];
    pub_key[0] = 0x04;
    std::memcpy(pub_key + 1, params->X, params->X_LENGTH);
    std::memcpy(pub_key + 1 + params->X_LENGTH, params->Y, params->Y_LENGTH);

    const BIGNUM* bn_exp = BN_bin2bn(params->EXP, params->EXP_LENGTH, NULL);
    if (!bn_exp)
        return handleErrors_asymmetric("Invalid Private Exponent (exp) format.", NULL);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld)
        return handleErrors_asymmetric("Failed to create OSSL_PARAM_BLD.", NULL);

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_exp) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_key, pub_key_len) ||
        !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, OBJ_nid2sn(params->CURVE_NID), 0)) {
        OSSL_PARAM_BLD_free(bld);
        return handleErrors_asymmetric("Failed to add parameters to OSSL_PARAM_BLD.", NULL);
    }
    OSSL_PARAM* paramters = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!paramters)
        return handleErrors_asymmetric("Failed to build OSSL_PARAM from OSSL_PARAM_BLD.", NULL);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY* pkey = NULL;

    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0 || EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, paramters) <= 0) {
        OSSL_PARAM_free(paramters);
        return handleErrors_asymmetric("Failed to generate ECC key.", ctx, NULL, NULL, pkey, NULL);
    }

    OSSL_PARAM_free(paramters);

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs.", pub_bio, priv_bio, pkey);

    switch (params->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_PUBKEY(pub_bio, pkey) || 1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
            return handleErrors_asymmetric("Failed to write keys in PEM format.", pub_bio, priv_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PUBKEY_bio(pub_bio, pkey) || 1 != i2d_PrivateKey_bio(priv_bio, pkey))
            return handleErrors_asymmetric("Failed to write keys in DER format.", pub_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    size_t pub_len = BIO_pending(pub_bio);
    size_t priv_len = BIO_pending(priv_bio);
    if (params->PUBLIC_KEY == nullptr || params->PRIVATE_KEY == nullptr || params->PUBLIC_KEY_LENGTH < pub_len || params->PRIVATE_KEY_LENGTH < priv_len) {
        params->PUBLIC_KEY = new unsigned char[pub_len];
        params->PRIVATE_KEY = new unsigned char[priv_len];
    }

    BIO_read(pub_bio, params->PUBLIC_KEY, pub_len);
    BIO_read(priv_bio, params->PRIVATE_KEY, priv_len);

    params->PUBLIC_KEY_LENGTH = pub_len;
    params->PRIVATE_KEY_LENGTH = priv_len;

    BIO_free_all(pub_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int EccExtractPublicKey(ECC_EXTRACT_PUBLIC_KEY* params) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!priv_bio)
        return handleErrors_asymmetric("Failed to create BIO for private key.", NULL);

    switch (params->PRIVATE_KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
        break;

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;

    default:
        BIO_free(priv_bio);
        return handleErrors_asymmetric("Invalid private key format.", NULL);
    }

    BIO_free(priv_bio);
    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", NULL);

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return handleErrors_asymmetric("Key is not an ECC key.", NULL);
    }

    BIO* pub_bio = BIO_new(BIO_s_mem());
    if (!pub_bio) {
        EVP_PKEY_free(pkey);
        return handleErrors_asymmetric("Failed to create BIO for public key.", NULL);
    }

    switch (params->PUBLIC_KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (PEM_write_bio_PUBKEY(pub_bio, pkey) != 1) {
            BIO_free(pub_bio);
            EVP_PKEY_free(pkey);
            return handleErrors_asymmetric("Failed to write public key in PEM format.", NULL);
        }
        break;

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (i2d_PUBKEY_bio(pub_bio, pkey) != 1) {
            BIO_free(pub_bio);
            EVP_PKEY_free(pkey);
            return handleErrors_asymmetric("Failed to write public key in DER format.", NULL);
        }
        break;

    default:
        BIO_free(pub_bio);
        EVP_PKEY_free(pkey);
        return handleErrors_asymmetric("Invalid public key format.", NULL);
    }

    size_t pub_len = BIO_pending(pub_bio);
    if (params->PUBLIC_KEY == nullptr || params->PUBLIC_KEY_LENGTH < pub_len) {
        params->PUBLIC_KEY = new unsigned char[pub_len];
    }

    BIO_read(pub_bio, params->PUBLIC_KEY, pub_len);
    params->PUBLIC_KEY_LENGTH = pub_len;

    BIO_free(pub_bio);
    EVP_PKEY_free(pkey);

    return 0;
}

int EccCheckPublicKey(ECC_CHECK_PUBLIC_KEY* check) {
    ERR_clear_error();
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(check->PUBLIC_KEY, static_cast<int>(check->PUBLIC_KEY_LENGTH));

    switch (check->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(bio, &pkey);
        break;
    default:
        return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public key.", bio, NULL, pkey);

    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_EC)
        return handleErrors_asymmetric("Key is not an ECC key.", bio, NULL, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);

    char curve_name[128] = { 0 };
    size_t curve_name_len = sizeof(curve_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_name_len, &curve_name_len) <= 0)
        return handleErrors_asymmetric("Failed to retrieve ECC curve name.", bio, NULL, pkey);
    int curve_nid = OBJ_sn2nid(curve_name);
    check->CURVE_NID = static_cast<ECC_CURVE>(curve_nid);

    check->IS_KEY_OK = EVP_PKEY_public_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int EccCheckPrivateKey(ECC_CHECK_PRIVATE_KEY* check) {
    ERR_clear_error();
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(check->PRIVATE_KEY, static_cast<int>(check->PRIVATE_KEY_LENGTH));

    switch (check->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (check->PEM_PASSWORD == NULL || check->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(check->PEM_PASSWORD)));
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PrivateKey_bio(bio, &pkey);
        break;
    default:
        return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", bio, NULL, pkey);

    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_EC)
        return handleErrors_asymmetric("Key is not an ECC key.", bio, NULL, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);

    char curve_name[128] = { 0 };
    size_t curve_name_len = sizeof(curve_name);
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name, curve_name_len, &curve_name_len) <= 0)
        return handleErrors_asymmetric("Failed to retrieve ECC curve name.", bio, NULL, pkey);
    int curve_nid = OBJ_sn2nid(curve_name);
    check->CURVE_NID = static_cast<ECC_CURVE>(curve_nid);

    check->IS_KEY_OK = EVP_PKEY_private_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}
