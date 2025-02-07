#include "pch.h"
#include "DsaIO.h"

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1) / (y))

int DsaGetParametersLength(DSA_PARAMETERS* params) {
    size_t q_bit_length = (params->KEY_LENGTH <= 1024) ? 160 : 256;
    params->P_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);
    params->Q_LENGTH = 28;
    params->G_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);
    params->X_LENGTH = params->Q_LENGTH;
    params->Y_LENGTH = params->P_LENGTH;
    return 0;
}

int DsaGetKeyLength(DSA_KEY_PAIR* params) {
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

    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER: {
        d2i_PUBKEY_bio(pub_bio, &pkey);
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;
    }
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_DSA)
        return handleErrors_asymmetric("Key is not a DSA key.", pub_bio, priv_bio, pkey);

    BIGNUM* p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", pub_bio, priv_bio, pkey);

    params->KEY_LENGTH = BN_num_bits(p);

    BIO_free(pub_bio);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int DsaGenerateParameters(DSA_PARAMETERS* params) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx_param = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx_param)
        return handleErrors_asymmetric("Failed to initialize DSA param gen context.", NULL);

    if (1 != EVP_PKEY_paramgen_init(ctx_param))
        return handleErrors_asymmetric("Failed to init param gen.", ctx_param);

    if (1 != EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx_param, params->KEY_LENGTH))
        return handleErrors_asymmetric("Failed to set key length.", ctx_param);

    EVP_PKEY* pkey_param = NULL;
    if (1 != EVP_PKEY_paramgen(ctx_param, &pkey_param))
        return handleErrors_asymmetric("Failed to generate DSA param.", ctx_param);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_param, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to initialize DSA key gen context.", NULL);

    if (1 != EVP_PKEY_keygen_init(ctx))
        return handleErrors_asymmetric("Failed to init key gen.", ctx_param);

    EVP_PKEY* pkey = NULL;
    if (1 != EVP_PKEY_keygen(ctx, &pkey))
        return handleErrors_asymmetric("Failed to generate DSA key.", ctx_param);

    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey_param, EVP_PKEY_KEY_PARAMETERS, &paramters))
        return handleErrors_asymmetric("Get Pkey param to data failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    OSSL_PARAM* param_y = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PUB_KEY);
    OSSL_PARAM* param_x = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PRIV_KEY);
    OSSL_PARAM* param_p = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_P);
    OSSL_PARAM* param_q = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_Q);
    OSSL_PARAM* param_g = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_G);

    BIGNUM* y = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* g = BN_new();

    if (param_y && OSSL_PARAM_get_BN(param_y, &y)) {
        params->Y_LENGTH = BN_num_bytes(y);
        BN_bn2bin(y, params->Y);
        BN_free(y);
    }
    else
        return handleErrors_asymmetric("Get Public Key (y) failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    if (param_x && OSSL_PARAM_get_BN(param_x, &x)) {
        params->X_LENGTH = BN_num_bytes(x);
        BN_bn2bin(x, params->X);
        BN_free(x);
    }
    else
        return handleErrors_asymmetric("Get Private Key (x) failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        params->P_LENGTH = BN_num_bytes(p);
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else
        return handleErrors_asymmetric("Get Prime Modulus (p) failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        params->Q_LENGTH = BN_num_bytes(q);
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else
        return handleErrors_asymmetric("Get Subprime (q) failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    if (param_g && OSSL_PARAM_get_BN(param_g, &g)) {
        params->G_LENGTH = BN_num_bytes(g);
        BN_bn2bin(g, params->G);
        BN_free(g);
    }
    else
        return handleErrors_asymmetric("Get Generator (g) failed.", ctx_param, NULL, NULL, pkey_param, NULL);

    EVP_PKEY_free(pkey_param);
    OSSL_PARAM_free(paramters);
    return 0;
}

int DsaGenerateKeys(DSA_KEY_PAIR* generate) {
    ERR_clear_error();
    RAND_poll();

    EVP_PKEY_CTX* ctx_param = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx_param)
        return handleErrors_asymmetric("Failed to initialize DSA param gen context.", NULL);

    if (1 != EVP_PKEY_paramgen_init(ctx_param))
        return handleErrors_asymmetric("Failed to init param gen.", ctx_param);

    if (1 != EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx_param, generate->KEY_LENGTH))
        return handleErrors_asymmetric("Failed to set key length.", ctx_param);

    EVP_PKEY* pkey_param = NULL;
    if (1 != EVP_PKEY_paramgen(ctx_param, &pkey_param))
        return handleErrors_asymmetric("Failed to generate DSA param.", ctx_param);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_param, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to initialize DSA key gen context.", NULL);

    if (1 != EVP_PKEY_keygen_init(ctx))
        return handleErrors_asymmetric("Failed to init key gen.", ctx_param);

    EVP_PKEY* pkey = NULL;
    if (1 != EVP_PKEY_keygen(ctx, &pkey))
        return handleErrors_asymmetric("Failed to generate DSA key.", ctx_param);

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER* cipher = GetSymmetryCrypter(generate->PEM_CIPHER, generate->PEM_CIPHER_SIZE, generate->PEM_CIPHER_SEGMENT);

    switch (generate->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_PUBKEY(pub_bio, pkey))
            return handleErrors_asymmetric("Unable to write public key in PKCS#8 PEM format to memory.", pub_bio, priv_bio, pkey);

        if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", pub_bio, priv_bio, pkey);
        }
        else {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", pub_bio, priv_bio, pkey);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PUBKEY_bio(pub_bio, pkey))
            return handleErrors_asymmetric("Unable to write public key in PKCS#8 DER format to memory.", pub_bio, priv_bio, pkey);
        if (1 != i2d_PrivateKey_bio(priv_bio, pkey))
            return handleErrors_asymmetric("Unable to write private key in PKCS#8 DER format to memory.", pub_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    size_t pub_len = BIO_pending(pub_bio);
    size_t priv_len = BIO_pending(priv_bio);
    if (generate->PUBLIC_KEY == nullptr || generate->PRIVATE_KEY == nullptr || generate->PUBLIC_KEY_LENGTH < pub_len || generate->PRIVATE_KEY_LENGTH < priv_len) {
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

int DsaExportParameters(DSA_EXPORT* params) {
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
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);

    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", pub_bio, priv_bio, pkey);

    OSSL_PARAM* param_y = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PUB_KEY);
    OSSL_PARAM* param_x = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_PRIV_KEY);
    OSSL_PARAM* param_p = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_P);
    OSSL_PARAM* param_q = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_Q);
    OSSL_PARAM* param_g = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_FFC_G);

    BIGNUM* y = NULL;
    BIGNUM* x = NULL;
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* g = NULL;

    if (param_y && OSSL_PARAM_get_BN(param_y, &y)) {
        params->Y_LENGTH = BN_num_bytes(y);
        BN_bn2bin(y, params->Y);
        BN_free(y);
    }
    else {
        handleErrors_asymmetric("Get Public Key (y) failed.", NULL);
        memset(params->Y, 0, params->Y_LENGTH);
        params->Y_LENGTH = 0;
    }

    if (param_x && OSSL_PARAM_get_BN(param_x, &x)) {
        params->X_LENGTH = BN_num_bytes(x);
        BN_bn2bin(x, params->X);
        BN_free(x);
    }
    else {
        handleErrors_asymmetric("Get Private Key (x) failed.", NULL);
        memset(params->X, 0, params->X_LENGTH);
        params->X_LENGTH = 0;
    }

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        params->P_LENGTH = BN_num_bytes(p);
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else {
        handleErrors_asymmetric("Get Prime Modulus (p) failed.", NULL);
        memset(params->P, 0, params->P_LENGTH);
        params->P_LENGTH = 0;
    }

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        params->Q_LENGTH = BN_num_bytes(q);
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else {
        handleErrors_asymmetric("Get Subprime (q) failed.", NULL);
        memset(params->Q, 0, params->Q_LENGTH);
        params->Q_LENGTH = 0;
    }

    if (param_g && OSSL_PARAM_get_BN(param_g, &g)) {
        params->G_LENGTH = BN_num_bytes(g);
        BN_bn2bin(g, params->G);
        BN_free(g);
    }
    else {
        handleErrors_asymmetric("Get Generator (g) failed.", NULL);
        memset(params->G, 0, params->G_LENGTH);
        params->G_LENGTH = 0;
    }

    p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", NULL, NULL, NULL, pkey, NULL);

    params->KEY_LENGTH = BN_num_bits(p);

    EVP_PKEY_free(pkey);

    return 0;
}

int DsaExportKeys(DSA_EXPORT* params) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create EVP_PKEY context.", ctx);

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (1 != EVP_PKEY_fromdata_init(ctx))
        return handleErrors_asymmetric("Failed to initialize fromdata.", ctx, NULL, NULL, pkey, NULL);

    const BIGNUM* bn_y = BN_bin2bn(params->Y, params->Y_LENGTH, NULL);
    if (!bn_y)
        return handleErrors_asymmetric("Invalid Public Key (y) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_x = BN_bin2bn(params->X, params->X_LENGTH, NULL);
    if (!bn_x)
        return handleErrors_asymmetric("Invalid Private Key (x) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_p = BN_bin2bn(params->P, params->P_LENGTH, NULL);
    if (!bn_p)
        return handleErrors_asymmetric("Invalid Prime Modulus (p) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_q = BN_bin2bn(params->Q, params->Q_LENGTH, NULL);
    if (!bn_q)
        return handleErrors_asymmetric("Invalid Subprime (q) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_g = BN_bin2bn(params->G, params->G_LENGTH, NULL);
    if (!bn_g)
        return handleErrors_asymmetric("Invalid Generator (g) format.", ctx, NULL, NULL, pkey, NULL);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld)
        return handleErrors_asymmetric("Failed to create OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn_y) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_x) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, bn_q) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, bn_g)) {
        OSSL_PARAM_BLD_free(bld);
        return handleErrors_asymmetric("Failed to add parameters to OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);
    }

    OSSL_PARAM* paramters = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!paramters)
        return handleErrors_asymmetric("Failed to build OSSL_PARAM from OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);

    if (1 != EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, paramters))
        return handleErrors_asymmetric("Failed to generate DSA key.", ctx, NULL, NULL, pkey, NULL);

    BIGNUM* p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", ctx, NULL, NULL, pkey, NULL);

    params->KEY_LENGTH = BN_num_bits(p);

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

int DsaExtractPublicKey(DSA_EXTRACT_PUBLIC_KEY* params) {
    ERR_clear_error();
    RAND_poll();

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);

    EVP_PKEY* pkey = nullptr;
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
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", pub_bio, priv_bio, pkey);

    switch (params->PUBLIC_KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_PUBKEY(pub_bio, pkey))
            return handleErrors_asymmetric("Failed to write public key in PEM format.", pub_bio, priv_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PUBKEY_bio(pub_bio, pkey))
            return handleErrors_asymmetric("Failed to write public key in DER format.", pub_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    size_t pub_len = BIO_pending(pub_bio);

    if (params->PUBLIC_KEY == nullptr || params->PUBLIC_KEY_LENGTH < pub_len)
        params->PUBLIC_KEY = new unsigned char[pub_len];

    BIO_read(pub_bio, params->PUBLIC_KEY, pub_len);

    params->PUBLIC_KEY_LENGTH = pub_len;

    BIO_free(pub_bio);
    BIO_free(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int DsaExtractParametersByKeys(DSA_EXTRACT_PARAMETERS_KEYS* params) {
    ERR_clear_error();

    BIO* pub_bio = BIO_new_mem_buf(params->PUBLIC_KEY, static_cast<int>(params->PUBLIC_KEY_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    BIO* param_bio = BIO_new(BIO_s_mem());

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
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);

    switch (params->PARAMETERS_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_Parameters(param_bio, pkey))
            return handleErrors_asymmetric("Failed to write parameters in PEM format.", pub_bio, priv_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_KeyParams_bio(param_bio, pkey))
            return handleErrors_asymmetric("Failed to write parameters in DER format.", pub_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", pub_bio, priv_bio, pkey);
    }

    size_t param_len = BIO_pending(param_bio);

    if (params->PARAMETERS == nullptr || params->PARAMETERS_LENGTH < param_len)
        params->PARAMETERS = new unsigned char[param_len];

    BIO_read(param_bio, params->PARAMETERS, param_len);

    params->PARAMETERS_LENGTH = param_len;

    BIO_free(param_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int DsaExtractKeysByParameters(DSA_EXTRACT_KEYS_PARAMETERS* params) {
    ERR_clear_error();

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    BIO* param_bio = BIO_new_mem_buf(params->PARAMETERS, static_cast<int>(params->PARAMETERS_LENGTH));

    if (!param_bio)
        return handleErrors_asymmetric("Failed to create BIOs for param data.", param_bio, NULL, NULL);

    EVP_PKEY* pkey = nullptr;
    switch (params->PARAMETERS_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_Parameters(param_bio, &pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_KeyParams_bio(EVP_PKEY_DSA, &pkey, param_bio);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", param_bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse parameters.", param_bio, NULL, pkey);

    BIO_free(param_bio);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create EVP_PKEY_CTX for key generation.", NULL);

    EVP_PKEY* keypair = NULL;
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return handleErrors_asymmetric("Failed to initialize key generation.", ctx);

    if (EVP_PKEY_keygen(ctx, &keypair) <= 0)
        return handleErrors_asymmetric("Failed to generate DSA key pair.", ctx);

    EVP_PKEY_free(pkey);
    pkey = keypair;

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
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int DsaCheckPublicKey(DSA_CHECK_PUBLIC_KEY* check) {
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
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public key.", bio, NULL, pkey);

    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_DSA)
        return handleErrors_asymmetric("Key is not a DSA key.", bio, NULL, pkey);

    BIGNUM* p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", bio, NULL, pkey);
    
    check->KEY_LENGTH = BN_num_bits(p);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_public_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int DsaCheckPrivateKey(DSA_CHECK_PRIVATE_KEY* check) {
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
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public key.", bio, NULL, pkey);

    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_DSA)
        return handleErrors_asymmetric("Key is not a DSA key.", bio, NULL, pkey);

    BIGNUM* p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", bio, NULL, pkey);

    check->KEY_LENGTH = BN_num_bits(p);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_private_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int DsaCheckParameters(DSA_CHECK_PARAMETERS* check) {
    ERR_clear_error();
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(check->PARAMETERS, static_cast<int>(check->PARAMETERS_LENGTH));

    switch (check->PARAM_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_Parameters(bio, &pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_KeyParams_bio(EVP_PKEY_DSA, &pkey, bio);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse parameters.", bio, NULL, pkey);

    BIGNUM* p = NULL;
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &p))
        return handleErrors_asymmetric("Failed to retrieve P parameter.", bio, NULL, pkey);

    check->KEY_LENGTH = BN_num_bits(p);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_param_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int DsaSigned(DSA_SIGNED* sign) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(sign->PRIVATE_KEY, static_cast<int>(sign->PRIVATE_KEY_LENGTH));
    if (!bio)
        return handleErrors_asymmetric("Failed to create BIO for private key.", NULL);

    switch (sign->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (sign->PEM_PASSWORD == NULL || sign->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(sign->PEM_PASSWORD)));
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PrivateKey_bio(bio, &pkey);
        break;
    default:return handleErrors_asymmetric("Invalid private key format.", bio, NULL, pkey);
    }

    BIO_free(bio);
    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", NULL);

    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_DSA)
        return handleErrors_asymmetric("Key is not a DSA key.", bio, NULL, pkey);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return handleErrors_asymmetric("Failed to create digest context.", bio, NULL, pkey);

    const EVP_MD* md = GetHashCrypter(sign->HASH_ALGORITHM);
    if (1 != EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)) {
        EVP_MD_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to initialize signing.", bio, NULL, pkey);
    }

    size_t siglen = 0;
    if (1 != EVP_DigestSign(ctx, NULL, &siglen, sign->DATA, sign->DATA_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to determine signature size.", bio, NULL, pkey);
    }

    if (1 != EVP_DigestSign(ctx, sign->SIGNATURE, &siglen, sign->DATA, sign->DATA_LENGTH)) {
        EVP_MD_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to generate signature.", bio, NULL, pkey);
    }

    sign->SIGNATURE_LENGTH = siglen;

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}

int DsaVerify(DSA_VERIFY* verify) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(verify->PUBLIC_KEY, static_cast<int>(verify->PUBLIC_KEY_LENGTH));

    switch (verify->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(bio, &pkey);
        break;
    default:return handleErrors_asymmetric("Invalid public key format.", bio, NULL, pkey);
    }

    BIO_free(bio);
    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public key.", NULL, bio, NULL);

    int type = EVP_PKEY_base_id(pkey);
    if (type != EVP_PKEY_DSA)
        return handleErrors_asymmetric("Key is not a DSA key.", bio, NULL, pkey);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        return handleErrors_asymmetric("Failed to create digest context.", bio, NULL, pkey);

    const EVP_MD* md = GetHashCrypter(verify->HASH_ALGORITHM);
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        return handleErrors_asymmetric("Failed to initialize verification.", bio, NULL, pkey);
    }

    int result = EVP_DigestVerify(ctx, verify->SIGNATURE, verify->SIGNATURE_LENGTH, verify->DATA, verify->DATA_LENGTH);
    verify->IS_VALID = result == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}
