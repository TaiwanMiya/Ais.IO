#include "pch.h"
#include "RsaIO.h"

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1) / (y))

int RsaGetParametersLength(RSA_PARAMETERS* params) {
    params->N_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);
    params->E_LENGTH = 3;
    params->D_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);
    params->P_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 16);
    params->Q_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 16);
    params->DP_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 16);
    params->DQ_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 16);
    params->QI_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 16);
    return 0;
}

int RsaGetKeyLength(RSA_KEY_PAIR* params) {
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
        PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(pub_bio, &pkey);
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;
    default:
        return handleErrors_asymmetric("Invalid RSA key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &params->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pkey);

    EVP_PKEY_free(pkey);
    return 0;
}

int RsaGenerateParameters(RSA_PARAMETERS* params) {
    ERR_clear_error();
    EVP_PKEY* pkey = EVP_RSA_gen(params->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA key generate Pair failed.", NULL);
    
    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", NULL, NULL, pkey);

    OSSL_PARAM* param_n = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_N);
    OSSL_PARAM* param_e = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_E);
    OSSL_PARAM* param_d = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_D);
    OSSL_PARAM* param_p = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_FACTOR1);
    OSSL_PARAM* param_q = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_FACTOR2);
    OSSL_PARAM* param_dp = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_EXPONENT1);
    OSSL_PARAM* param_dq = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_EXPONENT2);
    OSSL_PARAM* param_qi = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    BIGNUM* n = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* d = BN_new();
    BIGNUM* p = BN_new();
    BIGNUM* q = BN_new();
    BIGNUM* dp = BN_new();
    BIGNUM* dq = BN_new();
    BIGNUM* qi = BN_new();

    if (param_n && OSSL_PARAM_get_BN(param_n, &n)) {
        BN_bn2bin(n, params->N);
        BN_free(n);
    }
    else
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL);

    if (param_e && OSSL_PARAM_get_BN(param_e, &e)) {
        BN_bn2bin(e, params->E);
        BN_free(e);
    }
    else
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL);

    if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
        BN_bn2bin(d, params->D);
        BN_free(d);
    }
    else
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL);

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else
        return handleErrors_asymmetric("Get First Prime Factor (p) failed.", NULL);

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else
        return handleErrors_asymmetric("Get Second Prime Factor (q) failed.", NULL);

    if (param_dp && OSSL_PARAM_get_BN(param_dp, &dp)) {
        BN_bn2bin(dp, params->DP);
        BN_free(dp);
    }
    else
        return handleErrors_asymmetric("Get First CRT Exponent (dp) failed.", NULL);

    if (param_dq && OSSL_PARAM_get_BN(param_dq, &dq)) {
        BN_bn2bin(dq, params->DQ);
        BN_free(dq);
    }
    else
        return handleErrors_asymmetric("Get Second CRT Exponent (dq) failed.", NULL);

    if (param_qi && OSSL_PARAM_get_BN(param_qi, &qi)) {
        BN_bn2bin(qi, params->QI);
        BN_free(qi);
    }
    else
        return handleErrors_asymmetric("Get CRT Coefficient (qi) failed.", NULL);

    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(paramters);
    return 0;
}

int RsaGenerateKeys(RSA_KEY_PAIR* generate) {
    ERR_clear_error();
    RAND_poll();

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return handleErrors_asymmetric("An error occurred during ctx generation.", ctx);

    if (1 != EVP_PKEY_keygen_init(ctx))
        return handleErrors_asymmetric("Initial RSA key generation failed.", ctx);

    if (1 != EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, generate->KEY_LENGTH))
        return handleErrors_asymmetric("Set RSA key generate bits failed.", ctx);

    EVP_PKEY* pkey = EVP_RSA_gen(generate->KEY_LENGTH);

    if (!pkey)
        return handleErrors_asymmetric("RSA key generate Pair failed.", ctx);

    EVP_PKEY_CTX_free(ctx);

    RAND_poll();
    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    switch (generate->KEY_FORMAT) {
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

int RsaExportParameters(EXPORT_RSA* params) {
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
        PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(pub_bio, &pkey);
        d2i_PrivateKey_bio(priv_bio, &pkey);
        break;
    default:
        return handleErrors_asymmetric("Invalid RSA key format.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);

    OSSL_PARAM* paramters;
    if (1 != EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &paramters))
        return handleErrors_asymmetric("Get Pkey to data failed.", pub_bio, priv_bio, pkey);

    OSSL_PARAM* param_n = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_N);
    OSSL_PARAM* param_e = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_E);
    OSSL_PARAM* param_d = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_D);
    OSSL_PARAM* param_p = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_FACTOR1);
    OSSL_PARAM* param_q = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_FACTOR2);
    OSSL_PARAM* param_dp = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_EXPONENT1);
    OSSL_PARAM* param_dq = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_EXPONENT2);
    OSSL_PARAM* param_qi = OSSL_PARAM_locate(paramters, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);

    BIGNUM* n = NULL;
    BIGNUM* e = NULL;
    BIGNUM* d = NULL;
    BIGNUM* p = NULL;
    BIGNUM* q = NULL;
    BIGNUM* dp = NULL;
    BIGNUM* dq = NULL;
    BIGNUM* qi = NULL;

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &params->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pkey);

    if (param_n && OSSL_PARAM_get_BN(param_n, &n)) {
        BN_bn2bin(n, params->N);
        BN_free(n);
    }
    else
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL);

    if (param_e && OSSL_PARAM_get_BN(param_e, &e)) {
        BN_bn2bin(e, params->E);
        BN_free(e);
    }
    else
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL);

    if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
        BN_bn2bin(d, params->D);
        BN_free(d);
    }
    else
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL);

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else
        return handleErrors_asymmetric("Get First Prime Factor (p) failed.", NULL);

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else
        return handleErrors_asymmetric("Get Second Prime Factor (q) failed.", NULL);

    if (param_dp && OSSL_PARAM_get_BN(param_dp, &dp)) {
        BN_bn2bin(dp, params->DP);
        BN_free(dp);
    }
    else
        return handleErrors_asymmetric("Get First CRT Exponent (dp) failed.", NULL);

    if (param_dq && OSSL_PARAM_get_BN(param_dq, &dq)) {
        BN_bn2bin(dq, params->DQ);
        BN_free(dq);
    }
    else
        return handleErrors_asymmetric("Get Second CRT Exponent (dq) failed.", NULL);

    if (param_qi && OSSL_PARAM_get_BN(param_qi, &qi)) {
        BN_bn2bin(qi, params->QI);
        BN_free(qi);
    }
    else
        return handleErrors_asymmetric("Get CRT Coefficient (qi) failed.", NULL);

    EVP_PKEY_free(pkey);

    return 0;
}

int RsaExportKeys(EXPORT_RSA* params) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create EVP_PKEY context.", ctx);

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (1 != EVP_PKEY_fromdata_init(ctx))
        return handleErrors_asymmetric("Failed to initialize fromdata.", ctx, NULL, NULL, pkey, NULL);

    const BIGNUM* bn_n = BN_bin2bn(params->N, params->N_LENGTH, NULL);
    if (!bn_n)
        return handleErrors_asymmetric("Invalid Modulus (n) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_e = BN_bin2bn(params->E, params->E_LENGTH, NULL);
    if (!bn_e)
        return handleErrors_asymmetric("Invalid Public Exponent (e) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_d = BN_bin2bn(params->D, params->D_LENGTH, NULL);
    if (!bn_d)
        return handleErrors_asymmetric("Invalid Private Exponent (d) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_p = BN_bin2bn(params->P, params->P_LENGTH, NULL);
    if (!bn_p)
        return handleErrors_asymmetric("Invalid First Prime Factor (p) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_q = BN_bin2bn(params->Q, params->Q_LENGTH, NULL);
    if (!bn_q)
        return handleErrors_asymmetric("Invalid Second Prime Factor (q) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_dp = BN_bin2bn(params->DP, params->DP_LENGTH, NULL);
    if (!bn_dp)
        return handleErrors_asymmetric("Invalid First CRT Exponent (dp) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_dq = BN_bin2bn(params->DQ, params->DQ_LENGTH, NULL);
    if (!bn_dq)
        return handleErrors_asymmetric("Invalid Second CRT Exponent (dq) format.", ctx, NULL, NULL, pkey, NULL);
    const BIGNUM* bn_qi = BN_bin2bn(params->QI, params->QI_LENGTH, NULL);
    if (!bn_qi)
        return handleErrors_asymmetric("Invalid CRT Coefficient (qi) format.", ctx, NULL, NULL, pkey, NULL);

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld)
        return handleErrors_asymmetric("Failed to create OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);

    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, bn_d) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_q) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, bn_dp) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, bn_dq) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, bn_qi)) {
        OSSL_PARAM_BLD_free(bld);
        return handleErrors_asymmetric("Failed to add parameters to OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);
    }

    OSSL_PARAM* paramters = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!paramters)
        return handleErrors_asymmetric("Failed to build OSSL_PARAM from OSSL_PARAM_BLD.", ctx, NULL, NULL, pkey, NULL);

    if (1 != EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, paramters))
        return handleErrors_asymmetric("Failed to generate RSA key.", ctx, NULL, NULL, pkey, NULL);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &params->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pkey);

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