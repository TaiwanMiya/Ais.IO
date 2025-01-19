#include "pch.h"
#include "DsaIO.h"

#define DIV_ROUND_UP(x, y) (((x) + (y) - 1) / (y))

int DsaGetParametersLength(DSA_PARAMETERS* params) {
    size_t q_bit_length = (params->KEY_LENGTH <= 1024) ? 160 : 256;
    params->P_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);     // p 的長度為密鑰長度的字節數
    params->Q_LENGTH = 28;                                      // q 的長度為 q 位數的字節數
    params->G_LENGTH = DIV_ROUND_UP(params->KEY_LENGTH, 8);     // g 的長度與 p 相同
    params->X_LENGTH = params->Q_LENGTH;                        // x 的長度等於 q 的長度
    params->Y_LENGTH = params->P_LENGTH;                        // y 的長度等於 p 的長度
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