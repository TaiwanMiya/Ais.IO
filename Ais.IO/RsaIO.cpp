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
    /*if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);*/

    EVP_PKEY* pkey = nullptr;

    switch (params->KEY_PKCS) {
    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS8:
        if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
            PEM_read_bio_PUBKEY(pub_bio, &pkey, NULL, NULL);
            if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
                PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
            else
                PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
        }
        else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            d2i_PUBKEY_bio(pub_bio, &pkey);
            d2i_PrivateKey_bio(priv_bio, &pkey);
        }
        break;

    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10: {
        X509_REQ* req = nullptr;
        if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
            req = PEM_read_bio_X509_REQ(pub_bio, NULL, NULL, NULL);
        }
        else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            req = d2i_X509_REQ_bio(pub_bio, NULL);
        }
        if (req) {
            pkey = X509_REQ_get_pubkey(req);
            X509_REQ_free(req);
        }
        break;
    }

    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS12: {
        if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
            if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
                PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
            else
                PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
        }
        else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            PKCS12* p12 = d2i_PKCS12_bio(priv_bio, NULL);
            PKCS12_parse(p12, params->PKCS12_PASSWORD, &pkey, NULL, NULL);
        }
        break;
    }
    default:return handleErrors_asymmetric("Invalid asymmetric key PKCS padding.", pub_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", pub_bio, priv_bio, pkey);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &params->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", NULL, NULL, pkey);

    BIO_free(pub_bio);
    BIO_free(priv_bio);
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

    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER* cipher = GetSymmetryCrypter(generate->PEM_CIPHER, generate->PEM_CIPHER_SIZE, generate->PEM_CIPHER_SEGMENT);
    const EVP_MD* md = GetHashCrypter(generate->HASH_ALGORITHM);

    switch (generate->KEY_PKCS) {
    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS8: {
        if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
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
        }
        else if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            if (1 != i2d_PUBKEY_bio(pub_bio, pkey))
                return handleErrors_asymmetric("Unable to write public key in PKCS#8 DER format to memory.", pub_bio, priv_bio, pkey);
            if (1 != i2d_PrivateKey_bio(priv_bio, pkey))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 DER format to memory.", pub_bio, priv_bio, pkey);
        }
        break;
    }
    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10: {
        X509_REQ* req = X509_REQ_new();
        if (!req || !X509_REQ_set_pubkey(req, pkey) || !X509_REQ_sign(req, pkey, md))
            return handleErrors_asymmetric("Failed to create PKCS#10 CSR.", pub_bio, priv_bio, pkey);
        if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
            if (1 != PEM_write_bio_X509_REQ(pub_bio, req))
                return handleErrors_asymmetric("Unable to write CSR PEM to memory.", pub_bio, priv_bio, pkey);
            if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
                if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                    return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", pub_bio, priv_bio, pkey);
            }
            else {
                if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL))
                    return handleErrors_asymmetric("Unable to write private key in PKCS#10 PEM.", pub_bio, priv_bio, pkey);
            }
        }
        else if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            if (1 != i2d_X509_REQ_bio(pub_bio, req))
                return handleErrors_asymmetric("Unable to write CSR DER to memory.", pub_bio, priv_bio, pkey);
            if (1 != i2d_PrivateKey_bio(priv_bio, pkey))
                return handleErrors_asymmetric("Unable to write private key in PKCS#10 DER.", pub_bio, priv_bio, pkey);
        }
        X509_REQ_free(req);
        break;
    }
    case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS12: {
        X509* cert = X509_new();
        if (!cert || !X509_set_pubkey(cert, pkey) || !X509_sign(cert, pkey, md))
            return handleErrors_asymmetric("Failed to create X.509 certificate for PKCS#12.", pub_bio, priv_bio, pkey);
        PKCS12* p12 = PKCS12_create(generate->PKCS12_PASSWORD, generate->PKCS12_NAME, pkey, cert, NULL, 0, 0, 0, 0, 0);
        if (!p12)
            return handleErrors_asymmetric("Unable to create PKCS#12 object.", pub_bio, priv_bio, pkey);
        if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
            if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
                if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                    return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", pub_bio, priv_bio, pkey);
            }
            else {
                if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL))
                    return handleErrors_asymmetric("Unable to write PEM format PKCS#12 PEM to memory.", pub_bio, priv_bio, pkey);
            }
            if (1 != PEM_write_bio_X509(pub_bio, cert))
                return handleErrors_asymmetric("Unable to write X.509 PEM to memory.", pub_bio, priv_bio, pkey);
        }
        else if (generate->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
            if (1 != i2d_PKCS12_bio(priv_bio, p12))
                return handleErrors_asymmetric("Unable to write PEM format PKCS#12 DER to memory.", pub_bio, priv_bio, pkey);
            if (1 != i2d_X509_bio(pub_bio, cert))
                return handleErrors_asymmetric("Unable to write X.509 DER to memory.", pub_bio, priv_bio, pkey);
        }
        X509_free(cert);
        PKCS12_free(p12);
        break;
    }
    default:return handleErrors_asymmetric("Invalid asymmetric key PKCS padding.", pub_bio, priv_bio, pkey);
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

int RsaGeneratePKCS10(RSA_PKCS10_CERTIFICATE* params) {
    ERR_clear_error();

    BIO* cert_bio = BIO_new(BIO_s_mem());

    EVP_PKEY* pkey = EVP_RSA_gen(params->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA PKCS#10 certificate generate failed.", NULL);

    X509_REQ* req = X509_REQ_new();
    X509_NAME* name = X509_NAME_new();

    if (params->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, params->COUNTRY, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Country (C) failed.", cert_bio, NULL, pkey);
    if (params->ORGANIZETION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, params->ORGANIZETION, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization (O) failed.", cert_bio, NULL, pkey);
    if (params->ORGANIZETION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, params->ORGANIZETION_UNIT, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization Unit (OU) failed.", cert_bio, NULL, pkey);
    if (params->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, params->COMMON_NAME, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Common Name (CN) failed.", cert_bio, NULL, pkey);
    
    if (1 != X509_REQ_set_subject_name(req, name)) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set subject name.", NULL);
    }

    const EVP_MD* md = GetHashCrypter(params->HASH_ALGORITHM);
    if (!X509_REQ_set_pubkey(req, pkey))
        return handleErrors_asymmetric("Failed to set public key.", NULL);
    if (!X509_REQ_sign(req, pkey, md))
        return handleErrors_asymmetric("Failed to sign the request.", NULL);

    switch (params->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509_REQ(cert_bio, req))
            return handleErrors_asymmetric("Unable to write CSR PEM to memory.", cert_bio, NULL, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_REQ_bio(cert_bio, req))
            return handleErrors_asymmetric("Unable to write CSR DER to memory.", cert_bio, NULL, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", cert_bio, NULL, pkey);
    }

    size_t cert_len = BIO_pending(cert_bio);
    if (params->CERTIFICATE == nullptr || params->CERTIFICATE_LENGTH < cert_len) {
        params->CERTIFICATE = new unsigned char[cert_len];
    }

    BIO_read(cert_bio, params->CERTIFICATE, cert_len);

    params->CERTIFICATE_LENGTH = cert_len;

    X509_REQ_free(req);
    X509_NAME_free(name);
    BIO_free_all(cert_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaGeneratePKCS12(RSA_PKCS12_CERTIFICATE_KEY* params) {
    ERR_clear_error();

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    EVP_PKEY* pkey = EVP_RSA_gen(params->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA PKCS#12 certificate and key generate failed.", NULL);

    X509* x509 = X509_new();
    if (!x509)
        return handleErrors_asymmetric("Failed to create X.509 certificate.", NULL, NULL, pkey);
    
    // 設置憑證序列號
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // 設置有效期
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 有效期1年

    // 設置主題信息
    X509_NAME* name = X509_get_subject_name(x509);
    if (params->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, params->COUNTRY, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Country (C) failed.", cert_bio, NULL, pkey);
    if (params->ORGANIZETION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, params->ORGANIZETION, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization (O) failed.", cert_bio, NULL, pkey);
    if (params->ORGANIZETION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, params->ORGANIZETION_UNIT, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization Unit (OU) failed.", cert_bio, NULL, pkey);
    if (params->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, params->COMMON_NAME, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Common Name (CN) failed.", cert_bio, NULL, pkey);

    const EVP_CIPHER* cipher = GetSymmetryCrypter(params->PEM_CIPHER, params->PEM_CIPHER_SIZE, params->PEM_CIPHER_SEGMENT);
    const EVP_MD* md = GetHashCrypter(params->HASH_ALGORITHM);
    if (!X509_set_issuer_name(x509, name))
        return handleErrors_asymmetric("Failed to set issuer name.", NULL);
    if (!X509_set_pubkey(x509, pkey))
        return handleErrors_asymmetric("Failed to set public key.", NULL);
    if (!X509_sign(x509, pkey, md))
        return handleErrors_asymmetric("Failed to sign the certificate.", NULL);

    PKCS12* p12 = PKCS12_create(params->PKCS12_PASSWORD, params->PKCS12_NAME, pkey, x509, NULL, 0, 0, 0, 0, 0);
    if (!p12)
        return handleErrors_asymmetric("Unable to create PKCS#12 object.", cert_bio, priv_bio, pkey);

    switch (params->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (cipher == NULL || params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0) {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", cert_bio, priv_bio, pkey);
        }
        else {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, params->PEM_PASSWORD, params->PEM_PASSWORD_LENGTH, NULL, NULL))
                return handleErrors_asymmetric("Unable to write PEM format PKCS#12 PEM to memory.", cert_bio, priv_bio, pkey);
        }
        if (1 != PEM_write_bio_X509(cert_bio, x509))
            return handleErrors_asymmetric("Unable to write X.509 PEM to memory.", cert_bio, priv_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PKCS12_bio(priv_bio, p12))
            return handleErrors_asymmetric("Unable to write PEM format PKCS#12 DER to memory.", cert_bio, priv_bio, pkey);
        if (1 != i2d_X509_bio(cert_bio, x509))
            return handleErrors_asymmetric("Unable to write X.509 DER to memory.", cert_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", cert_bio, NULL, pkey);
    }

    size_t cert_len = BIO_pending(cert_bio);
    size_t priv_len = BIO_pending(priv_bio);
    if (params->CERTIFICATE == nullptr || params->PRIVATE_KEY == nullptr || params->CERTIFICATE_LENGTH < cert_len || params->PRIVATE_KEY_LENGTH < priv_len) {
        params->CERTIFICATE = new unsigned char[cert_len];
        params->PRIVATE_KEY = new unsigned char[priv_len];
    }

    BIO_read(cert_bio, params->CERTIFICATE, cert_len);
    BIO_read(priv_bio, params->PRIVATE_KEY, priv_len);

    params->CERTIFICATE_LENGTH = cert_len;
    params->PRIVATE_KEY_LENGTH = priv_len;

    X509_free(x509);
    PKCS12_free(p12);
    BIO_free_all(cert_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaExportParameters(EXPORT_RSA* params) {
    ERR_clear_error();
    RAND_poll();

    BIO* pub_bio = BIO_new_mem_buf(params->PUBLIC_KEY, static_cast<int>(params->PUBLIC_KEY_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    /*if (!pub_bio || !priv_bio)
        return handleErrors_asymmetric("Failed to create BIOs for key data.", NULL);*/

    EVP_PKEY* pkey = nullptr;
    switch (params->KEY_PKCS) {
        case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS8: {
            if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
                PEM_read_bio_PUBKEY(pub_bio, &pkey, NULL, NULL);
                if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
                else
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
            }
            else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
                d2i_PUBKEY_bio(pub_bio, &pkey);
                d2i_PrivateKey_bio(priv_bio, &pkey);
            }
            break;
        }
        case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10: {
            X509_REQ* req = nullptr;
            if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
                req = PEM_read_bio_X509_REQ(pub_bio, NULL, NULL, NULL);
                if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
                else
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
            }
            else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
                req = d2i_X509_REQ_bio(pub_bio, NULL);
                d2i_PrivateKey_bio(priv_bio, &pkey);
            }
            if (req) {
                pkey = X509_REQ_get_pubkey(req);
                X509_REQ_free(req);
            }   
            break;
        }
        case ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS12: {
            X509* cert = nullptr;
            if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
                if (params->PEM_PASSWORD == NULL || params->PEM_PASSWORD_LENGTH <= 0)
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
                else
                    PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(params->PEM_PASSWORD)));
                PEM_read_bio_X509(pub_bio, &cert, NULL, NULL);
            }
            else if (params->KEY_FORMAT == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER) {
                PKCS12* p12 = d2i_PKCS12_bio(priv_bio, NULL);
                PKCS12_parse(p12, params->PKCS12_PASSWORD, &pkey, NULL, NULL);
                d2i_X509_bio(pub_bio, &cert);
                PKCS12_free(p12);
            }
            X509_free(cert);
            break;
        }
        default:return handleErrors_asymmetric("Invalid asymmetric key PKCS padding.", pub_bio, priv_bio, pkey);
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
    else {
        handleErrors_asymmetric("Get Modulus (n) failed.", NULL);
        memset(params->N, 0, params->N_LENGTH);
        params->N_LENGTH = 0;
    }

    if (param_e && OSSL_PARAM_get_BN(param_e, &e)) {
        BN_bn2bin(e, params->E);
        BN_free(e);
    }
    else {
        handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL);
        memset(params->E, 0, params->E_LENGTH);
        params->E_LENGTH = 0;
    }

    if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
        BN_bn2bin(d, params->D);
        BN_free(d);
    }
    else {
        handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL);
        memset(params->D, 0, params->D_LENGTH);
        params->D_LENGTH = 0;
    }

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else {
        handleErrors_asymmetric("Get First Prime Factor (p) failed.", NULL);
        memset(params->P, 0, params->P_LENGTH);
        params->P_LENGTH = 0;
    }

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else {
        handleErrors_asymmetric("Get Second Prime Factor (q) failed.", NULL);
        memset(params->Q, 0, params->Q_LENGTH);
        params->Q_LENGTH = 0;
    }

    if (param_dp && OSSL_PARAM_get_BN(param_dp, &dp)) {
        BN_bn2bin(dp, params->DP);
        BN_free(dp);
    }
    else {
        handleErrors_asymmetric("Get First CRT Exponent (dp) failed.", NULL);
        memset(params->DP, 0, params->DP_LENGTH);
        params->DP_LENGTH = 0;
    }

    if (param_dq && OSSL_PARAM_get_BN(param_dq, &dq)) {
        BN_bn2bin(dq, params->DQ);
        BN_free(dq);
    }
    else {
        handleErrors_asymmetric("Get Second CRT Exponent (dq) failed.", NULL);
        memset(params->DQ, 0, params->DQ_LENGTH);
        params->DQ_LENGTH = 0;
    }

    if (param_qi && OSSL_PARAM_get_BN(param_qi, &qi)) {
        BN_bn2bin(qi, params->QI);
        BN_free(qi);
    }
    else {
        handleErrors_asymmetric("Get CRT Coefficient (qi) failed.", NULL);
        memset(params->QI, 0, params->QI_LENGTH);
        params->QI_LENGTH = 0;
    }

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