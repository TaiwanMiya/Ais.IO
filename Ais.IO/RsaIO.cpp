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

int RsaGenerateCSR(RSA_CSR* generate) {
    ERR_clear_error();

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    EVP_PKEY* pkey = EVP_RSA_gen(generate->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA CSR certificate generate failed.", NULL);

    X509_REQ* req = X509_REQ_new();
    X509_NAME* name = X509_NAME_new();

    //X509_NAME_add_entry_by_NID(name, NID_organizationName)
    if (generate->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, generate->COMMON_NAME, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Common Name (CN) failed.", cert_bio, priv_bio, pkey);
    if (generate->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, generate->COUNTRY, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Country (C) failed.", cert_bio, priv_bio, pkey);
    if (generate->ORGANIZATION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, generate->ORGANIZATION, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization (O) failed.", cert_bio, priv_bio, pkey);
    if (generate->ORGANIZATION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, generate->ORGANIZATION_UNIT, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization Unit (OU) failed.", cert_bio, priv_bio, pkey);
    
    if (1 != X509_REQ_set_subject_name(req, name)) {
        X509_NAME_free(name);
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set subject name.", cert_bio, priv_bio, pkey);
    }

    const EVP_MD* md = GetHashCrypter(generate->HASH_ALGORITHM);
    if (!X509_REQ_set_pubkey(req, pkey))
        return handleErrors_asymmetric("Failed to set public key.", cert_bio, priv_bio, pkey);

#pragma region Add Extensions To CSR

    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    if (!exts)
        return handleErrors_asymmetric("Failed to create extension stack.", cert_bio, priv_bio, pkey);

    // Add Subject Alternative Name
    // DNS:www.example.com,IP:192.168.1.1,email:user@example.com,URI:https://example.com
    if (generate->SUBJECT_ALTERNATIVE_NAME && !std::string(generate->SUBJECT_ALTERNATIVE_NAME).empty()) {
        X509_EXTENSION* ext_SAN = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, generate->SUBJECT_ALTERNATIVE_NAME);
        if (!ext_SAN) {
            sk_X509_EXTENSION_free(exts);
            return handleErrors_asymmetric("Failed to create SAN extension.", cert_bio, priv_bio, pkey);
        }
        sk_X509_EXTENSION_push(exts, ext_SAN);
    }

    // Add Key Usage
    std::string usage;
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DIGITAL_SIGNATURE) usage += "digitalSignature, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_ENCIPHERMENT)  usage += "keyEncipherment, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DATA_ENCIPHERMENT) usage += "dataEncipherment, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_AGREEMENT)     usage += "keyAgreement, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CERT_SIGN)         usage += "keyCertSign, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CRL_SIGN)          usage += "cRLSign, ";
    if (!usage.empty()) {
        usage.pop_back();
        usage.pop_back();
    }

    if (!usage.empty()) {
        X509_EXTENSION* ext_KU = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage.c_str());
        if (!ext_KU) {
            sk_X509_EXTENSION_free(exts);
            return handleErrors_asymmetric("Failed to create Key Usage extension.", cert_bio, priv_bio, pkey);
        }
        sk_X509_EXTENSION_push(exts, ext_KU);
    }

    if (!X509_REQ_add_extensions(req, exts)) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        return handleErrors_asymmetric("Failed to add extensions to CSR.", cert_bio, priv_bio, pkey);
    }

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
#pragma endregion

    if (!X509_REQ_sign(req, pkey, md))
        return handleErrors_asymmetric("Failed to sign the request.", cert_bio, priv_bio, pkey);

    const EVP_CIPHER* cipher = GetSymmetryCrypter(generate->PEM_CIPHER, generate->PEM_CIPHER_SIZE, generate->PEM_CIPHER_SEGMENT);
    switch (generate->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509_REQ(cert_bio, req))
            return handleErrors_asymmetric("Unable to write CSR PEM to memory.", cert_bio, priv_bio, pkey);
        if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", cert_bio, priv_bio, pkey);
        }
        else {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", cert_bio, priv_bio, pkey);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_REQ_bio(cert_bio, req))
            return handleErrors_asymmetric("Unable to write CSR DER to memory.", cert_bio, priv_bio, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", cert_bio, priv_bio, pkey);
    }

    size_t cert_len = BIO_pending(cert_bio);
    size_t priv_len = BIO_pending(priv_bio);
    if (generate->CSR == nullptr || generate->CSR_LENGTH < cert_len) {
        generate->CSR = new unsigned char[cert_len];
        generate->PRIVATE_KEY = new unsigned char[priv_len];
    }

    BIO_read(cert_bio, generate->CSR, cert_len);
    BIO_read(priv_bio, generate->PRIVATE_KEY, priv_len);

    generate->CSR_LENGTH = cert_len;
    generate->PRIVATE_KEY_LENGTH = priv_len;

    X509_REQ_free(req);
    X509_NAME_free(name);
    BIO_free_all(cert_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaGenerateCA(RSA_CA* generate) {
    ERR_clear_error();

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    // 生成 RSA 金鑰
    EVP_PKEY* pkey = EVP_RSA_gen(generate->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA CA certificate key generate failed.", NULL);

    // 創建 X.509 憑證
    X509* x509 = X509_new();
    if (!x509)
        return handleErrors_asymmetric("Failed to create X.509 certificate.", NULL, NULL, pkey);

    // 設置憑證序列號
    ASN1_INTEGER_set(X509_get_serialNumber(x509), generate->SERIAL_NUMBER);

    // 設置有效期
    unsigned long validity_days = generate->VALIDITY_DAYS > 0 ? generate->VALIDITY_DAYS : 365;
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validity_days * 86400);

    // 設置主題資訊
    X509_NAME* name = X509_get_subject_name(x509);
    if (generate->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, generate->COMMON_NAME, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Common Name (CN) failed.", cert_bio, NULL, pkey);
    if (generate->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, generate->COUNTRY, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Country (C) failed.", cert_bio, NULL, pkey);
    if (generate->ORGANIZATION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, generate->ORGANIZATION, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization (O) failed.", cert_bio, NULL, pkey);
    if (generate->ORGANIZATION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, generate->ORGANIZATION_UNIT, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization Unit (OU) failed.", cert_bio, NULL, pkey);

    // 設置 CA 為發行者 (自簽)
    if (!X509_set_issuer_name(x509, name))
        return handleErrors_asymmetric("Failed to set issuer name.", NULL);

    if (!X509_set_pubkey(x509, pkey))
        return handleErrors_asymmetric("Failed to set public key.", NULL);

    // 設置憑證擴展：Basic Constraints 為 CA
    X509_EXTENSION* ext_bc = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    if (!ext_bc || !X509_add_ext(x509, ext_bc, -1)) {
        X509_EXTENSION_free(ext_bc);
        return handleErrors_asymmetric("Failed to add Basic Constraints extension.", NULL);
    }
    X509_EXTENSION_free(ext_bc);

    // Add Key Usage
    std::string usage;
    usage += "critical, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DIGITAL_SIGNATURE) usage += "digitalSignature, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_ENCIPHERMENT)  usage += "keyEncipherment, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DATA_ENCIPHERMENT) usage += "dataEncipherment, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_AGREEMENT)     usage += "keyAgreement, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CERT_SIGN)         usage += "keyCertSign, ";
    if (generate->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CRL_SIGN)          usage += "cRLSign, ";
    if (!usage.empty()) {
        size_t find_key_cert_sign = usage.find("keyCertSign");
        size_t find_key_crl_sign = usage.find("cRLSign");
        if (find_key_cert_sign == std::string::npos)
            usage += "keyCertSign, ";
        if (find_key_crl_sign == std::string::npos)
            usage += "cRLSign, ";
        usage.pop_back();
        usage.pop_back();
    }

    // 設置 Key Usage
    if (!usage.empty()) {
        X509_EXTENSION* ext_ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage.c_str());
        if (!ext_ku || !X509_add_ext(x509, ext_ku, -1)) {
            X509_EXTENSION_free(ext_ku);
            return handleErrors_asymmetric("Failed to add Key Usage extension.", NULL);
        }
        X509_EXTENSION_free(ext_ku);
    }
    
    // 計算 Subject Key Identifier (SKI)
    X509_EXTENSION* ext_ski = NULL;
    ASN1_OCTET_STRING* skid = ASN1_OCTET_STRING_new();
    unsigned char skid_buf[EVP_MAX_MD_SIZE] = { 0 };
    unsigned int skid_len = 0;

    EVP_PKEY* pubkey = X509_get_pubkey(x509);
    if (!pubkey) {
        return handleErrors_asymmetric("Failed to get public key for SKI generation.", NULL);
    }

    // 計算 SHA1(SPKI) 作為 SKI
    const EVP_MD* md = GetHashCrypter(generate->HASH_ALGORITHM);
    if (!md)
        return handleErrors_asymmetric("Invalid or unsupported hash algorithm.", NULL);

    X509_PUBKEY* pubkey_struct = NULL;
    X509_PUBKEY_set(&pubkey_struct, pubkey);
    const unsigned char* spki_data = NULL;
    int spki_len = 0;
    X509_PUBKEY_get0_param(NULL, &spki_data, &spki_len, NULL, pubkey_struct);

    EVP_Digest(X509_PUBKEY_get0(pubkey_struct), spki_len, skid_buf, &skid_len, md, NULL);
    ASN1_OCTET_STRING_set(skid, skid_buf, skid_len);

    // 設置 Subject Key Identifier
    ext_ski = X509_EXTENSION_create_by_NID(NULL, NID_subject_key_identifier, 0, skid);
    if (!ext_ski || !X509_add_ext(x509, ext_ski, -1)) {
        X509_EXTENSION_free(ext_ski);
        return handleErrors_asymmetric("Failed to add Subject Key Identifier extension.", NULL);
    }
    X509_EXTENSION_free(ext_ski);

    // 簽名演算法
    if (!X509_sign(x509, pkey, md))
        return handleErrors_asymmetric("Failed to sign the certificate.", NULL);

    // 輸出憑證
    switch (generate->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509(cert_bio, x509))
            return handleErrors_asymmetric("Unable to write CA certificate in PEM format.", cert_bio, NULL, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_bio(cert_bio, x509))
            return handleErrors_asymmetric("Unable to write CA certificate in DER format.", cert_bio, NULL, pkey);
        break;
    default:
        return handleErrors_asymmetric("Invalid certificate format.", cert_bio, NULL, pkey);
    }

    // 儲存憑證
    size_t cert_len = BIO_pending(cert_bio);
    if (generate->CERTIFICATE == nullptr || generate->CERTIFICATE_LENGTH < cert_len)
        generate->CERTIFICATE = new unsigned char[cert_len];

    BIO_read(cert_bio, generate->CERTIFICATE, cert_len);
    generate->CERTIFICATE_LENGTH = cert_len;

    // 釋放資源
    BIO_free(cert_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return 0;
}

int RsaGenerateP12(RSA_P12* generate) {
    ERR_clear_error();

    BIO* cert_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    EVP_PKEY* pkey = EVP_RSA_gen(generate->KEY_LENGTH);
    if (!pkey)
        return handleErrors_asymmetric("RSA PKCS#12 certificate and key generate failed.", NULL);

    X509* x509 = X509_new();
    if (!x509)
        return handleErrors_asymmetric("Failed to create X.509 certificate.", NULL, NULL, pkey);
    
    // 設置憑證序列號
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // 設置有效期
    unsigned long validity_days = generate->VALIDITY_DAYS > 0 ? generate->VALIDITY_DAYS : 365;
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60 * 60 * 24 * validity_days);

    // 設置主題信息
    X509_NAME* name = X509_get_subject_name(x509);
    if (generate->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, generate->COMMON_NAME, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Common Name (CN) failed.", cert_bio, NULL, pkey);
    if (generate->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, generate->COUNTRY, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Country (C) failed.", cert_bio, NULL, pkey);
    if (generate->ORGANIZATION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, generate->ORGANIZATION, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization (O) failed.", cert_bio, NULL, pkey);
    if (generate->ORGANIZATION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, generate->ORGANIZATION_UNIT, -1, -1, 0))
        return handleErrors_asymmetric("Set Certificate Organization Unit (OU) failed.", cert_bio, NULL, pkey);

    const EVP_CIPHER* cipher = GetSymmetryCrypter(generate->PEM_CIPHER, generate->PEM_CIPHER_SIZE, generate->PEM_CIPHER_SEGMENT);
    const EVP_MD* md = GetHashCrypter(generate->HASH_ALGORITHM);
    if (!X509_set_issuer_name(x509, name))
        return handleErrors_asymmetric("Failed to set issuer name.", NULL);
    if (!X509_set_pubkey(x509, pkey))
        return handleErrors_asymmetric("Failed to set public key.", NULL);
    if (!X509_sign(x509, pkey, md))
        return handleErrors_asymmetric("Failed to sign the certificate.", NULL);

    PKCS12* p12 = PKCS12_create(generate->PKCS12_PASSWORD, generate->PKCS12_NAME, pkey, x509, NULL, 0, 0, 0, 0, 0);
    if (!p12)
        return handleErrors_asymmetric("Unable to create PKCS#12 object.", cert_bio, priv_bio, pkey);

    switch (generate->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (cipher == NULL || generate->PEM_PASSWORD == NULL || generate->PEM_PASSWORD_LENGTH <= 0) {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL))
                return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", cert_bio, priv_bio, pkey);
        }
        else {
            if (1 != PEM_write_bio_PrivateKey(priv_bio, pkey, cipher, generate->PEM_PASSWORD, generate->PEM_PASSWORD_LENGTH, NULL, NULL))
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
    if (generate->CERTIFICATE == nullptr || generate->PRIVATE_KEY == nullptr || generate->CERTIFICATE_LENGTH < cert_len || generate->PRIVATE_KEY_LENGTH < priv_len) {
        generate->CERTIFICATE = new unsigned char[cert_len];
        generate->PRIVATE_KEY = new unsigned char[priv_len];
    }

    BIO_read(cert_bio, generate->CERTIFICATE, cert_len);
    BIO_read(priv_bio, generate->PRIVATE_KEY, priv_len);

    generate->CERTIFICATE_LENGTH = cert_len;
    generate->PRIVATE_KEY_LENGTH = priv_len;

    X509_free(x509);
    PKCS12_free(p12);
    BIO_free_all(cert_bio);
    BIO_free_all(priv_bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaExportParameters(RSA_EXPORT* params) {
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
        params->N_LENGTH = BN_num_bytes(n);
        BN_bn2bin(n, params->N);
        BN_free(n);
    }
    else {
        handleErrors_asymmetric("Get Modulus (n) failed.", NULL);
        memset(params->N, 0, params->N_LENGTH);
        params->N_LENGTH = 0;
    }

    if (param_e && OSSL_PARAM_get_BN(param_e, &e)) {
        params->E_LENGTH = BN_num_bytes(e);
        BN_bn2bin(e, params->E);
        BN_free(e);
    }
    else {
        handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL);
        memset(params->E, 0, params->E_LENGTH);
        params->E_LENGTH = 0;
    }

    if (param_d && OSSL_PARAM_get_BN(param_d, &d)) {
        params->D_LENGTH = BN_num_bytes(d);
        BN_bn2bin(d, params->D);
        BN_free(d);
    }
    else {
        handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL);
        memset(params->D, 0, params->D_LENGTH);
        params->D_LENGTH = 0;
    }

    if (param_p && OSSL_PARAM_get_BN(param_p, &p)) {
        params->P_LENGTH = BN_num_bytes(p);
        BN_bn2bin(p, params->P);
        BN_free(p);
    }
    else {
        handleErrors_asymmetric("Get First Prime Factor (p) failed.", NULL);
        memset(params->P, 0, params->P_LENGTH);
        params->P_LENGTH = 0;
    }

    if (param_q && OSSL_PARAM_get_BN(param_q, &q)) {
        params->Q_LENGTH = BN_num_bytes(q);
        BN_bn2bin(q, params->Q);
        BN_free(q);
    }
    else {
        handleErrors_asymmetric("Get Second Prime Factor (q) failed.", NULL);
        memset(params->Q, 0, params->Q_LENGTH);
        params->Q_LENGTH = 0;
    }

    if (param_dp && OSSL_PARAM_get_BN(param_dp, &dp)) {
        params->DP_LENGTH = BN_num_bytes(dp);
        BN_bn2bin(dp, params->DP);
        BN_free(dp);
    }
    else {
        handleErrors_asymmetric("Get First CRT Exponent (dp) failed.", NULL);
        memset(params->DP, 0, params->DP_LENGTH);
        params->DP_LENGTH = 0;
    }

    if (param_dq && OSSL_PARAM_get_BN(param_dq, &dq)) {
        params->DQ_LENGTH = BN_num_bytes(dq);
        BN_bn2bin(dq, params->DQ);
        BN_free(dq);
    }
    else {
        handleErrors_asymmetric("Get Second CRT Exponent (dq) failed.", NULL);
        memset(params->DQ, 0, params->DQ_LENGTH);
        params->DQ_LENGTH = 0;
    }

    if (param_qi && OSSL_PARAM_get_BN(param_qi, &qi)) {
        params->QI_LENGTH = BN_num_bytes(qi);
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

int RsaExportKeys(RSA_EXPORT* params) {
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

int RsaExtractPublicKey(RSA_EXTRACT_PUBLIC_KEY* params) {
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
        PEM_write_bio_PUBKEY(pub_bio, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        i2d_PUBKEY_bio(pub_bio, pkey);
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

int RsaExtractCSR(RSA_EXTRACT_CSR* params) {
    ERR_clear_error();

    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!priv_bio)
        return handleErrors_asymmetric("Failed to create BIO for private key.", NULL);

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
    default:
        return handleErrors_asymmetric("Invalid private key format.", priv_bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", priv_bio, NULL, pkey);

    BIO_free(priv_bio);

    X509_REQ* req = X509_REQ_new();
    if (!req)
        return handleErrors_asymmetric("Failed to create CSR object.", NULL, NULL, pkey);

    X509_NAME* name = X509_NAME_new();
    if (!name) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to create X509_NAME.", NULL, NULL, pkey);
    }

    if (params->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, params->COMMON_NAME, -1, -1, 0)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set Common Name (CN).", NULL, NULL, pkey);
    }
    if (params->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, params->COUNTRY, -1, -1, 0)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set Country (C).", NULL, NULL, pkey);
    }
    if (params->ORGANIZATION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, params->ORGANIZATION, -1, -1, 0)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set Organization (O).", NULL, NULL, pkey);
    }
    if (params->ORGANIZATION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, params->ORGANIZATION_UNIT, -1, -1, 0)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set Organization Unit (OU).", NULL, NULL, pkey);
    }

    if (1 != X509_REQ_set_subject_name(req, name)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set subject name.", NULL, NULL, pkey);
    }

    if (!X509_REQ_set_pubkey(req, pkey)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to set public key.", NULL, NULL, pkey);
    }

    STACK_OF(X509_EXTENSION)* exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to create extension stack.", NULL, NULL, pkey);
    }

    if (params->SUBJECT_ALTERNATIVE_NAME && !std::string(params->SUBJECT_ALTERNATIVE_NAME).empty() && std::string(params->SUBJECT_ALTERNATIVE_NAME).length() > 0) {
        X509_EXTENSION* ext_SAN = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, params->SUBJECT_ALTERNATIVE_NAME);
        if (!ext_SAN) {
            sk_X509_EXTENSION_free(exts);
            X509_REQ_free(req);
            return handleErrors_asymmetric("Failed to create SAN extension.", NULL, NULL, pkey);
        }
        sk_X509_EXTENSION_push(exts, ext_SAN);
    }

    std::string usage;
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DIGITAL_SIGNATURE) usage += "digitalSignature, ";
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_ENCIPHERMENT)  usage += "keyEncipherment, ";
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_DATA_ENCIPHERMENT) usage += "dataEncipherment, ";
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_KEY_AGREEMENT)     usage += "keyAgreement, ";
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CERT_SIGN)         usage += "keyCertSign, ";
    if (params->KEY_USAGE & ASYMMETRIC_KEY_CSR_KEY_USAGE::CSR_KEY_USAGE_CRL_SIGN)          usage += "cRLSign, ";
    if (!usage.empty()) {
        usage.pop_back();
        usage.pop_back();
    }

    if (!usage.empty()) {
        X509_EXTENSION* ext_KU = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage.c_str());
        if (!ext_KU) {
            sk_X509_EXTENSION_free(exts);
            X509_REQ_free(req);
            return handleErrors_asymmetric("Failed to create Key Usage extension.", NULL, NULL, pkey);
        }
        sk_X509_EXTENSION_push(exts, ext_KU);
    }

    if (!X509_REQ_add_extensions(req, exts)) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to add extensions to CSR.", NULL, NULL, pkey);
    }
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    const EVP_MD* md = GetHashCrypter(params->HASH_ALGORITHM);
    if (!X509_REQ_sign(req, pkey, md)) {
        X509_REQ_free(req);
        return handleErrors_asymmetric("Failed to sign CSR.", NULL, NULL, pkey);
    }

    BIO* csr_bio = BIO_new(BIO_s_mem());
    switch (params->CSR_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509_REQ(csr_bio, req)) {
            X509_REQ_free(req);
            return handleErrors_asymmetric("Unable to write CSR PEM to memory.", csr_bio, NULL, pkey);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_REQ_bio(csr_bio, req)) {
            X509_REQ_free(req);
            return handleErrors_asymmetric("Unable to write CSR DER to memory.", csr_bio, NULL, pkey);
        }
        break;
    default:
        X509_REQ_free(req);
        return handleErrors_asymmetric("Invalid CSR format.", csr_bio, NULL, pkey);
    }

    size_t csr_len = BIO_pending(csr_bio);
    if (params->CSR == nullptr || params->CSR_LENGTH < csr_len)
        params->CSR = new unsigned char[csr_len];

    BIO_read(csr_bio, params->CSR, csr_len);
    params->CSR_LENGTH = csr_len;

    BIO_free_all(csr_bio);
    X509_REQ_free(req);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);

    return 0;
}

int RsaExtractCA(RSA_EXTRACT_CA* params) {
    ERR_clear_error();

    BIO* priv_bio = BIO_new_mem_buf(params->PRIVATE_KEY, static_cast<int>(params->PRIVATE_KEY_LENGTH));
    if (!priv_bio)
        return handleErrors_asymmetric("Failed to create BIO for private key.", NULL);

    EVP_PKEY* pkey = nullptr;

    // **讀取私鑰**
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
        return handleErrors_asymmetric("Invalid private key format.", priv_bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key.", priv_bio, NULL, pkey);

    BIO_free(priv_bio);

    // **創建 X.509 憑證**
    X509* x509 = X509_new();
    if (!x509)
        return handleErrors_asymmetric("Failed to create X.509 certificate.", NULL, NULL, pkey);

    // **設置證書序列號**
    ASN1_INTEGER_set(X509_get_serialNumber(x509), params->SERIAL_NUMBER);

    // **設置有效期**
    unsigned long validity_days = params->VALIDITY_DAYS > 0 ? params->VALIDITY_DAYS : 365;
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validity_days * 86400);

    // **設置主題資訊**
    X509_NAME* name = X509_get_subject_name(x509);
    if (params->COMMON_NAME && 1 != X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, params->COMMON_NAME, -1, -1, 0)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set Common Name (CN).", NULL, NULL, pkey);
    }
    if (params->COUNTRY && 1 != X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, params->COUNTRY, -1, -1, 0)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set Country (C).", NULL, NULL, pkey);
    }
    if (params->ORGANIZATION && 1 != X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, params->ORGANIZATION, -1, -1, 0)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set Organization (O).", NULL, NULL, pkey);
    }
    if (params->ORGANIZATION_UNIT && 1 != X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, params->ORGANIZATION_UNIT, -1, -1, 0)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set Organization Unit (OU).", NULL, NULL, pkey);
    }

    // **設置 CA 為發行者 (自簽)**
    if (!X509_set_issuer_name(x509, name)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set issuer name.", NULL, NULL, pkey);
    }

    if (!X509_set_pubkey(x509, pkey)) {
        X509_free(x509);
        return handleErrors_asymmetric("Failed to set public key.", NULL, NULL, pkey);
    }

    // **設置 Basic Constraints (CA:TRUE)**
    X509_EXTENSION* ext_bc = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    if (!ext_bc || !X509_add_ext(x509, ext_bc, -1)) {
        X509_free(x509);
        X509_EXTENSION_free(ext_bc);
        return handleErrors_asymmetric("Failed to add Basic Constraints extension.", NULL);
    }
    X509_EXTENSION_free(ext_bc);

    // **設置 Key Usage**
    std::string usage = "critical, keyCertSign, cRLSign";
    X509_EXTENSION* ext_ku = X509V3_EXT_conf_nid(NULL, NULL, NID_key_usage, usage.c_str());
    if (!ext_ku || !X509_add_ext(x509, ext_ku, -1)) {
        X509_EXTENSION_free(ext_ku);
        return handleErrors_asymmetric("Failed to add Key Usage extension.", NULL);
    }
    X509_EXTENSION_free(ext_ku);

    // **設置 Subject Key Identifier (SKI)**
    X509_EXTENSION* ext_ski = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_key_identifier, "hash");
    if (!ext_ski || !X509_add_ext(x509, ext_ski, -1)) {
        X509_EXTENSION_free(ext_ski);
        return handleErrors_asymmetric("Failed to add Subject Key Identifier extension.", NULL);
    }
    X509_EXTENSION_free(ext_ski);

    // **簽名憑證**
    const EVP_MD* md = GetHashCrypter(params->HASH_ALGORITHM);
    if (!md)
        return handleErrors_asymmetric("Invalid or unsupported hash algorithm.", NULL);

    if (!X509_sign(x509, pkey, md))
        return handleErrors_asymmetric("Failed to sign the certificate.", NULL);

    // **輸出憑證**
    BIO* cert_bio = BIO_new(BIO_s_mem());
    switch (params->CERTIFICATE_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509(cert_bio, x509)) {
            X509_free(x509);
            return handleErrors_asymmetric("Failed to write CA certificate in PEM format.", cert_bio, NULL, pkey);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_bio(cert_bio, x509)) {
            X509_free(x509);
            return handleErrors_asymmetric("Failed to write CA certificate in DER format.", cert_bio, NULL, pkey);
        }
        break;
    default:
        X509_free(x509);
        return handleErrors_asymmetric("Invalid certificate format.", cert_bio, NULL, pkey);
    }

    // **存儲憑證**
    size_t cert_len = BIO_pending(cert_bio);
    if (params->CERTIFICATE == nullptr || params->CERTIFICATE_LENGTH < cert_len)
        params->CERTIFICATE = new unsigned char[cert_len];

    BIO_read(cert_bio, params->CERTIFICATE, cert_len);
    params->CERTIFICATE_LENGTH = cert_len;

    // **釋放資源**
    BIO_free(cert_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return 0;
}

int RsaCheckPublicKey(RSA_CHECK_PUBLIC_KEY* check) {
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
    if (key_type != EVP_PKEY_RSA)
        return handleErrors_asymmetric("Key is not a RSA key.", bio, NULL, pkey);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &check->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", bio, NULL, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_public_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int RsaCheckPrivateKey(RSA_CHECK_PRIVATE_KEY* check) {
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
        return handleErrors_asymmetric("Failed to parse private key.", bio, NULL, pkey);

    int key_type = EVP_PKEY_base_id(pkey);
    if (key_type != EVP_PKEY_RSA)
        return handleErrors_asymmetric("Key is not a RSA key.", bio, NULL, pkey);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &check->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", bio, NULL, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_private_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int RsaCheckCSR(RSA_CHECK_CSR* check) {
    ERR_clear_error();
    X509_REQ* req = nullptr;
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(check->CSR, static_cast<int>(check->CSR_LENGTH));

    switch (check->CSR_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_X509_REQ(bio, &req, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_X509_REQ_bio(bio, &req);
        break;
    }
    if (!req)
        return handleErrors_asymmetric("Failed to get PKEY by CSR.", bio, NULL, pkey);

    int nid = X509_REQ_get_signature_nid(req);
    check->HASH_ALGORITHM = GetHashType(nid);

    pkey = X509_REQ_get_pubkey(req);
    if (!pkey)
        return handleErrors_asymmetric("Failed to parse CSR.", bio, NULL, pkey);

    if (X509_REQ_verify(req, pkey) != 1)
        return handleErrors_asymmetric("CSR signature verification failed.", bio, NULL, pkey);

    X509_NAME* name = X509_REQ_get_subject_name(req);
    if (!name)
        return handleErrors_asymmetric("Failed to get subject name from CSR.", bio, NULL, pkey);

    check->COMMON_NAME_LENGTH = X509_NAME_get_text_by_NID(name, NID_commonName, reinterpret_cast<char*>(check->COMMON_NAME), check->COMMON_NAME_LENGTH);
    check->COUNTRY_LENGTH = X509_NAME_get_text_by_NID(name, NID_countryName, reinterpret_cast<char*>(check->COUNTRY), check->COUNTRY_LENGTH);
    check->ORGANIZATION_LENGTH = X509_NAME_get_text_by_NID(name, NID_organizationName, reinterpret_cast<char*>(check->ORGANIZATION), check->ORGANIZATION_LENGTH);
    check->ORGANIZATION_UNIT_LENGTH = X509_NAME_get_text_by_NID(name, NID_organizationalUnitName, reinterpret_cast<char*>(check->ORGANIZATION_UNIT), check->ORGANIZATION_UNIT_LENGTH);

#pragma region Check Extensions To CSR

    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    if (exts) {
        for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
            ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
            char buf[256] = { 0 };
            OBJ_obj2txt(buf, sizeof(buf), obj, 1);

            // **Check Key Usage**
            if (OBJ_txt2nid(buf) == NID_key_usage) {
                ASN1_BIT_STRING* bit_str = (ASN1_BIT_STRING*)X509_EXTENSION_get_data(ext);
                if (!bit_str)
                    continue;

                int usage_flags = 0;
                for (int j = 0; j < bit_str->length; j++)
                    usage_flags = (usage_flags << 8) | bit_str->data[j];

                if (usage_flags & 0x0080) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_DIGITAL_SIGNATURE);
                if (usage_flags & 0x0020) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_KEY_ENCIPHERMENT);
                if (usage_flags & 0x0010) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_DATA_ENCIPHERMENT);
                if (usage_flags & 0x0008) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_KEY_AGREEMENT);
                if (usage_flags & 0x0004) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_CERT_SIGN);
                if (usage_flags & 0x0002) check->KEY_USAGE = static_cast<ASYMMETRIC_KEY_CSR_KEY_USAGE>(check->KEY_USAGE | CSR_KEY_USAGE_CRL_SIGN);
            }

            // **Check Subject Alternative Name (SAN)**
            if (OBJ_txt2nid(buf) == NID_subject_alt_name) {
                GENERAL_NAMES* san_names = (GENERAL_NAMES*)X509V3_EXT_d2i(ext);
                if (san_names) {
                    std::string san_list;
                    for (int j = 0; j < sk_GENERAL_NAME_num(san_names); j++) {
                        GENERAL_NAME* san = sk_GENERAL_NAME_value(san_names, j);
                        if (san->type == GEN_DNS) {
                            char* dns_name = (char*)ASN1_STRING_get0_data(san->d.dNSName);
                            if (dns_name)
                                san_list += "DNS:" + std::string(dns_name) + ",";
                        }
                        else if (san->type == GEN_IPADD) {
                            unsigned char* ip_data = (unsigned char*)ASN1_STRING_get0_data(san->d.iPAddress);
                            int ip_len = san->d.iPAddress->length;

                            if (!ip_data || ip_len == 0)
                                continue;

                            std::ostringstream ip_str;
                            if (ip_len == 4) {  // IPv4
                                for (int j = 0; j < ip_len; j++) {
                                    if (j > 0) ip_str << ".";
                                    ip_str << static_cast<int>(ip_data[j]);
                                }
                                san_list += "IP:" + ip_str.str() + ",";
                            }
                            else if (ip_len == 16) {  // IPv6
                                for (int j = 0; j < ip_len; j += 2) {
                                    if (j > 0) ip_str << ":";
                                    ip_str << std::hex << std::setw(2) << std::setfill('0')
                                        << static_cast<int>(ip_data[j]) << static_cast<int>(ip_data[j + 1]);
                                }
                                san_list += "IP:" + ip_str.str() + ",";
                            }
                        }
                        else if (san->type == GEN_EMAIL) {
                            char* email = (char*)ASN1_STRING_get0_data(san->d.rfc822Name);
                            if (email)
                                san_list += "email:" + std::string(email) + ",";
                        }
                        else if (san->type == GEN_URI) {
                            char* uri = (char*)ASN1_STRING_get0_data(san->d.uniformResourceIdentifier);
                            if (uri)
                                san_list += "URI:" + std::string(uri) + ",";
                        }
                    }
                    if (!san_list.empty()) {
                        san_list.pop_back();
                        std::memcpy(check->SUBJECT_ALTERNATIVE_NAME, san_list.c_str(), san_list.size());
                        check->SUBJECT_ALTERNATIVE_NAME_LENGTH = san_list.size();
                    }
                    GENERAL_NAMES_free(san_names);
                }
            }
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }

#pragma endregion

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &check->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", bio, NULL, pkey);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create PKEY context.", bio, NULL, pkey);
    check->IS_KEY_OK = EVP_PKEY_public_check(ctx) > 0;

    BIO_free(bio);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int RsaCheckCA(RSA_CHECK_CA* check) {
    ERR_clear_error();
    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    BIO* cert_bio = BIO_new_mem_buf(check->CERTIFICATE, static_cast<int>(check->CERTIFICATE_LENGTH));

    // 讀取 CA 憑證
    switch (check->CERTIFICATE_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_X509(cert_bio, &cert, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_X509_bio(cert_bio, &cert);
        break;
    default:
        X509_free(cert);
        return handleErrors_asymmetric("Invalid certificate format.", cert_bio, NULL, NULL);
    }

    if (!cert) {
        X509_free(cert);
        return handleErrors_asymmetric("Failed to parse CA certificate.", cert_bio, NULL, NULL);
    }

    // 檢查 CA 憑證是否為 CA
    X509_EXTENSION* ext_bc = (X509_EXTENSION*)X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (!ext_bc) {
        X509_free(cert);
        return handleErrors_asymmetric("CA certificate is missing Basic Constraints extension.", cert_bio, NULL, NULL);
    }

    BASIC_CONSTRAINTS* bc = (BASIC_CONSTRAINTS*)ext_bc;
    if (!bc->ca) {
        X509_free(cert);
        return handleErrors_asymmetric("CA certificate does not have CA:TRUE.", cert_bio, NULL, NULL);
    }

    BASIC_CONSTRAINTS_free(bc);

    // 檢查 Key Usage 是否包含 keyCertSign
    ASN1_BIT_STRING* key_usage = (ASN1_BIT_STRING*)X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
    if (key_usage) {
        int usage_flags = 0;
        for (int i = 0; i < key_usage->length; i++)
            usage_flags = (usage_flags << 8) | key_usage->data[i];

        if (!(usage_flags & 0x0004)) { // 0x0004 = KeyCertSign
            X509_free(cert);
            return handleErrors_asymmetric("CA certificate is missing keyCertSign permission.", cert_bio, NULL, NULL);
        }
        ASN1_BIT_STRING_free(key_usage);
    }
    else {
        X509_free(cert);
        return handleErrors_asymmetric("CA certificate does not contain Key Usage extension.", cert_bio, NULL, NULL);
    }

    // 取得公鑰並檢查其有效性
    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        X509_free(cert);
        return handleErrors_asymmetric("Failed to extract public key from CA certificate.", cert_bio, NULL, NULL);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) {
        X509_free(cert);
        return handleErrors_asymmetric("Failed to create PKEY context.", cert_bio, NULL, NULL, pkey);
    }

    check->IS_KEY_OK = EVP_PKEY_public_check(ctx) > 0;

    // 取得憑證的 Key 長度
    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &check->KEY_LENGTH)) {
        X509_free(cert);
        return handleErrors_asymmetric("Failed to get RSA key length from CA certificate.", cert_bio, NULL, NULL, pkey);
    }

    // 清理資源
    BIO_free(cert_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    X509_free(cert);

    return 0;
}

int RsaCheckCertificate(RSA_CHECK_CERTIFICATE* check) {
    ERR_clear_error();
    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    BIO* cert_bio = BIO_new_mem_buf(check->CERTIFICATE, static_cast<int>(check->CERTIFICATE_LENGTH));
    BIO* priv_bio = BIO_new_mem_buf(check->PRIVATE_KEY, static_cast<int>(check->PRIVATE_KEY_LENGTH));

    switch (check->PRIVATE_KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM: {
        if (check->PEM_PASSWORD == NULL || check->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(priv_bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(priv_bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(check->PEM_PASSWORD)));
        break;
    }
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER: {
        PKCS12* p12 = d2i_PKCS12_bio(priv_bio, NULL);
        PKCS12_parse(p12, check->PKCS12_PASSWORD, &pkey, NULL, NULL);
        break;
    }
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", cert_bio, priv_bio, pkey);
    }

    switch (check->CERTIFICATE_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_X509(cert_bio, &cert, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_X509_bio(cert_bio, &cert);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric cert format.", cert_bio, priv_bio, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse public or private key.", cert_bio, priv_bio, pkey);

    if (1 != EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, &check->KEY_LENGTH))
        return handleErrors_asymmetric("Get Bits (bits) failed.", cert_bio, priv_bio, pkey);

    check->IS_KEY_OK = X509_check_private_key(cert, pkey) > 0;
    return 0;
}

int RsaPemLock(RSA_PEM_LOCK* pem) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(pem->PRIVATE_KEY, static_cast<int>(pem->PRIVATE_KEY_LENGTH));

    switch (pem->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PrivateKey_bio(bio, &pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric private key format.", bio, NULL, pkey);
    }

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key, Please confirm whether the key is in PEM format or the input content is a private key.", bio, NULL, NULL);

    bio = BIO_new(BIO_s_mem());
    const EVP_CIPHER* cipher = GetSymmetryCrypter(pem->PEM_CIPHER, pem->PEM_CIPHER_SIZE, pem->PEM_CIPHER_SEGMENT);
    if (1 != PEM_write_bio_PrivateKey(bio, pkey, cipher, pem->PEM_PASSWORD, pem->PEM_PASSWORD_LENGTH, NULL, NULL))
        return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", bio, NULL, NULL);

    size_t len = BIO_pending(bio);
    if (pem->PRIVATE_KEY == nullptr || pem->PRIVATE_KEY_LENGTH < len)
        pem->PRIVATE_KEY = new unsigned char[len];

    BIO_read(bio, pem->PRIVATE_KEY, len);

    pem->PRIVATE_KEY_LENGTH = len;

    BIO_free_all(bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaPemUnlock(RSA_PEM_UNLOCK* pem) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(pem->PRIVATE_KEY, static_cast<int>(pem->PRIVATE_KEY_LENGTH));

    PEM_read_bio_PrivateKey(bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(pem->PEM_PASSWORD)));

    if (!pkey)
        return handleErrors_asymmetric("Failed to parse private key, Please confirm whether the key is in PEM format or the input content is a private key.", bio, NULL, NULL);

    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    switch (pem->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
            return handleErrors_asymmetric("Unable to write private key in PKCS#8 PEM format to memory.", bio, NULL, pkey);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_PrivateKey_bio(bio, pkey))
            return handleErrors_asymmetric("Unable to write private key in PKCS#8 DER format to memory.", bio, NULL, pkey);
        break;
    default:return handleErrors_asymmetric("Invalid asymmetric key format.", bio, NULL, pkey);
    }
    
    size_t len = BIO_pending(bio);
    if (pem->PRIVATE_KEY == nullptr || pem->PRIVATE_KEY_LENGTH < len)
        pem->PRIVATE_KEY = new unsigned char[len];

    BIO_read(bio, pem->PRIVATE_KEY, len);

    pem->PRIVATE_KEY_LENGTH = len;

    BIO_free_all(bio);
    EVP_PKEY_free(pkey);
    return 0;
}

int RsaEncryption(RSA_ENCRYPT* encrypt) {
    ERR_clear_error();
    
    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(encrypt->PUBLIC_KEY, static_cast<int>(encrypt->PUBLIC_KEY_LENGTH));

    switch (encrypt->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PUBKEY_bio(bio, &pkey);
        break;
    default:return handleErrors_asymmetric("Invalid public key format.", bio, NULL, pkey);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create encryption context.", bio, NULL, pkey);

    if (1 != EVP_PKEY_encrypt_init(ctx))
        return handleErrors_asymmetric("Failed to initialize encryption.", ctx, bio, NULL, pkey, NULL);

    size_t outlen = 0;
    if (1 != EVP_PKEY_encrypt(ctx, NULL, &outlen, encrypt->PLAIN_TEXT, encrypt->PLAIN_TEXT_LENGTH))
        return handleErrors_asymmetric("Failed to determine encrypted output length.", ctx, bio, NULL, pkey, NULL);

    if (1 != EVP_PKEY_encrypt(ctx, encrypt->CIPHER_TEXT, &outlen, encrypt->PLAIN_TEXT, encrypt->PLAIN_TEXT_LENGTH))
        return handleErrors_asymmetric("Encryption failed.", ctx, bio, NULL, pkey, NULL);

    BIO_free_all(bio);
    EVP_PKEY_CTX_free(ctx);
    return static_cast<int>(outlen);
}

int RsaDecryption(RSA_DECRYPT* decrypt) {
    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(decrypt->PRIVATE_KEY, static_cast<int>(decrypt->PRIVATE_KEY_LENGTH));

    switch (decrypt->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (decrypt->PEM_PASSWORD == NULL || decrypt->PEM_PASSWORD_LENGTH <= 0)
            PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);
        else
            PEM_read_bio_PrivateKey(bio, &pkey, PasswordCallback, const_cast<void*>(static_cast<const void*>(decrypt->PEM_PASSWORD)));
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        d2i_PrivateKey_bio(bio, &pkey);
        break;
    default:return handleErrors_asymmetric("Invalid private key format.", bio, NULL, pkey);
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create decryption context.", bio, NULL, pkey);

    if (1 != EVP_PKEY_decrypt_init(ctx))
        return handleErrors_asymmetric("Failed to initialize decryption.", ctx, bio, NULL, pkey, NULL);

    size_t outlen = 0;
    if (1 != EVP_PKEY_decrypt(ctx, NULL, &outlen, decrypt->CIPHER_TEXT, decrypt->CIPHER_TEXT_LENGTH))
        return handleErrors_asymmetric("Failed to determine decrypted output length.", ctx, bio, NULL, pkey, NULL);

    if (1 != EVP_PKEY_decrypt(ctx, decrypt->PLAIN_TEXT, &outlen, decrypt->CIPHER_TEXT, decrypt->CIPHER_TEXT_LENGTH))
        return handleErrors_asymmetric("decryption failed.", ctx, bio, NULL, pkey, NULL);

    BIO_free_all(bio);
    EVP_PKEY_CTX_free(ctx);
    return static_cast<int>(outlen);
}

int RsaSigned(RSA_SIGNED* sign) {
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
    if (type != EVP_PKEY_RSA)
        return handleErrors_asymmetric("Key is not a RSA key.", bio, NULL, pkey);

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

int RsaVerify(RSA_VERIFY* verify) {
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
    if (type != EVP_PKEY_RSA)
        return handleErrors_asymmetric("Key is not a RSA key.", bio, NULL, pkey);

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

int RsaSignCertificate(RSA_SIGN_CSR* sign) {
    ERR_clear_error();

    BIO* req_bio = BIO_new_mem_buf(sign->CSR, static_cast<int>(sign->CSR_LENGTH));
    BIO* ca_cert_bio = BIO_new_mem_buf(sign->PRIVATE_KEY, static_cast<int>(sign->PRIVATE_KEY_LENGTH));
    if (!req_bio || !ca_cert_bio)
        return handleErrors_asymmetric("Failed to create BIO for request and CA certificate.", NULL);

    // 讀取 CSR 和 CA 證書
    X509_REQ* req = PEM_read_bio_X509_REQ(req_bio, NULL, NULL, NULL);
    X509* ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if (!req || !ca_cert)
        return handleErrors_asymmetric("Failed to read CSR or CA certificate.", req_bio, ca_cert_bio, NULL);

    // 讀取 CA 私鑰
    EVP_PKEY* ca_key = EVP_PKEY_new();
    BIO* ca_key_bio = BIO_new_mem_buf(sign->PRIVATE_KEY, static_cast<int>(sign->PRIVATE_KEY_LENGTH));
    if (!ca_key_bio)
        return handleErrors_asymmetric("Failed to create BIO for CA key.", req_bio, ca_cert_bio, NULL);

    if (sign->PEM_PASSWORD == NULL || sign->PEM_PASSWORD_LENGTH <= 0)
        PEM_read_bio_PrivateKey(ca_key_bio, &ca_key, NULL, NULL);
    else
        PEM_read_bio_PrivateKey(ca_key_bio, &ca_key, PasswordCallback, const_cast<void*>(static_cast<const void*>(sign->PEM_PASSWORD)));

    if (!ca_key) {
        BIO_free(ca_key_bio);
        return handleErrors_asymmetric("Failed to read CA private key.", req_bio, ca_cert_bio, NULL);
    }

    // 創建新的 X.509 憑證
    X509* x509 = X509_new();
    if (!x509) {
        BIO_free(ca_key_bio);
        return handleErrors_asymmetric("Failed to create X.509 certificate.", req_bio, ca_cert_bio, ca_key);
    }

    // 設置證書序列號
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // 設置證書有效期
    unsigned long validity_days = sign->VALIDITY_DAYS > 0 ? sign->VALIDITY_DAYS : 365;
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), validity_days * 86400);

    // 設置證書主題
    X509_set_subject_name(x509, X509_REQ_get_subject_name(req));

    // 設置 CA 為發行者
    X509_set_issuer_name(x509, X509_get_subject_name(ca_cert));

    // 設置公鑰
    EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(x509, req_pubkey);
    EVP_PKEY_free(req_pubkey);

    // 簽名算法
    const EVP_MD* md = GetHashCrypter(sign->HASH_ALGORITHM);
    if (!md) {
        BIO_free(ca_key_bio);
        return handleErrors_asymmetric("Invalid or unsupported hash algorithm.", req_bio, ca_cert_bio, ca_key);
    }

    // 簽名憑證
    if (!X509_sign(x509, ca_key, md)) {
        X509_free(x509);
        BIO_free(ca_key_bio);
        return handleErrors_asymmetric("Failed to sign the certificate.", req_bio, ca_cert_bio, ca_key);
    }

    // 將簽發的證書寫入 PEM 或 DER 格式
    BIO* cert_bio = BIO_new(BIO_s_mem());
    switch (sign->KEY_FORMAT) {
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM:
        if (1 != PEM_write_bio_X509(cert_bio, x509)) {
            BIO_free(ca_key_bio);
            BIO_free(ca_cert_bio);
            return handleErrors_asymmetric("Failed to write signed certificate in PEM format.", cert_bio, req_bio, ca_key);
        }
        break;
    case ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER:
        if (1 != i2d_X509_bio(cert_bio, x509)) {
            BIO_free(ca_key_bio);
            BIO_free(ca_cert_bio);
            return handleErrors_asymmetric("Failed to write signed certificate in DER format.", cert_bio, req_bio, ca_key);
        }
        break;
    default:
        BIO_free(ca_key_bio);
        BIO_free(ca_cert_bio);
        return handleErrors_asymmetric("Invalid certificate format.", cert_bio, req_bio, ca_key);
    }

    // 讀取生成的證書
    size_t cert_len = BIO_pending(cert_bio);
    if (sign->CERTIFICATE == nullptr || sign->CERTIFICATE_LENGTH < cert_len)
        sign->CERTIFICATE = new unsigned char[cert_len];

    BIO_read(cert_bio, sign->CERTIFICATE, cert_len);
    sign->CERTIFICATE_LENGTH = cert_len;

    // 釋放資源
    BIO_free(cert_bio);
    BIO_free(req_bio);
    BIO_free(ca_cert_bio);
    BIO_free(ca_key_bio);
    X509_free(x509);
    EVP_PKEY_free(ca_key);
    X509_REQ_free(req);
    X509_free(ca_cert);

    return 0;
}