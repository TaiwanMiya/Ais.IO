#include "pch.h"
#include "RsaIO.h"

int GenerateRsaParameters(RSA_PARAMETERS* params) {
    ERR_clear_error();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx)
        return handleErrors_asymmetric("Failed to create RSA key context.", ctx);

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        return handleErrors_asymmetric("Failed to initialize RSA key generation.", ctx);

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, params->KEY_SIZE) <= 0)
        return handleErrors_asymmetric("Failed to set RSA key size.", ctx);

    EVP_PKEY* pkey = EVP_RSA_gen(params->KEY_SIZE);

    if (!pkey)
        return handleErrors_asymmetric("RSA key generate Pair failed.", ctx);

    /*if (EVP_PKEY_generate(ctx, &pkey) <= 0)
        return handleErrors_asymmetric("Failed to generate RSA key.", ctx);*/

    EVP_PKEY_CTX_free(ctx);

    std::cout << "Start Paramters." << std::endl;

    BIGNUM* bn = NULL;
    BIO* pub_bio = BIO_new(BIO_s_mem());
    BIO* priv_bio = BIO_new(BIO_s_mem());

    // 提取 Modulus (n)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "n", &bn) <= 0)
        return handleErrors_asymmetric("Get Modulus (n) failed.", NULL, NULL, pkey);
    params->MODULUS_LENGTH = BN_num_bytes(bn);
    params->MODULUS = new unsigned char[params->MODULUS_LENGTH];
    BN_bn2bin(bn, params->MODULUS);
    BN_free(bn);
    std::cout << "Modulus Success." << std::endl;

    // 提取 Public Exponent (e)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "e", &bn) <= 0)
        return handleErrors_asymmetric("Get Public Exponent (e) failed.", NULL, NULL, pkey);
    params->PUBLIC_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PUBLIC_EXPONENT = new unsigned char[params->PUBLIC_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PUBLIC_EXPONENT);
    BN_free(bn);
    std::cout << "Public Exponent Success." << std::endl;

    // 提取 Private Exponent (d)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "d", &bn) <= 0)
        return handleErrors_asymmetric("Get Private Exponent (d) failed.", NULL, NULL, pkey);
    params->PRIVATE_EXPONENT_LENGTH = BN_num_bytes(bn);
    params->PRIVATE_EXPONENT = new unsigned char[params->PRIVATE_EXPONENT_LENGTH];
    BN_bn2bin(bn, params->PRIVATE_EXPONENT);
    BN_free(bn);
    std::cout << "Private Exponent Success." << std::endl;

    // 提取 Prime1 (p)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "p", &bn) <= 0)
        return handleErrors_asymmetric("Get Prime1 (p) failed.", NULL, NULL, pkey);
    params->PRIME1_LENGTH = BN_num_bytes(bn);
    params->PRIME1 = new unsigned char[params->PRIME1_LENGTH];
    BN_bn2bin(bn, params->PRIME1);
    BN_free(bn);
    std::cout << "Prime1 Success." << std::endl;

    // 提取 Prime2 (q)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "q", &bn) <= 0)
        return handleErrors_asymmetric("Get Prime2 (q) failed.", NULL, NULL, pkey);
    params->PRIME2_LENGTH = BN_num_bytes(bn);
    params->PRIME2 = new unsigned char[params->PRIME2_LENGTH];
    BN_bn2bin(bn, params->PRIME2);
    BN_free(bn);
    std::cout << "Prime2 Success." << std::endl;

    // 提取 Exponent1 (dmp1)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "dmp1", &bn) <= 0)
        return handleErrors_asymmetric("Get Exponent1 (dmp1) failed.", NULL, NULL, pkey);
    params->EXPONENT1_LENGTH = BN_num_bytes(bn);
    params->EXPONENT1 = new unsigned char[params->EXPONENT1_LENGTH];
    BN_bn2bin(bn, params->EXPONENT1);
    BN_free(bn);
    std::cout << "Exponent1 Success." << std::endl;

    // 提取 Exponent2 (dmq1)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "dmq1", &bn) <= 0)
        return handleErrors_asymmetric("Get Exponent2 (dmq1) failed.", NULL, NULL, pkey);
    params->EXPONENT2_LENGTH = BN_num_bytes(bn);
    params->EXPONENT2 = new unsigned char[params->EXPONENT2_LENGTH];
    BN_bn2bin(bn, params->EXPONENT2);
    BN_free(bn);
    std::cout << "Exponent2 Success." << std::endl;

    // 提取 Coefficient (iqmp)
    bn = BN_new();
    if (EVP_PKEY_get_bn_param(pkey, "iqmp", &bn) <= 0)
        return handleErrors_asymmetric("Get Coefficient (iqmp) failed.", NULL, NULL, pkey);
    params->COEFFICIENT_LENGTH = BN_num_bytes(bn);
    params->COEFFICIENT = new unsigned char[params->COEFFICIENT_LENGTH];
    BN_bn2bin(bn, params->COEFFICIENT);
    BN_free(bn);
    std::cout << "Coefficient Success." << std::endl;

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
    
    /*EVP_PKEY_print_public(pub_bio, pkey, 4, nullptr);
    EVP_PKEY_print_private(priv_bio, pkey, 4, nullptr);*/

    /*std::string pubkeyStr(2056, 0);
    std::cout << "pub_bio num bytes read: " << BIO_read(pub_bio, pubkeyStr.data(), pubkeyStr.size()) << std::endl;
    std::cout << "pub_bio keyStr: " << pubkeyStr << std::endl;
    std::string privkeyStr(2056, 0);
    std::cout << "priv_bio num bytes read: " << BIO_read(pub_bio, privkeyStr.data(), privkeyStr.size()) << std::endl;
    std::cout << "priv_bio keyStr: " << privkeyStr << std::endl;*/

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