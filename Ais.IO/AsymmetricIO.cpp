#include "pch.h"
#include "AsymmetricIO.h"

int handleErrors_asymmetric(std::string message, EVP_PKEY_CTX* ctx) {
    std::cerr << "ERROR: " << message << std::endl;
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    return -1;
}

int handleErrors_asymmetric(std::string message, BIO* pub, BIO* priv, EVP_PKEY* pkey) {
    std::cerr << "ERROR: " << message << std::endl;
    if (pub != NULL)
        BIO_free(pub);
    if (priv != NULL)
        BIO_free(priv);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    return -1;
}