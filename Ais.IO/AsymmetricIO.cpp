#include "pch.h"
#include "AsymmetricIO.h"

int PasswordCallback(char* buf, int size, int rwflag, void* userdata) {
    const char* password = static_cast<const char*>(userdata);
    int password_length = static_cast<int>(strlen(password));

    if (password_length > size)
        return 0;

    memcpy(buf, password, password_length);
    return password_length;
}

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

int handleErrors_asymmetric(std::string message, BIO* pub, BIO* priv, EVP_PKEY* pkey, EVP_PKEY* pkey2) {
    std::cerr << "ERROR: " << message << std::endl;
    if (pub != NULL)
        BIO_free(pub);
    if (priv != NULL)
        BIO_free(priv);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pkey2 != NULL)
        EVP_PKEY_free(pkey2);
    return -1;
}

int handleErrors_asymmetric(std::string message, EVP_PKEY_CTX* ctx, BIO* pub, BIO* priv, EVP_PKEY* pkey, EVP_PKEY* pkey2) {
    std::cerr << "ERROR: " << message << std::endl;
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (pub != NULL)
        BIO_free(pub);
    if (priv != NULL)
        BIO_free(priv);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pkey2 != NULL)
        EVP_PKEY_free(pkey2);
    return -1;
}