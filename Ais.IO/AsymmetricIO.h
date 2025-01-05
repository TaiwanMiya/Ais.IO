#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define ASYMMETRICIO_API __declspec(dllexport)
#else
#define ASYMMETRICIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <ctime>
#include <cstring>
#include <random>

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

enum ASYMMETRIC_KEY_PKCS {
    ASYMMETRIC_KEY_PKCS8 = 0,
    ASYMMETRIC_KEY_PKCS10 = 1,
    ASYMMETRIC_KEY_PKCS12 = 2,
};

int PasswordCallback(char* buf, int size, int rwflag, void* userdata);
int handleErrors_asymmetric(std::string message, EVP_PKEY_CTX* ctx);
int handleErrors_asymmetric(std::string message, BIO* pub, BIO* priv, EVP_PKEY* pkey);
int handleErrors_asymmetric(std::string message, BIO* pub, BIO* priv, EVP_PKEY* pkey, EVP_PKEY* pkey2);
int handleErrors_asymmetric(std::string message, EVP_PKEY_CTX* ctx, BIO* pub, BIO* priv, EVP_PKEY* pkey, EVP_PKEY* pkey2);