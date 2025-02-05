#pragma once

/* Dll Export Define */
#ifndef BINARYIO_EXPORTS
#ifdef _WIN32
#define ECCIO_API __declspec(dllexport)
#else
#define ECCIO_API
#endif
#endif

#ifndef EXTERN
#define EXT extern "C"
#endif

#include <cstddef>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/ecerr.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/pkcs12.h>
#include <openssl/asn1.h>
#include <cstring>
#include <iostream>
#include <random>
#include <ctime>
#include <algorithm>
#include <string>
#include "AsymmetricIO.h"
#include "SymmetryIO.h"
#include "HashIO.h"

enum ECC_CURVE : int {
    ECC_PRIME_192_V1 = NID_X9_62_prime192v1,                    // 409
    ECC_PRIME_192_V2 = NID_X9_62_prime192v2,                    // 410
    ECC_PRIME_192_V3 = NID_X9_62_prime192v3,                    // 411
    ECC_PRIME_239_V1 = NID_X9_62_prime239v1,                    // 412
    ECC_PRIME_239_V2 = NID_X9_62_prime239v2,                    // 413
    ECC_PRIME_239_V3 = NID_X9_62_prime239v3,                    // 414
    ECC_PRIME_256_V1 = NID_X9_62_prime256v1,                    // 415
    ECC_C2PNB_163_V1 = NID_X9_62_c2pnb163v1,                    // 684
    ECC_C2PNB_163_V2 = NID_X9_62_c2pnb163v2,                    // 685
    ECC_C2PNB_163_V3 = NID_X9_62_c2pnb163v3,                    // 686
    ECC_C2PNB_176_V1 = NID_X9_62_c2pnb176v1,                    // 687
    ECC_C2TNB_191_V1 = NID_X9_62_c2tnb191v1,                    // 688
    ECC_C2TNB_191_V2 = NID_X9_62_c2tnb191v2,                    // 689
    ECC_C2TNB_191_V3 = NID_X9_62_c2tnb191v3,                    // 690
    ECC_C2PNB_208_W1 = NID_X9_62_c2pnb208w1,                    // 693
    ECC_C2TNB_239_V1 = NID_X9_62_c2tnb239v1,                    // 694
    ECC_C2TNB_239_V2 = NID_X9_62_c2tnb239v2,                    // 695
    ECC_C2TNB_239_V3 = NID_X9_62_c2tnb239v3,                    // 696
    ECC_C2PNB_272_W1 = NID_X9_62_c2pnb272w1,                    // 699
    ECC_C2PNB_304_W1 = NID_X9_62_c2pnb304w1,                    // 700
    ECC_C2TNB_359_V1 = NID_X9_62_c2tnb359v1,                    // 701
    ECC_C2PNB_368_W1 = NID_X9_62_c2pnb368w1,                    // 702
    ECC_C2TNB_431_R1 = NID_X9_62_c2tnb431r1,                    // 703
    ECC_SECP_112_R1 = NID_secp112r1,                            // 704
    ECC_SECP_112_R2 = NID_secp112r2,                            // 705
    ECC_SECP_128_R1 = NID_secp128r1,                            // 706
    ECC_SECP_128_R2 = NID_secp128r2,                            // 707
    ECC_SECP_160_K1 = NID_secp160k1,                            // 708
    ECC_SECP_160_R1 = NID_secp160r1,                            // 709
    ECC_SECP_160_R2 = NID_secp160r2,                            // 710
    ECC_SECP_192_K1 = NID_secp192k1,                            // 711
    ECC_SECP_224_K1 = NID_secp224k1,                            // 712
    ECC_SECP_224_R1 = NID_secp224r1,                            // 713
    ECC_SECP_256_K1 = NID_secp256k1,                            // 714
    ECC_SECP_384_R1 = NID_secp384r1,                            // 715
    ECC_SECP_521_R1 = NID_secp521r1,                            // 716
    ECC_SECT_113_R1 = NID_sect113r1,                            // 717
    ECC_SECT_113_R2 = NID_sect113r2,                            // 718
    ECC_SECT_131_R1 = NID_sect131r1,                            // 719
    ECC_SECT_131_R2 = NID_sect131r2,                            // 720
    ECC_SECT_163_K1 = NID_sect163k1,                            // 721
    ECC_SECT_163_R1 = NID_sect163r1,                            // 722
    ECC_SECT_163_R2 = NID_sect163r2,                            // 723
    ECC_SECT_193_R1 = NID_sect193r1,                            // 724
    ECC_SECT_193_R2 = NID_sect193r2,                            // 725
    ECC_SECT_233_K1 = NID_sect233k1,                            // 726
    ECC_SECT_233_R1 = NID_sect233r1,                            // 727
    ECC_SECT_239_K1 = NID_sect239k1,                            // 728
    ECC_SECT_283_K1 = NID_sect283k1,                            // 729
    ECC_SECT_283_R1 = NID_sect283r1,                            // 730
    ECC_SECT_409_K1 = NID_sect409k1,                            // 731
    ECC_SECT_409_R1 = NID_sect409r1,                            // 732
    ECC_SECT_571_K1 = NID_sect571k1,                            // 733
    ECC_SECT_571_R1 = NID_sect571r1,                            // 734
    ECC_WAP_WSG_IDM_ECID_WTLS1 = NID_wap_wsg_idm_ecid_wtls1,    // 735
    ECC_WAP_WSG_IDM_ECID_WTLS3 = NID_wap_wsg_idm_ecid_wtls3,    // 736
    ECC_WAP_WSG_IDM_ECID_WTLS4 = NID_wap_wsg_idm_ecid_wtls4,    // 737
    ECC_WAP_WSG_IDM_ECID_WTLS5 = NID_wap_wsg_idm_ecid_wtls5,    // 738
    ECC_WAP_WSG_IDM_ECID_WTLS6 = NID_wap_wsg_idm_ecid_wtls6,    // 739
    ECC_WAP_WSG_IDM_ECID_WTLS7 = NID_wap_wsg_idm_ecid_wtls7,    // 740
    ECC_WAP_WSG_IDM_ECID_WTLS8 = NID_wap_wsg_idm_ecid_wtls8,    // 741
    ECC_WAP_WSG_IDM_ECID_WTLS9 = NID_wap_wsg_idm_ecid_wtls9,    // 742
    ECC_WAP_WSG_IDM_ECID_WTLS10 = NID_wap_wsg_idm_ecid_wtls10,  // 743
    ECC_WAP_WSG_IDM_ECID_WTLS11 = NID_wap_wsg_idm_ecid_wtls11,  // 744
    ECC_WAP_WSG_IDM_ECID_WTLS12 = NID_wap_wsg_idm_ecid_wtls12,  // 745
    ECC_OAKLEY_EC2N_3 = NID_ipsec3,                             // 749
    ECC_OAKLEY_EC2N_4 = NID_ipsec4,                             // 750
    ECC_BRAINPOOL_P160_R1 = NID_brainpoolP160r1,                // 921
    ECC_BRAINPOOL_P160_T1 = NID_brainpoolP160t1,                // 922
    ECC_BRAINPOOL_P192_R1 = NID_brainpoolP192r1,                // 923
    ECC_BRAINPOOL_P192_T1 = NID_brainpoolP192t1,                // 924
    ECC_BRAINPOOL_P224_R1 = NID_brainpoolP224r1,                // 925
    ECC_BRAINPOOL_P224_T1 = NID_brainpoolP224t1,                // 926
    ECC_BRAINPOOL_P256_R1 = NID_brainpoolP256r1,                // 927
    ECC_BRAINPOOL_P256_T1 = NID_brainpoolP256t1,                // 928
    ECC_BRAINPOOL_P320_R1 = NID_brainpoolP320r1,                // 929
    ECC_BRAINPOOL_P320_T1 = NID_brainpoolP320t1,                // 930
    ECC_BRAINPOOL_P384_R1 = NID_brainpoolP384r1,                // 931
    ECC_BRAINPOOL_P384_T1 = NID_brainpoolP384t1,                // 932
    ECC_BRAINPOOL_P512_R1 = NID_brainpoolP512r1,                // 933
    ECC_BRAINPOOL_P512_T1 = NID_brainpoolP512t1,                // 934
};

struct ECC_PARAMETERS {
    ECC_CURVE CURVE_NID;
    unsigned char* X;
    unsigned char* Y;
    unsigned char* EXP;
    size_t X_LENGTH;
    size_t Y_LENGTH;
    size_t EXP_LENGTH;
};

struct ECC_KEY_PAIR {
    ECC_CURVE CURVE_NID;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct ECC_EXPORT {
    ECC_CURVE CURVE_NID;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* X;
    unsigned char* Y;
    unsigned char* EXP;
    size_t X_LENGTH;
    size_t Y_LENGTH;
    size_t EXP_LENGTH;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct ECC_EXTRACT_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT PRIVATE_KEY_FORMAT;
    const ASYMMETRIC_KEY_FORMAT PUBLIC_KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
};

struct ECC_CHECK_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    size_t PUBLIC_KEY_LENGTH;
    bool IS_KEY_OK;
    ECC_CURVE CURVE_NID;
};

struct ECC_CHECK_PRIVATE_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    bool IS_KEY_OK;
    ECC_CURVE CURVE_NID;
};

EXT ECCIO_API int EccGetParametersLength(ECC_PARAMETERS* params);
EXT ECCIO_API int EccGetKeyLength(ECC_KEY_PAIR* params);
EXT ECCIO_API int EccGenerateParameters(ECC_PARAMETERS* params);
EXT ECCIO_API int EccGenerateKeys(ECC_KEY_PAIR* generate);
EXT ECCIO_API int EccExportParameters(ECC_EXPORT* params);
EXT ECCIO_API int EccExportKeys(ECC_EXPORT* params);
EXT ECCIO_API int EccExtractPublicKey(ECC_EXTRACT_PUBLIC_KEY* params);
EXT ECCIO_API int EccCheckPublicKey(ECC_CHECK_PUBLIC_KEY* check);
EXT ECCIO_API int EccCheckPrivateKey(ECC_CHECK_PRIVATE_KEY* check);