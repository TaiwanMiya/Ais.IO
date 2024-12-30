#include "TestHeader.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <iostream>

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

struct RSA_PARAMETERS {
    const size_t KEY_SIZE;
    unsigned char* MODULUS;
    unsigned char* PUBLIC_EXPONENT;
    unsigned char* PRIVATE_EXPONENT;
    unsigned char* FACTOR1;
    unsigned char* FACTOR2;
    unsigned char* EXPONENT1;
    unsigned char* EXPONENT2;
    unsigned char* COEFFICIENT;
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
};

struct RSA_KEY_PAIR {
    const size_t KEY_SIZE;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

struct EXPORT_RSA_PARAMTERS {
    unsigned char* MODULUS;
    unsigned char* PUBLIC_EXPONENT;
    unsigned char* PRIVATE_EXPONENT;
    unsigned char* FACTOR1;
    unsigned char* FACTOR2;
    unsigned char* EXPONENT1;
    unsigned char* EXPONENT2;
    unsigned char* COEFFICIENT;
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const size_t PUBLIC_KEY_LENGTH;
    const size_t PRIVATE_KEY_LENGTH;
};

struct EXPORT_RSA_KEY {
    unsigned char* MODULUS;
    unsigned char* PUBLIC_EXPONENT;
    unsigned char* PRIVATE_EXPONENT;
    unsigned char* FACTOR1;
    unsigned char* FACTOR2;
    unsigned char* EXPONENT1;
    unsigned char* EXPONENT2;
    unsigned char* COEFFICIENT;
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

#pragma region RsaIO
typedef int (*GetRsaParametersLength)(RSA_PARAMETERS*);
typedef int (*GenerateRsaParameters)(RSA_PARAMETERS*);
typedef int (*GenerateRsaKeys)(RSA_KEY_PAIR*);
typedef int (*ExportRsaParametersFromKeys)(EXPORT_RSA_PARAMTERS*);
typedef int (*ExportRsaKeysFromParameters)(EXPORT_RSA_KEY*);

GetRsaParametersLength GetRsaParametersLength_Func = (GetRsaParametersLength)GET_PROC_ADDRESS(Lib, "GetRsaParametersLength");
GenerateRsaParameters GenerateRsaParameters_Func = (GenerateRsaParameters)GET_PROC_ADDRESS(Lib, "GenerateRsaParameters");
GenerateRsaKeys GenerateRsaKeys_Func = (GenerateRsaKeys)GET_PROC_ADDRESS(Lib, "GenerateRsaKeys");
ExportRsaParametersFromKeys ExportRsaParametersFromKeys_Func = (ExportRsaParametersFromKeys)GET_PROC_ADDRESS(Lib, "ExportRsaParametersFromKeys");
ExportRsaKeysFromParameters ExportRsaKeysFromParameters_Func = (ExportRsaKeysFromParameters)GET_PROC_ADDRESS(Lib, "ExportRsaKeysFromParameters");
#pragma endregion

void Test_GetRsaParametersLength() {
    RSA_PARAMETERS paramters = {
        4096,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    GetRsaParametersLength_Func(&paramters);
    std::cout << "Modulus (n) Size:" << paramters.MODULUS_LENGTH << std::endl;
    std::cout << "Public Exponent (e) Size:" << paramters.PUBLIC_EXPONENT_LENGTH << std::endl;
    std::cout << "Private Exponent (d) Size:" << paramters.PRIVATE_EXPONENT_LENGTH << std::endl;
    std::cout << "Factor1 (p) Size:" << paramters.FACTOR1_LENGTH << std::endl;
    std::cout << "Factor2 (p) Size:" << paramters.FACTOR2_LENGTH << std::endl;
    std::cout << "Exponent1 (dmp1) Size:" << paramters.EXPONENT1_LENGTH << std::endl;
    std::cout << "Exponent2 (dmp2) Size:" << paramters.EXPONENT2_LENGTH << std::endl;
    std::cout << "Coefficient (iqmp) Size:" << paramters.COEFFICIENT_LENGTH << std::endl;
}

void Test_GenerateRsaParameters() {
    RSA_PARAMETERS paramters = {
        2048,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };

    GenerateRsaParameters_Func(&paramters);

    std::vector<char> paramtersString;
    paramtersString.resize(paramters.MODULUS_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.MODULUS, paramters.MODULUS_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Modulus (n), Size:" << paramters.MODULUS_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.PUBLIC_EXPONENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PUBLIC_EXPONENT, paramters.PUBLIC_EXPONENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Public Exponent (e), Size:" << paramters.PUBLIC_EXPONENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.PRIVATE_EXPONENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PRIVATE_EXPONENT, paramters.PRIVATE_EXPONENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Private Exponent (d), Size:" << paramters.PRIVATE_EXPONENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.FACTOR1_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.FACTOR1, paramters.FACTOR1_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor1 (p), Size:" << paramters.FACTOR1_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.FACTOR2_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.FACTOR2, paramters.FACTOR2_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor2 (p), Size:" << paramters.FACTOR2_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.EXPONENT1_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.EXPONENT1, paramters.EXPONENT1_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent1 (dmp1), Size:" << paramters.EXPONENT1_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.EXPONENT2_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.EXPONENT2, paramters.EXPONENT2_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent2 (dmp2), Size:" << paramters.EXPONENT2_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.COEFFICIENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.COEFFICIENT, paramters.COEFFICIENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Coefficient (iqmp), Size:" << paramters.COEFFICIENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();
}

void Test_RsaGenerate() {
    for (int i = 0; i < 1; i++) {
        RSA_KEY_PAIR keypair = {
            2048,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
            NULL,
            NULL,
            0,
            0,
        };
        GenerateRsaKeys_Func(&keypair);

        std::cout << "PEM - [" << i << "]" << std::endl;
        std::cout << reinterpret_cast<char*>(keypair.PUBLIC_KEY) << std::endl;
        std::cout << reinterpret_cast<char*>(keypair.PRIVATE_KEY) << std::endl;
    }

    for (int i = 0; i < 1; i++) {
        RSA_KEY_PAIR keypair = {
            2048,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
            NULL,
            NULL,
            0,
            0,
        };
        GenerateRsaKeys_Func(&keypair);

        std::cout << "DER - [" << i << "]" << std::endl;
        char* pubString = new char[keypair.PUBLIC_KEY_LENGTH * 2 + 1] {};
        char* privString = new char[keypair.PRIVATE_KEY_LENGTH * 2 + 1] {};
        Base16Encode_Func(keypair.PUBLIC_KEY, keypair.PUBLIC_KEY_LENGTH, pubString, keypair.PUBLIC_KEY_LENGTH * 2 + 1);
        Base16Encode_Func(keypair.PRIVATE_KEY, keypair.PRIVATE_KEY_LENGTH, privString, keypair.PRIVATE_KEY_LENGTH * 2 + 1);
        std::cout << pubString << std::endl;
        std::cout << privString << std::endl;
        std::cout << "" << std::endl;
    }
}

void Test_ExportRsaParametersFromKeys() {
    std::string derPublicKey = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100C3779422AAF0CB7740E8EA3664AE204B24A55FFBB5154CC24B43CA2D3917B957E01912185D1E6DC50E7F1F3DBD291FB5A3DFAC92B9F0833AE10C363D2D47BF1B43F42B3991AF9B4A3A4CBEF8CA6ABF1CAEA7659F8AD8E5098C2172D0DE6C61D11926C2F5BA6F1676F52058BC9126A8DF0E4DD6637383D86BFC8A44319017E9AD851DFC302F24895E7E757B0A9E5AD8E354F9B4888D7BFF55FB93298E1EB21F87040BED2E1A97C2BE5C1CD691F1BC1D114E21A4DF1891CDB84277A921B042E39F8E5DE3697F9C256672B3DC4F31B49B864CC29D7BB3F3B0630D15CCCB4DA0BA086C115E9AFB8645E384C3205E1363A3BFD0856F1EB012D8B19901B62D86F581E90203010001";
    std::string derPrivateKey = "308204A10201000282010100C3779422AAF0CB7740E8EA3664AE204B24A55FFBB5154CC24B43CA2D3917B957E01912185D1E6DC50E7F1F3DBD291FB5A3DFAC92B9F0833AE10C363D2D47BF1B43F42B3991AF9B4A3A4CBEF8CA6ABF1CAEA7659F8AD8E5098C2172D0DE6C61D11926C2F5BA6F1676F52058BC9126A8DF0E4DD6637383D86BFC8A44319017E9AD851DFC302F24895E7E757B0A9E5AD8E354F9B4888D7BFF55FB93298E1EB21F87040BED2E1A97C2BE5C1CD691F1BC1D114E21A4DF1891CDB84277A921B042E39F8E5DE3697F9C256672B3DC4F31B49B864CC29D7BB3F3B0630D15CCCB4DA0BA086C115E9AFB8645E384C3205E1363A3BFD0856F1EB012D8B19901B62D86F581E9020301000102820100254D4BEF2850731ED72F3F1729847CABE70634B5434F5DFA1D9AEB0A3243142D91A95C744B1E55A22EFEBD00F532356ADA6995DD6AAF541509370236411AF0AD7A5DCB519ECAD090895547A86DB93313758AAB1A4DAB5CA79DE08694B4632DF40DCED0F6AED9C1283AA305F36275ABFF721EBEBFF2E516F9F5B372C488A3905E89207545C4A60ECF0C87035DCC118A3B1278826579FE628E8D23481A1B441F702EFB9C78C642A65E718829A94F630EB18F6CEFF566E1A261D0DB079ED249CDC64CC84E2095B229385890DFE94168FF57DC18F2EC1A961ADC7F1BB141175BF411830303E55F8EA3BA94E4E66648A174E30867FD758B1864761E01FC4E4E78725F0281807DA71DC785879AFF8A327F8695227480AA1A48B60F3CD735FCE4C4163688E725369CDD83C320873287D4A2CA4F000F3B81B49B76787A3F76264DE974FA85E18206F7E803B511820033F1887E703FFFA66F7038414BEE732DEE5DCF1EB2C772AE83AF8606A380BE15F87CD029CD9A1A0F6C64A5853051E27F15BF121D9EB602FB0281803F405D608AB37ED3445FF9422FB25946B66B8EDDB22C86B78307D7EEB0AC812F7B36DA9538F3486B0A3AB12CCE86BD2D38F5A4C341EB4E5E615498442F08CB6686F8201E425D7BAA879BC03FBA9498191B7C0833F3DA2F5870B96358B3C897DD0632128A2B87CB03265B2C66A695E44E4D3BF256F97A9989B65FCACF3E2E26EE0281803D04CFB2BEDE86D6AEE6835BF981584C295CD476E43FA6FFD95E880B1AEC806477F1A1569D4CF9CBBE9AA4803AFC3A6D6AC663E392F97DB5476BA0994F03DF1F67F9B08FBFED79E481B03BB19C8FE443C46ABB3009819366C42B5FEDFC2B7343A087A057E77B0EC042E5E3F206E1E88893E5B4A0BEA234984405EA74EE1968AB0281805FB43A6B42D1017223418E0F770D9CA66574DE64807F82638528E0F632EA12BF53C85B66216133B6AFA758CD7110429999F4DE653E499F26B9C4C3ACAF669781D6A13E5CE2BCA80AADE1598BAB36E5D0501C2727279E33EDA30CC642329E38B73C2DFC902314D7C2F0FEABCCB7A1A376C998C5A6B65FF554E58BAB08D8F0333F02818100960A917664576141085D33B15476C2AC0266337D7608A3A20A2A81606435863EA44D430B4356176B64B6E6198FBEB4F83767B8DDFEE417E46E740C2E7A20FBEBD30E68C47EE9688D099B1C2F676B46DC85E9A34DA6FBDF42ECF650D4D21E12B1535365DEA17EC76D32CD1B3BDFA085CB4FFAF6D02CB18C591F3C2332F1B2E0F1";
    std::string pemPublicKey = 
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBZwV+J3hELE2gi34Xv2od\n"
    "X1Xr1u6AYhB6TCZDQ/usozma1NPdyXHLkIM6N97uHbzw2YiRRwjlH5pqAYpnUCVF\n"
    "oOzgZhiWJeA3kwLGoe4HD4BMo3RB3RUkLA2fToqtJLzDPKY6dONyQd+F+uoq5f5L\n"
    "j3FPM0d0Ec5xR4dxSU/CvBPFWSkIOJ5TX0S9WMW73CDfvatUHEAvPVg3JmmCp/CH\n"
    "JeP+Z6mYbPPtIeIGFKLagbf3IotGNZrpXj3PZrCaSYZXbZvK4SUDYN3in7FaU5tS\n"
    "LzK6Var2iGjFzlvSf6yd7SqfAdQBjgCtj7yJW5vb167sOJVe6lmvACF/l7XcTbqz\n"
    "AAIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
    "";
    std::string pemPrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQFnBX4neEQsTaCL\n"
    "fhe/ah1fVevW7oBiEHpMJkND+6yjOZrU093JccuQgzo33u4dvPDZiJFHCOUfmmoB\n"
    "imdQJUWg7OBmGJYl4DeTAsah7gcPgEyjdEHdFSQsDZ9Oiq0kvMM8pjp043JB34X6\n"
    "6irl/kuPcU8zR3QRznFHh3FJT8K8E8VZKQg4nlNfRL1YxbvcIN+9q1QcQC89WDcm\n"
    "aYKn8Icl4/5nqZhs8+0h4gYUotqBt/cii0Y1mulePc9msJpJhldtm8rhJQNg3eKf\n"
    "sVpTm1IvMrpVqvaIaMXOW9J/rJ3tKp8B1AGOAK2PvIlbm9vXruw4lV7qWa8AIX+X\n"
    "tdxNurMAAgMBAAECggEAGVkG4LTNN1gIIh7tLukSe/9HJHbDwUeON6G6FMZfVJ/N\n"
    "62df9DdibtPJdn1m/Y2byIhIfRGMRnWm3QjAEu3XwFeMxj+5GoP9lRyvIReAxOsi\n"
    "pTdFYXu1ggArlcQm9kruTGH8HG+NA4CZiaQPawsXOpa1zpizP6myr7q9k0IOqPt2\n"
    "Hf2C85i4Aw94jS+Ygwmuk6mKlXj2Ai0jtaHbXA/RxPvgx0HmDDO11PMZv+fKIIpj\n"
    "FAt8BcSQT6Z1OR9ggzCPRiwKsJip+SUXuTYbhwbnOMC5DZ5/ij0OvVZiavzdgKVb\n"
    "dX1wjnvaoN5j/YB/IEWq07/roIVRwZ9DzyaUanAcWQKBggCzQU/86dJK0hmqaQtu\n"
    "KemxU2TLr8kZ/divQ/MryKd0hGX5ufqQqvK+LHfXBD5za6Djo/4srGYwArvytgaz\n"
    "GSTis4ut9Wwdq0rNJcKH5SviG+aBxGivcDNPZ/MS9kQSwOvHASXwY3y1Rsv9tlD+\n"
    "VK5YazvGZGhVKOp61K5WU9jS8AACgYF70sTBRPAJT80epqY1m7rYgH+r3zluNJvY\n"
    "KUYoFydk1LfSCwPBd5AsggC+4s8L5IFGW/Wfwy/PA9IRvftOSYNJgjGRWe+jkk9i\n"
    "7Tw3MlN0ozu5BUiY+BRkiFwkmNcCmweYDUV+AwheTAdoSAyZAPHUOjqPC7GSZh8D\n"
    "ep6iF9ANvwACgYIA/9dQC0wRRvPRL1H0HO6b9MRgsNBVU7r9BwvbI7tbwE88YV/0\n"
    "R04YCFSDoPlqLDOB8wFVR7QBf+fTqtny7z8Ma4fQnxUhuO0R/3pekyvqswi7t+07\n"
    "HvAaM9ibuAHOV1TH7JKLMMlP77MmZMDpqaqEWo2nJohTFTM3Km3W3zqNj94AAoGB\n"
    "AL8GGiL54P3mgq7XYMd2srUzqaJLJzLeQmWcUUCh+wC8I84VTuv4D4MWkrya97mO\n"
    "ifHfI6T4XT9melwEWEh4u9mNHw1GvITGZwyOckmiYJuWw+6o95m/tiq31AgteHNW\n"
    "BZhEaXDRAUDvZtaFh63FnWWUKTHDz+JdEeyo39CvlEs8AoGAFJXVrploo8kfL+A5\n"
    "CbvhsPckT4TC1LG8YrQeu8sO9eJ1heIPD1Xn55DjteiGyPYnS/TJ67hhUpTupP2J\n"
    "XEckqZYJGjFveCElKQgHg0Kp09kAipjrhwyfwoeSP1m2SKE2HYRzTngaVk7tNQ8Y\n"
    "EhsPkl7Cv3Ds52JQVAOd2/QNoV0=\n"
    "-----END PRIVATE KEY-----\n"
    "";
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    /*publicKey.resize(derPublicKey.size() / 2);
    privateKey.resize(derPrivateKey.size() / 2);
    Base16Decode_Func(derPublicKey.c_str(), derPublicKey.size(), publicKey.data(), publicKey.size());
    Base16Decode_Func(derPrivateKey.c_str(), derPrivateKey.size(), privateKey.data(), privateKey.size());*/
    publicKey.resize(pemPublicKey.size());
    privateKey.resize(pemPrivateKey.size());
    publicKey.assign(pemPublicKey.begin(), pemPublicKey.end());
    privateKey.assign(pemPrivateKey.begin(), pemPrivateKey.end());
    EXPORT_RSA_PARAMTERS paramters = {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };
    ExportRsaParametersFromKeys_Func(&paramters);

    std::vector<char> paramtersString;
    paramtersString.resize(paramters.MODULUS_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.MODULUS, paramters.MODULUS_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Modulus (n), Size:" << paramters.MODULUS_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.PUBLIC_EXPONENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PUBLIC_EXPONENT, paramters.PUBLIC_EXPONENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Public Exponent (e), Size:" << paramters.PUBLIC_EXPONENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.PRIVATE_EXPONENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PRIVATE_EXPONENT, paramters.PRIVATE_EXPONENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Private Exponent (d), Size:" << paramters.PRIVATE_EXPONENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.FACTOR1_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.FACTOR1, paramters.FACTOR1_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor1 (p), Size:" << paramters.FACTOR1_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.FACTOR2_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.FACTOR2, paramters.FACTOR2_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor2 (p), Size:" << paramters.FACTOR2_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.EXPONENT1_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.EXPONENT1, paramters.EXPONENT1_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent1 (dmp1), Size:" << paramters.EXPONENT1_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.EXPONENT2_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.EXPONENT2, paramters.EXPONENT2_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent2 (dmp2), Size:" << paramters.EXPONENT2_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.COEFFICIENT_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.COEFFICIENT, paramters.COEFFICIENT_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Coefficient (iqmp), Size:" << paramters.COEFFICIENT_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();
}

void Test_ExportRsaKeyFromParameters() {
    std::vector<unsigned char> Modulus;
    std::vector<unsigned char> PublicExponent;
    std::vector<unsigned char> PrivateExponent;
    std::vector<unsigned char> Factor1;
    std::vector<unsigned char> Factor2;
    std::vector<unsigned char> Exponent1;
    std::vector<unsigned char> Exponent2;
    std::vector<unsigned char> Coefficient;
    std::string Modulus_str = "00B3BA4DDCB5977F2100AF59EA5E9538ECAED7DB9B5B89BC8FAD008E01D4019F2AED9DAC7FD25BCEC56888F6AA55BA322F529B535AB19FE2DD600325E1CA9B6D5786499AB066CF3D5EE99A35468B22F7B781DAA21406E221EDF36C98A967FEE32587F0A782692637583D2F401C54ABBDDF20DCBBC558BD445F539E38082959C513BCC24F4971874771CE117447334F718F4BFEE52AEAFA85DF4172E3743AA63CC3BC24AD8A4E9F0D2C2415DD4174A34C800F07EEA1C6029337E025961866E0ECA0452550678A016A9A1FE508479188D9F0BC1DEEDE373A8390CB71C9DDD3D49A39A3ACFB4343264C7A106280EED6EB555F1D6ABF177E8BA04D2C4478277E056701";
    std::string PublicExponent_str = "010001";
    std::string PrivateExponent_str = "591C706A9426CF439FC15185A0EBBFD3AA45207F80FD63DEA0DA7B8E707D755BA580DDFC6A6256BD0E3D8A7F9E0DB9C038E706871B36B91725F9A998B00A2C468F3083601F3975A64F90C4057C0B14638A20CAE7BF19F3D4B5330CE641C7E0FBC4D10F5CDBA1B5232D02F678958AA993AE0983982F8D780F03B898F382FD1D76FBA80E4293BDBAAFB2A93FB398CEB5963A170B6B0FA4899980038D6F1CFC614CEE4AF626C4952B0082B57B614537A522EBC4801721AF1C95FD831AB93FC68C57C0D7ED12C008DDA675468C117D4888C89B8DFD667D76C9D36E6237F45F67EBCD9F545FC614BAA1378E47C1C3762447FF7B12E92EED1E22085837CDB4E0065919";
    std::string Factor1_str = "00F0D2D85356AED47AEA28556864C63B6B58AE54FE50B6FDCB46B57C63F02501C7EBC01244F612F3674F3370AF68C481E61BE22BE587C225CD4AAB1D6CF5AD8BB3E22419B306B6F2BB023066AC2CFEA3E3A06B733E04D7772CBEF2AA90FAB9F9658474A7C82BF343AFD8FD19C9AFCB6453B1E9296E0B69AA19D24AD2E9FC4F41B3";
    std::string Factor2_str = "00BF0DD017A29E7A031F6692B10B8F3A3AD4F100990C4868074C5E08037E450D98079B02D798245C886414F8984805B93BA3745332373CED624F92A3EF599131824983494EFBBD11D203CF2FC39FF55B4681E40BCFE2BE00822C9077C1030BD2B7D4642717284629D89B346E39DFAB7F80D8BA9B35A6A61ECD4F09F044C1C4D27B";
    std::string Exponent1_str = "00DE8F8D3ADFD66D2A373315538826A78D5A84AAA9E9C06426B3EF4FC9308B92ECC75457CE01B89BD8331AF01E3BEDB7BB08B3EA2B935E7AFF11EDB821159FD0876B0C3FEFF2D9AAD3E77F01B4475501F381332C6AF9A0835408184E47F45F613C4FC05BBB23DB0B07FDBA5355D0B060C4F49BEE1CF4512FD1F346114C0B50D7FF";
    std::string Exponent2_str = "3C4B94AFD0DFA8EC115DE2CFC3312994659DC5AD8785D666EF4001D170694498055673782D08D4B72AB6BF99F7A8EEC3969B60A249728E0C67C684BC460D1F8DD9BB784858045C7A663F5DF8A423DFF1898EB9F79ABC9216830FF8EB4E15CE23BC00FBA140519C6542DE32274BA2A933B5B276C760D7AE82E6FDE0F9221A06BF";
    std::string Coefficient_str = "5DA10DF4DB9D03545062E7EC70BFC25E920F1B12180F35ED4E561A784E73841D36A148B6593F9287C29F0C87EB988A00D9D3A942830708292521786F311A0996A924475C89FDA4EE945261B8EBC9F44B27F6C886E8B5E390E7E7550F0FE28575E2F50ECBBB1EB462BCB1D4C2844F24F7B0E1BB0939E02F1FC9A36899AED59514";
    Modulus.resize(Modulus_str.size() / 2);
    PublicExponent.resize(PublicExponent_str.size() / 2);
    PrivateExponent.resize(PrivateExponent_str.size() / 2);
    Factor1.resize(Factor1_str.size() / 2);
    Factor2.resize(Factor2_str.size() / 2);
    Exponent1.resize(Exponent1_str.size() / 2);
    Exponent2.resize(Exponent2_str.size() / 2);
    Coefficient.resize(Coefficient_str.size() / 2);
    Base16Decode_Func(Modulus_str.c_str(), Modulus_str.size(), Modulus.data(), Modulus.size());
    Base16Decode_Func(PublicExponent_str.c_str(), PublicExponent_str.size(), PublicExponent.data(), PublicExponent.size());
    Base16Decode_Func(PrivateExponent_str.c_str(), PrivateExponent_str.size(), PrivateExponent.data(), PrivateExponent.size());
    Base16Decode_Func(Factor1_str.c_str(), Factor1_str.size(), Factor1.data(), Factor1.size());
    Base16Decode_Func(Factor2_str.c_str(), Factor2_str.size(), Factor2.data(), Factor2.size());
    Base16Decode_Func(Exponent1_str.c_str(), Exponent1_str.size(), Exponent1.data(), Exponent1.size());
    Base16Decode_Func(Exponent2_str.c_str(), Exponent2_str.size(), Exponent2.data(), Exponent2.size());
    Base16Decode_Func(Coefficient_str.c_str(), Coefficient_str.size(), Coefficient.data(), Coefficient.size());
    EXPORT_RSA_KEY paramters = {
        Modulus.data(),
        PublicExponent.data(),
        PrivateExponent.data(),
        Factor1.data(),
        Factor2.data(),
        Exponent1.data(),
        Exponent2.data(),
        Coefficient.data(),
        Modulus.size(),
        PublicExponent.size(),
        PrivateExponent.size(),
        Factor1.size(),
        Factor2.size(),
        Exponent1.size(),
        Exponent2.size(),
        Coefficient.size(),
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        NULL,
        NULL,
        NULL,
        NULL,
    };
    ExportRsaKeysFromParameters_Func(&paramters);

    /*char* pubString = new char[paramters.PUBLIC_KEY_LENGTH * 2 + 1] {};
    char* privString = new char[paramters.PRIVATE_KEY_LENGTH * 2 + 1] {};
    Base16Encode_Func(paramters.PUBLIC_KEY, paramters.PUBLIC_KEY_LENGTH, pubString, paramters.PUBLIC_KEY_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PRIVATE_KEY, paramters.PRIVATE_KEY_LENGTH, privString, paramters.PRIVATE_KEY_LENGTH * 2 + 1);
    std::cout << pubString << std::endl;
    std::cout << privString << std::endl;*/

    std::cout << paramters.PUBLIC_KEY << std::endl;
    std::cout << paramters.PRIVATE_KEY << std::endl;
}

int main() {
#if _WIN32
	EnableVirtualTerminalProcessing();
#endif

    //Test_GetRsaParametersLength();

    //Test_GenerateRsaParameters();

    //Test_RsaGenerate();

    Test_ExportRsaParametersFromKeys();

    //Test_ExportRsaKeyFromParameters();
}