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
    const size_t KEY_LENGTH;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
};

struct RSA_KEY_PAIR {
    const size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

struct EXPORT_RSA_PARAMTERS {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const size_t PUBLIC_KEY_LENGTH;
    const size_t PRIVATE_KEY_LENGTH;
};

struct EXPORT_RSA_KEY {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* N;
    unsigned char* E;
    unsigned char* D;
    unsigned char* P;
    unsigned char* Q;
    unsigned char* DP;
    unsigned char* DQ;
    unsigned char* QI;
    size_t N_LENGTH;
    size_t E_LENGTH;
    size_t D_LENGTH;
    size_t P_LENGTH;
    size_t Q_LENGTH;
    size_t DP_LENGTH;
    size_t DQ_LENGTH;
    size_t QI_LENGTH;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

#pragma region RsaIO
typedef int (*GetRsaParametersLength)(RSA_PARAMETERS*);
typedef int (*GetRsaKeyLength)(RSA_KEY_PAIR*);
typedef int (*GenerateRsaParameters)(RSA_PARAMETERS*);
typedef int (*GenerateRsaKeys)(RSA_KEY_PAIR*);
typedef int (*ExportRsaParametersFromKeys)(EXPORT_RSA_PARAMTERS*);
typedef int (*ExportRsaKeysFromParameters)(EXPORT_RSA_KEY*);

GetRsaParametersLength GetRsaParametersLength_Func = (GetRsaParametersLength)GET_PROC_ADDRESS(Lib, "GetRsaParametersLength");
GetRsaKeyLength GetRsaKeyLength_Func = (GetRsaKeyLength)GET_PROC_ADDRESS(Lib, "GetRsaKeyLength");
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
    std::cout << "Modulus (n) Size:" << paramters.N_LENGTH << std::endl;
    std::cout << "Public Exponent (e) Size:" << paramters.E_LENGTH << std::endl;
    std::cout << "Private Exponent (d) Size:" << paramters.D_LENGTH << std::endl;
    std::cout << "Factor1 (p) Size:" << paramters.P_LENGTH << std::endl;
    std::cout << "Factor2 (p) Size:" << paramters.Q_LENGTH << std::endl;
    std::cout << "Exponent1 (dmp1) Size:" << paramters.DP_LENGTH << std::endl;
    std::cout << "Exponent2 (dmp2) Size:" << paramters.DQ_LENGTH << std::endl;
    std::cout << "Coefficient (iqmp) Size:" << paramters.QI_LENGTH << std::endl;
}

void Test_GetRsaKeyLength() {
    std::string derPublicKey = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100C3779422AAF0CB7740E8EA3664AE204B24A55FFBB5154CC24B43CA2D3917B957E01912185D1E6DC50E7F1F3DBD291FB5A3DFAC92B9F0833AE10C363D2D47BF1B43F42B3991AF9B4A3A4CBEF8CA6ABF1CAEA7659F8AD8E5098C2172D0DE6C61D11926C2F5BA6F1676F52058BC9126A8DF0E4DD6637383D86BFC8A44319017E9AD851DFC302F24895E7E757B0A9E5AD8E354F9B4888D7BFF55FB93298E1EB21F87040BED2E1A97C2BE5C1CD691F1BC1D114E21A4DF1891CDB84277A921B042E39F8E5DE3697F9C256672B3DC4F31B49B864CC29D7BB3F3B0630D15CCCB4DA0BA086C115E9AFB8645E384C3205E1363A3BFD0856F1EB012D8B19901B62D86F581E90203010001";
    std::string derPrivateKey = "308204A10201000282010100C3779422AAF0CB7740E8EA3664AE204B24A55FFBB5154CC24B43CA2D3917B957E01912185D1E6DC50E7F1F3DBD291FB5A3DFAC92B9F0833AE10C363D2D47BF1B43F42B3991AF9B4A3A4CBEF8CA6ABF1CAEA7659F8AD8E5098C2172D0DE6C61D11926C2F5BA6F1676F52058BC9126A8DF0E4DD6637383D86BFC8A44319017E9AD851DFC302F24895E7E757B0A9E5AD8E354F9B4888D7BFF55FB93298E1EB21F87040BED2E1A97C2BE5C1CD691F1BC1D114E21A4DF1891CDB84277A921B042E39F8E5DE3697F9C256672B3DC4F31B49B864CC29D7BB3F3B0630D15CCCB4DA0BA086C115E9AFB8645E384C3205E1363A3BFD0856F1EB012D8B19901B62D86F581E9020301000102820100254D4BEF2850731ED72F3F1729847CABE70634B5434F5DFA1D9AEB0A3243142D91A95C744B1E55A22EFEBD00F532356ADA6995DD6AAF541509370236411AF0AD7A5DCB519ECAD090895547A86DB93313758AAB1A4DAB5CA79DE08694B4632DF40DCED0F6AED9C1283AA305F36275ABFF721EBEBFF2E516F9F5B372C488A3905E89207545C4A60ECF0C87035DCC118A3B1278826579FE628E8D23481A1B441F702EFB9C78C642A65E718829A94F630EB18F6CEFF566E1A261D0DB079ED249CDC64CC84E2095B229385890DFE94168FF57DC18F2EC1A961ADC7F1BB141175BF411830303E55F8EA3BA94E4E66648A174E30867FD758B1864761E01FC4E4E78725F0281807DA71DC785879AFF8A327F8695227480AA1A48B60F3CD735FCE4C4163688E725369CDD83C320873287D4A2CA4F000F3B81B49B76787A3F76264DE974FA85E18206F7E803B511820033F1887E703FFFA66F7038414BEE732DEE5DCF1EB2C772AE83AF8606A380BE15F87CD029CD9A1A0F6C64A5853051E27F15BF121D9EB602FB0281803F405D608AB37ED3445FF9422FB25946B66B8EDDB22C86B78307D7EEB0AC812F7B36DA9538F3486B0A3AB12CCE86BD2D38F5A4C341EB4E5E615498442F08CB6686F8201E425D7BAA879BC03FBA9498191B7C0833F3DA2F5870B96358B3C897DD0632128A2B87CB03265B2C66A695E44E4D3BF256F97A9989B65FCACF3E2E26EE0281803D04CFB2BEDE86D6AEE6835BF981584C295CD476E43FA6FFD95E880B1AEC806477F1A1569D4CF9CBBE9AA4803AFC3A6D6AC663E392F97DB5476BA0994F03DF1F67F9B08FBFED79E481B03BB19C8FE443C46ABB3009819366C42B5FEDFC2B7343A087A057E77B0EC042E5E3F206E1E88893E5B4A0BEA234984405EA74EE1968AB0281805FB43A6B42D1017223418E0F770D9CA66574DE64807F82638528E0F632EA12BF53C85B66216133B6AFA758CD7110429999F4DE653E499F26B9C4C3ACAF669781D6A13E5CE2BCA80AADE1598BAB36E5D0501C2727279E33EDA30CC642329E38B73C2DFC902314D7C2F0FEABCCB7A1A376C998C5A6B65FF554E58BAB08D8F0333F02818100960A917664576141085D33B15476C2AC0266337D7608A3A20A2A81606435863EA44D430B4356176B64B6E6198FBEB4F83767B8DDFEE417E46E740C2E7A20FBEBD30E68C47EE9688D099B1C2F676B46DC85E9A34DA6FBDF42ECF650D4D21E12B1535365DEA17EC76D32CD1B3BDFA085CB4FFAF6D02CB18C591F3C2332F1B2E0F1";
    std::string pemPublicKey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu55P0TmB9ajqmU0fLElR\n"
        "Rq4fdp548rRI4Hv1ZFmmlCYV74xnqNqgIrH2QtOi0BsGF0Q/P26UacvxvJKYQmYD\n"
        "1Ws6GSmhA8i7zPxI9rKB8XYlhKBqnXo53J5KvcNza332QXiyhR1sfu2fIvdSWPx0\n"
        "pRPwiwE1xSJybyjdtKiN7tsSzqodUMC8AXDL3dQR9QlwAWA2RV9YgmLHuZCWbdFv\n"
        "urW2FWogF1zK8GF7BJB7xQy8xYjtU9laigeaPpHMCPPb4yWjvkw0yo9Qy8oUVWzJ\n"
        "+1O/buuyo/K9t9aPe4V0aLrSilAS05k2+BXGuMdEE6qLUDxwvD3xaYdiPtNLfpsR\n"
        "wwIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
        "";
    std::string pemPrivateKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7nk/ROYH1qOqZ\n"
        "TR8sSVFGrh92nnjytEjge/VkWaaUJhXvjGeo2qAisfZC06LQGwYXRD8/bpRpy/G8\n"
        "kphCZgPVazoZKaEDyLvM/Ej2soHxdiWEoGqdejncnkq9w3NrffZBeLKFHWx+7Z8i\n"
        "91JY/HSlE/CLATXFInJvKN20qI3u2xLOqh1QwLwBcMvd1BH1CXABYDZFX1iCYse5\n"
        "kJZt0W+6tbYVaiAXXMrwYXsEkHvFDLzFiO1T2VqKB5o+kcwI89vjJaO+TDTKj1DL\n"
        "yhRVbMn7U79u67Kj8r231o97hXRoutKKUBLTmTb4Fca4x0QTqotQPHC8PfFph2I+\n"
        "00t+mxHDAgMBAAECggEAB/a7K5s1zYArM8ZRcEH3yGNuuXcWP4hwiXrUL+Ya9dyR\n"
        "/3Y7FjCa2IOA+6rbv9qjImIGuey53Fhy/TlPFjkZ/jlMINz3/970PcoTAh8R+KEL\n"
        "tvqk2+S1cmG+XsSzmwNLQdHbk16W3Y0SPVvjK8d3ig7zyGq3kL5wE2Ytgal1RjIF\n"
        "NiorOgLn4hQbE4sHHgX4GPGVZKl09ZQVlCuOICaK7o80y6o52DFGW2qQr+HBdMfm\n"
        "y1fHH0hCNaWmbhPLKYsSLT9TtgzJFFc2H2anZdhN0oQJ0NbJAHqLZ5xMPRaFpXWV\n"
        "8/+2qsWzVFFTk9LpaIyxCKNhgKd5S9Y39HtRS4RbwQKBgQD/6nbX9wkMMJNDVlj6\n"
        "4Bs1kwpeXg/bi19MxsjQRqDJN4KWnZiwWTTtx4xuZU6yhB8VF27iA9lKeYiN0GMn\n"
        "tuwn3gMGTJNQtMsz2WKMNuBMLRlaRpWHFWvtHwtP96eBnajA1jPVZwm9IKsh4jzL\n"
        "f6Y9KlVFgWPe3NJ8pffiC4BigwKBgQC7rhmm2bKaumWUN9agJjVGuXUlqHCq5dTa\n"
        "1LysTj1L34jjil/oGsDSQJEQQxFhVoV9il+yCsb6GCW3GgjrhGxf1VPaQPrI5SpD\n"
        "0T/u5ZD8PBbALqV672zjwSyvvEz8iMpvbIOtRGdINRGqLVJzuEAZU18cgKfM42ik\n"
        "YOVPVF5vwQKBgDFwpXcBhaDyPXDz3IrTAs6t0oH6oAuk+EtH2AHMs0FMVREt7xKa\n"
        "mUwakfm93p9EQRD9DvHhFnh51DS5fn5sq2DkVidAYfFkjCE/LPeznk95Iv26xyZq\n"
        "sAgGSFQxnw2+XJyshSUEG/CKwCTypRYXWhFU/VZJMfcbKBrmoWXtHOdrAoGAL8rx\n"
        "C1Uqr05CKdFiXVv9eyolE9bmAg8O+j7sYPB3mYeuA0usip2tdp0sk7iQh3oR+lsv\n"
        "bVZjPzLA//SoStlpA6p+dPjRJDF/Zs+1eS+KkUD4Bi6aw0iPMRxzNbk83Z4z9tXq\n"
        "XkgqCPBCtFRgR8mmwQxDDy4QDRPoBNwL6PyyI8ECgYEA8XjevvGoEsUPB8AYNfVd\n"
        "XsXBtx+Wf+3fzSvF3MOop5HTo5KVAbnFnlu6Bp9XPGamO7soug0gred1aHue4C7y\n"
        "2C+bhizuuHEhnpCy9xixLTeVxzwFW3ZGQ3+eqsco1qjpMkUpEozTp1N1Q56iZKnG\n"
        "HBf0I0ENN9uLICfyDVKdjuQ=\n"
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
    RSA_KEY_PAIR length = {
        0,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };
    GetRsaKeyLength_Func(&length);
    
    std::cout << "Key Length (Bits):" << length.KEY_LENGTH << std::endl;
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

    GetRsaParametersLength_Func(&paramters);

    paramters.N = new unsigned char[paramters.N_LENGTH];
    paramters.E = new unsigned char[paramters.E_LENGTH];
    paramters.D = new unsigned char[paramters.D_LENGTH];
    paramters.P = new unsigned char[paramters.P_LENGTH];
    paramters.Q = new unsigned char[paramters.Q_LENGTH];
    paramters.DP = new unsigned char[paramters.DP_LENGTH];
    paramters.DQ = new unsigned char[paramters.DQ_LENGTH];
    paramters.QI = new unsigned char[paramters.QI_LENGTH];

    GenerateRsaParameters_Func(&paramters);

    std::vector<char> paramtersString;
    paramtersString.resize(paramters.N_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.N, paramters.N_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Modulus (n), Size:" << paramters.N_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.E_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.E, paramters.E_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Public Exponent (e), Size:" << paramters.E_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.D_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.D, paramters.D_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Private Exponent (d), Size:" << paramters.D_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.P_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.P, paramters.P_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor1 (p), Size:" << paramters.P_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.Q_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.Q, paramters.Q_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Factor2 (p), Size:" << paramters.Q_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.DP_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.DP, paramters.DP_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent1 (dmp1), Size:" << paramters.DP_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.DQ_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.DQ, paramters.DQ_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Exponent2 (dmp2), Size:" << paramters.DQ_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.QI_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.QI, paramters.QI_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Coefficient (iqmp), Size:" << paramters.QI_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();
}

void Test_RsaGenerate() {
    for (int i = 0; i < 1; i++) {
        size_t keysize = 2048;
        std::vector<unsigned char> publicKey;
        std::vector<unsigned char> privateKey;
        publicKey.resize(keysize);
        privateKey.resize(keysize);
        RSA_KEY_PAIR keypair = {
            keysize,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
            publicKey.data(),
            privateKey.data(),
            publicKey.size(),
            privateKey.size(),
        };
        GenerateRsaKeys_Func(&keypair);

        publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
        privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

        std::cout << "PEM - [" << i << ". Size:" << keypair.PUBLIC_KEY_LENGTH << ", " << keypair.PRIVATE_KEY_LENGTH << "]" << std::endl;
        std::cout << reinterpret_cast<char*>(publicKey.data()) << std::endl;
        std::cout << reinterpret_cast<char*>(privateKey.data()) << std::endl;
    }

    for (int i = 0; i < 1; i++) {
        size_t keysize = 2048;
        std::vector<unsigned char> publicKey;
        std::vector<unsigned char> privateKey;
        publicKey.resize(keysize);
        privateKey.resize(keysize);
        RSA_KEY_PAIR keypair = {
            keysize,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
            publicKey.data(),
            privateKey.data(),
            publicKey.size(),
            privateKey.size(),
        };
        GenerateRsaKeys_Func(&keypair);

        publicKey.resize(keypair.PUBLIC_KEY_LENGTH);
        privateKey.resize(keypair.PRIVATE_KEY_LENGTH);

        std::cout << "DER - [" << i << ". Size:" << keypair.PUBLIC_KEY_LENGTH << ", " << keypair.PRIVATE_KEY_LENGTH << "]" << std::endl;
        char* pubString = new char[keypair.PUBLIC_KEY_LENGTH * 2 + 1] {};
        char* privString = new char[keypair.PRIVATE_KEY_LENGTH * 2 + 1] {};
        Base16Encode_Func(publicKey.data(), publicKey.size(), pubString, keypair.PUBLIC_KEY_LENGTH * 2 + 1);
        Base16Encode_Func(privateKey.data(), privateKey.size(), privString, keypair.PRIVATE_KEY_LENGTH * 2 + 1);
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
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu55P0TmB9ajqmU0fLElR\n"
    "Rq4fdp548rRI4Hv1ZFmmlCYV74xnqNqgIrH2QtOi0BsGF0Q/P26UacvxvJKYQmYD\n"
    "1Ws6GSmhA8i7zPxI9rKB8XYlhKBqnXo53J5KvcNza332QXiyhR1sfu2fIvdSWPx0\n"
    "pRPwiwE1xSJybyjdtKiN7tsSzqodUMC8AXDL3dQR9QlwAWA2RV9YgmLHuZCWbdFv\n"
    "urW2FWogF1zK8GF7BJB7xQy8xYjtU9laigeaPpHMCPPb4yWjvkw0yo9Qy8oUVWzJ\n"
    "+1O/buuyo/K9t9aPe4V0aLrSilAS05k2+BXGuMdEE6qLUDxwvD3xaYdiPtNLfpsR\n"
    "wwIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
    "";
    std::string pemPrivateKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7nk/ROYH1qOqZ\n"
    "TR8sSVFGrh92nnjytEjge/VkWaaUJhXvjGeo2qAisfZC06LQGwYXRD8/bpRpy/G8\n"
    "kphCZgPVazoZKaEDyLvM/Ej2soHxdiWEoGqdejncnkq9w3NrffZBeLKFHWx+7Z8i\n"
    "91JY/HSlE/CLATXFInJvKN20qI3u2xLOqh1QwLwBcMvd1BH1CXABYDZFX1iCYse5\n"
    "kJZt0W+6tbYVaiAXXMrwYXsEkHvFDLzFiO1T2VqKB5o+kcwI89vjJaO+TDTKj1DL\n"
    "yhRVbMn7U79u67Kj8r231o97hXRoutKKUBLTmTb4Fca4x0QTqotQPHC8PfFph2I+\n"
    "00t+mxHDAgMBAAECggEAB/a7K5s1zYArM8ZRcEH3yGNuuXcWP4hwiXrUL+Ya9dyR\n"
    "/3Y7FjCa2IOA+6rbv9qjImIGuey53Fhy/TlPFjkZ/jlMINz3/970PcoTAh8R+KEL\n"
    "tvqk2+S1cmG+XsSzmwNLQdHbk16W3Y0SPVvjK8d3ig7zyGq3kL5wE2Ytgal1RjIF\n"
    "NiorOgLn4hQbE4sHHgX4GPGVZKl09ZQVlCuOICaK7o80y6o52DFGW2qQr+HBdMfm\n"
    "y1fHH0hCNaWmbhPLKYsSLT9TtgzJFFc2H2anZdhN0oQJ0NbJAHqLZ5xMPRaFpXWV\n"
    "8/+2qsWzVFFTk9LpaIyxCKNhgKd5S9Y39HtRS4RbwQKBgQD/6nbX9wkMMJNDVlj6\n"
    "4Bs1kwpeXg/bi19MxsjQRqDJN4KWnZiwWTTtx4xuZU6yhB8VF27iA9lKeYiN0GMn\n"
    "tuwn3gMGTJNQtMsz2WKMNuBMLRlaRpWHFWvtHwtP96eBnajA1jPVZwm9IKsh4jzL\n"
    "f6Y9KlVFgWPe3NJ8pffiC4BigwKBgQC7rhmm2bKaumWUN9agJjVGuXUlqHCq5dTa\n"
    "1LysTj1L34jjil/oGsDSQJEQQxFhVoV9il+yCsb6GCW3GgjrhGxf1VPaQPrI5SpD\n"
    "0T/u5ZD8PBbALqV672zjwSyvvEz8iMpvbIOtRGdINRGqLVJzuEAZU18cgKfM42ik\n"
    "YOVPVF5vwQKBgDFwpXcBhaDyPXDz3IrTAs6t0oH6oAuk+EtH2AHMs0FMVREt7xKa\n"
    "mUwakfm93p9EQRD9DvHhFnh51DS5fn5sq2DkVidAYfFkjCE/LPeznk95Iv26xyZq\n"
    "sAgGSFQxnw2+XJyshSUEG/CKwCTypRYXWhFU/VZJMfcbKBrmoWXtHOdrAoGAL8rx\n"
    "C1Uqr05CKdFiXVv9eyolE9bmAg8O+j7sYPB3mYeuA0usip2tdp0sk7iQh3oR+lsv\n"
    "bVZjPzLA//SoStlpA6p+dPjRJDF/Zs+1eS+KkUD4Bi6aw0iPMRxzNbk83Z4z9tXq\n"
    "XkgqCPBCtFRgR8mmwQxDDy4QDRPoBNwL6PyyI8ECgYEA8XjevvGoEsUPB8AYNfVd\n"
    "XsXBtx+Wf+3fzSvF3MOop5HTo5KVAbnFnlu6Bp9XPGamO7soug0gred1aHue4C7y\n"
    "2C+bhizuuHEhnpCy9xixLTeVxzwFW3ZGQ3+eqsco1qjpMkUpEozTp1N1Q56iZKnG\n"
    "HBf0I0ENN9uLICfyDVKdjuQ=\n"
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
    RSA_KEY_PAIR keyLength = {
        0,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };

    GetRsaKeyLength_Func(&keyLength);

    RSA_PARAMETERS paramLength = {
        keyLength.KEY_LENGTH,
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

    GetRsaParametersLength_Func(&paramLength);

    EXPORT_RSA_PARAMTERS paramters = {
        0,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        new unsigned char[paramLength.N_LENGTH],
        new unsigned char[paramLength.E_LENGTH],
        new unsigned char[paramLength.D_LENGTH],
        new unsigned char[paramLength.P_LENGTH],
        new unsigned char[paramLength.Q_LENGTH],
        new unsigned char[paramLength.DP_LENGTH],
        new unsigned char[paramLength.DQ_LENGTH],
        new unsigned char[paramLength.QI_LENGTH],
        paramLength.N_LENGTH,
        paramLength.E_LENGTH,
        paramLength.D_LENGTH,
        paramLength.P_LENGTH,
        paramLength.Q_LENGTH,
        paramLength.DP_LENGTH,
        paramLength.DQ_LENGTH,
        paramLength.QI_LENGTH,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };

    ExportRsaParametersFromKeys_Func(&paramters);

    std::cout << "Key Length (Bits):" << paramters.KEY_LENGTH << std::endl;

    std::vector<char> paramtersString;
    paramtersString.resize(paramters.N_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.N, paramters.N_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Modulus (n), Size:" << paramters.N_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.E_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.E, paramters.E_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Public Exponent (e), Size:" << paramters.E_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.D_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.D, paramters.D_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Private Exponent (d), Size:" << paramters.D_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.P_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.P, paramters.P_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[First Prime Factor (p), Size:" << paramters.P_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.Q_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.Q, paramters.Q_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Second Prime Factor (q), Size:" << paramters.Q_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.DP_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.DP, paramters.DP_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[First CRT Exponent (dp), Size:" << paramters.DP_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.DQ_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.DQ, paramters.DQ_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Second CRT Exponent (dq), Size:" << paramters.DQ_LENGTH << " ]\n" << paramtersString.data() << std::endl;
    paramtersString.clear();

    paramtersString.resize(paramters.QI_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.QI, paramters.QI_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[CRT Coefficient (qi), Size:" << paramters.QI_LENGTH << " ]\n" << paramtersString.data() << std::endl;
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
    std::string Modulus_str = "BB9E4FD13981F5A8EA994D1F2C495146AE1F769E78F2B448E07BF56459A6942615EF8C67A8DAA022B1F642D3A2D01B0617443F3F6E9469CBF1BC9298426603D56B3A1929A103C8BBCCFC48F6B281F1762584A06A9D7A39DC9E4ABDC3736B7DF64178B2851D6C7EED9F22F75258FC74A513F08B0135C522726F28DDB4A88DEEDB12CEAA1D50C0BC0170CBDDD411F50970016036455F588262C7B990966DD16FBAB5B6156A20175CCAF0617B04907BC50CBCC588ED53D95A8A079A3E91CC08F3DBE325A3BE4C34CA8F50CBCA14556CC9FB53BF6EEBB2A3F2BDB7D68F7B857468BAD28A5012D39936F815C6B8C74413AA8B503C70BC3DF16987623ED34B7E9B11C3";
    std::string PublicExponent_str = "010001";
    std::string PrivateExponent_str = "07F6BB2B9B35CD802B33C6517041F7C8636EB977163F8870897AD42FE61AF5DC91FF763B16309AD88380FBAADBBFDAA3226206B9ECB9DC5872FD394F163919FE394C20DCF7FFDEF43DCA13021F11F8A10BB6FAA4DBE4B57261BE5EC4B39B034B41D1DB935E96DD8D123D5BE32BC7778A0EF3C86AB790BE7013662D81A975463205362A2B3A02E7E2141B138B071E05F818F19564A974F59415942B8E20268AEE8F34CBAA39D831465B6A90AFE1C174C7E6CB57C71F484235A5A66E13CB298B122D3F53B60CC91457361F66A765D84DD28409D0D6C9007A8B679C4C3D1685A57595F3FFB6AAC5B354515393D2E9688CB108A36180A7794BD637F47B514B845BC1";
    std::string Factor1_str = "FFEA76D7F7090C3093435658FAE01B35930A5E5E0FDB8B5F4CC6C8D046A0C93782969D98B05934EDC78C6E654EB2841F15176EE203D94A79888DD06327B6EC27DE03064C9350B4CB33D9628C36E04C2D195A469587156BED1F0B4FF7A7819DA8C0D633D56709BD20AB21E23CCB7FA63D2A55458163DEDCD27CA5F7E20B806283";
    std::string Factor2_str = "BBAE19A6D9B29ABA659437D6A0263546B97525A870AAE5D4DAD4BCAC4E3D4BDF88E38A5FE81AC0D240911043116156857D8A5FB20AC6FA1825B71A08EB846C5FD553DA40FAC8E52A43D13FEEE590FC3C16C02EA57AEF6CE3C12CAFBC4CFC88CA6F6C83AD4467483511AA2D5273B84019535F1C80A7CCE368A460E54F545E6FC1";
    std::string Exponent1_str = "3170A5770185A0F23D70F3DC8AD302CEADD281FAA00BA4F84B47D801CCB3414C55112DEF129A994C1A91F9BDDE9F444110FD0EF1E1167879D434B97E7E6CAB60E456274061F1648C213F2CF7B39E4F7922FDBAC7266AB008064854319F0DBE5C9CAC8525041BF08AC024F2A516175A1154FD564931F71B281AE6A165ED1CE76B";
    std::string Exponent2_str = "2FCAF10B552AAF4E4229D1625D5BFD7B2A2513D6E6020F0EFA3EEC60F0779987AE034BAC8A9DAD769D2C93B890877A11FA5B2F6D56633F32C0FFF4A84AD96903AA7E74F8D124317F66CFB5792F8A9140F8062E9AC3488F311C7335B93CDD9E33F6D5EA5E482A08F042B4546047C9A6C10C430F2E100D13E804DC0BE8FCB223C1";
    std::string Coefficient_str = "F178DEBEF1A812C50F07C01835F55D5EC5C1B71F967FEDDFCD2BC5DCC3A8A791D3A3929501B9C59E5BBA069F573C66A63BBB28BA0D20ADE775687B9EE02EF2D82F9B862CEEB871219E90B2F718B12D3795C73C055B7646437F9EAAC728D6A8E9324529128CD3A75375439EA264A9C61C17F423410D37DB8B2027F20D529D8EE4";
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

    size_t keysize = Modulus.size() * 8;
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    publicKey.resize(keysize);
    privateKey.resize(keysize);

    EXPORT_RSA_KEY paramters = {
        0,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
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
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };
    ExportRsaKeysFromParameters_Func(&paramters);

    publicKey.resize(paramters.PUBLIC_KEY_LENGTH);
    privateKey.resize(paramters.PRIVATE_KEY_LENGTH);

    std::cout << "Key Length (Bits):" << paramters.KEY_LENGTH << std::endl;

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

    //Test_GetRsaKeyLength();

    //Test_GenerateRsaParameters();

    //Test_RsaGenerate();

    //Test_ExportRsaParametersFromKeys();

    Test_ExportRsaKeyFromParameters();
}