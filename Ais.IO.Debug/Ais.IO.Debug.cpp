#include "TestHeader.h"

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
    const size_t MODULUS_LENGTH;
    const size_t PUBLIC_EXPONENT_LENGTH;
    const size_t PRIVATE_EXPONENT_LENGTH;
    const size_t FACTOR1_LENGTH;
    const size_t FACTOR2_LENGTH;
    const size_t EXPONENT1_LENGTH;
    const size_t EXPONENT2_LENGTH;
    const size_t COEFFICIENT_LENGTH;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

#pragma region RsaIO
typedef int (*GetRsaParametersLength)(RSA_PARAMETERS*);
typedef int (*GenerateRsaParameters)(RSA_PARAMETERS*);
typedef int (*RsaGenerate)(RSA_KEY_PAIR*);
typedef int (*ExportRsaParametersFromKeys)(EXPORT_RSA_PARAMTERS*);
typedef int (*ExportRsaKeysFromParameters)(EXPORT_RSA_KEY*);

GetRsaParametersLength GetRsaParametersLength_Func = (GetRsaParametersLength)GET_PROC_ADDRESS(Lib, "GetRsaParametersLength");
GenerateRsaParameters GenerateRsaParameters_Func = (GenerateRsaParameters)GET_PROC_ADDRESS(Lib, "GenerateRsaParameters");
RsaGenerate RsaGenerate_Func = (RsaGenerate)GET_PROC_ADDRESS(Lib, "RsaGenerate");
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
        RsaGenerate_Func(&keypair);

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
        RsaGenerate_Func(&keypair);

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
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    publicKey.resize(derPublicKey.size() / 2);
    privateKey.resize(derPrivateKey.size() / 2);
    Base16Decode_Func(derPublicKey.c_str(), derPublicKey.size(), publicKey.data(), publicKey.size());
    Base16Decode_Func(derPrivateKey.c_str(), derPrivateKey.size(), privateKey.data(), privateKey.size());
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
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
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
    std::string Modulus_str = "C3779422AAF0CB7740E8EA3664AE204B24A55FFBB5154CC24B43CA2D3917B957E01912185D1E6DC50E7F1F3DBD291FB5A3DFAC92B9F0833AE10C363D2D47BF1B43F42B3991AF9B4A3A4CBEF8CA6ABF1CAEA7659F8AD8E5098C2172D0DE6C61D11926C2F5BA6F1676F52058BC9126A8DF0E4DD6637383D86BFC8A44319017E9AD851DFC302F24895E7E757B0A9E5AD8E354F9B4888D7BFF55FB93298E1EB21F87040BED2E1A97C2BE5C1CD691F1BC1D114E21A4DF1891CDB84277A921B042E39F8E5DE3697F9C256672B3DC4F31B49B864CC29D7BB3F3B0630D15CCCB4DA0BA086C115E9AFB8645E384C3205E1363A3BFD0856F1EB012D8B19901B62D86F581E9";
    std::string PublicExponent_str = "010001";
    std::string PrivateExponent_str = "254D4BEF2850731ED72F3F1729847CABE70634B5434F5DFA1D9AEB0A3243142D91A95C744B1E55A22EFEBD00F532356ADA6995DD6AAF541509370236411AF0AD7A5DCB519ECAD090895547A86DB93313758AAB1A4DAB5CA79DE08694B4632DF40DCED0F6AED9C1283AA305F36275ABFF721EBEBFF2E516F9F5B372C488A3905E89207545C4A60ECF0C87035DCC118A3B1278826579FE628E8D23481A1B441F702EFB9C78C642A65E718829A94F630EB18F6CEFF566E1A261D0DB079ED249CDC64CC84E2095B229385890DFE94168FF57DC18F2EC1A961ADC7F1BB141175BF411830303E55F8EA3BA94E4E66648A174E30867FD758B1864761E01FC4E4E78725F";
    std::string Factor1_str = "7DA71DC785879AFF8A327F8695227480AA1A48B60F3CD735FCE4C4163688E725369CDD83C320873287D4A2CA4F000F3B81B49B76787A3F76264DE974FA85E18206F7E803B511820033F1887E703FFFA66F7038414BEE732DEE5DCF1EB2C772AE83AF8606A380BE15F87CD029CD9A1A0F6C64A5853051E27F15BF121D9EB602FB";
    std::string Factor2_str = "3F405D608AB37ED3445FF9422FB25946B66B8EDDB22C86B78307D7EEB0AC812F7B36DA9538F3486B0A3AB12CCE86BD2D38F5A4C341EB4E5E615498442F08CB6686F8201E425D7BAA879BC03FBA9498191B7C0833F3DA2F5870B96358B3C897DD0632128A2B87CB03265B2C66A695E44E4D3BF256F97A9989B65FCACF3E2E26EE";
    std::string Exponent1_str = "3D04CFB2BEDE86D6AEE6835BF981584C295CD476E43FA6FFD95E880B1AEC806477F1A1569D4CF9CBBE9AA4803AFC3A6D6AC663E392F97DB5476BA0994F03DF1F67F9B08FBFED79E481B03BB19C8FE443C46ABB3009819366C42B5FEDFC2B7343A087A057E77B0EC042E5E3F206E1E88893E5B4A0BEA234984405EA74EE1968AB";
    std::string Exponent2_str = "5FB43A6B42D1017223418E0F770D9CA66574DE64807F82638528E0F632EA12BF53C85B66216133B6AFA758CD7110429999F4DE653E499F26B9C4C3ACAF669781D6A13E5CE2BCA80AADE1598BAB36E5D0501C2727279E33EDA30CC642329E38B73C2DFC902314D7C2F0FEABCCB7A1A376C998C5A6B65FF554E58BAB08D8F0333F";
    std::string Coefficient_str = "960A917664576141085D33B15476C2AC0266337D7608A3A20A2A81606435863EA44D430B4356176B64B6E6198FBEB4F83767B8DDFEE417E46E740C2E7A20FBEBD30E68C47EE9688D099B1C2F676B46DC85E9A34DA6FBDF42ECF650D4D21E12B1535365DEA17EC76D32CD1B3BDFA085CB4FFAF6D02CB18C591F3C2332F1B2E0F1";
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
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        NULL,
        NULL,
        NULL,
        NULL,
    };
    ExportRsaKeysFromParameters_Func(&paramters);

    char* pubString = new char[paramters.PUBLIC_KEY_LENGTH * 2 + 1] {};
    char* privString = new char[paramters.PRIVATE_KEY_LENGTH * 2 + 1] {};
    Base16Encode_Func(paramters.PUBLIC_KEY, paramters.PUBLIC_KEY_LENGTH, pubString, paramters.PUBLIC_KEY_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.PRIVATE_KEY, paramters.PRIVATE_KEY_LENGTH, privString, paramters.PRIVATE_KEY_LENGTH * 2 + 1);
    std::cout << pubString << std::endl;
    std::cout << privString << std::endl;

    /*std::cout << paramters.PUBLIC_KEY << std::endl;
    std::cout << paramters.PRIVATE_KEY << std::endl;*/
}

int main() {
#if _WIN32
	EnableVirtualTerminalProcessing();
#endif

    //Test_GetRsaParametersLength();

    //Test_GenerateRsaParameters();

    //Test_RsaGenerate();

    Test_ExportRsaParametersFromKeys();

    Test_ExportRsaKeyFromParameters();
}