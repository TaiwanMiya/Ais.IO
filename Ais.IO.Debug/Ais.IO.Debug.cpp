#include "TestHeader.h"

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
    unsigned char* BITS;
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
    size_t BITS_LENGTH;
};

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

struct RSA_KEY_PAIR {
    const size_t KEY_SIZE;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
};

struct IMPORT_RSA_PARAMTERS {
    unsigned char* MODULUS;
    unsigned char* PUBLIC_EXPONENT;
    unsigned char* PRIVATE_EXPONENT;
    unsigned char* FACTOR1;
    unsigned char* FACTOR2;
    unsigned char* EXPONENT1;
    unsigned char* EXPONENT2;
    unsigned char* COEFFICIENT;
    unsigned char* BITS;
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
    size_t BITS_LENGTH;
    const ASYMMETRIC_KEY_FORMAT FORMAT;
    const unsigned char* PUBLIC_KEY;
    const unsigned char* PRIVATE_KEY;
    const size_t PUBLIC_KEY_LENGTH;
    const size_t PRIVATE_KEY_LENGTH;
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
    unsigned char* BITS;
    const size_t MODULUS_LENGTH;
    const size_t PUBLIC_EXPONENT_LENGTH;
    const size_t PRIVATE_EXPONENT_LENGTH;
    const size_t FACTOR1_LENGTH;
    const size_t FACTOR2_LENGTH;
    const size_t EXPONENT1_LENGTH;
    const size_t EXPONENT2_LENGTH;
    const size_t COEFFICIENT_LENGTH;
    const size_t BITS_LENGTH;
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
typedef int (*ImportRsaParametersFromKeys)(IMPORT_RSA_PARAMTERS*);
typedef int (*ExportRsaKeysFromParameters)(EXPORT_RSA_PARAMTERS*);

GetRsaParametersLength GetRsaParametersLength_Func = (GetRsaParametersLength)GET_PROC_ADDRESS(Lib, "GetRsaParametersLength");
GenerateRsaParameters GenerateRsaParameters_Func = (GenerateRsaParameters)GET_PROC_ADDRESS(Lib, "GenerateRsaParameters");
RsaGenerate RsaGenerate_Func = (RsaGenerate)GET_PROC_ADDRESS(Lib, "RsaGenerate");
ImportRsaParametersFromKeys ImportRsaParametersFromKeys_Func = (ImportRsaParametersFromKeys)GET_PROC_ADDRESS(Lib, "ImportRsaParametersFromKeys");
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
    std::cout << "Bits (bits) Size:" << paramters.BITS_LENGTH << std::endl;
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
        NULL,
        0,
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

    paramtersString.resize(paramters.BITS_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.BITS, paramters.BITS_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Bits (bits), Size:" << paramters.BITS_LENGTH << " ]\n" << paramtersString.data() << std::endl;
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

void Test_ImportRsaParameters() {
    std::string derPublicKey = "30820122300D06092A864886F70D01010105000382010F003082010A0282010100AF0AD6319F6D5192119C7B1AAC56CFDF8A45E7FD3CEABC8BCAADB116D69227C84699519AD8461D042F6E59A58C91818E7FDF544E18EFE3C0AF7D91A76A87965F3AEB9C6F522BD2418D48C5014A26CEC6917B8623731C06EE043704A139C33644F1339AEC04816923C6CD1A64B43CAF9684C32BFC4D1E02F0004072F4B3D29F30FE8CAEFF1826D73A6DBDC9339B02BC5C73A1737C446B777C5400AEEF0D9AA01DC5733BF5BEDAEAD2310CCD794011301358C68A61BF31496769B26BABCEE8E3353C67C7BCBF748D40E087E976FB79AFA0AFFE8FB147F1FA95194D388053A6A583F0B3166BE1C1EEF5B378563EDD82956DD476163489F61FF42B86F1C94B5086D90203010001";
    std::string derPrivateKey = "308204A20201000282010100AF0AD6319F6D5192119C7B1AAC56CFDF8A45E7FD3CEABC8BCAADB116D69227C84699519AD8461D042F6E59A58C91818E7FDF544E18EFE3C0AF7D91A76A87965F3AEB9C6F522BD2418D48C5014A26CEC6917B8623731C06EE043704A139C33644F1339AEC04816923C6CD1A64B43CAF9684C32BFC4D1E02F0004072F4B3D29F30FE8CAEFF1826D73A6DBDC9339B02BC5C73A1737C446B777C5400AEEF0D9AA01DC5733BF5BEDAEAD2310CCD794011301358C68A61BF31496769B26BABCEE8E3353C67C7BCBF748D40E087E976FB79AFA0AFFE8FB147F1FA95194D388053A6A583F0B3166BE1C1EEF5B378563EDD82956DD476163489F61FF42B86F1C94B5086D90203010001028201001ADE82FAA30A58D71F34F200AA2BB9450B28A7EFCB860CE3387D690DA46A5308FF2D51C57F256416DC610809CD861869135FE8C50436EEB3093D313A8DB3BA756BC9F6FD6F93A276C58542186C95807022ACDF6E59A117BF398E687B872E5C0A412C36BFBC01516E5879EB6F41EB7ED890109593E9128E48E10103A464661461635A3AB500F6B7129257CD1E958B984074F1D9D9A4AF1E123EACD934BD9F742DE43E3782679466700367AC63FB82BB889A3A3194F03E91C5103881E988AD413DDFD9BB621595EF19A2DB4E0A8BE3FF3B05649C6ED78795F3B909587C7ED395787094772C29F305B2D7013A84ECD29F70ADDE96A31D26914FDB20DA19366240B102818100F2895C888E9FB85E1F6ECA32CA8BAC2DB5855FD5772F3A58895C93D102EAAE7630DA86CBF5945DDD4CCC0AEAB0EEAEDBAE5410D1A7A1C2651EA0F3C9533B793A28930842B39E6A33216EA30D0BF1717F9D9BCB961E1E2DCE5F8A6DB14F926C75DABFCFA89E27A956672E3D768C09FFE95778847DD7E2335469880EDE78409C8B02818100B8C25402676F8128004711FA215505161444365FE45275E74F4BA771BE08F6B5B7EA2537A71AD4E93DA1C5364F72891277C96861EF5DCD8EEA541603659EB51F978E6E5AF9D1BE16F5A242B3C917C9B50EBB12997C1CF2DCF1015A970CA0952C77F3486017C08DBE5369B6E8801A1DEED31F73BE89EE190B567CF8D9EA48A2AB0281804A96B9F179435F94FABFBCC970071275A03C9B636FDB036B951AF68EB201F09382A4C20DD9C1BE383FD5048A76CD80D328C2CBC55E735DF07141F89772D4788CCD4BA29FB8D3C03F6749BA3559F5EFFCDA40BE94B5407CBFDA1C1D6E0955B3AB6F11CC50440B5885AD07C8793BCA1B7CEC9CB0CA6EE92EF607DA8310221564CF02818044101AC0B3F828DD6294CBF39879E8A0C4A08863750A47B309CC360839D8B582261994D256B614BF43DC2779A574ED382776C4046818E75401D12E36DC25C655B81059691C64FF211826496A4FE77A803FC7FCC71C28D1F340B99DF4CD4B0F094DBB0AEB937475032B59636F6D59B1B33C8576AF37C2C5E91E58759859AD9E77028180201EE46F49019D6F2E0AC2DAE060BB228E6ECFA0F4DBED88C603051876BA294AD6E4372FD746EDB14C36C364F3DA943531010A5FCE5A17AC4561EAB30F6A00F416D231B8594B48DD3C543D04DF8C8652E3A84C3FEE8B6BA41807F38737A5A383CD2271AC323D77C8FD4FCCC18751F7AE55FA1F7492146B17A3B21C6085ED6AFE";
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    publicKey.resize(derPublicKey.size() / 2);
    privateKey.resize(derPrivateKey.size() / 2);
    Base16Decode_Func(derPublicKey.c_str(), derPublicKey.size(), publicKey.data(), publicKey.size());
    Base16Decode_Func(derPrivateKey.c_str(), derPrivateKey.size(), privateKey.data(), privateKey.size());
    IMPORT_RSA_PARAMTERS paramters = {
        NULL,
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
        0,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
    };
    ImportRsaParametersFromKeys_Func(&paramters);

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

    paramtersString.resize(paramters.BITS_LENGTH * 2 + 1);
    Base16Encode_Func(paramters.BITS, paramters.BITS_LENGTH, paramtersString.data(), paramtersString.size());
    std::cout << "[Bits (bits), Size:" << paramters.BITS_LENGTH << " ]\n" << paramtersString.data() << std::endl;
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
    std::vector<unsigned char> Bits;
    std::vector<unsigned char> Primes;
    std::string Modulus_str = std::string("AF0AD6319F6D5192119C7B1AAC56CFDF8A45E7FD3CEABC8BCAADB116D69227C84699519AD8461D042F6E59A58C91818E7FDF544E18EFE3C0AF7D91A76A87965F3AEB9C6F522BD2418D48C5014A26CEC6917B8623731C06EE043704A139C33644F1339AEC04816923C6CD1A64B43CAF9684C32BFC4D1E02F0004072F4B3D29F30FE8CAEFF1826D73A6DBDC9339B02BC5C73A1737C446B777C5400AEEF0D9AA01DC5733BF5BEDAEAD2310CCD794011301358C68A61BF31496769B26BABCEE8E3353C67C7BCBF748D40E087E976FB79AFA0AFFE8FB147F1FA95194D388053A6A583F0B3166BE1C1EEF5B378563EDD82956DD476163489F61FF42B86F1C94B5086D9");
    std::string PublicExponent_str = std::string("010001");
    std::string PrivateExponent_str = std::string("1ADE82FAA30A58D71F34F200AA2BB9450B28A7EFCB860CE3387D690DA46A5308FF2D51C57F256416DC610809CD861869135FE8C50436EEB3093D313A8DB3BA756BC9F6FD6F93A276C58542186C95807022ACDF6E59A117BF398E687B872E5C0A412C36BFBC01516E5879EB6F41EB7ED890109593E9128E48E10103A464661461635A3AB500F6B7129257CD1E958B984074F1D9D9A4AF1E123EACD934BD9F742DE43E3782679466700367AC63FB82BB889A3A3194F03E91C5103881E988AD413DDFD9BB621595EF19A2DB4E0A8BE3FF3B05649C6ED78795F3B909587C7ED395787094772C29F305B2D7013A84ECD29F70ADDE96A31D26914FDB20DA19366240B1");
    std::string Factor1_str = std::string("F2895C888E9FB85E1F6ECA32CA8BAC2DB5855FD5772F3A58895C93D102EAAE7630DA86CBF5945DDD4CCC0AEAB0EEAEDBAE5410D1A7A1C2651EA0F3C9533B793A28930842B39E6A33216EA30D0BF1717F9D9BCB961E1E2DCE5F8A6DB14F926C75DABFCFA89E27A956672E3D768C09FFE95778847DD7E2335469880EDE78409C8B");
    std::string Factor2_str = std::string("B8C25402676F8128004711FA215505161444365FE45275E74F4BA771BE08F6B5B7EA2537A71AD4E93DA1C5364F72891277C96861EF5DCD8EEA541603659EB51F978E6E5AF9D1BE16F5A242B3C917C9B50EBB12997C1CF2DCF1015A970CA0952C77F3486017C08DBE5369B6E8801A1DEED31F73BE89EE190B567CF8D9EA48A2AB");
    std::string Exponent1_str = std::string("4A96B9F179435F94FABFBCC970071275A03C9B636FDB036B951AF68EB201F09382A4C20DD9C1BE383FD5048A76CD80D328C2CBC55E735DF07141F89772D4788CCD4BA29FB8D3C03F6749BA3559F5EFFCDA40BE94B5407CBFDA1C1D6E0955B3AB6F11CC50440B5885AD07C8793BCA1B7CEC9CB0CA6EE92EF607DA8310221564CF");
    std::string Exponent2_str = std::string("44101AC0B3F828DD6294CBF39879E8A0C4A08863750A47B309CC360839D8B582261994D256B614BF43DC2779A574ED382776C4046818E75401D12E36DC25C655B81059691C64FF211826496A4FE77A803FC7FCC71C28D1F340B99DF4CD4B0F094DBB0AEB937475032B59636F6D59B1B33C8576AF37C2C5E91E58759859AD9E77");
    std::string Coefficient_str = std::string("201EE46F49019D6F2E0AC2DAE060BB228E6ECFA0F4DBED88C603051876BA294AD6E4372FD746EDB14C36C364F3DA943531010A5FCE5A17AC4561EAB30F6A00F416D231B8594B48DD3C543D04DF8C8652E3A84C3FEE8B6BA41807F38737A5A383CD2271AC323D77C8FD4FCCC18751F7AE55FA1F7492146B17A3B21C6085ED6AFE");
    std::string Bits_str = std::string("0800");
    Modulus.resize(Modulus_str.size());
    PublicExponent.resize(PublicExponent_str.size());
    PrivateExponent.resize(PrivateExponent_str.size());
    Factor1.resize(Factor1_str.size());
    Factor2.resize(Factor2_str.size());
    Exponent1.resize(Exponent1_str.size());
    Exponent2.resize(Exponent2_str.size());
    Coefficient.resize(Coefficient_str.size());
    Bits.resize(Bits_str.size());
    Base16Decode_Func(Modulus_str.c_str(), Modulus_str.size(), Modulus.data(), Modulus.size());
    Base16Decode_Func(PublicExponent_str.c_str(), PublicExponent_str.size(), PublicExponent.data(), PublicExponent.size());
    Base16Decode_Func(PrivateExponent_str.c_str(), PrivateExponent_str.size(), PrivateExponent.data(), PrivateExponent.size());
    Base16Decode_Func(Factor1_str.c_str(), Factor1_str.size(), Factor1.data(), Factor1.size());
    Base16Decode_Func(Factor2_str.c_str(), Factor2_str.size(), Factor2.data(), Factor2.size());
    Base16Decode_Func(Exponent1_str.c_str(), Exponent1_str.size(), Exponent1.data(), Exponent1.size());
    Base16Decode_Func(Exponent2_str.c_str(), Exponent2_str.size(), Exponent2.data(), Exponent2.size());
    Base16Decode_Func(Coefficient_str.c_str(), Coefficient_str.size(), Coefficient.data(), Coefficient.size());
    Base16Decode_Func(Bits_str.c_str(), Bits_str.size(), Bits.data(), Bits.size());
    EXPORT_RSA_PARAMTERS paramters = {
        Modulus.data(),
        PublicExponent.data(),
        PrivateExponent.data(),
        Factor1.data(),
        Factor2.data(),
        Exponent1.data(),
        Exponent2.data(),
        Coefficient.data(),
        Bits.data(),
        Modulus.size(),
        PublicExponent.size(),
        PrivateExponent.size(),
        Factor1.size(),
        Factor2.size(),
        Exponent1.size(),
        Exponent2.size(),
        Coefficient.size(),
        Bits.size(),
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

    //Test_ImportRsaParameters();

    Test_ExportRsaKeyFromParameters();
}