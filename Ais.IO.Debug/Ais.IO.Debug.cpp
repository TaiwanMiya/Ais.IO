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

void Test_ImportRsaParameters() {
    std::string derPublicKey = "30820122300D06092A864886F70D01010105000382010F003082010A028201010099FC6170AFE23CA76A6518D39B8D8356F72259277B6BD9AA4AED8505ACFE934A12723F745B45884BFB0F0DBC64A1F76206C36EA04F2B36E1ACEE5D971E974C910E46C90333CF14374B77D7F18FFB086ADAA0E34C959B2570F2F32919C9F68C76606E96821FB352802E75D6571CC58A2ED43B3BD78F58A12FA84E4159D67A3A9F9D053D40B8756D44B7DBD52BFD4D2EBE5A24569DEF57EAC12629B6C17DAD82A812E0BCE052EF55A168860E5D0BC1051C0C09277F0EF4B644EFC2E68A50C4020F3AC1B556FA0605F1F439CC5DF4536C13B09EE33432B4EA1FF3AD7F56C711108FFE2F6C7EA3BA499B2C3FCE37FA57E633E8494A5E5D3C0E7C8878EE1881228FB10203010001";
    std::string derPrivateKey = "308204A0020100028201010099FC6170AFE23CA76A6518D39B8D8356F72259277B6BD9AA4AED8505ACFE934A12723F745B45884BFB0F0DBC64A1F76206C36EA04F2B36E1ACEE5D971E974C910E46C90333CF14374B77D7F18FFB086ADAA0E34C959B2570F2F32919C9F68C76606E96821FB352802E75D6571CC58A2ED43B3BD78F58A12FA84E4159D67A3A9F9D053D40B8756D44B7DBD52BFD4D2EBE5A24569DEF57EAC12629B6C17DAD82A812E0BCE052EF55A168860E5D0BC1051C0C09277F0EF4B644EFC2E68A50C4020F3AC1B556FA0605F1F439CC5DF4536C13B09EE33432B4EA1FF3AD7F56C711108FFE2F6C7EA3BA499B2C3FCE37FA57E633E8494A5E5D3C0E7C8878EE1881228FB102030100010281FF11B4492C20DDEC8A134EE26AB1FAE14A9D732A4AC6C880253337A9C99DE458B59CE8D2F1DF98D0719F5CF766BD9DDA88BC301C6823CEC7536C2683547D3CCEE61E2E998E738F89D5D8322D6FB5081A055BE001596329CEB31AFDDA2BDC942A21F67F6C9B9428A58BFED9F598C269B056080315EDBFEE635DDD9CADB138E0A155E206F664049D2ED77391314B692AD28791A354AA735AB8FEFE8128FDC82681733D2DC1F0C344671BAD149941A97F3C28DA46ECD7B14037850EF6C1784A0B29E50310D097444AF22D02C22D0763D0EDC79586FC865511FD4A727B4210FEB33F1B26C1E2AD2374B5B2424A6C01268FD324F74661AEED2E66BE5804CA53FE68C502818051B7CF4465EFD5BC414381E5E21C3E6D5D978860A1E9F8DA6D703C5276D482C6DED4A278D4BF5A7041D4D70B3EBB6C124A31DC22F5D33C3F8CB9D4D8B0F861E65E618C6D1B0FCA0CF9B31974AFC90CD1A0826C231A07E9BC78345ADEA9262F63C2F640BE935E9ABAF9736B862E4334DEB9BC42819E92558D0C57EBA8C65978E202818100C9AE12272FB47B65A779526C18CB72298998F39883DCED1A3EC2EDA7DE2DF322EAF5722E486A03683902CA08F5E950F3EFD9EA859F1FD72E13E38E7C28FEFA6EEBC539945332FE96806311E64FEC3ED92552E6A116A346AC24A84907DCDFC387E1AABC27D3D55C6127835095C4E6316ADE39B1DAFD8FF8E808B2ECD34C1EB6C80281810081F2E1A58FD6BA07AF17816FDC85819B1678E404C255A469AE53A651F441FAEEA76D4F0476527CCF7E5193AD5BE2C3D21870EC242A918904280F1395A90AC9628720099685B00FAE4B5C1F6D9C1CBAFEDA97812049CA17AF8B18AE6DCD0B6B83FC85C4E0537C704F89C90F70AE119843603E8FE63FFE3C1C062A24E1401C0C1302818061C7F987B1AEB64E14DFDD87FCFE5741174EC2260625FF6046942B42BAB41F89BEDC737263D3D48D6B55870C949641B467F116859E78A4F8225F1266AFD88466A551FB1278981CF06A9CF8545AEF2CB6074F72786B6438CB5F3DE2CAA3DB6206BBD05F64466140D2B9EBCF492A9C8FD82293683B8F9282D283F2FD7BF2456F580281807D270FC9B07D6D06E309BE75361F2BD75CF325D7E11EB6D29FFC10B5F69696A419245F595C10F79998D1B57D3E0D5BDBA8D87CBED261AD8B9A349EEB10F649EBFEE0DD966556A8C69D6A07719CAA9D2939FFA124B0CD7E4ADC321A398B652234F92AB0DEFB754B1113BC6D3D418D7DDA590D4BDA8FF1F5CA3D4D6F65D3354A09";
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
    std::string Modulus_str = std::string("99FC6170AFE23CA76A6518D39B8D8356F72259277B6BD9AA4AED8505ACFE934A12723F745B45884BFB0F0DBC64A1F76206C36EA04F2B36E1ACEE5D971E974C910E46C90333CF14374B77D7F18FFB086ADAA0E34C959B2570F2F32919C9F68C76606E96821FB352802E75D6571CC58A2ED43B3BD78F58A12FA84E4159D67A3A9F9D053D40B8756D44B7DBD52BFD4D2EBE5A24569DEF57EAC12629B6C17DAD82A812E0BCE052EF55A168860E5D0BC1051C0C09277F0EF4B644EFC2E68A50C4020F3AC1B556FA0605F1F439CC5DF4536C13B09EE33432B4EA1FF3AD7F56C711108FFE2F6C7EA3BA499B2C3FCE37FA57E633E8494A5E5D3C0E7C8878EE1881228FB1");
    std::string PublicExponent_str = std::string("010001");
    std::string PrivateExponent_str = std::string("11B4492C20DDEC8A134EE26AB1FAE14A9D732A4AC6C880253337A9C99DE458B59CE8D2F1DF98D0719F5CF766BD9DDA88BC301C6823CEC7536C2683547D3CCEE61E2E998E738F89D5D8322D6FB5081A055BE001596329CEB31AFDDA2BDC942A21F67F6C9B9428A58BFED9F598C269B056080315EDBFEE635DDD9CADB138E0A155E206F664049D2ED77391314B692AD28791A354AA735AB8FEFE8128FDC82681733D2DC1F0C344671BAD149941A97F3C28DA46ECD7B14037850EF6C1784A0B29E50310D097444AF22D02C22D0763D0EDC79586FC865511FD4A727B4210FEB33F1B26C1E2AD2374B5B2424A6C01268FD324F74661AEED2E66BE5804CA53FE68C5");
    std::string Factor1_str = std::string("51B7CF4465EFD5BC414381E5E21C3E6D5D978860A1E9F8DA6D703C5276D482C6DED4A278D4BF5A7041D4D70B3EBB6C124A31DC22F5D33C3F8CB9D4D8B0F861E65E618C6D1B0FCA0CF9B31974AFC90CD1A0826C231A07E9BC78345ADEA9262F63C2F640BE935E9ABAF9736B862E4334DEB9BC42819E92558D0C57EBA8C65978E2");
    std::string Factor2_str = std::string("C9AE12272FB47B65A779526C18CB72298998F39883DCED1A3EC2EDA7DE2DF322EAF5722E486A03683902CA08F5E950F3EFD9EA859F1FD72E13E38E7C28FEFA6EEBC539945332FE96806311E64FEC3ED92552E6A116A346AC24A84907DCDFC387E1AABC27D3D55C6127835095C4E6316ADE39B1DAFD8FF8E808B2ECD34C1EB6C8");
    std::string Exponent1_str = std::string("81F2E1A58FD6BA07AF17816FDC85819B1678E404C255A469AE53A651F441FAEEA76D4F0476527CCF7E5193AD5BE2C3D21870EC242A918904280F1395A90AC9628720099685B00FAE4B5C1F6D9C1CBAFEDA97812049CA17AF8B18AE6DCD0B6B83FC85C4E0537C704F89C90F70AE119843603E8FE63FFE3C1C062A24E1401C0C13");
    std::string Exponent2_str = std::string("61C7F987B1AEB64E14DFDD87FCFE5741174EC2260625FF6046942B42BAB41F89BEDC737263D3D48D6B55870C949641B467F116859E78A4F8225F1266AFD88466A551FB1278981CF06A9CF8545AEF2CB6074F72786B6438CB5F3DE2CAA3DB6206BBD05F64466140D2B9EBCF492A9C8FD82293683B8F9282D283F2FD7BF2456F58");
    std::string Coefficient_str = std::string("7D270FC9B07D6D06E309BE75361F2BD75CF325D7E11EB6D29FFC10B5F69696A419245F595C10F79998D1B57D3E0D5BDBA8D87CBED261AD8B9A349EEB10F649EBFEE0DD966556A8C69D6A07719CAA9D2939FFA124B0CD7E4ADC321A398B652234F92AB0DEFB754B1113BC6D3D418D7DDA590D4BDA8FF1F5CA3D4D6F65D3354A09");
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