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

struct IMPORT_RSA_PARAMTERS {
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

struct EXPORT_RSA_PARAMTERS {
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

void Test_ImportRsaParameters() {
    std::string derPublicKey = "30820121300D06092A864886F70D01010105000382010E0030820109028201007354565FDA8F271B9D6F70680D6212775278C2EB15D9C55F965FB80B6D1261C6523B93B66F20B64489D2E3A8058BBC0EC0F0A27F366F67FE6D36ECCADC79E0F744EBC6CA0E1B146CAFD86FD9C9BF906665626BDFDF0B99BE6EADDAF2CF7EC44CAAF240168CB41A95F284D833C9962748BB842C85E2A39FF1CDE1E257D440A48F92DA3825276EC8C4B2BB320B907827DFDCCA15B73552C763B046828450F96076E3DF86CA87C5AA2F8F62E1BC583900B5C7120310477E15FC405BA2F7C3632FD60C2284F3CEF1E847EAE1E2BDC079BF5FBE9279ADD598A3C467B50C26FDEE1D31CFA91409093E8D21AC3DA23E2FAA84814AB21F4DE735F4EDEEE8979D9BD8FACD0203010001";
    std::string derPrivateKey = "3082049E020100028201007354565FDA8F271B9D6F70680D6212775278C2EB15D9C55F965FB80B6D1261C6523B93B66F20B64489D2E3A8058BBC0EC0F0A27F366F67FE6D36ECCADC79E0F744EBC6CA0E1B146CAFD86FD9C9BF906665626BDFDF0B99BE6EADDAF2CF7EC44CAAF240168CB41A95F284D833C9962748BB842C85E2A39FF1CDE1E257D440A48F92DA3825276EC8C4B2BB320B907827DFDCCA15B73552C763B046828450F96076E3DF86CA87C5AA2F8F62E1BC583900B5C7120310477E15FC405BA2F7C3632FD60C2284F3CEF1E847EAE1E2BDC079BF5FBE9279ADD598A3C467B50C26FDEE1D31CFA91409093E8D21AC3DA23E2FAA84814AB21F4DE735F4EDEEE8979D9BD8FACD02030100010281FF01E759BF834D9A469E39EE34ABD490040737544F0274BF4A72354113FE1C3FB7F14C8202534E7C9C6EF8F56883D8505C1536FC17258A78D9B86FC3FC21767E50A719A2F76271A26A63D743AF4FBA5A5DA87D0BFEA6F9CB1CD000CAFC1A69BEFC864033A750E79F6366997E7CF443E264B1F543DB4B7BF4D621554B106420F4731828152FEF45D81B65A3FFD5FCA1B480EF7C92A74F58B629D4E0F40D8B079934980AB37328A612B60E5DD805D5440AD23408AC155DD10F9926F123163684CAFDD4353DB54A3CB92FF3DDA9F42422CE142E628A3F0737DA663B783CC052E425525A315A625EE94755B6997D1A50F949A64A0813379265569EB40FB32DD695CD02818100B33AB5AB1FF188A55219210104A8CEAF018474BC51346DE4859169E20B39401F755091CC9F35E18354089C03776F6551F2125D2B3A05C4CE3AD1C28AA254AAF92717803DA022B09C847387BB03428D88C33C8FBDAA6DBEE1E40BA27B30B51B63F0BEC5C29CA9E8DED2E192097D896FEF13A9AE049C5B1AF1311E4EEE4502C8FF028180415F4E51FF378916ED9D914436B810E435626B1C0809B51636F879977E15536D598E07E0714178815C232322DE1AD1EB623DA0754CB124864A56D1140ED3C835B28BF3DA26CB8371D9D3EA45722AE1B94F94BFBAFACD5312550ED5334F84AE7FE039EA4CC6E9BFACB56D67479FFC404DBFF17807202BB13CF0AECA6183EF27CE0281800DF4B03F9A0C95B91527167A83A4F86E3D8AA427EA8E5EADEDD5EF0AC730EE1CEE34CB26824E1EEAED608E82B65D7FE890AFFD78C9CA0E73294665D136C4D4165D49259FCB5F858044535497A7548DF7C9A6D2667F32880EC24FE1EA0CFCBF3441606F7DEC669DC17A301156F68E494FD6F09BE26E8EE82E291804EE65D44FAB0281800197155E13C8E6F36C43047C56FDE35B28D2DA625731F1196D3FDC65B160B02D3BD9E0EB2A0C1A5F82494BD0EB541D06F3535D6A3CB51B2AEBD78F189D1DF6EEE45F6DB40F69444E93BD25C6F5E4B0512739BD1C3ADED26C719009EC50811EAA6E15E7D605E37906FE4ADAABE63A4A340B04302A86B059B03A05406398F2C78F0281805E83A30851F199D0B67BE51F52CDDE84286A4B7132D3A5D52A4D76A07AA1C5166B36A126B737EDC03D5DB8A6AFF59DC6CC50DFED9F46990878B97EA65CA65DEE76B59EF3AF43283CB48972CE834872133C277B9BC1C92705F6D6379631217CBB44EC4B773D37647829FDD2DEE08FB1539409F398F1CF94957FB1566BDC15ED35";
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
    std::string Modulus_str = std::string("CDFAD89B9D97E8EEEDF435E74D1FB24A8184AA2F3EA23DAC218D3E090914A9CF311DEEFD260CB567C4A398D5AD7992BE5FBF79C0BDE2E1EA47E8F1CEF384220CD62F63C3F7A25B40FC157E47100312C7B5003958BCE1628F2FAAC587CA86DFE37660F950848246B063C75235B715CADCDF2778900B32BBB2C4C86E272538DA928FA440D457E2E1CDF19FA3E2852C84BB482796C933D884F2951AB48C1640F2AA4CC47ECFF2DAAD6EBE990BDFDF6B62656690BFC9D96FD8AF6C141B0ECAC6EB44F7E079DCCAEC366DFE676F367FA2F0C00EBC8B05A8E3D28944B6206FB6933B52C661126D0BB85F965FC5D915EBC278527712620D68706F9D1B278FDA5F565473");
    std::string PublicExponent_str = std::string("010001");
    std::string PrivateExponent_str = std::string("CD95D62DB30FB49E5665923713084AA649F9501A7D99B65547E95E625A315A5225E452C03C783B66DA37073F8A622E14CE2224F4A9DDF32FB93C4AB53D35D4FDCA84361623F126990FD15D15AC0834D20A44D505D85D0EB612A62873B30A983499078B0DF4E0D429B6584FA7927CEF80B4A1FCD5FFA3651BD845EF2F15281873F42064104B5521D6F47B4BDB43F5B164E243F47C7E9966639FE750A7334086FCBE691AFCCA00D01CCBF9A6FE0B7DA85D5ABA4FAF43D7636AA27162F7A219A7507E7621FCC36FB8D9788A2517FC36155C50D88368F5F86E9C7C4E5302824CF1B73F1CFE134135724ABF74024F5437070490D4AB34EE399E469A4D83BF59E701");
    std::string Factor1_str = std::string("FFC80245EE4E1E31F11A5B9C04AEA913EF6F897D0992E1D2DEE8A99CC2C5BEF0631BB5307BA20BE4E1BE6DAABD8F3CC3888D4203BB8773849CB022A03D801727F9AA54A28AC2D13ACEC4053A2B5D12F251656F77039C085483E1359FCC9150751F40390BE2699185E46D3451BC748401AFCEA80401211952A588F11FABB53AB3");
    std::string Factor2_str = std::string("CE27EF8361CAAEF03CB12B200778F1BF4D40FC9F47676DB5ACBFE9C64CEA39E07FAE844F33D50E551253CDFABABF944FB9E12A7245EAD3D97183CB26DAF38BB235C8D30E14D1564A8624B14C75A03D62EBD11ADE2223235C81784171E0078E596D53157E9779F83616B509081C6B6235E410B83644919DED168937FF514E5F41");
    std::string Exponent1_str = std::string("AB4FD465EE0418292EE88E6EE29BF0D64F498EF65611307AC19D66EC7D6F604134BFFC0CEAE14FC20E88327F66D2A6C9F78D54A79754534480855FCB9F25495D16D4C436D1654629730ECAC978FDAF90E87F5DB6828E60EDEA1E4E8226CB34EE1CEE30C70AEFD5EDAD5E8EEA27A48A3D6EF8A4837A162715B9950C9A3FB0F40D");
    std::string Exponent2_str = std::string("8FC7F2986340053AB059B0862A30040B344A3AE6ABDA4AFE0679E305D6E7156EAA1E8150EC0990716CD2DE3A1CBD392751B0E4F5C625BD934E44690FB46D5FE4EEF61D9D188FD7EB2A1BB53C6A5D53F3061D54EBD04B49825F1A0C2AEBE0D93B2DB060B165DC3F6D19F1315762DAD2285BE3FD567C04436CF3E6C8135E159701");
    std::string Coefficient_str = std::string("35ED15DC6B56B17F9594CFF198F3099453B18FE0DED2FD297864373D774BEC44BB7C21319637D6F60527C9C19B7B273C13724883CE7289B43C2843AFF39EB576EE5DA65CA67EB9780899469FEDDF50CCC69DF5AFA6B85D3DC0ED37B726A1366B16C5A17AA0764D2AD5A5D332714B6A2884DECD521FE57BB6D099F15108A3835E");
    Modulus.resize(Modulus_str.size());
    PublicExponent.resize(PublicExponent_str.size());
    PrivateExponent.resize(PrivateExponent_str.size());
    Factor1.resize(Factor1_str.size());
    Factor2.resize(Factor2_str.size());
    Exponent1.resize(Exponent1_str.size());
    Exponent2.resize(Exponent2_str.size());
    Coefficient.resize(Coefficient_str.size());
    Base16Decode_Func(Modulus_str.c_str(), Modulus_str.size(), Modulus.data(), Modulus.size());
    Base16Decode_Func(PublicExponent_str.c_str(), PublicExponent_str.size(), PublicExponent.data(), PublicExponent.size());
    Base16Decode_Func(PrivateExponent_str.c_str(), PrivateExponent_str.size(), PrivateExponent.data(), PrivateExponent.size());
    Base16Decode_Func(Factor1_str.c_str(), Factor1_str.size(), Factor1.data(), Factor1.size());
    Base16Decode_Func(Factor2_str.c_str(), Factor2_str.size(), Factor2.data(), Factor2.size());
    Base16Decode_Func(Exponent1_str.c_str(), Exponent1_str.size(), Exponent1.data(), Exponent1.size());
    Base16Decode_Func(Exponent2_str.c_str(), Exponent2_str.size(), Exponent2.data(), Exponent2.size());
    Base16Decode_Func(Coefficient_str.c_str(), Coefficient_str.size(), Coefficient.data(), Coefficient.size());
    EXPORT_RSA_PARAMTERS paramters = {
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

    Test_ImportRsaParameters();

    //Test_ExportRsaKeyFromParameters();
}