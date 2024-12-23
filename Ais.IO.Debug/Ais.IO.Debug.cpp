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
    size_t MODULUS_LENGTH;
    size_t PUBLIC_EXPONENT_LENGTH;
    size_t PRIVATE_EXPONENT_LENGTH;
    size_t FACTOR1_LENGTH;
    size_t FACTOR2_LENGTH;
    size_t EXPONENT1_LENGTH;
    size_t EXPONENT2_LENGTH;
    size_t COEFFICIENT_LENGTH;
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

#pragma region RsaIO
typedef int (*GetRsaParametersLength)(RSA_PARAMETERS*);
typedef int (*GenerateRsaParameters)(RSA_PARAMETERS*);
typedef int (*ImportRsaParameters)(RSA_PARAMETERS*, const unsigned char*, size_t, ASYMMETRIC_KEY_FORMAT);
typedef int (*RsaGenerate)(RSA_KEY_PAIR*);

GetRsaParametersLength GetRsaParametersLength_Func = (GetRsaParametersLength)GET_PROC_ADDRESS(Lib, "GetRsaParametersLength");
GenerateRsaParameters GenerateRsaParameters_Func = (GenerateRsaParameters)GET_PROC_ADDRESS(Lib, "GenerateRsaParameters");
ImportRsaParameters ImportRsaParameters_Func = (ImportRsaParameters)GET_PROC_ADDRESS(Lib, "ImportRsaParameters");
RsaGenerate RsaGenerate_Func = (RsaGenerate)GET_PROC_ADDRESS(Lib, "RsaGenerate");
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

void Test_ImportRsaParameters() {
    std::string derPrivateKey = "308209290201000282020100D56A128C500457DB2FD2B7A0D4BC3230EA7C183EBEB732AB285BE53C3A88D3E99112D717431D9B8486E0683128B2549DB781B2E38DBCDF287DC293B9927B5C8B5F7DB19000D0AB88B7BF95F92D09C9D86501B24C930EDDC82E89EE8398A4DAC344283AA6DA1C9FD0B6BD0D448397C17F204C22770D2BC61680810307D2B3FDB23BA6EB2A5219D1A9920DA749C375E06FEFE96A5DDBACE292657B11FB4C676211A7C51341630EAFE0C2201B813C8DE3C06A3507FE4EAD1FC7AA328BDF312166D0A2C8012B42744EDD71A261FB49E1C822D7D63FEB9D23272567F604141C8F0DA144DA02FD1085F635C1D39DFAD9050FC7B197D1B695CF259DB409BF8AB9E9474F54F5838187E4A4A25C972900E4D6581D8BCB9CC1B3A6006B96A9EDEB822ABDED66BC5108AE4BA514B29608BB591F46C6C5B9C4173E13704EB2E076F1108D949D41E623E93355E2A14C86373716FA257482C8948B910B2D9003FF765030DDFF73C46925A51E0EEA501F596F778374FC72E8E2B839BA22A236A264A9EDE1A4C504F2B6419D0849064CBBD8AC901AA16CC2237069F2C35AC81B313F7931002F83925BA3FDFFBFC7BD8484ACC0D05AA750648C73D752DE591E7D6A51DBEC88CAF3AE506A5CBC5C1861C86D5016414E82431F3AA2770CD90C927789F902360F8536052C966B2B76B7C27855435A3272C3E366E626D1ECE834CB93C52E1C97E0C0AB9F0203010001028202004B4D06066425642A7E914721846E72F7378559B8A9EA52027A57126751EFFD75A82E919E2F9C3EC7601FC623B24C59F6DC4CF325BF5929144C6B5F5C570717FC45514059A32FFD965BDF49B785E0B24B9C3821054BCE2F0AF700CC1BBABC50441DC4640D83601E33B286BA2BB692D13F5DD1FF472A6A8B965CF9286C9637D408136C2E05DCBA2774418877C25B29386BC6A70154E4B1F7AFD806B8AD86A3E3C27F03D66B77DC32CA8734750000B1BFEEA08ADDAB296F848B1ACE82F3D98E038D1222A7E6EFA7C23BF860675A1713875E63F1C0D40DB9DD92214078E7EFBBB9FF711FCB7627625D2152A6AC535A47A2EDBF07E6831A10E120E7E998A00640FD5BA7492E24C9328B5AA1DB37811C5BF403672450C054A4F5874C86716DB3E27F6F38CCB254C5AA5F65D82D334FBD612C0FB177119DCCE0B4949F3BF577A240DE82E20A6B61301902669657B35EACA02F238C877AFE6906DD9EDB6C55086B5D39E979A9545AD4415E9E2A712F151C39A416892BF3A676810BE248D09BA2DA66F6AADF09ED0B291A10C35BA682CB7297248B4735A8AF88CEFF914E830CA9479516EB5F846018CEC9EEA3E1D71DAF5AC44BA9E250D493210128BE3D9E08DF1EE41F2142461A813892ED1E4B9B5F8CBAEB8EB246982D0EC19D2F2D035BF2995CDF9253F0454E003B6246A52D1242BB351D553B540A1AA76D497BEE9B6E423CDD9993010282010100F8785D6AEA73E913980A1089CFD6FA5714AB7939973BBCFDE6FD63F81B5DC6BACFA417C925F222A735C3EF80767C5C86221EA6BCE9647D37F812572BE7A809B560D6CB402D6F34A3016833AEF265C881CEFE46B89BF62FA1ACD0698B88D527AC3CB5F92E1BFB5297F2A621E3B5DD3B67AFF901CC04CCB6E4626491B98FA395DFB21C2D460E0321D2C238E9C5555F2356671D2DC053B63F3F8076A72D5D56AA3A1AF3FE977103DA0412B59D383BB3C24735A281D2DAC9D2BB6D1DB95BF5C3138C188595AC452198410EAC1DD845F47C2A237FB7D990770A2A1DB88A483F1560AD6318BAE52336FF100AB83DE20D0B374300F0B9111DC273C8F69A06E868CABB210282010100DBE1BE71C1B72E482AD30C31F530C831C5BB21662167A06B7E5E22E7138BE08CCAC6169A44BD2DC195F092280EB0186E19CF99A546382A9ADF49B5CE3252C7C0DC15F91A1554DF543D0DE03643807036D02FB7A3B508DF93FDDFBBE62C998055BA3D72797B303641F8B82844034711265A95B2DBF2FBA4DFDBFA332DBE6EFE80A2315968C171C19C28306808D708327498500C4504B72C6FA94BF393BAF47F88A084C82111947D7421124A2E803EB8837A6424F7622521575FAF9CDC910BE205C5EA91EE448792EA11867CBA0B407C46A53674E7C05ECA372A2BC4422286F53B6ACCD76763E77A36B286AF3A914A346444CD6D33621B17895D1DA74C301B4EBF0282010023262BD8EF17BC961800FC7BF259F00A1793764FAE54361518F3298C349ADC7D1AD894C0D0CC631892638862FCDFF4DAC8C2DB458822BE1007D8D85A0EA857CF3FC6C2F3EE397811C3263181832AE0E57419C679611EBF783891370D152B4A3474562DCCD70A83919932E542683CC6A59160415FD221FF916955DEC3884D54EB532FE73BACC9C6A420F39A265F40592864E7DCCC034B99C0EAF45E0BEDD34FBB6E8AABAE52BF7FBCE9C4A55C0A1E10D2B004B026DAEA8814198885EB3B660042E64927763A45595B82AED87DFACF6E2D2BDE6A6CADA2195F01DB543C8A2805082227A270BDBD8EF17F02B7465E20030E4878C54565975777CB62D8AD51FDB3E1028201010096A49EB989225B0F0E67F15EF8C1272712751678C6421CE2087DAE23EA7C56A79EF4FFDF4960E2CC5251B390C61F575D774987D677B95B5727CB744784AABA382390DA4D48781159C14A946618F111F03BC9B562EF50D8FCA75E757948ED11C3AA091738AB71687AE25029260FA8CCD31E1499A99F5B50A61E2BD88C6A7FD8D58049971BF20C61BCFEBBCB4AE327B689B320848774A79A461612F71A2B67FF4837D140DB8713D8AF8B48E091E343155EDEA765BC26FD914E2F3C3D97CFB7F86E441E65447CA6F5BC6FAD581E8E3EEBE5EAA2D88D3E7AB2C8009863A97BC6429526A298A1390D09EA177DB6E7C54AB5824CB10133C6EF10BD07929D5FD145A43902820101009FC65592D75CB692C39065CD934A3DCB8F8093F65B7E74DE0C0775F5D50F38ADF77628A1C8BF0C9ABC8F12FF25453470458DD9FF44840A62D9E66B0B03FA493FE1882BC1AF4D09A950CBD41A6F1BA6EB58E3581020A038BC3F276067A7E4B8D22DC23128A3F207E5539F007BADEDA1F11D194D8477A4591D7B7BD8C06E86B5EFDD2FDFCE66047B28E6D59E5B86D29296D260E024483E6FD09B71F3FE978EBDF175421C4B6D945C5E7499A2BA2D797450AE561535185EF60E44718FA2AD8F00EECDD0866FFB98D847E621FB63959693A90CBF21EB6A89539935F0EED6010DB79E51EB6B32D751AA57FA2EE28B7B95A12CB98DEC6B172D7A521DFD729F52E4E620";
    std::vector<unsigned char> derKey;
    derKey.resize(derPrivateKey.size() / 2);
    Base16Decode_Func(derPrivateKey.c_str(), derPrivateKey.size(), derKey.data(), derKey.size());
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
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    ImportRsaParameters_Func(&paramters, derKey.data(), derKey.size(), ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER);

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
            4096,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
            NULL,
            NULL,
            0,
            0,
        };
        RsaGenerate_Func(&keypair);

        std::cout << "PEM - [" << i << "]" << std::endl;
        std::cout << keypair.PUBLIC_KEY << std::endl;
        std::cout << keypair.PRIVATE_KEY << std::endl;
    }

    for (int i = 0; i < 1; i++) {
        RSA_KEY_PAIR keypair = {
            4096,
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

int main() {
#if _WIN32
	EnableVirtualTerminalProcessing();
#endif

    //Test_GetRsaParametersLength();

    //Test_GenerateRsaParameters();

    Test_ImportRsaParameters();

    //Test_RsaGenerate();
}