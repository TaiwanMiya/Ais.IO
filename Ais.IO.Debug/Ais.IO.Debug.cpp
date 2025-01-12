#include "TestHeader.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <iostream>

enum ASYMMETRIC_KEY_FORMAT {
    ASYMMETRIC_KEY_PEM = 0,
    ASYMMETRIC_KEY_DER = 1,
};

enum ASYMMETRIC_KEY_PKCS {
    ASYMMETRIC_KEY_PKCS8 = 0,
    ASYMMETRIC_KEY_PKCS10 = 1,
    ASYMMETRIC_KEY_PKCS12 = 2,
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
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const ASYMMETRIC_KEY_PKCS KEY_PKCS;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
    const HASH_TYPE HASH_ALGORITHM;
    const char* PKCS12_NAME;
    const char* PKCS12_PASSWORD;
};

struct RSA_CHECK_PUBLIC_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PUBLIC_KEY;
    size_t PUBLIC_KEY_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_PRIVATE_KEY {
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const unsigned char* PRIVATE_KEY;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_CSR {
    const ASYMMETRIC_KEY_FORMAT CSR_FORMAT;
    const unsigned char* CSR;
    size_t CSR_LENGTH;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_CHECK_CERTIFICATE {
    const ASYMMETRIC_KEY_FORMAT CERTIFICATE_FORMAT;
    const ASYMMETRIC_KEY_FORMAT PRIVATE_KEY_FORMAT;
    const unsigned char* CERTIFICATE;
    const unsigned char* PRIVATE_KEY;
    size_t CERTIFICATE_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const char* PKCS12_PASSWORD;
    bool IS_KEY_OK;
    size_t KEY_LENGTH;
};

struct RSA_PKCS8_KEY {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* PUBLIC_KEY;
    unsigned char* PRIVATE_KEY;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
};

struct RSA_PKCS10_CSR {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT CSR_FORMAT;
    unsigned char* CSR;
    size_t CSR_LENGTH;
    const HASH_TYPE HASH_ALGORITHM;
    const unsigned char* COUNTRY;
    const unsigned char* ORGANIZETION;
    const unsigned char* ORGANIZETION_UNIT;
    const unsigned char* COMMON_NAME;
};

struct RSA_PKCS12_CERTIFICATE_KEY {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    unsigned char* CERTIFICATE;
    unsigned char* PRIVATE_KEY;
    size_t CERTIFICATE_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    const unsigned char* PEM_PASSWORD;
    size_t PEM_PASSWORD_LENGTH;
    const SYMMETRY_CRYPTER PEM_CIPHER;
    const int PEM_CIPHER_SIZE;
    const SEGMENT_SIZE_OPTION PEM_CIPHER_SEGMENT;
    const HASH_TYPE HASH_ALGORITHM;
    const char* PKCS12_NAME;
    const char* PKCS12_PASSWORD;
    const unsigned char* COUNTRY;
    const unsigned char* ORGANIZETION;
    const unsigned char* ORGANIZETION_UNIT;
    const unsigned char* COMMON_NAME;
    const unsigned long VALIDITY_DAYS;
};

struct EXPORT_RSA {
    size_t KEY_LENGTH;
    const ASYMMETRIC_KEY_FORMAT KEY_FORMAT;
    const ASYMMETRIC_KEY_PKCS KEY_PKCS;
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
    const unsigned char* PEM_PASSWORD;
    size_t PUBLIC_KEY_LENGTH;
    size_t PRIVATE_KEY_LENGTH;
    size_t PEM_PASSWORD_LENGTH;
    const char* PKCS12_PASSWORD;
};

#pragma region RsaIO
typedef int (*RsaGetParametersLength)(RSA_PARAMETERS*);
typedef int (*RsaGetKeyLength)(RSA_KEY_PAIR*);
typedef int (*RsaCheckPublicKey)(RSA_CHECK_PUBLIC_KEY*);
typedef int (*RsaCheckPrivateKey)(RSA_CHECK_PRIVATE_KEY*);
typedef int (*RsaCheckCSR)(RSA_CHECK_CSR*);
typedef int (*RsaCheckCertificate)(RSA_CHECK_CERTIFICATE*);
typedef int (*RsaGenerateParameters)(RSA_PARAMETERS*);
typedef int (*RsaGenerateKeys)(RSA_KEY_PAIR*);
typedef int (*RsaGeneratePKCS8)(RSA_PKCS8_KEY*);
typedef int (*RsaGeneratePKCS10)(RSA_PKCS10_CSR*);
typedef int (*RsaGeneratePKCS12)(RSA_PKCS12_CERTIFICATE_KEY*);
typedef int (*RsaExportParameters)(EXPORT_RSA*);
typedef int (*RsaExportKeys)(EXPORT_RSA*);

RsaGetParametersLength RsaGetParametersLength_Func = (RsaGetParametersLength)GET_PROC_ADDRESS(Lib, "RsaGetParametersLength");
RsaGetKeyLength RsaGetKeyLength_Func = (RsaGetKeyLength)GET_PROC_ADDRESS(Lib, "RsaGetKeyLength");
RsaCheckPublicKey RsaCheckPublicKey_Func = (RsaCheckPublicKey)GET_PROC_ADDRESS(Lib, "RsaCheckPublicKey");
RsaCheckPrivateKey RsaCheckPrivateKey_Func = (RsaCheckPrivateKey)GET_PROC_ADDRESS(Lib, "RsaCheckPrivateKey");
RsaCheckCSR RsaCheckCSR_Func = (RsaCheckCSR)GET_PROC_ADDRESS(Lib, "RsaCheckCSR");
RsaCheckCertificate RsaCheckCertificate_Func = (RsaCheckCertificate)GET_PROC_ADDRESS(Lib, "RsaCheckCertificate");
RsaGenerateParameters RsaGenerateParameters_Func = (RsaGenerateParameters)GET_PROC_ADDRESS(Lib, "RsaGenerateParameters");
RsaGenerateKeys RsaGenerateKeys_Func = (RsaGenerateKeys)GET_PROC_ADDRESS(Lib, "RsaGenerateKeys");
RsaGeneratePKCS8 RsaGeneratePKCS8_Func = (RsaGeneratePKCS8)GET_PROC_ADDRESS(Lib, "RsaGeneratePKCS8");
RsaGeneratePKCS10 RsaGeneratePKCS10_Func = (RsaGeneratePKCS10)GET_PROC_ADDRESS(Lib, "RsaGeneratePKCS10");
RsaGeneratePKCS12 RsaGeneratePKCS12_Func = (RsaGeneratePKCS12)GET_PROC_ADDRESS(Lib, "RsaGeneratePKCS12");
RsaExportParameters RsaExportParameters_Func = (RsaExportParameters)GET_PROC_ADDRESS(Lib, "RsaExportParameters");
RsaExportKeys RsaExportKeys_Func = (RsaExportKeys)GET_PROC_ADDRESS(Lib, "RsaExportKeys");
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

    RsaGetParametersLength_Func(&paramters);
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
    std::string pemPassowrd = "7331323239616263646232";
    std::string p12Name = "Ais IO Debug";
    std::string p12Password = "debug-123456";
    std::string derPublicKey = "3082045A30820242020100300D06092A864886F70D01010B0500300030041F001F00300030820222300D06092A864886F70D01010105000382020F003082020A0282020100F4583DB2BEDAD63CCD901578E0DC486A6A95BD04D552C30DA18D6F3B213CB27C821F6F9CC22B93F4812ACF61A5A42493AC626A80C80211798EBC35FA8C9BC829D7C3EBA6F894CC1940932807BA3365B445710D3F6E5990CC7A8AE40A5E1DD37499D4F28B91A666AEA11B348AB47E8A7EA81185E0E43942560FB4A218123F351F768923B4997D8046531DCC39449C0C3C93BA357293A5306FDA7CB5354E53F0595564AFBF6A0EF1F5FB0187A472EA8046D849E6A5DC86432983B40C21430F0D0E6D9939C5EA85FDF25849F0A2E68DF25C36A98AA1CB38F804CB1E61DA3AB0081E8AD1AE156F9CC8CA4384D04166E8BF93601227128D34B72CBB29A404E1544E88410144556BA08943C6C604C8EFA282E749820FEDA6D261F6E285C9E47BC6FE27D68933DAAA8F1989E6245CEC8CC7E2354BC2724768AF0CB7BFC701C37E4E705C4DCC02E47D47F4F16D2E6780DBEBE0EA052BBDD60BC65326666F7D1ACA57EB19610D2BFDB6CCB5CD20315115B0CD18CDE2D3BB68ACDB80E26CA24326103D1D74F19C531EDAA0963C60B7E35E81AB1838246AFDC226F34C6F644BCD80C65D85B852ECBF49998A9947126D32334E1402B5216E77EEE22945AE35DBB3FB7DE3F1EFDDA5CCC1AC790C72BAC0A092BFE6ABA191293E74FEB9C319BDD2C0445C98F8E0E17F521D78E824FA824FF950F8B09E45ACDD48BAE334B8D8F5735CA36AE5C2CB0203010001300D06092A864886F70D01010B05000382020100F4456281DC61537FE37921F160C0FC313A5A9F488036CF1E9547486FEAE32BDABCC7D4C36C317D95E3FBCD91D7E5C99A78D9D5DCFD9F63CC44487DAA69B66D33EF67262E5822EE9C7C5F861CCD484DC0E0929B50CA5B84E8835E566608142730C63EEFA38E5FEAE234AAA100B8861EBB57C870FF1CEFE06B0942A33665471429067836028ACE51A754BAF2A108358DC45720A6579EB07E81D38568786D29A42B46903CD1AA1697B253637ACE5B62CE755C58AB47B9BBC149869EBBFE806575B3BFD63052F802D553624EA09A949D083DA870FECF84E47C8DD6AC4C7BFC7294735FA3AB785C962064034268B8BFD65BB57208E15A5CA290509A45903025711BD089621E8904C023B0CEA2800AFA4714B8309D490FBF121257B0C939A1B88648936C21D8CFD68469EEEFA509B5C59FDD3EAF9E7E3278DE9C5663DB89C9D169B6619F01DD1303654AABB559B7730304D17C9F827ABE0CEA9CB00D07D3E608EACB140EC3C65004E112C1512BDF756A71AA1B8C5DC176672F956847D81F7DE0B00C08E8B9A5B8637195888B019F7DB0F0E8A6A6F4305DBE896B4890F001967AD5351F23E78D9EC5D9DFFE65238E95C7956A12722444794660B8F6B501CF065E63A0B9B71A3AAA00054AF8C7866B917CD3D59ACCE90E31D0D5DFF04BEC98FCFABBA6E98183A9675BE8B40CF87AC06EC9BE2A844F5CBE8F39167904B88729A81A24BE24";
    std::string derPrivateKey = "3082100602010330820FBC06092A864886F70D010701A0820FAD04820FA930820FA53082056A06092A864886F70D010706A082055B308205570201003082055006092A864886F70D010701305F06092A864886F70D01050D3052303106092A864886F70D01050C3024041098A2CA153BF5D780C227B4095FD393A802020800300C06082A864886F70D02090500301D060960864801650304012A041061BD24712C2AD08EA342724CD055D609808204E08B88A488317490C9327CB98DBB931680113488CD09A3758FFC496AD6E7511AAFED1C4E9904BDB52D180069CD6CA829A85F3C223C4DDC6379F557A41ACC3729AC48A6CAED2C8C8E79F0CF1E8361A7BD3B6A1DD34F63C81C0F870787D8221DF8984A2F4A9A8416434903C4F089F20FF5DA65C32B3954F76C88B85C9722EBFE8B8BB94D2FB24D0EA3E2E0CF1B201C5D776DBAC3FDBB83C946F574B89181D44951AD3A807510EE75A1A656268A6AE8B9EB70C3D4BD25B9C50B3B8B5767683898BB5A2B9B2CCEB585575943C8B82A57F91E8CA6E08783780A417CF5765E67DF68818799B99F32C60CD0DC937471135B495D9C0FA4CDBFA8FF98C2B6F03934120714131D9A6F2D370CDEB28CCEC71806DD94E8BB5FEF78D7D28EE0799B1A30ACDB1DA1287216849870FDA0D9BD0B2BA8684445BBA07D8C431188FAE0177272E59F60C5C5697A4B3DE8D4185595EEF9B189BBE8F7AAAFEAA905AF6991A5D766E57DB936324F8E2D8A889BA107739A9C18EB4D71A15328C963FFFA7AB9D657931C37A425984E8604E9C81E4BA0132BAD9538404E06118B566B426BB9ACEB8894D8965209198AF978E717BD8093D9C198B16FDA10673C8D8A2C7C9D1DB55943C3CD417D5D6A64370A24FE1FAE34E6322165736BE153BB9FD7C09A6D4341E727906FA06183E366CE28511B7DC665A8A58BB86CD63637285DDB882860BD9776B6FF9A1F5355F0A50FC81FC658A685969132086E7688169CD6979A5937533F3A614C5BB477C8DCA91FED56C1B5FD2DA7DECF9F2E53805C54ED9D91FBEED89B5E80431C7DAFFA8A20508F8DA02AF28789B19C4ED522862AA6123765FB8C2E46D219055901DABA477E03AE38999AEF50263B3BEF0E98779F66D8D67D585DBD4ABE17E263C8376FC4738EA225DF7DEF0985684150B9B8CDCFE37FF4727ABA970E77A86D329963FEA6BE562E243424F06E7605E5A709858B61DA661E50D911B715E35971E4F6F3F93C27A5A129860C1696F6C42CD543EF837B781499AFCE29882BE92FA3D1202273A2D792D6ECE04D3AC2B71A1304DF09A8A73A1A3DCC848DB83337E013D9A2B7F101372CADA536D147664242C5C82D03ADE8F0E01A911E1990C4846F0251F48F082DF613F2EE22AFE22831029218EF4D6EDF79093E1F7D4C37E9ED450EA800CFE953DA070B9407C3F9C92CBDA38008315BEE70DF38C5A9D8A5CDBFD708CC45D0345C0E1EB55E9CB648ACE23A2C405BEAD08F60ADB25F218AA5BD49309EBE9CF678E5153DA1FDECF7874A18CF8443A1A948AB1991E715CABE88FEB606C392FA5158205A882E8A38DD5085899B0B621C8E0F8CC592E7C7A6626F08A2DFB7DB60A76DF533C222A151A620E622267212732079326CA72D91439BE10EC6CAFC3AB6113C4D2E4D12170A8BE773300FAC48334F2F576B2ED376CCAFFEFF512DC000963B01C71677DB6825BFCF6EDEFFDAF4CA79F8B67E2B4712F0B64055AA3E23B69A5CB85318EC782291CDE41883DC9A6CBDDF5B36A016FD3AD8A96E47C526C46F37A3965655F22C8C5B360444C7AFF750D4E004194DA8E1C6735FA1E05B2713838986BD63A10227D7A80BC8AFDFBD696EEE2AA753BBD79695D81CABF9350187A08C0F6EEA4752DBA8CE8B9BBB7C122B66778D70BF2704075EE6D848A02658A4E18A635CE84F486B9B88BC7ED5A4A039D3CDF80BF0830B1FE7287CA88124A2D3C64C6593B516C08C7E57B7AF2B258E1117A0F23642E270F7FD5FC5057D866538CED9680430820A3306092A864886F70D010701A0820A2404820A2030820A1C30820A18060B2A864886F70D010C0A0102A08209B9308209B5305F06092A864886F70D01050D3052303106092A864886F70D01050C30240410591F2028CA0C74EA6F9E2478C924C14B02020800300C06082A864886F70D02090500301D060960864801650304012A0410DB4528F5E3FF28411D9FD05D40A85CE20482095017B001AABFA80C766A6AA22237618F684A244DF3830878CAEE31ADA24E2BE06BE90CD84312C8AFD0D8EF2B1D1619CE116EF0421FF9044808B437D162DE08686A252A2F74C048F0A4AA4124CFFFC79402EC273B4E4AA389661643D61D4E565B7028FDDD65AED142714846890D59AA0E3CA788C79F70569B8C38DE7E81EC7E2FC64152FBC7C32CA29D334C7E4585FA630BF7B8C50D2895110DEC6B127CA453D8FB1F5227CB85CDBA9C3555F95EDB090556E3052E3CF01A966307E8F6B0C283D719255716895B8B2382B2133B365F32A91D2A6189FB4F9C31473A916C3F4593F31159E5193015D753E80F2E87A24504B60AFF7C3DCD4A3327A1C8C3E6140190A1431D946A980E83D3CB9D8774CDB0FF7BF7858BCF973BBBFB4D2E5A066119EDBB0243E79787DEAE51BC626256C65D7CC0B3945678C6AAB62D66355F894794C79530C80498802561E16DC3EFB2F83E23468B2FFB18897CFB5967B39035FF825D658774B9DADEF8A77287B37BA2C4EBA44ACD13904F7DBD3BF119076D5023697850E89F7B51163FA79FD249CE7C11451B73549FE8DDDFA205476A61D424466C726418FF166132D4BF304638E3BF698598B87ED5C167939D8B7AAED59365CDC323D5866470DE56BE27AA36D29EEE870BD4042CC78F358FC62A5BB328C5E098FBD835EE4B11D84418331FB8284D786E849EB4A163B5FE60BE5B1A5368AFCB60B39DB80C4176B959C85251DDE483EBF970599C82D300F222CCCA5EC563DE2A6881AA45BF5B882A517C522F0709CE62C1B03FA73EF75D4B86E3DD9D58D302F377B05B94E9739FBD636D3018DDD2C6BBFFE62D725D0FB744FE010195D5DC932C0BD1568225EF98FD0F40D5AD3472E23AABB0D384B26DCA2502875EB2BF239C8894B849DCFCAB991D720DF64754F08D43035A8A1A4F89F3E15604757052CC1ADAE56C84604BC09D5B657F0E36412EEE37E720DD7B55874214A71512BC662EAAA98740344B0F34D2850068DD74F0F0BC1B679A11D72FBD4783F917DC246B1578A6AF0DF4373506F671F2CCF8EE2A4FA877F9D7F56AE1349FDE5250856B3FE980CEAE4C1336F1B0E96CBB24839A05F77B510DE9D5EB6908EBAECC6BF3809D6DB49AD8CDB8798268D98A3ADB4E4A6FA68E4E7A97742FCCF1AD60B7F0254C6769831DF5D5A14E6C18A0B56B2B8B5FEBAAD8B87E42607289753E2A2A2F601EC5ACC560A4F2BA4CAE64122E46D1D5EA5B99D9EAB03082A16BAFC2ADFE7D5606A541BA64883173BBADFD3B427D14E90E4DEA6E3318F6DA9EB5AB8025D9971FF28C8FE3842A576744C9638ADFF1E2668EDBDF18E3E2A48CBFAA4362C7D35B57F49DF46A62F4F5DF981BDCBF419A1D19A6785FA0D1EEA582BEC3751A7DBF39DC87B4D4C165F708D7682080021DFC90B6F56395078AAC55AFC5D1DDC9ACE25C173D4CEA87707579F7F37AC52D6B501B31A3647B5DBFE4F828B8B0719426B1F825CB3426DC92A24F1E1231B923DBE82F3F9FC15407641E06A3C9B98834A4DBAC5750260F9EFF4214E1530AA6E795D5EEEEEF7923F141E22CE3A0B30332FF4F3E8CA5D3843777BC71ADD30A158B25134F7F1B4DC12A839F15BCC5595CFE28D7262484BD5FFF0C8CB6C0B32639A8523CF6AADA4A531787A3B69E845C2E51D79E9ED0EA098C126492B91CC19364A00462227D3EF52FC3DADDBD741664E96ADDDE10F0DE30181300C3F866A50E4DD267A03BA5D3823E216342894AF0090D39155F52A5F7613960563C4A61879896EE0AED03CBAB640A0124B6477CEE8789F326EDD4EE787CFDFAA592A2557D3498FAB277EBDE312B37A3C6D30CA134C91F3366D070BA5C6DDB822809BE728F6BA2B04D245B5A3B35BD96867476194BFBD8D5FCFA6F838A1FBFC72E120F6CD79F59F809FE2FB53C31D4F30643D228AF1476E0B2BE1A937A0B8E82B46DFDEFA2CCB7F11CC752542368B84FAFE7F6C1FF65D15622F637E1BD51EC5EC841AF4247B6FEC70165D76D9E6006BAAD54A1B0BEDF6EE9258D404098E34DE07FF0CBF722F49A1409F0EAC896D5B5B5A13AF8A98FFAEBE1EDA7D50D27EF4475CCA9E60680980E0D8CCD1F2F5D2D329850610D160D90CE400E8CB4C24D26CC031267B42BFC3860606BA424E0A5A963727CD15939C7FE4285C713880A4ABA05DFAC1526DFC24D35FBA86805E947ECFA64FB272DBF70F91C72F4BFDB5E64C21412DC915A9F476238908FC90004C58943C969A91E163F2A5CBE6D1FAA68F34178119A076CCB1A8E5A14487FC6266177B25D2C5A83033823D4AA9A76715155750980F224F7EC9989C52BFAB5DE66381AEEE529D1A2D08AD3D641FE76DFC80F7260A51CB7B68E034C04A3A013D9BD47948DCC182A8B0936D762A74C57255DFC0C0C1D6C99CC19648421A072844E23191376B0072C0514824054457BD3D7EBEC41D6CCAFBCF9DBFB3E660C06328F06E3B22C6B044645FFDE9DEB66C201255692B00C9F7A65B7363A11F389AC9D496818FFD8D7C2A42186BBB749A117670F151E9AD6333122D8B2375773F23BE22FFD9DA0C6123168C342C4463DEE60D5C7182D233ED28A62D21F3C746927B76E113944A4C4D47EF36356C8514126B824E98BCC8BADF5FE6301707B314C34CC6CCA9C6665BDACB11DDFDA6F29149AD7F5E22E09AD58294D740BF26B557B9282D6E5F2A2A656C5276BC89B2F0C3E006B1A9BC35EFECFFDCF09AECE248C6AF2F82506F6F42953554E34D067971A11046BACCE5DE331A78055BC4484695C0393D99C4566DEFB5B43AC6558AFB4E7BA2AFE6874E02A8F7A55E3AE4AA58970B9D2B79C959BDBEE84BA5B122B794E87BCEA127CBEE1E086A2961E4B6CD51F2B7E559867E1BA927CEE2FA1030F2062B61BFD286F5C194C4F7DB8F75DC1F59FF2820363A79F6B45CA352AE038D385B2498ED68FE4E964AE0BF80487B3FE80A0BB45697AAFF4D8A6A440E31759DF55AA0C9F83EFC13E0351500DB076A4E5A2DF8FDD80BEBFF81757931B708D8C566B8C615477EE5D1226F2F47E4A49CF825AFF6EDC10C57EC16119CFC9F2A8D16A6BC05128715A30C0F4D46570045915B377C673CD92411332657026737FDCB105800BBB09E260DEB01BB2F7177CFD8C146C9110E2576AD51B1FB9306A4E1AC41066003F712AB297E7933C0F05255B7A122DA838C9A6589C6F1DE27172C14BA66080611F703977DE7C232F8120082FC4BB9D3259D705C0CB9A3CCF1FD809FD0755A0F0FCC2FB86C6B9F1DBA963B74F475335C9542046B4B61522ECA753815516131C2C34F82B286E6EB58C2AF0042C73B50C96F219233BB62B4960CE8AF8A65FFEFB5181D8C57451EE3A17587C2AE65AF8163219E0EEB23D386FB270915B24B2AAAC6B9B314C302306092A864886F70D0109153116041419749199F237E42D4423E64EE972A17D461D28B1302506092A864886F70D01091431181E16004D00790020004B006500790020005000610069007230413031300D060960864801650304020105000420AADCB566B5F7F87017D701FB977FD4EDD407928018BC9DB6F7E3237D196F54030408E4A3235512C3C5A402020800";
    std::string pemPublicKey =
        "-----BEGIN CERTIFICATE-----\n"
        "MIICWjCCAUICAQAwDQYJKoZIhvcNAQELBQAwADAEHwAfADAAMIIBIjANBgkqhkiG\n"
        "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjkfv3ul8S4hmJ95aZ9DKTsurBn9JU4BzK6Zx\n"
        "+TPYMFjdCojzQndas2tS4KYG8CSMBoQwox5LAu/UgzXbT8umyG816yKzbKuP7meA\n"
        "z3YBO1TlDTeMRAU1yZCpeP697zvDIo7/KRZUCMCKKdbsOLOvfbcZqIApYSf2usUX\n"
        "GNz+D3XT+26eITVvi+BjcNGemA0uP2c9US/L09G8DWg8GDEkf3wd1SosyiYzhMo2\n"
        "sxzvFfdhjog91jMNhvTxwx6N03IJwrWHdV9WCWXhekm7alsbTlftx+nBP7bKDMRO\n"
        "w3h46eW7AWT+Ci2Ii/JYFIr3m9is5eo6gTFXSaF9XKc8GD43FwIDAQABMA0GCSqG\n"
        "SIb3DQEBCwUAA4IBAQAkAYXxMfsYu+cqt2S4iGLbzMJXOCBuc0k5RJ0WrV6ya2j7\n"
        "5ULnDqUkvRkvmhSWqYQm9YqYkYA1k/r37l65u79nbebe+XX9UMrFv6A7NfhNwTut\n"
        "JyQBAkOFbSA7DlF++pzr3XzaUbJo26rcrEyPynO8ZZSnNO3VjFgk40SLi3MrvIHf\n"
        "oYKmWyEG+6hJef6b0+YNMfflzhHI4jB+rRY2CQH4aMNLnEySXF3O1jETPeQjh0F5\n"
        "4tw7tgcwbUaq470ZMTlx3vEIf44Al+kMruywyBhtQfdF8YwXilbPR6EFtlm1XN4r\n"
        "3x+tAhZSWvu6VampviDj8b/gpmV8fDJ8uwTWqXzz\n"
        "-----END CERTIFICATE-----\n"
        "";

    std::string pemPrivateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "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\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
        "";


    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    pemPass.push_back('\0');

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
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS12,
        publicKey.data(),
        privateKey.data(),
        pemPass.data(),
        publicKey.size(),
        privateKey.size(),
        pemPass.size(),
    };
    RsaGetKeyLength_Func(&length);
    
    std::cout << "Key Length (Bits):" << length.KEY_LENGTH << std::endl;
}

void Test_RsaCheckPublicKey() {
    std::string pemPublicKey =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkDJ9SkQuB/wfwZdYSWsE\n"
        "TbYuW6aVluWnONbm6L0SP4EyKHSPd1hwX3LzJinTtu+R3mwS01SwtYx9CPQVaNiP\n"
        "MV3DysxIx26IVrk5DGFlNHChF6+9S8BNNSue+liQos1rzBwwjByFizBffW1UF9hN\n"
        "0QtOc8R1beCKxkpj4yxqQDsAxVK7/khUR1eRkGqAVU458tytbkobm0tYlMRTf+K7\n"
        "e3zC2IPBL8FtwPpuS/+UTZoRkiZWs3Zs9Mb3/5K/nmmVZompiZlaFfzjQh2FthJ0\n"
        "69qFwZn58CBo2bRmkqY70vqJSO1BBq3oD1nfUJVGoFJ5ppL/YwRgb/DMUSj/GGKd\n"
        "FQIDAQAB\n"
        "-----END PUBLIC KEY-----\n"
        "";
    std::vector<unsigned char> publicKey;
    publicKey.resize(pemPublicKey.size());
    publicKey.assign(pemPublicKey.begin(), pemPublicKey.end());

    RSA_CHECK_PUBLIC_KEY pub = {
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        publicKey.data(),
        publicKey.size()
    };

    RsaCheckPublicKey_Func(&pub);

    std::cout << "Key Length (Bits):" << pub.KEY_LENGTH << std::endl;
    if (pub.IS_KEY_OK)
        std::cout << "Key Check Success." << std::endl;
    else
        std::cout << "Key Check Falture." << std::endl;
}

void Test_RsaCheckPrivateKey() {
    std::string pemPassowrd = "7331323239616263646232";
    std::string pemPrivateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "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\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
        "";
    
    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    pemPass.push_back('\0');

    std::vector<unsigned char> privateKey;
    privateKey.resize(pemPrivateKey.size());
    privateKey.assign(pemPrivateKey.begin(), pemPrivateKey.end());

    RSA_CHECK_PRIVATE_KEY priv = {
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        privateKey.data(),
        privateKey.size(),
        pemPass.data(),
        pemPass.size(),
    };

    RsaCheckPrivateKey_Func(&priv);
    std::cout << "Key Length (Bits):" << priv.KEY_LENGTH << std::endl;
    if (priv.IS_KEY_OK)
        std::cout << "Key Check Success." << std::endl;
    else
        std::cout << "Key Check Falture." << std::endl;
}

void Test_RsaCheckCSR() {
    std::string pemCsr =
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        "MIICfzCCAWcCAQAwOjELMAkGA1UEBhMCVFcxDDAKBgNVBAoMA0FpczEPMA0GA1UE\n"
        "CwwGQWlzIElPMQwwCgYDVQQDDANBaXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
        "ggEKAoIBAQDCwIQpjbsDY99VK6onJ6N2hYyuF1XXv20ekqSBInOXylKMenX+D+jb\n"
        "jo61UrGLJsyD9KjyPXrV+5pviDrL1kNg2uwH1zeYYEX8IkN2WEUidG1Fz4YhIlAs\n"
        "rPScces5gUKLXh0xo4rCcZ6NjCbyWEJycrq5L1oA38S/U+L793FwUPyGeyI/u9b0\n"
        "s1XRXB3vIkqqgsrTD5EOsL632cVL1cVC/7pHg3iKC2UPJ0IZ2sc+w/bMHtCkwuhC\n"
        "AhMnYXYP8NvCUpvrU6UI3Rbe7NAPrhyJ8KimJ5kZGiq84jlL9g0Jd4dxOTPAuuzu\n"
        "2vo9bXeJvGi+XP9l7uZtoJnRXFCNmfubAgMBAAGgADANBgkqhkiG9w0BAQsFAAOC\n"
        "AQEAOh5K7sCs2DVoy2kv0inFTbn3uhz6aoJud+ebyAuC5ftojTjATQEp1hdPXYgr\n"
        "NZ9tYWMMn/V76flo8YlPqhjnXI2UhSEEPTw3EWpeb9ideTsG7wX9GL1NjpbbEkdW\n"
        "ENlNtaa+vKZ+NEDtse3u8DV0N4b5f141RIeynf2lkKWpHkBBHPxmy9Ny9eP9flbk\n"
        "JRroWaL6SZlbu1aZR9hb8qnMfKQCz/30nyPCQFVI6xHeTlNw2AaZCvF8lVK7ILya\n"
        "tyxpDPeyBelmveCdShvo4yeuIT5c4AcM/5vTb8SeJDgwM+IJoHPvNCWPk96SpjCc\n"
        "JcC+GHHTBINiI7AV2dKzJxKTfA==\n"
        "-----END CERTIFICATE REQUEST-----\n"
        "";

    std::vector<unsigned char> csr;
    csr.resize(pemCsr.size());
    csr.assign(pemCsr.begin(), pemCsr.end());

    RSA_CHECK_CSR certificate = {
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        csr.data(),
        csr.size(),
    };

    RsaCheckCSR_Func(&certificate);
    std::cout << "Key Length (Bits):" << certificate.KEY_LENGTH << std::endl;
    if (certificate.IS_KEY_OK)
        std::cout << "Key Check Success." << std::endl;
    else
        std::cout << "Key Check Falture." << std::endl;
}

void Test_RsaCheckCertificate() {
    std::string pemPassowrd = "7331323239616263646232";
    std::string p12Password = "debug-123456";
    std::string pemCertificate =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIC6DCCAdACAQEwDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCVFcxDDAKBgNV\n"
        "BAoMA0FpczEPMA0GA1UECwwGQWlzIElPMQwwCgYDVQQDDANBaXMwHhcNMjUwMTEx\n"
        "MDY1NzI0WhcNMjkwMTEwMDY1NzI0WjA6MQswCQYDVQQGEwJUVzEMMAoGA1UECgwD\n"
        "QWlzMQ8wDQYDVQQLDAZBaXMgSU8xDDAKBgNVBAMMA0FpczCCASIwDQYJKoZIhvcN\n"
        "AQEBBQADggEPADCCAQoCggEBAMN/YzHsBH6qN4lus8lkf34qwNCe084zvZtacg4M\n"
        "5eLMS2zSSH7Eac73sXc2AuAefRD1wPp7wou2ab0rWd2SeigQIxUHWLhnUUPayjWZ\n"
        "3G8+65EARZ1IjHIgtI4ksj4gj+itmSGi3kxvOpEXGpg2iK0FwQ7E6gxbVGVtBGCa\n"
        "U213wJrVsOqzCMyHMNiPHoE49HMW2AcW6x8l6qdunlknX3NxTCQ/N+DdOKB9JeZE\n"
        "GQTHp/84Jl91d2x1Tr/tpBWV52ZGlIKPpZfNkCSxgZgHddmeFbG6lrvmXVg4wZTj\n"
        "hXRjRhSEeuW4Esib8qzt+UVjezpS7RIdagk3hg0b0JN9uZcCAwEAATANBgkqhkiG\n"
        "9w0BAQsFAAOCAQEAZj00hReyVWYELyPgtIl0XCCucwZ3hyvWvovR0fxyrR+PjLYv\n"
        "s5B3qYLLdijkn3bReov/Xz02u/J32o2xuzF+6W6eEn9WX4ZQD+KtOwDzzjA+M5KN\n"
        "KJySyJUHyuvhv8LbWusdYxz68NesKr35g0nFDoFrrpEtC2FIrjHXzUADs+u3XKkw\n"
        "WZpx8kWpicjXWIjJXgeZKjoXuPoLeRFOJ3ShEQZQttUXSScDcvM23wC05Ou3cs0i\n"
        "ksLRfq4Nv6N9A93/rDqqnlXAJo8/Fd0JbSCE+bvV/XRiV4OyPooXXCvIjSMq1UuT\n"
        "PTo6Y05wFZJYKPbgmHPMQWVnY4UflhNQ8RiJBw==\n"
        "-----END CERTIFICATE-----\n"
        "";
    std::string pemPrivateKey =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "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\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
        "";

    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    pemPass.push_back('\0');

    std::vector<unsigned char> certificate;
    std::vector<unsigned char> privateKey;
    certificate.resize(pemCertificate.size());
    certificate.assign(pemCertificate.begin(), pemCertificate.end());
    privateKey.resize(pemPrivateKey.size());
    privateKey.assign(pemPrivateKey.begin(), pemPrivateKey.end());

    RSA_CHECK_CERTIFICATE cert = {
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        certificate.data(),
        privateKey.data(),
        certificate.size(),
        privateKey.size(),
        pemPass.data(),
        pemPass.size(),
        p12Password.c_str()
    };

    RsaCheckCertificate_Func(&cert);
    std::cout << "Key Length (Bits):" << cert.KEY_LENGTH << std::endl;
    if (cert.IS_KEY_OK)
        std::cout << "Key Check Success." << std::endl;
    else
        std::cout << "Key Check Falture." << std::endl;
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

    RsaGetParametersLength_Func(&paramters);

    paramters.N = new unsigned char[paramters.N_LENGTH];
    paramters.E = new unsigned char[paramters.E_LENGTH];
    paramters.D = new unsigned char[paramters.D_LENGTH];
    paramters.P = new unsigned char[paramters.P_LENGTH];
    paramters.Q = new unsigned char[paramters.Q_LENGTH];
    paramters.DP = new unsigned char[paramters.DP_LENGTH];
    paramters.DQ = new unsigned char[paramters.DQ_LENGTH];
    paramters.QI = new unsigned char[paramters.QI_LENGTH];

    RsaGenerateParameters_Func(&paramters);

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
    std::string pemPassowrd = "7331323239616263646232";
    std::string p12Name = "Ais IO Debug";
    std::string p12Password = "debug-123456";
    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    for (int i = 0; i < 1; i++) {
        size_t keysize = 2048;
        std::vector<unsigned char> publicKey;
        std::vector<unsigned char> privateKey;
        publicKey.resize(keysize * 2);
        privateKey.resize(keysize * 2);
        RSA_KEY_PAIR keypair = {
            keysize,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
            ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10,
            publicKey.data(),
            privateKey.data(),
            pemPass.data(),
            publicKey.size(),
            privateKey.size(),
            pemPass.size(),
            SYMMETRY_CRYPTER::SYMMETRY_AES_CBC,
            256,
            SEGMENT_SIZE_OPTION::SEGMENT_NULL,
            HASH_TYPE::HASH_SHA2_256,
            p12Name.c_str(),
            p12Password.c_str(),
        };
        RsaGenerateKeys_Func(&keypair);

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
        publicKey.resize(keysize * 2);
        privateKey.resize(keysize * 2);
        RSA_KEY_PAIR keypair = {
            keysize,
            ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
            ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10,
            publicKey.data(),
            privateKey.data(),
            NULL,
            publicKey.size(),
            privateKey.size(),
            0,
            SYMMETRY_CRYPTER::SYMMETRY_NULL,
            0,
            SEGMENT_SIZE_OPTION::SEGMENT_NULL,
            HASH_TYPE::HASH_NULL,
            NULL,
            NULL,
        };
        RsaGenerateKeys_Func(&keypair);

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

void Test_RsaGeneratePKCS8() {
    ASYMMETRIC_KEY_FORMAT format = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
    std::string pemPassowrd = "7331323239616263646232";
    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    size_t keysize = 2048;
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    publicKey.resize(keysize * 2);
    privateKey.resize(keysize * 2);

    RSA_PKCS8_KEY key = {
        keysize,
        format,
        publicKey.data(),
        privateKey.data(),
        publicKey.size(),
        privateKey.size(),
        pemPass.data(),
        pemPass.size(),
        SYMMETRY_CRYPTER::SYMMETRY_AES_CBC,
        256,
        SEGMENT_SIZE_OPTION::SEGMENT_NULL
    };
    RsaGeneratePKCS8_Func(&key);

    publicKey.resize(key.PUBLIC_KEY_LENGTH);
    privateKey.resize(key.PRIVATE_KEY_LENGTH);

    if (format == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
        std::cout << "PEM - [Size:" << key.PUBLIC_KEY_LENGTH << ", " << key.PRIVATE_KEY_LENGTH << "]" << std::endl;
        std::cout << reinterpret_cast<char*>(publicKey.data()) << std::endl;
        std::cout << reinterpret_cast<char*>(privateKey.data()) << std::endl;
    }
    else {
        std::cout << "DER - [Size:" << key.PUBLIC_KEY_LENGTH << ", " << key.PRIVATE_KEY_LENGTH << "]" << std::endl;
        char* pubString = new char[key.PUBLIC_KEY_LENGTH * 2 + 1] {};
        char* privString = new char[key.PRIVATE_KEY_LENGTH * 2 + 1] {};
        Base16Encode_Func(publicKey.data(), publicKey.size(), pubString, key.PUBLIC_KEY_LENGTH * 2 + 1);
        Base16Encode_Func(privateKey.data(), privateKey.size(), privString, key.PRIVATE_KEY_LENGTH * 2 + 1);
        std::cout << pubString << std::endl;
        std::cout << privString << std::endl;
        std::cout << "" << std::endl;
    }
}

void Test_RsaGeneratePKCS10() {
    ASYMMETRIC_KEY_FORMAT format = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
    std::string country = "TW";
    std::string organizetion = "Ais";
    std::string organizetion_unit = "Ais IO";
    std::string common_name = "Ais";
    size_t keysize = 2048;
    std::vector<unsigned char> certificate;
    certificate.resize(keysize * 2);
    RSA_PKCS10_CSR cert = {
        keysize,
        format,
        certificate.data(),
        certificate.size(),
        HASH_TYPE::HASH_SHA2_256,
        reinterpret_cast<const unsigned char*>(country.c_str()),
        reinterpret_cast<const unsigned char*>(organizetion.c_str()),
        reinterpret_cast<const unsigned char*>(organizetion_unit.c_str()),
        reinterpret_cast<const unsigned char*>(common_name.c_str())
    };
    RsaGeneratePKCS10_Func(&cert);

    certificate.resize(cert.CSR_LENGTH);

    if (format == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
        std::cout << "PEM - [Size:" << cert.CSR_LENGTH << "]" << std::endl;
        std::cout << reinterpret_cast<char*>(certificate.data()) << std::endl;
    }
    else {
        std::cout << "DER - [Size:" << cert.CSR_LENGTH << "]" << std::endl;
        char* certString = new char[cert.CSR_LENGTH * 2 + 1] {};
        Base16Encode_Func(certificate.data(), certificate.size(), certString, cert.CSR_LENGTH * 2 + 1);
        std::cout << certString << std::endl;
        std::cout << "" << std::endl;
    }
}

void Test_RsaGeneratePKCS12() {
    ASYMMETRIC_KEY_FORMAT format = ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM;
    std::string country = "TW";
    std::string organizetion = "Ais";
    std::string organizetion_unit = "Ais IO";
    std::string common_name = "Ais";
    std::string pemPassowrd = "7331323239616263646232";
    std::string p12Name = "Ais IO Debug";
    std::string p12Password = "debug-123456";
    size_t keysize = 2048;
    std::vector<unsigned char> certificate;
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> pemPass;

    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    
    certificate.resize(keysize * 2);
    privateKey.resize(keysize * 2);
    RSA_PKCS12_CERTIFICATE_KEY cert_key = {
        keysize,
        format,
        certificate.data(),
        privateKey.data(),
        certificate.size(),
        privateKey.size(),
        pemPass.data(),
        pemPass.size(),
        SYMMETRY_CRYPTER::SYMMETRY_AES_CBC,
        256,
        SEGMENT_SIZE_OPTION::SEGMENT_NULL,
        HASH_TYPE::HASH_SHA2_256,
        p12Name.c_str(),
        p12Password.c_str(),
        reinterpret_cast<const unsigned char*>(country.c_str()),
        reinterpret_cast<const unsigned char*>(organizetion.c_str()),
        reinterpret_cast<const unsigned char*>(organizetion_unit.c_str()),
        reinterpret_cast<const unsigned char*>(common_name.c_str()),
        365 * 4
    };

    RsaGeneratePKCS12_Func(&cert_key);

    certificate.resize(cert_key.CERTIFICATE_LENGTH);
    privateKey.resize(cert_key.PRIVATE_KEY_LENGTH);

    if (format == ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM) {
        std::cout << "PEM - [Size:" << cert_key.CERTIFICATE_LENGTH << ", " << cert_key.PRIVATE_KEY_LENGTH << "]" << std::endl;
        std::cout << reinterpret_cast<char*>(certificate.data()) << std::endl;
        std::cout << reinterpret_cast<char*>(privateKey.data()) << std::endl;
    }
    else {
        std::cout << "DER - [Size:" << cert_key.CERTIFICATE_LENGTH << ", " << cert_key.PRIVATE_KEY_LENGTH << "]" << std::endl;
        char* certString = new char[cert_key.CERTIFICATE_LENGTH * 2 + 1] {};
        char* privString = new char[cert_key.PRIVATE_KEY_LENGTH * 2 + 1] {};
        Base16Encode_Func(certificate.data(), certificate.size(), certString, cert_key.CERTIFICATE_LENGTH * 2 + 1);
        Base16Encode_Func(privateKey.data(), privateKey.size(), privString, cert_key.PRIVATE_KEY_LENGTH * 2 + 1);
        std::cout << certString << std::endl;
        std::cout << privString << std::endl;
        std::cout << "" << std::endl;
    }
}

void Test_ExportRsaParametersFromKeys() {
    std::string pemPassowrd = "7331323239616263646232";
    std::string derPublicKey = "308202453082012D020100300030820122300D06092A864886F70D01010105000382010F003082010A0282010100C4CC17980B075D932C3A844E09B57CA2FFA9D90ABE3741557433E53EE63C84C210DDD7E4D137E5A93A5A15E24D6AAA3637F9F941823B9624BDC2F7524B3024D853457A93DE7345D76D57E631CDD93FC11AADFAC73878C588B3ADE281427F60324729B409DB520B20A93B8CA8DF88E1E239D656A5255EEEA175CE92F15E0B32F9E735117A583434570704EEE236CE88E6593D7216F87BC9B841424AE493D93B3609B3F534999B42E5D65C953C3EDBBCCE5ACC869A64A2001EE0DBE5B8030DBB533EFF3FA6D85D021BC744FFC4D1E5D951CCFAAD47F4014202B801A92D7B19653758631CE91B27DA16A10D9040B46436A0BDE3E02F66F08251A08D68240D8AD1590203010001A000300D06092A864886F70D01010B050003820101004F069B25D76CB0B13D62A7A3E0FA2036EDA8F49D72A492D0CAE95383FB7534D4FBC6856A9331ADD9FF1A15008BF10B3B358EF27ADF0CE53B5E0735700B81CBB54BAF6DED92935A5AE08A8BE5A8AF02DA7E4866C14E9548560B957878B94DD0A7CDEC0ACC17DE906D871D0C6392DD3E501BCA999714814C8440810C698D2D850C36A042F8E9E1D5FCC3B8F4B66B93732C4AD4EE6B99E67A8D2D7AA89BEB9CFC9DA0CCA18EB67BE594CB27EFEBB65CBE9DAECA2540C6B1664D46A4D900B8E98746EC0D2C0CE437D0564F380E773D743F124956F56CA0816E7CCB6CBE3CC33A0A4D868EA7F979519C39571823BB55F8B9731AEC89AFCF50A1E723443E41FC65B8EA";
    std::string derPrivateKey = "308204A40201000282010100C4CC17980B075D932C3A844E09B57CA2FFA9D90ABE3741557433E53EE63C84C210DDD7E4D137E5A93A5A15E24D6AAA3637F9F941823B9624BDC2F7524B3024D853457A93DE7345D76D57E631CDD93FC11AADFAC73878C588B3ADE281427F60324729B409DB520B20A93B8CA8DF88E1E239D656A5255EEEA175CE92F15E0B32F9E735117A583434570704EEE236CE88E6593D7216F87BC9B841424AE493D93B3609B3F534999B42E5D65C953C3EDBBCCE5ACC869A64A2001EE0DBE5B8030DBB533EFF3FA6D85D021BC744FFC4D1E5D951CCFAAD47F4014202B801A92D7B19653758631CE91B27DA16A10D9040B46436A0BDE3E02F66F08251A08D68240D8AD159020301000102820100094E61ECBE93C4F6EB53E2930AA63E8C3A3512D68D5771535C4D02719AA360BF491B268513683667EDE299EF934BE09BF302730928228F7772124CCE035075E3956F7F0C0C4C4CF092A302179795870C6789B3E6D51AAFF3A69489D62539FF076DA2511958B9DCDD18E7A01F91BF883801966B4F40B0C82DD23378332A08734AF50B7DAE675FEA3D9D28EEF4D16144A799E3321D49E2AA09EB1D29BE38D701D961FC02F188284D3414362D8295AB78FA1A193CDCD722FC179A847850BEE0DFDEAC07FCF2D0EDF3964BEB6AF9A790F8CF1E23C07C431BAEBFA86E8DBD7DC4E7032E7A1C91BEC9CC44B0D9BF896C23A0C038BE613CED19D76AF826973C68E0A02102818100E2434DE446151D97C7B180D195962AC820B6A6EAC6BDF96A810E0258E9B526F438853DC5A106E653ED1B52570EBEA97D27923749E8E5BDA24A1575C963D83CABFDAE4E0135BA41C03D820CBC92F234CBA3ED1AC6451CB56AF1736D826C7E0244FB1429030EA87680CA67B3302BF382ACDE2928635937194D4D1A52957B0854E102818100DEA967A81D794B0DBAB62F07179AEE95202F7B2962C2AEEA20CD8689FC2B1B023C73D4BE756B0F8FDD076B93A1F52FAF7C7D75B013AB3971CF7763836D60E73C87573E8169C838A3B12FEC489F3758CF649C65003ED067D8E77C9D2865C0AB54F40409956B2090B80EC2FDA09EFCA9EDBDB5741693604222EA2D18D7240E137902818046B2FD1DBD005014E32305BB77604AD1E9D6E8E52760A914AC6AB2351221B6A04D20E52261A48447E928C65BC991ADE81B7B46A7638C95EAA5F77AAC88F44251039D79664B617DB6120216F4BD7DCD1D6C8563FE5C0E1269EE34411DA5C4E1F4A7F7AEB0F3DD93D9BE6514CA92912E5DD1B54E976C8318F6DC86C3134E34564102818100B312652624861F216C8F06A55A8BA4E3541E3B9C1E2C5A863B596FA15BA7C331FA3261DFC709125BEE3400859C14578477C762B5F82B95A87D65142867F82E2054EC8A7D83F89DECB01CCD97DE4CA1E5319241FC7F88166CB0475D11573C2BCEC7ECD35452F2BED0F83643CA40F30D2B018E844D7FBB439556E66BFAE2A95B6902818100C66E3ED5728F326017644866D6838666ADBBB9105C6DF7E5098CC94D54EB1F44CD598D20873005AA30805765D16EA36D002EBA9DA014BD248341C71ACDA4EA7BDE9218D4E4A8128A08DE4F8305294495DB9F1101EDB1B9885A2F1C7439DF5E76E5FB1D58778220D683FEFD5D138E1731527555CA58C175B01670E052E774A95E";
    std::string pemPublicKey = 
    "-----BEGIN CERTIFICATE-----\n"
    "MIICWjCCAUICAQAwDQYJKoZIhvcNAQELBQAwADAEHwAfADAAMIIBIjANBgkqhkiG\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEArT46athM9uRy13bj2GL3bNQSm0VFLHRbaHjC\n"
    "QZwCNWI9v1ChZf530UoTU054w3BLDO5uWOTu8b7D65YNXCKL6paV2q/wJOoLFUIN\n"
    "rf1pu28xBKMBCYlIlTnC47fkIiL44PFKkNtq+BSRkNpehcCamFrpzJBkHf4Bu2K3\n"
    "9rD/sAD+KMji1mRohJxVx6JLIb0cJ8HKIy8onzZm9Iu097JmBStKNlJHxwZz8vGT\n"
    "mpB56rgrN/LkIyDKsdWuNu+R5NDqcgcDw0iljZ1eVJrTvHOxRhg8mN3C+Lop6zkI\n"
    "z3kdaqbBqKiqlfQepgNrDGIBoKltoZATVV7FyF/bYM/1llkGkwIDAQABMA0GCSqG\n"
    "SIb3DQEBCwUAA4IBAQBOcK/uJ9F2QQJXbsZ7I6cW+RMVmX9weUsqrCuRip1tV4iu\n"
    "utpqNy6sv7U3QcfkMy+1H1OL2mtoiEDYC152yu6lHK4FUOeWfp7ZUi9apN2aMTJ/\n"
    "+m01FxHUnS6/8orU8Ccgs4aXg/IX2+SBYApA7f6LSUYBF1s4MZUwV4Qt7JSdn7FR\n"
    "MeE8w0/K9Lk/lJ3jLW9bdtZUflP2ZrYh51ajezfUws4PVAwri818IIISqbMILA9J\n"
    "dndoUORpTJiY4CaeYtiBlQ14peeELSh+O3/d/ky5ehlSBFYV5kMggK5XJESDrY0R\n"
    "IjFhy/1jz6HYSNb3qNn3uXiP/GtLYlZ62x4UZKln\n"
    "-----END CERTIFICATE-----\n"
    "";
    std::string pemPrivateKey =
    "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
    "MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQVvSzvZygU/bu4xPr\n"
    "aJdalwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEECc1gXZJh3+6fIXG\n"
    "TlSCtggEggTQ5/s6r6kaSyyAPeyA+KscbSBkOkmeGsdJldFWM951xbzd6vtLu9PZ\n"
    "3+/dAbDxEOw9oU8Oyr/qlfgO5xrt9h1sclkzrWiQfIGRVj4JOa7p0vRQKqtUusbI\n"
    "A2JtPKbQuapzPym/aYDhMuoXZ/jje0zbBsosAfUT1mJX26pDokVFtwhln5ZPdiR4\n"
    "L+rBN+5lwGUeCQDg/VAllCCxUEA8f4fHVNATdAgqV4vEWt8ej+2xQHlvrf7odX3y\n"
    "BdFL5zQ35gp3rCjFbhPZ4KzTFD5CJPCqxspN3bXLb+j42PNh/+ZE092JTTkFfLsg\n"
    "8BgI7F45HAulTYV/FUtwxHwbdfATpf3/LkSR2wN8CKUnNOJBECUkTSItbTIZQErk\n"
    "eMKcnM4HKoSfgCM4iB4rFuCUxAlglQuvOMjyaCucG55kB6hgi71ney2K9jkCbKmC\n"
    "wBasSar5OLYEEyRjbCMxjKJ7ruivQlVrjjJx4wIcOZ/7T3yrw3EKQdzoOHRZn99W\n"
    "EkX+U+ewRZVJ9Dkp/7d+2ov/sx7H+Vnug5TmL5lbSe/aZGFQ7jKqkEnzLV9VEwwi\n"
    "6De5GG20GP3cPsNjyjSFgjjxWqP9UUxVLHuBSu2VW3IGOKtOVHUx7kBJoWWQghIT\n"
    "zHJo40FvPOkgGUp+81f0sRIRB7gDMjbg43C9cGuPKbkaKD9BJJxaYAr24n3kOs9o\n"
    "WNo1ZOHvjOCVA7eIj1vyE8tvjhZ0t+UFnSq5DnpzVrL4ehzccw/QmNJJUfUFpsJX\n"
    "JGUCwAUjr+ELnDAbcUFFjqhpyy1vtOe3skNwVZOFi3371z6XK+3n252Pgs283I6Y\n"
    "EXQR+CO4KIIPphauMi8PCx0NUtMbmfovOBi6ZawBnw7Q9eFPFUr++Y4gLvlkFh3x\n"
    "HC7yWoymjJHHmYyDFlDYHpc07Q6D03EIDXOCmZTsTOD9vIrGQWsGWj1cysCeaIz+\n"
    "yPvowHkuR1zBV0aiMAxgiKSDoIWnpAYSB20/kpEC7rCaicQunwjdcqoFgZGZwmi/\n"
    "ZYWlpbRpGp2+z75nMirc5PV6Oj2BUMrIRZbY8Jf0y2iE6udTs5nASkWRDlujOiFH\n"
    "i4yklyhymVChZXR91hHVs0n+kI3gUahxBOKruk+g6AwzlFskGLBWY7bn9TEDvbxC\n"
    "QizfvRL7b2jubsd5sC0iSfcFgD6eVotSGMOyPHJGGJJSk4llJEsry2BjPgXtJg3s\n"
    "pNQKx/Lm7tKCw7s0K5Y8sgG5EA+30m3Svq/VPfUJhCcnmp1MiiqUmmXQS4TM5BfA\n"
    "aEGFDocelRaoa8pedZlD9OjNDSAiDK0amW0R4yHk3AaGiULz9k/sRdxiyPTCSR5H\n"
    "d2d6/P+PWgcXXBoedKEOPNl9RW7r3bqjekXDcMwJFKWCHt4ZkX+/hGMb1vBUXo+s\n"
    "avYAJhtfG68fKIbZG2JPdIOhssL4dzjXmN6ecROZnVopQKkr2p65fKioKusFIUHV\n"
    "Udj6Kx8xpaWxYVfGRCCWlTqRaOhUOScD7mMiJvPxLwBGZpvWAgmDHb9uzCnrXb7M\n"
    "BJIK6wbIuwNwPBEEwKhbDAd4gB5GOHtKPl4Ov690NN1piqua8VbDvkows9YiBFNj\n"
    "03OU3RJArUYXFGwUMlpovsX4W55AA2ScgRjmIC2jklwhG/QdYtdR3FI=\n"
    "-----END ENCRYPTED PRIVATE KEY-----\n"
    "";

    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    pemPass.push_back('\0');

    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    publicKey.resize(derPublicKey.size() / 2);
    privateKey.resize(derPrivateKey.size() / 2);
    Base16Decode_Func(derPublicKey.c_str(), derPublicKey.size(), publicKey.data(), publicKey.size());
    Base16Decode_Func(derPrivateKey.c_str(), derPrivateKey.size(), privateKey.data(), privateKey.size());
    /*publicKey.resize(pemPublicKey.size());
    privateKey.resize(pemPrivateKey.size());
    publicKey.assign(pemPublicKey.begin(), pemPublicKey.end());
    privateKey.assign(pemPrivateKey.begin(), pemPrivateKey.end());*/
    RSA_KEY_PAIR keyLength = {
        0,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10,
        publicKey.data(),
        privateKey.data(),
        pemPass.data(),
        publicKey.size(),
        privateKey.size(),
        pemPass.size()
    };

    RsaGetKeyLength_Func(&keyLength);

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

    RsaGetParametersLength_Func(&paramLength);

    EXPORT_RSA paramters = {
        0,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS10,
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
        pemPass.data(),
        publicKey.size(),
        privateKey.size(),
        pemPass.size()
    };

    RsaExportParameters_Func(&paramters);

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
    std::string pemPassowrd = "7331323239616263646232";

    std::vector<unsigned char> pemPass;
    pemPass.resize(pemPassowrd.size() / 2);
    Base16Decode_Func(pemPassowrd.c_str(), pemPassowrd.size(), pemPass.data(), pemPass.size());
    pemPass.push_back('\0');

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

    EXPORT_RSA paramters = {
        0,
        //ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_DER,
        ASYMMETRIC_KEY_FORMAT::ASYMMETRIC_KEY_PEM,
        ASYMMETRIC_KEY_PKCS::ASYMMETRIC_KEY_PKCS8,
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
        pemPass.data(),
        publicKey.size(),
        privateKey.size(),
        pemPass.size()
    };
    RsaExportKeys_Func(&paramters);

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

    //Test_RsaCheckPublicKey();

    //Test_RsaCheckPrivateKey();
    
    //Test_RsaCheckCSR();

    Test_RsaCheckCertificate();

    //Test_GenerateRsaParameters();

    //Test_RsaGenerate();

    //Test_RsaGeneratePKCS8();

    //Test_RsaGeneratePKCS10();

    //Test_RsaGeneratePKCS12();

    //Test_ExportRsaParametersFromKeys();

    //Test_ExportRsaKeyFromParameters();
}