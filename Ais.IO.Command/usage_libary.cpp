#include "usage_libary.h"
#include "output_colors.h"

void usage_libary::ShowWayUsage() {
    std::cout << Hint("    Supported [--way]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("<value>") << Warn("                      -> Raw data.") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-b10 | -base10]") << Warn("             -> Base10 data.") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-b16 | -base16]") << Warn("             -> Base16 data.") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-b32 | -base32]") << Warn("             -> Base32 data.") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("[-b58 | -base58]") << Warn("             -> Base58 data.") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("[-b62 | -base62]") << Warn("             -> Base62 data.") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("[-b64 | -base64]") << Warn("             -> Base64 data.") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("[-b85 | -base85]") << Warn("             -> Base85 data.") << std::endl;
    std::cout << "        " << Mark(" 9") << ". " << Info("[-b91 | -base91]") << Warn("             -> Base91 data.") << std::endl;
    std::cout << "        " << Mark("10") << ". " << Info("[-f | -file] <path>") << Warn("          -> Archival data.") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowKeysWayUsage() {
    std::cout << Hint("    Supported [--keys-way]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-pem") << Warn("                                     -> PEM Raw data.") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-pem [-f | -file] <path>]") << Warn("                -> PEM Archival data.") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("-der") << Warn("                                     -> DER Raw data.") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("-der [-b10 | -base10]") << Warn("                    -> DER Base10 data.") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("-der [-b16 | -base16]") << Warn("                    -> DER Base16 data.") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("-der [-b32 | -base32]") << Warn("                    -> DER Base32 data.") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("-der [-b58 | -base58]") << Warn("                    -> DER Base58 data.") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("-der [-b62 | -base62]") << Warn("                    -> DER Base62 data.") << std::endl;
    std::cout << "        " << Mark(" 9") << ". " << Info("-der [-b64 | -base64]") << Warn("                    -> DER Base64 data.") << std::endl;
    std::cout << "        " << Mark("10") << ". " << Info("-der [-b85 | -base85]") << Warn("                    -> DER Base85 data.") << std::endl;
    std::cout << "        " << Mark("11") << ". " << Info("-der [-b91 | -base91]") << Warn("                    -> DER Base91 data.") << std::endl;
    std::cout << "        " << Mark("12") << ". " << Info("-der [-f | -file] <path>") << Warn("                 -> DER Archival data.") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowHashTypeUsage() {
    std::cout << Hint("    Supported [--hash-type]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-md5") << Warn("                                     -> Hash MD5 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-md5-sha1") << Warn("                                -> Hash MD5-SHA1 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("-sha1") << Warn("                                    -> Hash SHA1 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-sha224 | -sha2-224]") << Warn("                    -> Hash SHA2-224 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("[-sha256 | -sha2-256]") << Warn("                    -> Hash SHA2-256 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("[-sha384 | -sha2-384]") << Warn("                    -> Hash SHA2-384 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("[-sha512 | -sha2-512]") << Warn("                    -> Hash SHA2-512 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("[-sha512-224 | -sha2-512-224]") << Warn("            -> Hash SHA2-512-224 Calculation.") << std::endl;
    std::cout << "        " << Mark(" 9") << ". " << Info("[-sha512-256 | -sha2-512-256]") << Warn("            -> Hash SHA2-512-256 Calculation.") << std::endl;
    std::cout << "        " << Mark("10") << ". " << Info("-sha3-224") << Warn("                                -> Hash SHA3-224 Calculation.") << std::endl;
    std::cout << "        " << Mark("11") << ". " << Info("-sha3-256") << Warn("                                -> Hash SHA3-256 Calculation.") << std::endl;
    std::cout << "        " << Mark("12") << ". " << Info("-sha3-384") << Warn("                                -> Hash SHA3-384 Calculation.") << std::endl;
    std::cout << "        " << Mark("13") << ". " << Info("-sha3-512") << Warn("                                -> Hash SHA3-512 Calculation.") << std::endl;
    std::cout << "        " << Mark("14") << ". " << Info("[-shake128 | -sha3-ke-128]") << Warn("               -> Hash SHA3-KE-128 Calculation.") << std::endl;
    std::cout << "        " << Mark("15") << ". " << Info("[-shake256 | -sha3-ke-256]") << Warn("               -> Hash SHA3-KE-256 Calculation.") << std::endl;
    std::cout << "        " << Mark("16") << ". " << Info("[-blake2s | -blake256 | -blake2s-256]") << Warn("    -> Hash BLAKE2S-256 Calculation.") << std::endl;
    std::cout << "        " << Mark("17") << ". " << Info("[-blake2b | -blake512 | -blake2b-512]") << Warn("    -> Hash BLAKE2B-512 Calculation.") << std::endl;
    std::cout << "        " << Mark("18") << ". " << Info("-sm3") << Warn("                                     -> Hash SM3 Calculation.") << std::endl;
    std::cout << "        " << Mark("19") << ". " << Info("-ripemd160") << Warn("                               -> Hash RIPEMD160 Calculation.") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowAlgorithm() {
    std::cout << Hint("    Supported [--algorithm]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-alg -aes -cbc <size>") << Warn("                    -> Use AES CBC algorithm.") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-alg -aes -cfb <size> <segment>") << Warn("          -> Use AES CFB algorithm.") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("-alg -aes -ofb <size>") << Warn("                    -> Use AES OFB algorithm.") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("-alg -aes -ecb <size>") << Warn("                    -> Use AES ECB algorithm.") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("-alg -des -cbc <size>") << Warn("                    -> Use AES CBC algorithm.") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("-alg -des -cfb <size> <segment>") << Warn("          -> Use AES CFB algorithm.") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("-alg -des -ofb <size>") << Warn("                    -> Use DES OFB algorithm.") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("-alg -des -ecb <size>") << Warn("                    -> Use DES ECB algorithm.") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowSubject() {
    std::cout << Hint("    Supported [--subject]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-cn") << Warn("                                      -> Certificate Common Name (CN) Failed by [--way].") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-c") << Warn("                                       -> Certificate Country (C) Failed by [--way].") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("-o") << Warn("                                       -> Certificate Organization (O) Failed by [--way].") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("-ou") << Warn("                                      -> Certificate Organization Unit (OU) Failed by [--way].") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowSubjectAlternativeName() {
    std::cout << Hint("    Supported [--subject-alternative-name]:\n");
    std::cout << "" << std::endl;
    std::cout << Error("    ** The command must start with ") << Ask("-san") << Error(", this setting can be multiple. **\n");
    std::cout << "" << std::endl;
    std::cout << "        " << Mark(" 1") << ". " << Info("-dns") << Warn("                                     -> Certificate Subject Alternative Name of DNS by [--way].") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-ip") << Warn("                                      -> Certificate Subject Alternative Name of IP by [--way].") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-mail | -email]") << Warn("                         -> Certificate Subject Alternative Name of Email by [--way].") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-uri | -url]") << Warn("                            -> Certificate Subject Alternative Name of URI / URL by [--way].") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowKeyUsage() {
    std::cout << Hint("    Supported [--key-usage]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("[-ds | -digital-signature]") << Warn("               -> Certificate Key Usage of Digital Signature.") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-ke | -key-encipherment]") << Warn("                -> Certificate Key Usage of Key Encipherment.") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-de | -data-encipherment]") << Warn("               -> Certificate Key Usage of Data Encipherment.") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-ka | -key-agreement]") << Warn("                   -> Certificate Key Usage of Key Agreement.") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("[-kc | -key-cert-sign]") << Warn("                   -> Certificate Key Usage of Certificate Sign.") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("[-cs | -crl-sign]") << Warn("                        -> Certificate Key Usage of CRL Sign.") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowUsage() {
    std::cout << Any("                                                                                            ", TERMINAL_STYLE::STYLE_FLASHING, 30) << std::endl;
    std::cout << Any("               AAA                 iiii                        IIIIIIIIII     OOOOOOOOO     ", TERMINAL_STYLE::STYLE_FLASHING, 31) << std::endl;
    std::cout << Any("              A:::A               i::::i                       I::::::::I   OO:::::::::OO   ", TERMINAL_STYLE::STYLE_FLASHING, 32) << std::endl;
    std::cout << Any("             A:::::A               iiii                        I::::::::I OO:::::::::::::OO ", TERMINAL_STYLE::STYLE_FLASHING, 33) << std::endl;
    std::cout << Any("            A:::::::A                                          II::::::IIO:::::::OOO:::::::O", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;
    std::cout << Any("           A:::::::::A           iiiiiii     ssssssssss          I::::I  O::::::O   O::::::O", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("          A:::::A:::::A          i:::::i   ss::::::::::s         I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("         A:::::A A:::::A          i::::i ss:::::::::::::s        I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 37) << std::endl;
    std::cout << Any("        A:::::A   A:::::A         i::::i s::::::ssss:::::s       I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 31) << std::endl;
    std::cout << Any("       A:::::A     A:::::A        i::::i  s:::::s  ssssss        I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 32) << std::endl;
    std::cout << Any("      A:::::AAAAAAAAA:::::A       i::::i    s::::::s             I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 33) << std::endl;
    std::cout << Any("     A:::::::::::::::::::::A      i::::i       s::::::s          I::::I  O:::::O     O:::::O", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;
    std::cout << Any("    A:::::AAAAAAAAAAAAA:::::A     i::::i ssssss   s:::::s        I::::I  O::::::O   O::::::O", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("   A:::::A             A:::::A   i::::::is:::::ssss::::::s     II::::::IIO:::::::OOO:::::::O", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("  A:::::A               A:::::A  i::::::is::::::::::::::s      I::::::::I OO:::::::::::::OO ", TERMINAL_STYLE::STYLE_FLASHING, 37) << std::endl;
    std::cout << Any(" A:::::A                 A:::::A i::::::i s:::::::::::ss       I::::::::I   OO:::::::::OO   ", TERMINAL_STYLE::STYLE_FLASHING, 36) << std::endl;
    std::cout << Any("AAAAAAA                   AAAAAAAiiiiiiii  sssssssssss         IIIIIIIIII     OOOOOOOOO     ", TERMINAL_STYLE::STYLE_FLASHING, 35) << std::endl;
    std::cout << Any("                                                                                            ", TERMINAL_STYLE::STYLE_FLASHING, 34) << std::endl;
    
    std::cout << Mark("Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Help List:\n") << std::endl;
    std::cout << Hint("    1. Helper by Binary:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-bin | -binary]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    2. Helper by Base:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-b | -base]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    3. Helper by Aes:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-a | -aes]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    4. Helper by Des:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-d | -des]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    5. Helper by Hash:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-h | -hash]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    6. Helper by Dsa:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-ds | -dsa]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    7. Helper by Rsa:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-r | -rsa]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    8. Helper by Ecc:") << std::endl;
    std::cout << Info("        [-h | -help | --help] [-e | -ecc]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Show Colors:") << std::endl;
    std::cout << Info("        --colors") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Check System Environment Variables / System Environment Paths:") << std::endl;
    std::cout << Info("        --path <file>") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Generate Symmetry Key / Generate Random Bytes:") << std::endl;
    std::cout << Info("        [-gen | --generate] <bytes-size> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Convert Bytes:") << std::endl;
    std::cout << Info("        [-conv | --convert] [--way] <value> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "" << std::endl;
    std::cout << Hint("    Tip:") << std::endl;
    std::cout << "        " << Mark("1") << ". " << Hint("Output Only Raw Data (Just Add It After Any Command.):") << std::endl;
    std::cout << Info("            -raw") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "        " << Mark("2") << ". " << Hint("Output Directed to File (Just Add It After Any Command.):") << std::endl;
    std::cout << Info("            [> <path> | >> <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "        " << Mark("3") << ". " << Hint("Pipe Symbol Receiving (Can Be Added Between Any Two Instructions.):") << std::endl;
    std::cout << Info("            <first-command> | <second-command>") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();
}

void usage_libary::ShowBinaryUsage() {
    std::cout << Common("      :::::::::") << Error("      :::::::::::") << Warn("      ::::    :::") << Hint("          ::: ") << Ask("      :::::::::") << Mark("   :::   ::: ") << std::endl;
    std::cout << Common("     :+:    :+:") << Error("         :+:     ") << Warn("     :+:+:   :+: ") << Hint("       :+: :+:") << Ask("     :+:    :+:") << Mark("  :+:   :+:  ") << std::endl;
    std::cout << Common("    +:+    +:+ ") << Error("        +:+      ") << Warn("    :+:+:+  +:+  ") << Hint("     +:+   +:+") << Ask("    +:+    +:+ ") << Mark("  +:+ +:+    ") << std::endl;
    std::cout << Common("   +#++:++#+   ") << Error("       +#+       ") << Warn("   +#+ +:+ +#+   ") << Hint("   +#++:++#++:") << Ask("   +#++:++#:   ") << Mark("  +#++:      ") << std::endl;
    std::cout << Common("  +#+    +#+   ") << Error("      +#+        ") << Warn("  +#+  +#+#+#    ") << Hint("  +#+     +#+ ") << Ask("  +#+    +#+   ") << Mark("  +#+        ") << std::endl;
    std::cout << Common(" #+#    #+#    ") << Error("     #+#         ") << Warn(" #+#   #+#+#     ") << Hint(" #+#     #+#  ") << Ask(" #+#    #+#    ") << Mark(" #+#         ") << std::endl;
    std::cout << Common("#########      ") << Error("###########      ") << Warn("###    ####      ") << Hint("###     ###   ") << Ask("###    ###     ") << Mark("###          ") << std::endl;

    std::cout << Mark("Binary Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("1") << ". " << Hint("Get Information About All Data Indexes:") << std::endl;
    std::cout << Info("        [-id | --indexes] <path>") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("2") << ". " << Hint("Read Binary Data (All):") << std::endl;
    std::cout << Info("        [-rl | --read-all] [--way] <path>") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("3") << ". " << Hint("Read Binary Data (Index):") << std::endl;
    std::cout << Info("        [-ri | --read-index] [--way] <path> <--index> ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("4") << ". " << Hint("Read Binary Data (Specify):") << std::endl;
    std::cout << Info("        [-r | --read] <path> [--way] [--type] ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("5") << ". " << Hint("Write Binary Data:") << std::endl;
    std::cout << Info("        [-w | --write] <path> [--way] [--type] <value> ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("6") << ". " << Hint("Append Binary Data:") << std::endl;
    std::cout << Info("        [-a | --append] <path> [--way] [--type] <value> ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("7") << ". " << Hint("Insert Binary Data:") << std::endl;
    std::cout << Info("        [-i | --insert] <path> [--way] [--type] <value> <position> ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("8") << ". " << Hint("Remove Binary Data (Index information input, fast speed):") << std::endl;
    std::cout << Info("        [-rm | --remove] <path> [--type] <position> <length> ...") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("9") << ". " << Hint("Remove Binary Data (Index position input, slow speed):") << std::endl;
    std::cout << Info("        [-rs | --remove-index] <path> <--index> ...") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();

    std::cout << Hint("    Supported [--type]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-bool") << Warn("   Boolean                -> false, true") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("-byte") << Warn("   Unsigned Byte          -> 0 ~ 255") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("-sbyte") << Warn("  Signed Byte            -> -128 ~ 127") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("-short") << Warn("  Signed Short Integer   -> -32768 ~ 32767") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("-ushort") << Warn(" Unsigned Short Integer -> 0 ~ 65535") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("-int") << Warn("    Signed Integer         -> -2147483648 ~ 2147483647") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("-uint") << Warn("   Unsigned Integer       -> 0 ~ 4294967295") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("-long") << Warn("   Signed Long Integer    -> -9223372036854775808 ~ 9223372036854775807") << std::endl;
    std::cout << "        " << Mark(" 9") << ". " << Info("-ulong") << Warn("  Unsigned Long Integer  -> 0 ~ 18446744073709551615") << std::endl;
    std::cout << "        " << Mark("10") << ". " << Info("-float") << Warn("  Single Floating Point  -> ~-3.402823e38 ~ ~3.402823e38") << std::endl;
    std::cout << "        " << Mark("11") << ". " << Info("-double") << Warn(" Double Floating Point  -> ~-1.7976931348623157e308 ~ ~1.7976931348623157e308") << std::endl;
    std::cout << "        " << Mark("12") << ". " << Info("-bytes") << Warn("  Bytes Array            -> N/A") << std::endl;
    std::cout << "        " << Mark("13") << ". " << Info("-string") << Warn(" String                 -> N/A") << std::endl;
    std::cout << "" << std::endl;

    std::cout << Hint("    Supported <--index>:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("index") << Warn("                5 36 74   -> Read/Remove 5, 36, 74") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("index~index") << Warn("          5~10      -> Read/Remove 5, 6, 7, 8, 9, 10") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("index*count") << Warn("          5*4       -> Read/Remove 5, 10, 15, 20") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("index+interval*count") << Warn(" 5+2*4     -> Read/Remove 5, 7, 9, 11") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowBaseUsage() {
    std::cout << Error("      :::::::::") << Warn("          ::: ") << Hint("      ::::::::") << Info("      :::::::::: ") << std::endl;
    std::cout << Error("     :+:    :+:") << Warn("       :+: :+:") << Hint("    :+:    :+:") << Info("     :+:         ") << std::endl;
    std::cout << Error("    +:+    +:+ ") << Warn("     +:+   +:+") << Hint("   +:+        ") << Info("    +:+          ") << std::endl;
    std::cout << Error("   +#++:++#+   ") << Warn("   +#++:++#++:") << Hint("  +#++:++#++  ") << Info("   +#++:++#      ") << std::endl;
    std::cout << Error("  +#+    +#+   ") << Warn("  +#+     +#+ ") << Hint("        +#+   ") << Info("  +#+            ") << std::endl;
    std::cout << Error(" #+#    #+#    ") << Warn(" #+#     #+#  ") << Hint("#+#    #+#    ") << Info(" #+#             ") << std::endl;
    std::cout << Error("#########      ") << Warn("###     ###   ") << Hint("########      ") << Info("##########       ") << std::endl;
    
    std::cout << Mark("Base Encoding Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("1") << ". " << Hint("Base10 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b10 | --base10] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("2") << ". " << Hint("Base16 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b16 | --base16] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("3") << ". " << Hint("Base32 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b32 | --base32] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("4") << ". " << Hint("Base58 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b58 | --base58] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("5") << ". " << Hint("Base62 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b62 | --base62] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("6") << ". " << Hint("Base64 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b64 | --base64] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("7") << ". " << Hint("Base85 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b85 | --base85] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("8") << ". " << Hint("Base91 Encode/Decode:") << std::endl;
    std::cout << Info("        [-b91 | --base91] [-e | -encode | -d -decode] [-f <path> | -file <path> | <value>] [-out | -output <path>]") << std::endl;
    std::cout << "" << std::endl;
}

void usage_libary::ShowAesUsage() {
    std::cout << Error("          ::: ") << Hint("      ::::::::::") << Ask("      :::::::: ") << std::endl;
    std::cout << Error("       :+: :+:") << Hint("     :+:        ") << Ask("    :+:    :+: ") << std::endl;
    std::cout << Error("     +:+   +:+") << Hint("    +:+         ") << Ask("   +:+         ") << std::endl;
    std::cout << Error("   +#++:++#++:") << Hint("   +#++:++#     ") << Ask("  +#++:++#++   ") << std::endl;
    std::cout << Error("  +#+     +#+ ") << Hint("  +#+           ") << Ask("        +#+    ") << std::endl;
    std::cout << Error(" #+#     #+#  ") << Hint(" #+#            ") << Ask("#+#    #+#     ") << std::endl;
    std::cout << Error("###     ###   ") << Hint("##########      ") << Ask("########       ") << std::endl;
    
    std::cout << Mark("Aes Cryptography Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("AES CTR Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -ctr [-e | -encrypt | -d | -decrypt] -key [--way] [-count | -counter] <counter> -iv [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("AES CBC Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -cbc [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-pad | -padding] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("AES CFB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -cfb [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-seg | -segment] <segment> [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("AES OFB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -ofb [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("AES ECB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -ecb [-e | -encrypt | -d | -decrypt] -key [--way] [-pad | -padding] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 6") << ". " << Hint("AES GCM Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -gcm [-e | -encrypt | -d | -decrypt] -key [--way] -nonce [--way] -tag [--way] -aad [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 7") << ". " << Hint("AES CCM Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -ccm [-e | -encrypt | -d | -decrypt] -key [--way] -nonce [--way] -tag [--way] -aad [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 8") << ". " << Hint("AES XTS Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -xts [-e | -encrypt | -d | -decrypt] -key [--way] -key2 [--way] -tweak [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 9") << ". " << Hint("AES OCB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -ocb [-e | -encrypt | -d | -decrypt] -key [--way] -nonce [--way] -tag [--way] -aad [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("10") << ". " << Hint("AES WRAP Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-aes | --aes] -wrap [-e | -encrypt | -d | -decrypt] -key [--way] -kek [--way] -wrapkey [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();
}

void usage_libary::ShowDesUsage() {
    std::cout << Warn("      :::::::::") << Info("      ::::::::::") << Mark("      :::::::: ") << std::endl;
    std::cout << Warn("     :+:    :+:") << Info("     :+:        ") << Mark("    :+:    :+: ") << std::endl;
    std::cout << Warn("    +:+    +:+ ") << Info("    +:+         ") << Mark("   +:+         ") << std::endl;
    std::cout << Warn("   +#+    +:+  ") << Info("   +#++:++#     ") << Mark("  +#++:++#++   ") << std::endl;
    std::cout << Warn("  +#+    +#+   ") << Info("  +#+           ") << Mark("        +#+    ") << std::endl;
    std::cout << Warn(" #+#    #+#    ") << Info(" #+#            ") << Mark("#+#    #+#     ") << std::endl;
    std::cout << Warn("#########      ") << Info("##########      ") << Mark("########       ") << std::endl;
    std::cout << Mark("Des Cryptography Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("DES CBC Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-des | --des] -cbc [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-pad | -padding] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("DES CFB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-des | --des] -cfb [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-seg | -segment] <segment> [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("DES OFB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-des | --des] -ofb [-e | -encrypt | -d | -decrypt] -key [--way] -iv [--way] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("DES ECB Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-des | --des] -ecb [-e | -encrypt | -d | -decrypt] -key [--way] [-pad | -padding] [-pt | -plain-text | -ct | -cipher-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("DES WRAP Encrypt/Decrypt:") << std::endl;
    std::cout << Info("        [-des | --des] -wrap [-e | -encrypt | -d | -decrypt] -key [--way] -kek [--way] -wrapkey [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();
}

void usage_libary::ShowHashUsage() {
    std::cout << Common("      :::    :::") << Error("          ::: ") << Warn("      ::::::::") << Hint("      :::    ::: ") << std::endl;
    std::cout << Common("     :+:    :+: ") << Error("       :+: :+:") << Warn("    :+:    :+:") << Hint("     :+:    :+:  ") << std::endl;
    std::cout << Common("    +:+    +:+  ") << Error("     +:+   +:+") << Warn("   +:+        ") << Hint("    +:+    +:+   ") << std::endl;
    std::cout << Common("   +#++:++#++   ") << Error("   +#++:++#++:") << Warn("  +#++:++#++  ") << Hint("   +#++:++#++    ") << std::endl;
    std::cout << Common("  +#+    +#+    ") << Error("  +#+     +#+ ") << Warn("        +#+   ") << Hint("  +#+    +#+     ") << std::endl;
    std::cout << Common(" #+#    #+#     ") << Error(" #+#     #+#  ") << Warn("#+#    #+#    ") << Hint(" #+#    #+#      ") << std::endl;
    std::cout << Common("###    ###      ") << Error("###     ###   ") << Warn("########      ") << Hint("###    ###       ") << std::endl;
    std::cout << Mark("Hash Calculation Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("HASH MD5 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -md5 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("HASH MD5-SHA1 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -md5-sha1 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("HASH SHA1 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sha1 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("HASH SHA2-224 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha224 | -sha2-224] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("HASH SHA2-256 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha256 | -sha2-256] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 6") << ". " << Hint("HASH SHA2-384 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha384 | -sha2-384] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 7") << ". " << Hint("HASH SHA2-512 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha512 | -sha2-512] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 8") << ". " << Hint("HASH SHA2-512-224 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha512-224 | -sha2-512-224] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 9") << ". " << Hint("HASH SHA2-512-256 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-sha512-256 | -sha2-512-256] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("10") << ". " << Hint("HASH SHA3-224 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sha3-224 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("11") << ". " << Hint("HASH SHA3-256 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sha3-256 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("12") << ". " << Hint("HASH SHA3-384 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sha3-384 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("13") << ". " << Hint("HASH SHA3-512 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sha3-512 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("14") << ". " << Hint("HASH SHA3-KE-128 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-shake128 | -sha3-ke-128] [--way] -salt [--way] [--salt-pos] [-len | -length] <length> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("15") << ". " << Hint("HASH SHA3-KE-256 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-shake256 | -sha3-ke-256] [--way] -salt [--way] [--salt-pos] [-len | -length] <length> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("16") << ". " << Hint("HASH BLAKE2S-256 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-blake2s | -blake256 | -blake2s-256] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("17") << ". " << Hint("HASH BLAKE2B-512 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] [-blake2b | -blake512 | -blake2s-512] [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("18") << ". " << Hint("HASH SM3 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -sm3 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("19") << ". " << Hint("HASH RIPEMD160 Hash Calculation:") << std::endl;
    std::cout << Info("        [-hash | --hash] -ripemd160 [--way] -salt [--way] [--salt-pos] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;

    std::cout << Hint("    Supported [--salt-pos]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("[-fir | -first]") << Warn("           -> Add Salt (First, can be added)") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-mid | -middle]") << Warn("          -> Add Salt (Middle, can be added)") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-las | -last]") << Warn("            -> Add Salt (Last, can be added)") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();
}

void usage_libary::ShowDsaUsage() {
    std::cout << Ask("      :::::::::") << Warn("      ::::::::") << Error("          ::: ") << std::endl;
    std::cout << Ask("     :+:    :+:") << Warn("    :+:    :+:") << Error("       :+: :+:") << std::endl;
    std::cout << Ask("    +:+    +:+ ") << Warn("   +:+        ") << Error("     +:+   +:+") << std::endl;
    std::cout << Ask("   +#+    +:+  ") << Warn("  +#++:++#++  ") << Error("   +#++:++#++:") << std::endl;
    std::cout << Ask("  +#+    +#+   ") << Warn("        +#+   ") << Error("  +#+     +#+ ") << std::endl;
    std::cout << Ask(" #+#    #+#    ") << Warn("#+#    #+#    ") << Error(" #+#     #+#  ") << std::endl;
    std::cout << Ask("#########      ") << Warn("########      ") << Error("###     ###   ") << std::endl;
    std::cout << Mark("Dsa Cryptography Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("DSA Generate Parameters:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-gen | -generate] [-param | -params | -parameter | -parameters] <size> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("DSA Generate Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-gen | -generate] [-key | -keys] <size> [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("DSA Export Parameters from Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-exp | -export] [-param | -params | -parameter | -parameters] [-pub | -public | -public-key] [--keys-way] [-priv | -private | -private-key] [--keys-way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("DSA Export Public Key & Private Key from Parameters:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-exp | -export] [-key | -keys] [-param | -params | -parameter | -parameters] [--way] [--dsa-parameters-list] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("DSA Extract Public Key from Private Key:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-ext | -extract] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 6") << ". " << Hint("DSA Extract Parameters from Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-ext | -extract] [-param | -params | -parameter | -parameters] [-pub | -public | -public-key] [--keys-way] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 7") << ". " << Hint("DSA Extract Public Key & Private Key from Parameters:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-ext | -extract] [-key | -keys] [-param | -params | -parameter | -parameters] [--keys-way] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 8") << ". " << Hint("DSA Confirms Whether the Public Key is Valid:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-chk | -check] [-pub | -public | -public-key] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 9") << ". " << Hint("DSA Confirms Whether the Private Key is Valid:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-chk | -check] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("10") << ". " << Hint("DSA Confirms Whether the Parameters is Valid:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-chk | -check] [-param | -params | -parameter | -parameters] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("11") << ". " << Hint("DSA Private Key Add Password to PEM:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-lk | -lock] [-pem <value> | -pem -f <path>] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [-pem | -pem -f <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("12") << ". " << Hint("DSA Private Key Remove Password from PEM:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-uk | -unlock] [-pem <value> | -pem -f <path>] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("13") << ". " << Hint("DSA Signed Data:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-sign | -signed] [-priv | -private | -private-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("14") << ". " << Hint("DSA Verify Data:") << std::endl;
    std::cout << Info("        [-dsa | --dsa] [-ver | -verify] [-pub | -public | -public-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-sg | -signature] [--way]") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();

    usage_libary::ShowKeysWayUsage();

    std::cout << Hint("    Supported [--dsa-parameters-list]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("[-y | -public-param]") << Warn("                     -> Public Key data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-x | -private-param]") << Warn("                    -> Private Key data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-p | -prime | -modulus | -prime-modulus]") << Warn("-> Prime Modulus data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-q | -subprime]") << Warn("                         -> Subprime data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("[-g | -generator]") << Warn("                        -> Generator data by [--way].") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowHashTypeUsage();
    
    usage_libary::ShowAlgorithm();
}

void usage_libary::ShowRsaUsage() {
    std::cout << Mark("      :::::::::") << Error("      ::::::::") << Ask("          ::: ") << std::endl;
    std::cout << Mark("     :+:    :+:") << Error("    :+:    :+:") << Ask("       :+: :+:") << std::endl;
    std::cout << Mark("    +:+    +:+ ") << Error("   +:+        ") << Ask("     +:+   +:+") << std::endl;
    std::cout << Mark("   +#++:++#:   ") << Error("  +#++:++#++  ") << Ask("   +#++:++#++:") << std::endl;
    std::cout << Mark("  +#+    +#+   ") << Error("        +#+   ") << Ask("  +#+     +#+ ") << std::endl;
    std::cout << Mark(" #+#    #+#    ") << Error("#+#    #+#    ") << Ask(" #+#     #+#  ") << std::endl;
    std::cout << Mark("###    ###     ") << Error("########      ") << Ask("###     ###   ") << std::endl;
    std::cout << Mark("Rsa Cryptography Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("RSA Generate Parameters:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-gen | -generate] [-param | -params | -parameter | -parameters] <size> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("RSA Generate Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-gen | -generate] [-key | -keys] <size> [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("RSA Generate X509-REQ CSR Certificate:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-gen | -generate] -csr <size> [--subject] -san [--subject-alternative-name] -ku [--key-usage] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("RSA Export Parameters from Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-exp | -export] [-param | -params | -parameter | -parameters] [-pub | -public | -public-key] [--keys-way] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("RSA Export Public Key & Private Key from Parameters:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-exp | -export] [-key | -keys] [-param | -params | -parameter | -parameters] [--way] [--rsa-parameters-list] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 6") << ". " << Hint("RSA Extract Public Key from Private Key:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-ext | -extract] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 7") << ". " << Hint("RSA Confirms Whether the Public Key is Valid:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-chk | -check] [-pub | -public | -public-key] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 8") << ". " << Hint("RSA Confirms Whether the Private Key is Valid:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-chk | -check] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 9") << ". " << Hint("RSA Confirms Whether the X509-REQ CSR Certificate is Valid:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-chk | -check] -csr [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("10") << ". " << Hint("RSA Private Key Add Password to PEM:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-lk | -lock] [-pem <value> | -pem -f <path>] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [-pem | -pem -f <path>]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("11") << ". " << Hint("RSA Private Key Remove Password from PEM:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-uk | -unlock] [-pem <value> | -pem -f <path>] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("12") << ". " << Hint("RSA Encryption:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-en | -encrypt] [-pub | -public | -public-key] [--keys-way] [-pt | -plain-text] [--way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("13") << ". " << Hint("RSA Decryption:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-de | -decrypt] [-priv | -private | -private-key] [--keys-way] [-ct | -cipher-text] [--way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("14") << ". " << Hint("RSA Signed Data:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-sign | -signed] [-priv | -private | -private-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("15") << ". " << Hint("RSA Verify Data:") << std::endl;
    std::cout << Info("        [-rsa | --rsa] [-ver | -verify] [-pub | -public | -public-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-sg | -signature] [--way]") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();

    usage_libary::ShowKeysWayUsage();

    std::cout << Hint("    Supported [--rsa-parameters-list]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("[-n | -modulus]") << Warn("                          -> Modulus data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-e | -public-exponent]") << Warn("                  -> Public Exponent data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-d | -private-exponent]") << Warn("                 -> Private Exponent data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-p | -prime1 | -first-prime-factor]") << Warn("     -> First Prime Factor data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 5") << ". " << Info("[-q | -prime2 | -second-prime-factor]") << Warn("    -> Second Prime Factor data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 6") << ". " << Info("[-dp | -exponent1 | -first-crt-exponent]") << Warn(" -> First CRT Exponent data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 7") << ". " << Info("[-dq | -exponent2 | -second-crt-exponent]") << Warn("-> Second CRT Exponent data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 8") << ". " << Info("[-qi | -coefficient | -crt-coefficient]") << Warn("  -> CRT Coefficient data by [--way].") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowHashTypeUsage();

    usage_libary::ShowAlgorithm();

    usage_libary::ShowSubject();

    usage_libary::ShowSubjectAlternativeName();

    usage_libary::ShowKeyUsage();
}

void usage_libary::ShowEccUsage() {
    std::cout << Info("      ::::::::::") << Common("      ::::::::") << Warn("      ::::::::") << std::endl;
    std::cout << Info("     :+:        ") << Common("    :+:    :+:") << Warn("    :+:    :+:") << std::endl;
    std::cout << Info("    +:+         ") << Common("   +:+        ") << Warn("   +:+        ") << std::endl;
    std::cout << Info("   +#++:++#     ") << Common("  +#+         ") << Warn("  +#+         ") << std::endl;
    std::cout << Info("  +#+           ") << Common(" +#+          ") << Warn(" +#+          ") << std::endl;
    std::cout << Info(" #+#            ") << Common("#+#    #+#    ") << Warn("#+#    #+#    ") << std::endl;
    std::cout << Info("##########      ") << Common("########      ") << Warn("########      ") << std::endl;
    std::cout << Mark("Ecc Cryptography Usage") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 1") << ". " << Hint("ECC Curve List:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] -list") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 2") << ". " << Hint("ECC Generate Parameters:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-gen | -generate] [-param | -params | -parameter | -parameters] <curve | nid> [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 3") << ". " << Hint("ECC Generate Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-gen | -generate] [-key | -keys] <curve | nid> [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 4") << ". " << Hint("ECC Export Parameters from Public Key & Private Key:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-exp | -export] [-param | -params | -parameter | -parameters] [-pub | -public | -public-key] [--keys-way] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 5") << ". " << Hint("ECC Export Public Key & Private Key from Parameters:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-exp | -export] [-key | -keys] [-param | -params | -parameter | -parameters] [--way] [--ecc-parameters-list] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 6") << ". " << Hint("ECC Extract Public Key from Private Key:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-ext | -extract] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 7") << ". " << Hint("ECC Confirms Whether the Public Key is Valid:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-chk | -check] [-pub | -public | -public-key] [--keys-way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 8") << ". " << Hint("ECC Confirms Whether the Private Key is Valid:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-chk | -check] [-priv | -private | -private-key] [--keys-way] [-pwd | -pass | null] [--way] [--algorithm | null]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark(" 9") << ". " << Hint("ECC Signed Data:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-sign | -signed] [-priv | -private | -private-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-pwd | -pass | null] [--way] [--algorithm | null] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("10") << ". " << Hint("ECC Verify Data:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-ver | -verify] [-pub | -public | -public-key] [--keys-way] [-dat | -data] [--way] [--hash-type] [-sg | -signature] [--way]") << std::endl;
    std::cout << "" << std::endl;
    std::cout << "    " << Mark("11") << ". " << Hint("ECC Key Derive:") << std::endl;
    std::cout << Info("        [-ecc | --ecc] [-dv | -derive | -key-derive] [-pub | -public | -public-key] [--keys-way] [-priv | -private | -private-key] [--keys-way] [-out | -output] [--way]") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowWayUsage();

    usage_libary::ShowKeysWayUsage();

    std::cout << Hint("    Supported [--ecc-parameters-list]:\n");
    std::cout << "        " << Mark(" 1") << ". " << Info("-curve") << Warn("                                   -> Curve data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 2") << ". " << Info("[-x | -public-x]") << Warn("                         -> Public Key X Coordinate data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 3") << ". " << Info("[-y | -public-y]") << Warn("                         -> Public Key Y Coordinate data by [--way].") << std::endl;
    std::cout << "        " << Mark(" 4") << ". " << Info("[-p | -private-exp]") << Warn("                      -> Private Exponent data by [--way].") << std::endl;
    std::cout << "" << std::endl;

    usage_libary::ShowHashTypeUsage();

    usage_libary::ShowAlgorithm();
}