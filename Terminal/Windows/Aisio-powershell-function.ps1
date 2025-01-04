# Cryptography Settings...
$BASE = "-base16"

# Aes Settings...
$AES_KEY = "Key length must be 128, 192, 256"
$AES_IV = "IvMustBe128Size."
$AES_TAG = "TagMustBe128Size"
$AES_AAD = "Additional Authenticated Data (AAD) can be of any length"
$AES_KEY2 = "Secondary Key for AES-XTS Tweak."
$AES_TWEAK = "SectorNumber0001"
$AES_COUNTER = 1

$AES_GCM_TAG = "73DD32019CD29E7251D17128DE27FFDD"
$AES_CCM_TAG = "DB9A881B8A159B079F826BD043A4F8C9"
$AES_OCB_TAG = "F7F64A75E6575C9093E12AB272CBF024"
$AES_NONCE = "Nonce12bytes"
$AES_KEK = "This is AES WRAP, 128, 192, 256."

# Des Settings...
$DES_KEY = "Key Must Be 128,192 Size"
$DES_IV = "Iv8Bytes"
$DES_KEK = "WRAP Key 128 192 by DES."

# Rsa Settings...
$RSA_DER_PUB="30820122300D06092A864886F70D01010105000382010F003082010A0282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC4950203010001"
$RSA_DER_PRIV="308204A10201000282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC49502030100010281FF3FD0B5DB416111ADBB5EAAE3E3028B78F61250713EB4897F31B9F559BCB865C4E006E44F98BFD965E3EBB36A34AC52FD6F0AF41221876068F357DCCF09719BF2FF7D54FA1F1E879FA4647F9989265AABB4E475A8A6B5EFFBCDCE7FA0E1F87723B2AE573B09CEC1B9108625ED0FBAD3E9274560921E2958B9F83D7F653A9AC4C5492D7EBFF70DDE5893657AD2DF6E9A96A3A8D4D9674405607F23852C688339EBA85BEB51656CCD008C541F4082984BCAD1BCAB12234058E37F4D6FFEC3AA1BFEAE41F4C0B775EAD85B0045C725DBEC62C77680660AB463126FEE68EBAF470AABA6F0817C0E7697067605A2BE08AB176D330DE8FD7B77D0E9F9F4B7E414E58102818100C66264D04FD3453E55A7FBD0D8EAB7B5E9DAFB3D1806A8145919F033ECFFC87D797DA687380F5D65AE510EC1A1102E643725623BE5E5E7153823C759C288C94A7F57C47B2F1CB5D13351B70A7277903565D30D7E9F7A7F2B9970ED1DD6A9E7D882E8D20EC586004A718C77E77E2E56FEFA4904936F69021519D8849E9BC8F7B502818100D8584CDA06965E193FCAE823111201590260370F86AFA0CD2720ACD9E95A00CC8BF2FFB88858422ECC7F462EB3D6998E65030EA0987331F4EA130434F832F6C225E2B545440A4B7F9CB04FF9F463D0BE594193DDCA514BA58F34BD6F190B287A9A32514C122F5C20775B6387D1FAC769648F808EE2760569723791FCC5E7E5610281804BE74BB154497E7DDA221ABC0EB2C7B587936C7B349D1F6421AF45F36823799F60838DDAC0BD483BE6554733189FEB5016B56BFF84F7D0D1929845E6F7028519C6DD5AE4D2E2C64213C399281B21DA0044445B2E6E705D05DE809188D02053FFC81EB2784A64F9E981C67FFE078E4D64E3785A92DA96AFE048F249D3B1C153DD02818100A492D7336B9B6B4D8DC78EBB4E3B022771B53B6D6629A80B27DEA55EC7329E34FBA9087A99CD79DB1BD91DCC5D25BC7E23BD259D691B083FA4E87E64C5020FD034FDB6A35054FC85C0EE2688A02E6616C6D329E6A8071BA27FC3C0EF08800274F163A1905AAD0849F241E4FEE6EEFC4EE21E7FCF31DA51D79AF946E6A0ADFD41028180539ABF6CFEF34FC1CD48176B679CD6960608B9177BA9C3256FB2E8395B7D96C57C11ED6B8889BB264C45AB87AC1885CAEC064E0D3F7CDD30261A522DFC1F6E88B378F96B843F3C13AB960434CE24FEC96B038F5560151A611DF3070519140E508EDF398615A35FB8EB771D3BAADFA0D362263C10D90772AC0FA43C4D62F376D9"
$N="A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC495"
$E="010001"
$D="3FD0B5DB416111ADBB5EAAE3E3028B78F61250713EB4897F31B9F559BCB865C4E006E44F98BFD965E3EBB36A34AC52FD6F0AF41221876068F357DCCF09719BF2FF7D54FA1F1E879FA4647F9989265AABB4E475A8A6B5EFFBCDCE7FA0E1F87723B2AE573B09CEC1B9108625ED0FBAD3E9274560921E2958B9F83D7F653A9AC4C5492D7EBFF70DDE5893657AD2DF6E9A96A3A8D4D9674405607F23852C688339EBA85BEB51656CCD008C541F4082984BCAD1BCAB12234058E37F4D6FFEC3AA1BFEAE41F4C0B775EAD85B0045C725DBEC62C77680660AB463126FEE68EBAF470AABA6F0817C0E7697067605A2BE08AB176D330DE8FD7B77D0E9F9F4B7E414E581A7"
$P="C66264D04FD3453E55A7FBD0D8EAB7B5E9DAFB3D1806A8145919F033ECFFC87D797DA687380F5D65AE510EC1A1102E643725623BE5E5E7153823C759C288C94A7F57C47B2F1CB5D13351B70A7277903565D30D7E9F7A7F2B9970ED1DD6A9E7D882E8D20EC586004A718C77E77E2E56FEFA4904936F69021519D8849E9BC8F7B5"
$Q="D8584CDA06965E193FCAE823111201590260370F86AFA0CD2720ACD9E95A00CC8BF2FFB88858422ECC7F462EB3D6998E65030EA0987331F4EA130434F832F6C225E2B545440A4B7F9CB04FF9F463D0BE594193DDCA514BA58F34BD6F190B287A9A32514C122F5C20775B6387D1FAC769648F808EE2760569723791FCC5E7E561"
$DP="4BE74BB154497E7DDA221ABC0EB2C7B587936C7B349D1F6421AF45F36823799F60838DDAC0BD483BE6554733189FEB5016B56BFF84F7D0D1929845E6F7028519C6DD5AE4D2E2C64213C399281B21DA0044445B2E6E705D05DE809188D02053FFC81EB2784A64F9E981C67FFE078E4D64E3785A92DA96AFE048F249D3B1C153DD"
$DQ="A492D7336B9B6B4D8DC78EBB4E3B022771B53B6D6629A80B27DEA55EC7329E34FBA9087A99CD79DB1BD91DCC5D25BC7E23BD259D691B083FA4E87E64C5020FD034FDB6A35054FC85C0EE2688A02E6616C6D329E6A8071BA27FC3C0EF08800274F163A1905AAD0849F241E4FEE6EEFC4EE21E7FCF31DA51D79AF946E6A0ADFD41"
$QI="539ABF6CFEF34FC1CD48176B679CD6960608B9177BA9C3256FB2E8395B7D96C57C11ED6B8889BB264C45AB87AC1885CAEC064E0D3F7CDD30261A522DFC1F6E88B378F96B843F3C13AB960434CE24FEC96B038F5560151A611DF3070519140E508EDF398615A35FB8EB771D3BAADFA0D362263C10D90772AC0FA43C4D62F376D9"

function Usage {
    $scriptName = ".\$(Split-Path -Path $PSCommandPath -Leaf)"
    Write-Host "Usage:"
    Write-Host "    $scriptName <operation> [-f <filename>] [-n <iterations>]"
    Write-Host "Available operations:"
    Write-Host "    -w  (write)"
    Write-Host "    -a  (append)"
    Write-Host "    -i  (insert)"
    Write-Host "    -r  (read-all)"
    Write-Host "    -id (indexes)"
    Write-Host "    -rm (remove)"
    Write-Host "    -rs (remove-index)"
    exit 0
}

function BinaryWrite {
    Write-Host "Ais Binary IO Write..."
    .\aisio --write $BASE $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

function BinaryAppend {
    Write-Host "Ais Binary IO Append..."
    .\aisio --append $BASE $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

function BinaryInsert {
    Write-Host "Ais Binary IO Insert..."
    .\aisio --insert $BASE $file -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "0123456789ABCDEF0123456789ABCDEF" 0 -string "This is Ais.IO Function String." 0
}

function BinaryReadAll {
    Write-Host "Ais Binary IO Read all..."
    $arguments = @("--read-all", $BASE, $file)
    Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BinaryIndexes {
    Write-Host "Ais Binary IO Indexes..."
    $arguments = @("--indexes", $file)
    Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BinaryRemove {
    Write-Host "Ais Binary IO Remove..."
    $arguments = @("--remove", $file, "-string 0 32")
    Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BinaryRemoveIndex {
    Write-Host "Ais Binary IO Remove Index..."
    $arguments = @("--remove-index", $file, $indexList)
    Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BinaryReadIndex {
    Write-Host "Ais Binary IO Read Indexes..."
    $arguments = @("--read-index", $BASE, $file, $indexList)
    Start-Process -FilePath "./aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BASE_16 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 16 Encode..."
        .\aisio "--base16" "-encode" "This is Base16 Encode/Decode."
    }
    else {
        Write-Host "Ais Base 16 Decode..."
        .\aisio "--base16" "-decode" "546869732069732042617365313620456E636F64652F4465636F64652E"
    }
}
function BASE_32 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 32 Encode..."
        .\aisio "--base32" "-encode" "This is Base32 Encode/Decode."
    }
    else {
        Write-Host "Ais Base 32 Decode..."
        .\aisio "--base32" "-decode" "KRUGS4ZANFZSAQTBONSTGMRAAES_IVXGG33EMUXUIZLDN5SGKLQ="
    }
}
function BASE_64 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 64 Encode..."
        .\aisio "--base64" "-encode" "This is Base64 Encode/Decode."
    }
    else {
        Write-Host "Ais Base 64 Decode..."
        .\aisio "--base64" "-decode" "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="
    }
}
function BASE_85 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 85 Encode..."
        .\aisio "--base85" "-encode" "This is Base85 Encode/Decode."
    }
    else {
        Write-Host "Ais Base 85 Decode..."
        .\aisio "--base85" "-decode" 'RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k'
    }
}

function Generate {
    Write-Host "Ais Generate Any Random Value..."
    .\aisio -gen 32 -out $BASE
}

function Import {
    Write-Host "Ais Import Any String..."
    .\aisio -imp $AES_KEY -out $BASE
}

function AES_CTR {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CTR Encrypt..."
        .\aisio --aes -ctr -encrypt -key $AES_KEY -counter $AES_COUNTER -plain-text "This is AES CTR Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES CTR Decrypt..."
        .\aisio --aes -ctr -decrypt -key $AES_KEY -counter $AES_COUNTER -cipher-text $BASE "7F603AB98AF7073B205309B91FCAFC9581DD36055EB25C533429C9EB0C41ACF5070FA94FD62A"
    }
}

function AES_CBC {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CBC Encrypt..."
        .\aisio --aes -cbc -encrypt -key $AES_KEY -iv $AES_IV -padding -plain-text "This is AES CBC Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES CBC Decrypt..."
        .\aisio --aes -cbc -decrypt -key $AES_KEY -iv $AES_IV -padding -cipher-text $BASE "FAFEF277E6AF54441F3407175D3860D16BEDC9570CBB83F9609E2CE90AB1596D02167AA72C5A199D7810C0D0FEC674F8"
    }
}

function AES_CFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CFB Encrypt..."
        .\aisio --aes -cfb -encrypt -key $AES_KEY -iv $AES_IV -segment 128 -plain-text "This is AES CFB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES CFB Decrypt..."
        .\aisio --aes -cfb -decrypt -key $AES_KEY -iv $AES_IV -segment 128 -cipher-text $BASE "8A30BF00B0F15E4616BF4C9B5742591D658641BE4CE31B24041FA41B791F3021531F171CD401"
    }
}

function AES_OFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES OFB Encrypt..."
        .\aisio --aes -ofb -encrypt -key $AES_KEY -iv $AES_IV -plain-text "This is AES OFB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES OFB Decrypt..."
        .\aisio --aes -ofb -decrypt -key $AES_KEY -iv $AES_IV -cipher-text $BASE "8A30BF00B0F15E4616BF4C9B5B42591DCF29C1A2F23F43E35CB140041964E890070AAC2913E0"
    }
}

function AES_ECB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES ECB Encrypt..."
        .\aisio --aes -ecb -encrypt -key $AES_KEY -padding -plain-text "This is AES ECB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES ECB Decrypt..."
        .\aisio --aes -ecb -decrypt -key $AES_KEY -padding -cipher-text $BASE "1CD7A6E38BDBDD9F1EFE4BA5A17AB72CDB9CE185F374FBA7DC7C839C5AC30F7CC070E0DD9FA85879BCF8C8049E637406"
    }
}

function AES_GCM {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES GCM Encrypt..."
        .\aisio --aes -gcm -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES GCM Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES GCM Decrypt..."
        .\aisio --aes -gcm -decrypt -key $AES_KEY -nonce $AES_NONCE -tag $BASE $AES_GCM_TAG -aad $AES_AAD -cipher-text $BASE "742389440288A533843D6156F6CC67C28C543B1F397734BA01BE7173FC3E486B70E7A4CD2DF0"
    }
}

function AES_CCM {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CCM Encrypt..."
        .\aisio --aes -ccm -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES CCM Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES CCM Decrypt..."
        .\aisio --aes -ccm -decrypt -key $AES_KEY -nonce $AES_NONCE -tag $BASE $AES_CCM_TAG -aad $AES_AAD -cipher-text $BASE "5245E1C1520D7BC2E1530310E52BA74D96D1C97A8BE395AF88EEFF71D44BEC2EFEF8F6B65761"
    }
}

function AES_XTS {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES XTS Encrypt..."
        .\aisio --aes -xts -encrypt -key $AES_KEY -key2 $AES_KEY2 -tweak $AES_TWEAK -plain-text "This is AES XTS Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES XTS Decrypt..."
        .\aisio --aes -xts -decrypt -key $AES_KEY -key2 $AES_KEY2 -tweak $AES_TWEAK -cipher-text $BASE "2BC71BB83EEA376368F9429D09470359293905826B14EDA8B170C3E7A4958020C6AF061181B4"
    }
}

function AES_OCB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES OCB Encrypt..."
        .\aisio --aes -ocb -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES OCB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais AES OCB Decrypt..."
        .\aisio --aes -ocb -decrypt -key $AES_KEY -nonce $AES_NONCE -tag $BASE $AES_OCB_TAG -aad $AES_AAD -cipher-text $BASE "3F405A527F7E26DAA3DB8F55D32D33A63C48A9ED40E0ED410CD9E8FC3E090B9627FCC10355A3"
    }
}

function AES_WRAP {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES WRAP Encrypt..."
        .\aisio --aes -wrap -encrypt -key $AES_KEY -kek $AES_KEK -out $BASE
    }
    else {
        Write-Host "Ais AES WRAP Decrypt..."
        .\aisio --aes -wrap -decrypt -wrapkey $BASE "4A0953B24807510E39F18A1AF98153FBA9BF306092D15BB4FB75A04A95148C25B99D7F3A5589FD26" -kek $AES_KEK
    }
}

function DES_CBC {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES CBC Encrypt..."
        .\aisio --des -cbc -encrypt -key $DES_KEY -iv $DES_IV -padding -plain-text "This is DES CBC Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais DES CBC Decrypt..."
        .\aisio --des -cbc -decrypt -key $DES_KEY -iv $DES_IV -padding -cipher-text $BASE "D53DB3162D7E9A594C574BD6BFE734EBFE30DF7625F68AAD45932111EE6E421FA19624C47AE22DCF"
    }
}

function DES_CFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES CFB Encrypt..."
        .\aisio --des -cfb -encrypt -key $DES_KEY -iv $DES_IV -segment 64 -plain-text "This is DES CFB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais DES CFB Decrypt..."
        .\aisio --des -cfb -decrypt -key $DES_KEY -iv $DES_IV -segment 64 -cipher-text $BASE "479A7330CE6D3098CA0FD5A2569AB8C9A2D8C5BAC89A7273C28AC546F187007DC010D6FBFE00"
    }
}

function DES_OFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES OFB Encrypt..."
        .\aisio --des -ofb -encrypt -key $DES_KEY -iv $DES_IV -plain-text "This is DES OFB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais DES OFB Decrypt..."
        .\aisio --des -ofb -decrypt -key $DES_KEY -iv $DES_IV -cipher-text $BASE "479A7330CE6D3098F01B383128162351EDD36481B3A3364FF992EA0B491FCD420B2A24C1DC19"
    }
}

function DES_ECB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES ECB Encrypt..."
        .\aisio --des -ecb -encrypt -key $DES_KEY -padding -plain-text "This is DES ECB Encryption/Decryption." -out $BASE
    }
    else {
        Write-Host "Ais DES ECB Decrypt..."
        .\aisio --des -ecb -decrypt -key $DES_KEY -padding -cipher-text $BASE "8F10D1E43B42177E6EB26786CAC82B3A2E677A1B59AB8CD5C283E7605F4F42E957D594E8885EF5B1"
    }
}

function DES_WRAP {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES WRAP Encrypt..."
        .\aisio --des -wrap -encrypt -key $DES_KEY -kek $DES_KEK -out $BASE
    }
    else {
        Write-Host "Ais DES WRAP Decrypt..."
        .\aisio --des -wrap -decrypt -wrapkey $BASE "F033669ADDDD49C08A5D3BEE5198897D97F6B4E14644E30547CE756961857C28E437634A8D4A1C0B" -kek $DES_KEK
    }
}

function HASH_MD5 {
    Write-Host "Ais HASH MD5 Calculation..."
    $content = "This is HASH MD5 Calculation."
    $salt = "This is Salt by the HASH MD5."
    .\aisio --hash -md5 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_MD5_SHA1 {
    Write-Host "Ais HASH MD5-SHA1 Calculation..."
    $content = "This is HASH MD5-SHA1 Calculation."
    $salt = "This is Salt by the HASH MD5-SHA1."
    .\aisio --hash -md5-sha1 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA1 {
    Write-Host "Ais HASH SHA1 Calculation..."
    $content = "This is HASH SHA1 Calculation."
    $salt = "This is Salt by the HASH SHA1."
    .\aisio --hash -sha1 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_224 {
    Write-Host "Ais HASH SHA2-224 Calculation..."
    $content = "This is HASH SHA2-224 Calculation."
    $salt = "This is Salt by the HASH SHA2-224."
    .\aisio --hash -sha2-224 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_256 {
    Write-Host "Ais HASH SHA2-256 Calculation..."
    $content = "This is HASH SHA2-256 Calculation."
    $salt = "This is Salt by the HASH SHA2-256."
    .\aisio --hash -sha2-256 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_384 {
    Write-Host "Ais HASH SHA2-384 Calculation..."
    $content = "This is HASH SHA2-384 Calculation."
    $salt = "This is Salt by the HASH SHA2-384."
    .\aisio --hash -sha2-384 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_512 {
    Write-Host "Ais HASH SHA2-512 Calculation..."
    $content = "This is HASH SHA2-512 Calculation."
    $salt = "This is Salt by the HASH SHA2-512."
    .\aisio --hash -sha2-512 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_512_224 {
    Write-Host "Ais HASH SHA2-512-224 Calculation..."
    $content = "This is HASH SHA2-512-224 Calculation."
    $salt = "This is Salt by the HASH SHA2-512-224."
    .\aisio --hash -sha2-512-224 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA2_512_256 {
    Write-Host "Ais HASH SHA2-512-256 Calculation..."
    $content = "This is HASH SHA2-512-256 Calculation."
    $salt = "This is Salt by the HASH SHA2-512-256."
    .\aisio --hash -sha2-512-256 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA3_224 {
    Write-Host "Ais HASH SHA3-224 Calculation..."
    $content = "This is HASH SHA3-224 Calculation."
    $salt = "This is Salt by the HASH SHA3-224."
    .\aisio --hash -sha3-224 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA3_256 {
    Write-Host "Ais HASH SHA3-256 Calculation..."
    $content = "This is HASH SHA3-256 Calculation."
    $salt = "This is Salt by the HASH SHA3-256."
    .\aisio --hash -sha3-256 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA3_384 {
    Write-Host "Ais HASH SHA3-384 Calculation..."
    $content = "This is HASH SHA3-384 Calculation."
    $salt = "This is Salt by the HASH SHA3-384."
    .\aisio --hash -sha3-384 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA3_512 {
    Write-Host "Ais HASH SHA3-512 Calculation..."
    $content = "This is HASH SHA3-512 Calculation."
    $salt = "This is Salt by the HASH SHA3-512."
    .\aisio --hash -sha3-512 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SHA3_KE_128 {
    Write-Host "Ais HASH SHA3-KE-128 Calculation..."
    $content = "This is HASH SHA3-KE-128 Calculation."
    $salt = "This is Salt by the HASH SHA3-KE-128."
    .\aisio --hash -sha3-ke-128 -input $content -salt $salt -first -middle -last -length 16 -out $BASE
}

function HASH_SHA3_KE_256 {
    Write-Host "Ais HASH SHA3-KE-256 Calculation..."
    $content = "This is HASH SHA3-KE-256 Calculation."
    $salt = "This is Salt by the HASH SHA3-KE-256."
    .\aisio --hash -sha3-ke-256 -input $content -salt $salt -first -middle -last -length 32 -out $BASE
}

function HASH_BLAKE2S_256 {
    Write-Host "Ais HASH BLAKE2S-256 Calculation..."
    $content = "This is HASH BLAKE2S-256 Calculation."
    $salt = "This is Salt by the HASH BLAKE2S-256."
    .\aisio --hash -blake2s-256 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_BLAKE2B_512 {
    Write-Host "Ais HASH BLAKE2B-512 Calculation..."
    $content = "This is HASH BLAKE2B-512 Calculation."
    $salt = "This is Salt by the HASH BLAKE2B-512."
    .\aisio --hash -blake2b-512 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_SM3 {
    Write-Host "Ais HASH SM3 Calculation..."
    $content = "This is HASH SM3 Calculation."
    $salt = "This is Salt by the HASH SM3."
    .\aisio --hash -sm3 -input $content -salt $salt -first -middle -last -out $BASE
}

function HASH_RIPEMD160 {
    Write-Host "Ais HASH RIPEMD160 Calculation..."
    $content = "This is HASH RIPEMD160 Calculation."
    $salt = "This is Salt by the HASH RIPEMD160."
    .\aisio --hash -ripemd160 -input $content -salt $salt -first -middle -last -out $BASE
}

function RSA_Generate_Paramters {
    Write-Host "Ais RSA Generate Paramters..."
    .\aisio --rsa -generate -param 2048 -out $BASE
}

function RSA_Generate_Keys_PEM {
    .\aisio --rsa -generate -key 2048 -out -pem
}

function RSA_Generate_Keys_DER {
    .\aisio --rsa -generate -key 2048 -out -der $BASE
}

function RSA_Export_Paramters {
    ./aisio -rsa -export -param -pub -der $BASE $RSA_DER_PUB -priv -der $BASE $RSA_DER_PRIV -out $BASE
}

function RSA_Export_Keys {
    ./aisio -rsa -export -key -param $BASE -n $N -e $E -d $D -p $P -q $Q -dp $DP -dq $DQ -qi $QI -out -pem
}