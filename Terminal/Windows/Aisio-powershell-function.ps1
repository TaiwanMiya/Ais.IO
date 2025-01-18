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
$RSA_PEM_PUB=@"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp6dycJXIORK+KCoiJkTb
ByrhMq6RdtDzU3zAkScCZbNclNe6pIAmVbgnNWyih6sL6nwzYbe5O631bUPUPfaa
3bDhDJwxSvqna8FRa81tLMYSHjX9qfu1WFnwcrGaiBDtdJT5DdbxKIJNth+KVFTx
64RrEDkN5FJQhVAKuA6YXhwI2MS9pQD9t1P4JQq7qZ1hli/hnFfKFNva6AyBiQwO
JhqbnYTiwgwfd5iWZCCKUnOkjdhGPKPuf1zOHz2GwYxc84nLgypx8FAR3brVV5mY
eT2pXPvCzmDaVHEDe/ZbmyJv26A8gJV9hLszbC8aEc3MrJaLrED6FaIysLWVmg3E
lQIDAQAB
-----END PUBLIC KEY-----
"@
$RSA_PEM_PRIV=@"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnp3Jwlcg5Er4o
KiImRNsHKuEyrpF20PNTfMCRJwJls1yU17qkgCZVuCc1bKKHqwvqfDNht7k7rfVt
Q9Q99prdsOEMnDFK+qdrwVFrzW0sxhIeNf2p+7VYWfBysZqIEO10lPkN1vEogk22
H4pUVPHrhGsQOQ3kUlCFUAq4DpheHAjYxL2lAP23U/glCrupnWGWL+GcV8oU29ro
DIGJDA4mGpudhOLCDB93mJZkIIpSc6SN2EY8o+5/XM4fPYbBjFzzicuDKnHwUBHd
utVXmZh5Palc+8LOYNpUcQN79lubIm/boDyAlX2EuzNsLxoRzcyslousQPoVojKw
tZWaDcSVAgMBAAECggEAP9C120FhEa27Xqrj4wKLePYSUHE+tIl/Mbn1Wby4ZcTg
BuRPmL/ZZePrs2o0rFL9bwr0EiGHYGjzV9zPCXGb8v99VPofHoefpGR/mYkmWqu0
5HWoprXv+83Of6Dh+Hcjsq5XOwnOwbkQhiXtD7rT6SdFYJIeKVi5+D1/ZTqaxMVJ
LX6/9w3eWJNletLfbpqWo6jU2WdEBWB/I4UsaIM566hb61FlbM0AjFQfQIKYS8rR
vKsSI0BY439Nb/7Dqhv+rkH0wLd16thbAEXHJdvsYsd2gGYKtGMSb+5o669HCqum
8IF8DnaXBnYFor4IqxdtMw3o/Xt30On59LfkFOWBpwKBgQDGYmTQT9NFPlWn+9DY
6re16dr7PRgGqBRZGfAz7P/IfXl9poc4D11lrlEOwaEQLmQ3JWI75eXnFTgjx1nC
iMlKf1fEey8ctdEzUbcKcneQNWXTDX6fen8rmXDtHdap59iC6NIOxYYASnGMd+d+
Llb++kkEk29pAhUZ2ISem8j3tQKBgQDYWEzaBpZeGT/K6CMREgFZAmA3D4avoM0n
IKzZ6VoAzIvy/7iIWEIuzH9GLrPWmY5lAw6gmHMx9OoTBDT4MvbCJeK1RUQKS3+c
sE/59GPQvllBk93KUUuljzS9bxkLKHqaMlFMEi9cIHdbY4fR+sdpZI+AjuJ2BWly
N5H8xeflYQKBgEvnS7FUSX592iIavA6yx7WHk2x7NJ0fZCGvRfNoI3mfYION2sC9
SDvmVUczGJ/rUBa1a/+E99DRkphF5vcChRnG3Vrk0uLGQhPDmSgbIdoARERbLm5w
XQXegJGI0CBT/8gesnhKZPnpgcZ//geOTWTjeFqS2pav4EjySdOxwVPdAoGBAKSS
1zNrm2tNjceOu047AidxtTttZimoCyfepV7HMp40+6kIepnNedsb2R3MXSW8fiO9
JZ1pGwg/pOh+ZMUCD9A0/bajUFT8hcDuJoigLmYWxtMp5qgHG6J/w8DvCIACdPFj
oZBarQhJ8kHk/ubu/E7iHn/PMdpR15r5Ruagrf1BAoGAU5q/bP7zT8HNSBdrZ5zW
lgYIuRd7qcMlb7LoOVt9lsV8Ee1riIm7JkxFq4esGIXK7AZODT983TAmGlIt/B9u
iLN4+WuEPzwTq5YENM4k/slrA49VYBUaYR3zBwUZFA5Qjt85hhWjX7jrdx07qt+g
02ImPBDZB3KsD6Q8TWLzdtk=
-----END PRIVATE KEY-----
"@
$RSA_DER_PUB="30820122300D06092A864886F70D01010105000382010F003082010A0282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC4950203010001"
$RSA_DER_PRIV="308204A30201000282010100A7A7727095C83912BE282A222644DB072AE132AE9176D0F3537CC091270265B35C94D7BAA4802655B827356CA287AB0BEA7C3361B7B93BADF56D43D43DF69ADDB0E10C9C314AFAA76BC1516BCD6D2CC6121E35FDA9FBB55859F072B19A8810ED7494F90DD6F128824DB61F8A5454F1EB846B10390DE4525085500AB80E985E1C08D8C4BDA500FDB753F8250ABBA99D61962FE19C57CA14DBDAE80C81890C0E261A9B9D84E2C20C1F77989664208A5273A48DD8463CA3EE7F5CCE1F3D86C18C5CF389CB832A71F05011DDBAD5579998793DA95CFBC2CE60DA5471037BF65B9B226FDBA03C80957D84BB336C2F1A11CDCCAC968BAC40FA15A232B0B5959A0DC4950203010001028201003FD0B5DB416111ADBB5EAAE3E3028B78F61250713EB4897F31B9F559BCB865C4E006E44F98BFD965E3EBB36A34AC52FD6F0AF41221876068F357DCCF09719BF2FF7D54FA1F1E879FA4647F9989265AABB4E475A8A6B5EFFBCDCE7FA0E1F87723B2AE573B09CEC1B9108625ED0FBAD3E9274560921E2958B9F83D7F653A9AC4C5492D7EBFF70DDE5893657AD2DF6E9A96A3A8D4D9674405607F23852C688339EBA85BEB51656CCD008C541F4082984BCAD1BCAB12234058E37F4D6FFEC3AA1BFEAE41F4C0B775EAD85B0045C725DBEC62C77680660AB463126FEE68EBAF470AABA6F0817C0E7697067605A2BE08AB176D330DE8FD7B77D0E9F9F4B7E414E581A702818100C66264D04FD3453E55A7FBD0D8EAB7B5E9DAFB3D1806A8145919F033ECFFC87D797DA687380F5D65AE510EC1A1102E643725623BE5E5E7153823C759C288C94A7F57C47B2F1CB5D13351B70A7277903565D30D7E9F7A7F2B9970ED1DD6A9E7D882E8D20EC586004A718C77E77E2E56FEFA4904936F69021519D8849E9BC8F7B502818100D8584CDA06965E193FCAE823111201590260370F86AFA0CD2720ACD9E95A00CC8BF2FFB88858422ECC7F462EB3D6998E65030EA0987331F4EA130434F832F6C225E2B545440A4B7F9CB04FF9F463D0BE594193DDCA514BA58F34BD6F190B287A9A32514C122F5C20775B6387D1FAC769648F808EE2760569723791FCC5E7E5610281804BE74BB154497E7DDA221ABC0EB2C7B587936C7B349D1F6421AF45F36823799F60838DDAC0BD483BE6554733189FEB5016B56BFF84F7D0D1929845E6F7028519C6DD5AE4D2E2C64213C399281B21DA0044445B2E6E705D05DE809188D02053FFC81EB2784A64F9E981C67FFE078E4D64E3785A92DA96AFE048F249D3B1C153DD02818100A492D7336B9B6B4D8DC78EBB4E3B022771B53B6D6629A80B27DEA55EC7329E34FBA9087A99CD79DB1BD91DCC5D25BC7E23BD259D691B083FA4E87E64C5020FD034FDB6A35054FC85C0EE2688A02E6616C6D329E6A8071BA27FC3C0EF08800274F163A1905AAD0849F241E4FEE6EEFC4EE21E7FCF31DA51D79AF946E6A0ADFD41028180539ABF6CFEF34FC1CD48176B679CD6960608B9177BA9C3256FB2E8395B7D96C57C11ED6B8889BB264C45AB87AC1885CAEC064E0D3F7CDD30261A522DFC1F6E88B378F96B843F3C13AB960434CE24FEC96B038F5560151A611DF3070519140E508EDF398615A35FB8EB771D3BAADFA0D362263C10D90772AC0FA43C4D62F376D9"
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
    .\aisio --write "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

function BinaryAppend {
    Write-Host "Ais Binary IO Append..."
    .\aisio --append "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

function BinaryInsert {
    Write-Host "Ais Binary IO Insert..."
    .\aisio --insert "$BASE" "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "0123456789ABCDEF0123456789ABCDEF" 0 -string "This is Ais.IO Function String." 0
}

function BinaryReadAll {
    Write-Host "Ais Binary IO Read all..."
    .\aisio --read-all "$BASE" "$file"
}

function BinaryIndexes {
    Write-Host "Ais Binary IO Indexes..."
    .\aisio --indexes "$file"
}

function BinaryRemove {
    Write-Host "Ais Binary IO Remove..."
    .\aisio --remove "$file" -bool 118 1 -byte 116 1 -sbyte 114 1 -short 111 2 -ushort 108 2 -int 103 4 -uint 98 4 -long 89 8 -ulong 80 8 -float 75 4 -double 66 8 -bytes 41 16 -string 0 32
}

function BinaryRemoveIndex {
    Write-Host "Ais Binary IO Remove Index..."
    $arguments = @("--remove-index", "$file", $indexList)
    Start-Process -FilePath ".\aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BinaryReadIndex {
    Write-Host "Ais Binary IO Read Indexes..."
    $arguments = @("--read-index", "$BASE", "$file", $indexList)
    Start-Process -FilePath ".\aisio" -ArgumentList $arguments -NoNewWindow -Wait
}

function BASE_10 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 10 Encode..."
        .\aisio "--base10" "-encode" "This is Base10 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 10 Decode..."
        .\aisio "--base10" "-decode" "2275631377870141336533466315340532913972637215315185916509608405656878"
    }
}

function BASE_16 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 16 Encode..."
        .\aisio "--base16" "-encode" "This is Base16 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 16 Decode..."
        .\aisio "--base16" "-decode" "546869732069732042617365313620456E636F64652F4465636F64652E"
    }
}

function BASE_32 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 32 Encode..."
        .\aisio "--base32" "-encode" "This is Base32 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 32 Decode..."
        .\aisio "--base32" "-decode" "KRUGS4ZANFZSAQTBONSTGMRAAES_IVXGG33EMUXUIZLDN5SGKLQ="
    }
}

function BASE_58 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 58 Encode..."
        .\aisio "--base58" "-encode" "This is Base58 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 58 Decode..."
        .\aisio "--base58" "-decode" "4qFPnPkVdmicitJgEZS1kVZHMXD55q1CmJ6MssHP"
    }
}

function BASE_62 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 62 Encode..."
        .\aisio "--base62" "-encode" "This is Base62 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 62 Decode..."
        .\aisio "--base62" "-decode" "HcyJuDO7FzrCwYNWtbLv0nkZbFlzeZg5gRAMIYQ"
    }
}

function BASE_64 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 64 Encode..."
        .\aisio "--base64" "-encode" "This is Base64 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 64 Decode..."
        .\aisio "--base64" "-decode" "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="
    }
}

function BASE_85 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 85 Encode..."
        .\aisio "--base85" "-encode" "This is Base85 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 85 Decode..."
        .\aisio "--base85" "-decode" 'RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k'
    }
}

function BASE_91 {
    if ($encoder -eq '-e') {
        Write-Host "Ais Base 91 Encode..."
        .\aisio "--base91" "-encode" "This is Base91 Encode/Decode."
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais Base 91 Decode..."
        .\aisio "--base91" "-decode" 'nX,<:WRT$F,ue9QUz\"y+|irMn<{vJT1T20DC'
    }
}

function Generate {
    Write-Host "Ais Generate Any Random Value..."
    .\aisio -gen 32 -out "$BASE"
}

function Import {
    Write-Host "Ais Import Any String..."
    .\aisio -imp $AES_KEY -out "$BASE"
}

function AES_CTR {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CTR Encrypt..."
        .\aisio --aes -ctr -encrypt -key $AES_KEY -counter $AES_COUNTER -plain-text "This is AES CTR Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES CTR Decrypt..."
        .\aisio --aes -ctr -decrypt -key $AES_KEY -counter $AES_COUNTER -cipher-text "$BASE" "7F603AB98AF7073B205309B91FCAFC9581DD36055EB25C533429C9EB0C41ACF5070FA94FD62A"
    }
}

function AES_CBC {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CBC Encrypt..."
        .\aisio --aes -cbc -encrypt -key $AES_KEY -iv $AES_IV -padding -plain-text "This is AES CBC Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES CBC Decrypt..."
        .\aisio --aes -cbc -decrypt -key $AES_KEY -iv $AES_IV -padding -cipher-text "$BASE" "FAFEF277E6AF54441F3407175D3860D16BEDC9570CBB83F9609E2CE90AB1596D02167AA72C5A199D7810C0D0FEC674F8"
    }
}

function AES_CFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CFB Encrypt..."
        .\aisio --aes -cfb -encrypt -key $AES_KEY -iv $AES_IV -segment 128 -plain-text "This is AES CFB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES CFB Decrypt..."
        .\aisio --aes -cfb -decrypt -key $AES_KEY -iv $AES_IV -segment 128 -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5742591D658641BE4CE31B24041FA41B791F3021531F171CD401"
    }
}

function AES_OFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES OFB Encrypt..."
        .\aisio --aes -ofb -encrypt -key $AES_KEY -iv $AES_IV -plain-text "This is AES OFB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES OFB Decrypt..."
        .\aisio --aes -ofb -decrypt -key $AES_KEY -iv $AES_IV -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5B42591DCF29C1A2F23F43E35CB140041964E890070AAC2913E0"
    }
}

function AES_ECB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES ECB Encrypt..."
        .\aisio --aes -ecb -encrypt -key $AES_KEY -padding -plain-text "This is AES ECB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES ECB Decrypt..."
        .\aisio --aes -ecb -decrypt -key $AES_KEY -padding -cipher-text "$BASE" "1CD7A6E38BDBDD9F1EFE4BA5A17AB72CDB9CE185F374FBA7DC7C839C5AC30F7CC070E0DD9FA85879BCF8C8049E637406"
    }
}

function AES_GCM {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES GCM Encrypt..."
        .\aisio --aes -gcm -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES GCM Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES GCM Decrypt..."
        .\aisio --aes -gcm -decrypt -key $AES_KEY -nonce $AES_NONCE -tag "$BASE" $AES_GCM_TAG -aad $AES_AAD -cipher-text "$BASE" "742389440288A533843D6156F6CC67C28C543B1F397734BA01BE7173FC3E486B70E7A4CD2DF0"
    }
}

function AES_CCM {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES CCM Encrypt..."
        .\aisio --aes -ccm -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES CCM Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES CCM Decrypt..."
        .\aisio --aes -ccm -decrypt -key $AES_KEY -nonce $AES_NONCE -tag "$BASE" $AES_CCM_TAG -aad $AES_AAD -cipher-text "$BASE" "5245E1C1520D7BC2E1530310E52BA74D96D1C97A8BE395AF88EEFF71D44BEC2EFEF8F6B65761"
    }
}

function AES_XTS {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES XTS Encrypt..."
        .\aisio --aes -xts -encrypt -key $AES_KEY -key2 $AES_KEY2 -tweak $AES_TWEAK -plain-text "This is AES XTS Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES XTS Decrypt..."
        .\aisio --aes -xts -decrypt -key $AES_KEY -key2 $AES_KEY2 -tweak $AES_TWEAK -cipher-text "$BASE" "2BC71BB83EEA376368F9429D09470359293905826B14EDA8B170C3E7A4958020C6AF061181B4"
    }
}

function AES_OCB {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES OCB Encrypt..."
        .\aisio --aes -ocb -encrypt -key $AES_KEY -nonce $AES_NONCE -tag $AES_TAG -aad $AES_AAD -plain-text "This is AES OCB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES OCB Decrypt..."
        .\aisio --aes -ocb -decrypt -key $AES_KEY -nonce $AES_NONCE -tag "$BASE" $AES_OCB_TAG -aad $AES_AAD -cipher-text "$BASE" "3F405A527F7E26DAA3DB8F55D32D33A63C48A9ED40E0ED410CD9E8FC3E090B9627FCC10355A3"
    }
}

function AES_WRAP {
    if ($encoder -eq '-e') {
        Write-Host "Ais AES WRAP Encrypt..."
        .\aisio --aes -wrap -encrypt -key $AES_KEY -kek $AES_KEK -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais AES WRAP Decrypt..."
        .\aisio --aes -wrap -decrypt -wrapkey "$BASE" "4A0953B24807510E39F18A1AF98153FBA9BF306092D15BB4FB75A04A95148C25B99D7F3A5589FD26" -kek $AES_KEK
    }
}

function DES_CBC {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES CBC Encrypt..."
        .\aisio --des -cbc -encrypt -key $DES_KEY -iv $DES_IV -padding -plain-text "This is DES CBC Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais DES CBC Decrypt..."
        .\aisio --des -cbc -decrypt -key $DES_KEY -iv $DES_IV -padding -cipher-text "$BASE" "D53DB3162D7E9A594C574BD6BFE734EBFE30DF7625F68AAD45932111EE6E421FA19624C47AE22DCF"
    }
}

function DES_CFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES CFB Encrypt..."
        .\aisio --des -cfb -encrypt -key $DES_KEY -iv $DES_IV -segment 64 -plain-text "This is DES CFB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais DES CFB Decrypt..."
        .\aisio --des -cfb -decrypt -key $DES_KEY -iv $DES_IV -segment 64 -cipher-text "$BASE" "479A7330CE6D3098CA0FD5A2569AB8C9A2D8C5BAC89A7273C28AC546F187007DC010D6FBFE00"
    }
}

function DES_OFB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES OFB Encrypt..."
        .\aisio --des -ofb -encrypt -key $DES_KEY -iv $DES_IV -plain-text "This is DES OFB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais DES OFB Decrypt..."
        .\aisio --des -ofb -decrypt -key $DES_KEY -iv $DES_IV -cipher-text "$BASE" "479A7330CE6D3098F01B383128162351EDD36481B3A3364FF992EA0B491FCD420B2A24C1DC19"
    }
}

function DES_ECB {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES ECB Encrypt..."
        .\aisio --des -ecb -encrypt -key $DES_KEY -padding -plain-text "This is DES ECB Encryption/Decryption." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais DES ECB Decrypt..."
        .\aisio --des -ecb -decrypt -key $DES_KEY -padding -cipher-text "$BASE" "8F10D1E43B42177E6EB26786CAC82B3A2E677A1B59AB8CD5C283E7605F4F42E957D594E8885EF5B1"
    }
}

function DES_WRAP {
    if ($encoder -eq '-e') {
        Write-Host "Ais DES WRAP Encrypt..."
        .\aisio --des -wrap -encrypt -key $DES_KEY -kek $DES_KEK -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        Write-Host "Ais DES WRAP Decrypt..."
        .\aisio --des -wrap -decrypt -wrapkey "$BASE" "F033669ADDDD49C08A5D3BEE5198897D97F6B4E14644E30547CE756961857C28E437634A8D4A1C0B" -kek $DES_KEK
    }
}

function HASH_MD5 {
    Write-Host "Ais HASH MD5 Calculation..."
    $content = "This is HASH MD5 Calculation."
    $salt = "This is Salt by the HASH MD5."
    .\aisio --hash -md5 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_MD5_SHA1 {
    Write-Host "Ais HASH MD5-SHA1 Calculation..."
    $content = "This is HASH MD5-SHA1 Calculation."
    $salt = "This is Salt by the HASH MD5-SHA1."
    .\aisio --hash -md5-sha1 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA1 {
    Write-Host "Ais HASH SHA1 Calculation..."
    $content = "This is HASH SHA1 Calculation."
    $salt = "This is Salt by the HASH SHA1."
    .\aisio --hash -sha1 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_224 {
    Write-Host "Ais HASH SHA2-224 Calculation..."
    $content = "This is HASH SHA2-224 Calculation."
    $salt = "This is Salt by the HASH SHA2-224."
    .\aisio --hash -sha2-224 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_256 {
    Write-Host "Ais HASH SHA2-256 Calculation..."
    $content = "This is HASH SHA2-256 Calculation."
    $salt = "This is Salt by the HASH SHA2-256."
    .\aisio --hash -sha2-256 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_384 {
    Write-Host "Ais HASH SHA2-384 Calculation..."
    $content = "This is HASH SHA2-384 Calculation."
    $salt = "This is Salt by the HASH SHA2-384."
    .\aisio --hash -sha2-384 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_512 {
    Write-Host "Ais HASH SHA2-512 Calculation..."
    $content = "This is HASH SHA2-512 Calculation."
    $salt = "This is Salt by the HASH SHA2-512."
    .\aisio --hash -sha2-512 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_512_224 {
    Write-Host "Ais HASH SHA2-512-224 Calculation..."
    $content = "This is HASH SHA2-512-224 Calculation."
    $salt = "This is Salt by the HASH SHA2-512-224."
    .\aisio --hash -sha2-512-224 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA2_512_256 {
    Write-Host "Ais HASH SHA2-512-256 Calculation..."
    $content = "This is HASH SHA2-512-256 Calculation."
    $salt = "This is Salt by the HASH SHA2-512-256."
    .\aisio --hash -sha2-512-256 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA3_224 {
    Write-Host "Ais HASH SHA3-224 Calculation..."
    $content = "This is HASH SHA3-224 Calculation."
    $salt = "This is Salt by the HASH SHA3-224."
    .\aisio --hash -sha3-224 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA3_256 {
    Write-Host "Ais HASH SHA3-256 Calculation..."
    $content = "This is HASH SHA3-256 Calculation."
    $salt = "This is Salt by the HASH SHA3-256."
    .\aisio --hash -sha3-256 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA3_384 {
    Write-Host "Ais HASH SHA3-384 Calculation..."
    $content = "This is HASH SHA3-384 Calculation."
    $salt = "This is Salt by the HASH SHA3-384."
    .\aisio --hash -sha3-384 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA3_512 {
    Write-Host "Ais HASH SHA3-512 Calculation..."
    $content = "This is HASH SHA3-512 Calculation."
    $salt = "This is Salt by the HASH SHA3-512."
    .\aisio --hash -sha3-512 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SHA3_KE_128 {
    Write-Host "Ais HASH SHA3-KE-128 Calculation..."
    $content = "This is HASH SHA3-KE-128 Calculation."
    $salt = "This is Salt by the HASH SHA3-KE-128."
    .\aisio --hash -sha3-ke-128 -input $content -salt $salt -first -middle -last -length 16 -out "$BASE"
}

function HASH_SHA3_KE_256 {
    Write-Host "Ais HASH SHA3-KE-256 Calculation..."
    $content = "This is HASH SHA3-KE-256 Calculation."
    $salt = "This is Salt by the HASH SHA3-KE-256."
    .\aisio --hash -sha3-ke-256 -input $content -salt $salt -first -middle -last -length 32 -out "$BASE"
}

function HASH_BLAKE2S_256 {
    Write-Host "Ais HASH BLAKE2S-256 Calculation..."
    $content = "This is HASH BLAKE2S-256 Calculation."
    $salt = "This is Salt by the HASH BLAKE2S-256."
    .\aisio --hash -blake2s-256 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_BLAKE2B_512 {
    Write-Host "Ais HASH BLAKE2B-512 Calculation..."
    $content = "This is HASH BLAKE2B-512 Calculation."
    $salt = "This is Salt by the HASH BLAKE2B-512."
    .\aisio --hash -blake2b-512 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_SM3 {
    Write-Host "Ais HASH SM3 Calculation..."
    $content = "This is HASH SM3 Calculation."
    $salt = "This is Salt by the HASH SM3."
    .\aisio --hash -sm3 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function HASH_RIPEMD160 {
    Write-Host "Ais HASH RIPEMD160 Calculation..."
    $content = "This is HASH RIPEMD160 Calculation."
    $salt = "This is Salt by the HASH RIPEMD160."
    .\aisio --hash -ripemd160 -input $content -salt $salt -first -middle -last -out "$BASE"
}

function RSA_Generate_Paramters {
    Write-Host "Ais RSA Generate Paramters..."
    .\aisio --rsa -generate -param 2048 -out "$BASE"
}

function RSA_Generate_Keys_PEM {
    .\aisio --rsa -generate -key 2048 -out -pem
}

function RSA_Generate_Keys_DER {
    .\aisio --rsa -generate -key 2048 -out -der "$BASE"
}

function RSA_Export_Paramters {
    .\aisio -rsa -export -param -pub -der "$BASE" $RSA_DER_PUB -priv -der "$BASE" $RSA_DER_PRIV -out "$BASE"
}

function RSA_Export_Keys_PEM {
    .\aisio -rsa -export -key -param "$BASE" -n $N -e $E -d $D -p $P -q $Q -dp $DP -dq $DQ -qi $QI -out -pem
}

function RSA_Export_Keys_DER {
    .\aisio -rsa -export -key -param "$BASE" -n $N -e $E -d $D -p $P -q $Q -dp $DP -dq $DQ -qi $QI -out -der "$BASE"
}

function RSA_Check_Keys_PEM {
    .\aisio -rsa -check -pub -pem "$RSA_PEM_PUB"
    .\aisio -rsa -check -priv -pem "$RSA_PEM_PRIV"
}

function RSA_Check_Keys_DER {
    .\aisio -rsa -check -pub -der "$BASE" "$RSA_DER_PUB"
    .\aisio -rsa -check -priv -der "$BASE" "$RSA_DER_PRIV"
}

function RSA_Cryption_PEM {
    if ($encoder -eq '-e') {
        .\aisio -rsa -encrypt -pub -pem "$RSA_PEM_PUB" -plain-text "This is Encryption/Decryption by RSA PEM 2048 Key." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        .\aisio -rsa -decrypt -priv -pem "$RSA_PEM_PRIV" -cipher-text "$BASE" "829E60D6D00A3A2F30AFDA987D7665F235A5DD6B8CF7251506C3C714B0BD47E0A62D3ACE880067F7691513EC4588C355E4839374C4FA4CF0EB26236F307766D9141B9863412B8B141C9923F8ADC1C63C15EF028812E9F993F2134FFC0B29B49A65780C7646EDC3CECA50460868EFF8A189016076D9FB048DED4416247B053A164D9B24FF1E54B9DFEB9D55515F34314A41B8AED3FFA2492A790865CD789F5AABCA030FA43A4A0275DF330E5F68342158179C37A5DEFB21833FA5248AB79BB21B7D18CCAE1A6EFEDC91C95A0147FDAC390537526BFD8515C72EA9D1818AE921D284B533A6329E0D6B45CDDF39386952C31CB859993A28722EB71E12F7B605C698"
    }
}

function RSA_Cryption_DER {
    if ($encoder -eq '-e') {
        .\aisio -rsa -encrypt -pub -der "$BASE" "$RSA_DER_PUB" -plain-text "This is Encryption/Decryption by RSA DER 2048 Key." -out "$BASE"
    }
    elseif ($encoder -eq '-d') {
        .\aisio -rsa -decrypt -priv -der "$BASE" "$RSA_DER_PRIV" -cipher-text "$BASE" "724E1EAF36ECC5127CE7FB9FA975EF02493A77A712C8FD3F9009320499F949CC1ED827B2551CB6361A657FCCB106CA4F4858B5C544790A04573E900CC53F9E479EDE9C6C9A93C40034DFB4652F4A25F9896D82FD99B1D0CB44FFFF44D64CFB6E20855AC6A4E062853310C7AE8764F1A68788F3D43E634D3C10880552F1B1E5E060C23E6F5DE82E0BD2C59642128A66015E33B644323F4E384B7A34169036F57746D74DBA37ACB06438CDB8085AB50FB1C482FC2CCDDA04FD74799B2CA44B132E7A292604E327E925A40E04DE2AB52854181F35C65792055504C671992B0B1EA9BDCFBC8591B1F08781864AEB80E89617EBC1FEE8996D22F7C42FC3B93AD8585D"
    }
}

function RSA_Digital_PEM {
    if ($encoder -eq '-s') {
        .\aisio -rsa -signed -priv -pem "$RSA_PEM_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -out "$BASE"
    }
    elseif ($encoder -eq '-v') {
        .\aisio -rsa -verify -pub -pem "$RSA_PEM_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -signature "$BASE" "18DEF0246E638E737074FFF2351185B9B0596923867E79365EE0A78C86D8457E9A164FC55DFBE1656E4691F121FEA751A4A9BD90BA5E5648CB5EFD4E961DE25B284F7ABF94D7510B9DCF0ADE7725EB465207B0EB9F11A4DDEF3E1E9AD6C9D3303E2D597BCD0E32326DD88F98FB6D15A5488B17947155A5AB8F2EF2C1B224ECD5D626F5826E33713D07EBC5F99CD5366D8DD24356D427C205B844F9357F4880093E494C1A4B942D2A6D4DC1FD83970E44D3B5DAD4382F9494559410E865DB290AFE83BC4A74A5EB7AF6C6D3F6F04CA39028ACE83404667766D8E92EEF1C5FD4984010B8FDDD5D2191A076854D61FEA8382D356C53A4B3DFA8264C8FD46806CC0F"
    }
}

function RSA_Digital_DER {
    if ($encoder -eq '-s') {
        .\aisio -rsa -signed -priv -der "$BASE" "$RSA_DER_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -out "$BASE"
    }
    elseif ($encoder -eq '-v') {
        .\aisio -rsa -verify -pub -der "$BASE" "$RSA_DER_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -signature "$BASE" "5DAB236FD6B3E8680C825693391719507B2B9219488EA59E9DE38A0A334A5C592E633CE9E3BA1A90F54FA809E5B52239A6103B73027C1A8DC2D06CC2A79E67822E3CE858C962867BB15C6AA51F84A050E2AD3DE86A3F6D720FDE01152B344CE3BFC4A4A6557F3BD7BA507C1CE3F4AB231E36845BC496093137D90D51397521AEC9A05CA7C2A75EE9DCCA62D09051D0C10037353C68869C09D9B8B5FAE438D9AA0108473AC72F6F073347A71AB425D2EE168DD90A995665768F3386A2AADCC1F3C245C14E19E239ADB52B5B892E10930283532899F8EC92D54A57FE628514395CEF769CAD5DEB657CB9CB6F930AF863B17F4D4EF89C0DABCB36487B8B6A477B14"
    }
}