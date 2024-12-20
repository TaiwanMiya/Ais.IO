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
    .\aisio --write $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
}

function BinaryAppend {
    Write-Host "Ais Binary IO Append..."
    .\aisio --append $file -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
}

function BinaryInsert {
    Write-Host "Ais Binary IO Insert..."
    .\aisio --insert $file -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0
}

function BinaryReadAll {
    Write-Host "Ais Binary IO Read all..."
    $arguments = @("--read-all", $file)
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
