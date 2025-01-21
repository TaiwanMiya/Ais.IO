#!/bin/bash
Usage() {
	echo "Usage:"
	echo "	$0 <operation> [-f <filename>] [-n <iterations>]"
	echo "IO operations:"
	echo ""
	echo "	-w  (write)"
	echo "	-a  (append)"
	echo "	-i  (insert)"
	echo "	-r  (read-all)"
	echo "	-id (indexes)"
	echo "	-rm (remove)"
	echo "	-rs (remove-index)"
	echo "	-ri (read-index)"
	echo ""
	echo "Base operations:"
	echo "	-b16 (Base 16 Encode/Decode)"
	echo "	-b32 (Base 32 Encode/Decode)"
	echo "	-b64 (Base 64 Encode/Decode)"
	echo "	-b85 (Base 85 Encode/Decode)"
	echo ""
	echo "Aes operations:"
	echo "	-ctr (Aes ctr Encrypt/Decrypt)"
	echo "	-cbc (Aes cbc Encrypt/Decrypt)"
	echo "	-cfb (Aes cfb Encrypt/Decrypt)"
	echo "	-ofb (Aes ofb Encrypt/Decrypt)"
	echo "	-ecb (Aes ecb Encrypt/Decrypt)"
	echo "	-gcm (Aes gcm Encrypt/Decrypt)"
	echo "	-ccm (Aes ccm Encrypt/Decrypt)"
	echo "	-xts (Aes xts Encrypt/Decrypt)"
	echo "	-ocb (Aes ocb Encrypt/Decrypt)"
	echo "	-wrap (Aes wrap Encrypt/Decrypt)"
	echo ""
	echo "Des operations:"
	echo "	-cbc (Des cbc Encrypt/Decrypt)"
	echo "	-cfb (Des cfb Encrypt/Decrypt)"
	echo "	-ofb (Des ofb Encrypt/Decrypt)"
	echo "	-ecb (Des ecb Encrypt/Decrypt)"
	echo "	-wrap (Des wrap Encrypt/Decrypt)"
	echo ""
	echo "Hash operations:"
	echo "	-md5 (Hash Calculation)"
	echo "	-md5-sha1 (Hash Calculation)"
	echo "	-sha1 (Hash Calculation)"
	echo "	-sha2-224 (Hash Calculation)"
	echo "	-sha2-256 (Hash Calculation)"
	echo "	-sha2-384 (Hash Calculation)"
	echo "	-sha2-512 (Hash Calculation)"
	echo "	-sha2-512-224 (Hash Calculation)"
	echo "	-sha2-512-256 (Hash Calculation)"
	echo "	-sha3-224 (Hash Calculation)"
	echo "	-sha3-256 (Hash Calculation)"
	echo "	-sha3-384 (Hash Calculation)"
	echo "	-sha3-512 (Hash Calculation)"
	echo "	-sha3-ke-128 (Hash Calculation)"
	echo "	-sha3-ke-256 (Hash Calculation)"
	echo "	-blake2s-256 (Hash Calculation)"
	echo "	-blake2b-512 (Hash Calculation)"
	echo "	-sm3 (Hash Calculation)"
	echo "	-ripemd160 (Hash Calculation)"
	echo ""
	echo "Rsa operations:"
	echo "	-generate -param (Generate Rsa Parameters)"
	echo "	-generate -key -out -pem (Generate Rsa PEM Public Key / Private Key)"
	echo "	-generate -key -out -der -b16 (Generate Rsa DER Public Key / Private Key)"
	echo "	-export -param (Export Rsa Parameters)"
	echo "	-export -key (Export Rsa Public Key / Private Key)"
	echo ""
	exit 1
}

BinaryWrite() {
	echo "Ais Binary IO Write..."
	./aisio --write "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

BinaryAppend() {
	echo "Ais Binary IO Append..."
	./aisio --append "$BASE" "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "0123456789ABCDEF0123456789ABCDEF" -string "This is Ais.IO Function String."
}

BinaryInsert() {
	echo "Ais Binary IO Insert..."
	./aisio --insert "$BASE" "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "0123456789ABCDEF0123456789ABCDEF" 0 -string "This is Ais.IO Function String." 0
}

BinaryReadAll() {
	echo "Ais Binary IO Read all..."
	./aisio --read-all "$BASE" "$file"
}

BinaryIndexes() {
	echo "Ais Binary IO Indexes..."
	./aisio --indexes "$file"
}

BinaryRemove() {
	echo "Ais Binary IO Remove..."
	./aisio --remove "$file" -string 0 32
}

BinaryRemoveIndex() {
	echo "Ais Binary IO Remove Index..."
	./aisio --remove-index "$file" $index_list
}

BinaryReadIndex() {
	echo "Ais Binary IO Read Index..."
	./aisio --read-index "$BASE" "$file" $index_list
}

BASE_10() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base10 -encode "This is Base10 Encode/Decode."
	else
		./aisio --base10 -decode "2275631377870141336533466315340532913972637215315185916509608405656878"
	fi
}

BASE_16() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base16 -encode "This is Base16 Encode/Decode."
	else
		./aisio --base16 -decode "546869732069732042617365313620456E636F64652F4465636F64652E"
	fi
}

BASE_32() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base32 -encode "This is Base32 Encode/Decode."
	else
		./aisio --base32 -decode "KRUGS4ZANFZSAQTBONSTGMRAIVXGG33EMUXUIZLDN5SGKLQ="
	fi
}

BASE_58() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base58 -encode "This is Base58 Encode/Decode."
	else
		./aisio --base58 -decode "4qFPnPkVdmicitJgEZS1kVZHMXD55q1CmJ6MssHP"
	fi
}

BASE_62() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base62 -encode "This is Base62 Encode/Decode."
	else
		./aisio --base62 -decode "HcyJuDO7FzrCwYNWtbLv0nkZbFlzeZg5gRAMIYQ"
	fi
}

BASE_64() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base64 -encode "This is Base64 Encode/Decode."
	else
		./aisio --base64 -decode "VGhpcyBpcyBCYXNlNjQgRW5jb2RlL0RlY29kZS4="
	fi
}

BASE_85() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base85 -encode "This is Base85 Encode/Decode."
	else
		./aisio --base85 -decode 'RA^~)AZc?TLSb`dI5i+eZewp`WiLc!V{c?-E&u=k'
	fi
}

BASE_91() {
	if [[ $encoder == '-e' ]]; then
		./aisio --base91 -encode "This is Base91 Encode/Decode."
	else
		./aisio --base91 -decode 'nX,<:WRT$F,ue9QUz\"y+|irMn<{vJT1T20DC'
	fi
}

Generate() {
	./aisio --generate 32 -out "$BASE"
}

Import() {
	./aisio --import "$AES_KEY" -out "$BASE"
}

AES_CTR() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -ctr -encrypt -key "$AES_KEY" -counter "$AES_COUNTER" -plain-text "This is AES CTR Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -ctr -decrypt -key "$AES_KEY" -counter "$AES_COUNTER" -cipher-text "$BASE" "7F603AB98AF7073B205309B91FCAFC9581DD36055EB25C533429C9EB0C41ACF5070FA94FD62A"
	fi
}

AES_CBC() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -cbc -encrypt -key "$AES_KEY" -iv "$AES_IV" -padding -plain-text "This is AES CBC Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -cbc -decrypt -key "$AES_KEY" -iv "$AES_IV" -padding -cipher-text "$BASE" "FAFEF277E6AF54441F3407175D3860D16BEDC9570CBB83F9609E2CE90AB1596D02167AA72C5A199D7810C0D0FEC674F8"
	fi
}

AES_CFB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -cfb -encrypt -key "$AES_KEY" -iv "$AES_IV" -segment 128 -plain-text "This is AES CFB Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -cfb -decrypt -key "$AES_KEY" -iv "$AES_IV" -segment 128 -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5742591D658641BE4CE31B24041FA41B791F3021531F171CD401"
	fi
}

AES_OFB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -ofb -encrypt -key "$AES_KEY" -iv "$AES_IV" -plain-text "This is AES OFB Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -ofb -decrypt -key "$AES_KEY" -iv "$AES_IV" -cipher-text "$BASE" "8A30BF00B0F15E4616BF4C9B5B42591DCF29C1A2F23F43E35CB140041964E890070AAC2913E0"
	fi
}
 
AES_ECB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -ecb -encrypt -key "$AES_KEY" -padding -plain-text "This is AES ECB Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -ecb -decrypt -key "$AES_KEY" -padding -cipher-text "$BASE" "1CD7A6E38BDBDD9F1EFE4BA5A17AB72CDB9CE185F374FBA7DC7C839C5AC30F7CC070E0DD9FA85879BCF8C8049E637406"
	fi
}

AES_GCM() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -gcm -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES GCM Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -gcm -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_GCM_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "742389440288A533843D6156F6CC67C28C543B1F397734BA01BE7173FC3E486B70E7A4CD2DF0"
	fi
}

AES_CCM() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -ccm -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES CCM Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -ccm -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_CCM_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "5245E1C1520D7BC2E1530310E52BA74D96D1C97A8BE395AF88EEFF71D44BEC2EFEF8F6B65761"
	fi
}

AES_XTS() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -xts -encrypt -key "$AES_KEY" -key2 "$AES_KEY2" -tweak "$AES_TWEAK" -plain-text "This is AES XTS Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -xts -decrypt -key "$AES_KEY" -key2 "$AES_KEY2" -tweak "$AES_TWEAK" -cipher-text "$BASE" "2BC71BB83EEA376368F9429D09470359293905826B14EDA8B170C3E7A4958020C6AF061181B4"
	fi
}

AES_OCB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -ocb -encrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$AES_TAG" -aad "$AES_AAD" -plain-text "This is AES OCB Encryption/Decryption." -out "$BASE"
	else
		./aisio -aes -ocb -decrypt -key "$AES_KEY" -nonce "$AES_NONCE" -tag "$BASE" "$AES_OCB_TAG" -aad "$AES_AAD" -cipher-text "$BASE" "3F405A527F7E26DAA3DB8F55D32D33A63C48A9ED40E0ED410CD9E8FC3E090B9627FCC10355A3"
	fi
}

AES_WRAP() {
	if [[ $encoder == "-e" ]]; then
		./aisio -aes -wrap -encrypt -key "$AES_KEY" -kek "$AES_KEK" -out "$BASE"
	else
		./aisio -aes -wrap -decrypt -wrapkey "$BASE" "4A0953B24807510E39F18A1AF98153FBA9BF306092D15BB4FB75A04A95148C25B99D7F3A5589FD26" -kek "$AES_KEK"  
	fi
}

DES_CBC() {
	if [[ $encoder == "-e" ]]; then
		./aisio -des -cbc -encrypt -key "$DES_KEY" -iv "$DES_IV" -padding -plain-text "This is DES CBC Encryption/Decryption." -out "$BASE"
	else
		./aisio -des -cbc -decrypt -key "$DES_KEY" -iv "$DES_IV" -padding -cipher-text "$BASE" "D53DB3162D7E9A594C574BD6BFE734EBFE30DF7625F68AAD45932111EE6E421FA19624C47AE22DCF"
	fi
}

DES_CFB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -des -cfb -encrypt -key "$DES_KEY" -iv "$DES_IV" -segment 128 -plain-text "This is DES CFB Encryption/Decryption." -out "$BASE"
	else
		./aisio -des -cfb -decrypt -key "$DES_KEY" -iv "$DES_IV" -segment 128 -cipher-text "$BASE" "479A7330CE6D3098CA0FD5A2569AB8C9A2D8C5BAC89A7273C28AC546F187007DC010D6FBFE00"
	fi
}

DES_OFB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -des -ofb -encrypt -key "$DES_KEY" -iv "$DES_IV" -plain-text "This is DES OFB Encryption/Decryption." -out "$BASE"
	else
		./aisio -des -ofb -decrypt -key "$DES_KEY" -iv "$DES_IV" -cipher-text "$BASE" "479A7330CE6D3098F01B383128162351EDD36481B3A3364FF992EA0B491FCD420B2A24C1DC19"
	fi
} 

DES_ECB() {
	if [[ $encoder == "-e" ]]; then
		./aisio -des -ecb -encrypt -key "$DES_KEY" -padding -plain-text "This is DES ECB Encryption/Decryption." -out "$BASE"
	else
		./aisio -des -ecb -decrypt -key "$DES_KEY" -padding -cipher-text "$BASE" "8F10D1E43B42177E6EB26786CAC82B3A2E677A1B59AB8CD5C283E7605F4F42E957D594E8885EF5B1"
	fi
} 

DES_WRAP() {
	if [[ $encoder == "-e" ]]; then
		./aisio -des -wrap -encrypt -key "$DES_KEY" -kek "$DES_KEK" -out "$BASE"
	else
		./aisio -des -wrap -decrypt -wrapkey "$BASE" "F033669ADDDD49C08A5D3BEE5198897D97F6B4E14644E30547CE756961857C28E437634A8D4A1C0B" -kek "$DES_KEK"
	fi
}

HASH_MD5() {
	./aisio -hash -md5 "This is HASH-MD5 by the Hash libary." -salt "This is HASH-MD5 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_MD5_SHA1() {
	./aisio -hash -md5-sha1 "This is HASH-MD5-SHA1 by the Hash libary." -salt "This is HASH-MD5-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA1() {
	./aisio -hash -sha1 "This is HASH-SHA1 by the Hash libary." -salt "This is HASH-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_224() {
	./aisio -hash -sha2-224 "This is HASH-SHA2-224 by the Hash libary." -salt "This is HASH-SHA2-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_256() {
	./aisio -hash -sha2-256 "This is HASH-SHA2-256 by the Hash libary." -salt "This is HASH-SHA2-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_384() {
	./aisio -hash -sha2-384 "This is HASH-SHA2-384 by the Hash libary." -salt "This is HASH-SHA2-384 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512() {
	./aisio -hash -sha2-512 "This is HASH-SHA2-512 by the Hash libary." -salt "This is HASH-SHA2-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512_224() {
	./aisio -hash -sha2-512-224 "This is HASH-SHA2-512-224 by the Hash libary." -salt "This is HASH-SHA2-512-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512_256() {
	./aisio -hash -sha2-512-256 "This is HASH-SHA2-512-256 by the Hash libary." -salt "This is HASH-SHA2-512-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_224() {
	./aisio -hash -sha3-224 "This is HASH-SHA3-224 by the Hash libary." -salt "This is HASH-SHA3-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_256() {
	./aisio -hash -sha3-256 "This is HASH-SHA3-256 by the Hash libary." -salt "This is HASH-SHA3-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_384() {
	./aisio -hash -sha3-384 "This is HASH-SHA3-384 by the Hash libary." -salt "This is HASH-SHA3-384 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_512() {
	./aisio -hash -sha3-512 "This is HASH-SHA3-512 by the Hash libary." -salt "This is HASH-SHA3-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_KE_128() {
	./aisio -hash -sha3-ke-128 "This is HASH-SHA3-KE-128 by the Hash libary." -salt "This is HASH-SHA3-KE-128 Salt by the Hash." -length 16 -fir -mid -las -out "$BASE"
} 

HASH_SHA3_KE_256() {
	./aisio -hash -sha3-ke-256 "This is HASH-SHA3-KE-256 by the Hash libary." -salt "This is HASH-SHA3-KE-256 Salt by the Hash." -length 32 -fir -mid -las -out "$BASE"
} 

HASH_BLAKE2S_256() {
	./aisio -hash -blake2s-256 "This is HASH-BLAKE2S-256 by the Hash libary." -salt "This is HASH-BLAKE2S-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_BLAKE2B_512() {
	./aisio -hash -blake2b-512 "This is HASH-BLAKE2B-512 by the Hash libary." -salt "This is HASH-BLAKE2B-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SM3() {
	./aisio -hash -sm3 "This is HASH-SM3 by the Hash libary." -salt "This is HASH-SM3 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_RIPEMD160() {
	./aisio -hash -ripemd160 "This is HASH-SM3 by the Hash libary." -salt "This is HASH-RIPEMD160 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

RSA_Generate_Parameters() {
	./aisio -rsa -generate -param 2048 -out "$BASE"
}

RSA_Generate_Keys_PEM() {
	./aisio -rsa -generate -key 2048 -out -pem
}

RSA_Generate_Keys_DER() {
	./aisio -rsa -generate -key 2048 -out -der "$BASE"
}

RSA_Export_Parameters() {
	./aisio -rsa -export -param -pub -der "$BASE" "$RSA_DER_PUB" -priv -der "$BASE" "$RSA_DER_PRIV" -out "$BASE"
}

RSA_Export_Keys_PEM() {
	./aisio -rsa -export -key -param "$BASE" -n "$N" -e "$E" -d "$D" -p "$P" -q "$Q" -dp "$DP" -dq "$DQ" -qi "$QI" -out -pem
}

RSA_Export_Keys_DER() {
	./aisio -rsa -export -key -param "$BASE" -n "$N" -e "$E" -d "$D" -p "$P" -q "$Q" -dp "$DP" -dq "$DQ" -qi "$QI" -out -der "$BASE"
}

RSA_Extract_Public_Key_PEM() {
	./aisio -rsa -extract -priv -pem "$RSA_PEM_PRIV" -out -pem
}

RSA_Extract_Public_Key_DER() {
	./aisio -rsa -extract -priv -der "$BASE" "$RSA_DER_PRIV" -out -der "$BASE"
}

RSA_Check_Keys_PEM() {
	./aisio -rsa -check -pub -pem "$RSA_PEM_PUB"
	./aisio -rsa -check -priv -pem "$RSA_PEM_PRIV"
}

RSA_Check_Keys_DER() {
	./aisio -rsa -check -pub -der "$BASE" "$RSA_DER_PUB"
	./aisio -rsa -check -priv -der "$BASE" "$RSA_DER_PRIV"
}

RSA_Cryption_PEM() {
	if [[ $encoder == "-e" ]]; then
		./aisio -rsa -encrypt -pub -pem "$RSA_PEM_PUB" -plain-text "This is Encryption/Decryption by RSA PEM 2048 Key." -out "$BASE"
	elif [[ $encoder == "-d"  ]]; then
		./aisio -rsa -decrypt -priv -pem "$RSA_PEM_PRIV" -cipher-text "$BASE" "829E60D6D00A3A2F30AFDA987D7665F235A5DD6B8CF7251506C3C714B0BD47E0A62D3ACE880067F7691513EC4588C355E4839374C4FA4CF0EB26236F307766D9141B9863412B8B141C9923F8ADC1C63C15EF028812E9F993F2134FFC0B29B49A65780C7646EDC3CECA50460868EFF8A189016076D9FB048DED4416247B053A164D9B24FF1E54B9DFEB9D55515F34314A41B8AED3FFA2492A790865CD789F5AABCA030FA43A4A0275DF330E5F68342158179C37A5DEFB21833FA5248AB79BB21B7D18CCAE1A6EFEDC91C95A0147FDAC390537526BFD8515C72EA9D1818AE921D284B533A6329E0D6B45CDDF39386952C31CB859993A28722EB71E12F7B605C698"
	fi
}

RSA_Cryption_DER() {
	if [[ $encoder == "-e" ]]; then
		./aisio -rsa -encrypt -pub -der "$BASE" "$RSA_DER_PUB" -plain-text "This is Encryption/Decryption by RSA DER 2048 Key." -out "$BASE"
	elif [[ $encoder == "-d"  ]]; then
		./aisio -rsa -decrypt -priv -der "$BASE" "$RSA_DER_PRIV" -cipher-text "$BASE" "724E1EAF36ECC5127CE7FB9FA975EF02493A77A712C8FD3F9009320499F949CC1ED827B2551CB6361A657FCCB106CA4F4858B5C544790A04573E900CC53F9E479EDE9C6C9A93C40034DFB4652F4A25F9896D82FD99B1D0CB44FFFF44D64CFB6E20855AC6A4E062853310C7AE8764F1A68788F3D43E634D3C10880552F1B1E5E060C23E6F5DE82E0BD2C59642128A66015E33B644323F4E384B7A34169036F57746D74DBA37ACB06438CDB8085AB50FB1C482FC2CCDDA04FD74799B2CA44B132E7A292604E327E925A40E04DE2AB52854181F35C65792055504C671992B0B1EA9BDCFBC8591B1F08781864AEB80E89617EBC1FEE8996D22F7C42FC3B93AD8585D"
	fi
}

RSA_Digital_PEM() {
	if [[ $encoder == "-s" ]]; then
		./aisio -rsa -signed -priv -pem "$RSA_PEM_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -out "$BASE"
	elif [[ $encoder == "-v"  ]]; then
		./aisio -rsa -verify -pub -pem "$RSA_PEM_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA PEM 2048 Key." -signature "$BASE" "18DEF0246E638E737074FFF2351185B9B0596923867E79365EE0A78C86D8457E9A164FC55DFBE1656E4691F121FEA751A4A9BD90BA5E5648CB5EFD4E961DE25B284F7ABF94D7510B9DCF0ADE7725EB465207B0EB9F11A4DDEF3E1E9AD6C9D3303E2D597BCD0E32326DD88F98FB6D15A5488B17947155A5AB8F2EF2C1B224ECD5D626F5826E33713D07EBC5F99CD5366D8DD24356D427C205B844F9357F4880093E494C1A4B942D2A6D4DC1FD83970E44D3B5DAD4382F9494559410E865DB290AFE83BC4A74A5EB7AF6C6D3F6F04CA39028ACE83404667766D8E92EEF1C5FD4984010B8FDDD5D2191A076854D61FEA8382D356C53A4B3DFA8264C8FD46806CC0F"
	fi
}

RSA_Digital_DER() {
	if [[ $encoder == "-s" ]]; then
		./aisio -rsa -signed -priv -der "$BASE" "$RSA_DER_PRIV" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -out "$BASE"
	elif [[ $encoder == "-v"  ]]; then
		./aisio -rsa -verify -pub -der "$BASE" "$RSA_DER_PUB" -hash -sha3-512 -data "This is Signed/Verify Data by RSA DER 2048 Key." -signature "$BASE" "5DAB236FD6B3E8680C825693391719507B2B9219488EA59E9DE38A0A334A5C592E633CE9E3BA1A90F54FA809E5B52239A6103B73027C1A8DC2D06CC2A79E67822E3CE858C962867BB15C6AA51F84A050E2AD3DE86A3F6D720FDE01152B344CE3BFC4A4A6557F3BD7BA507C1CE3F4AB231E36845BC496093137D90D51397521AEC9A05CA7C2A75EE9DCCA62D09051D0C10037353C68869C09D9B8B5FAE438D9AA0108473AC72F6F073347A71AB425D2EE168DD90A995665768F3386A2AADCC1F3C245C14E19E239ADB52B5B892E10930283532899F8EC92D54A57FE628514395CEF769CAD5DEB657CB9CB6F930AF863B17F4D4EF89C0DABCB36487B8B6A477B14"
	fi
}
