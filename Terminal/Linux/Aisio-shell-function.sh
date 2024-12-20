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
	exit 1
}

BinaryWrite() {
	echo "Ais Binary IO Write..."
	./aisio --write "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
}

BinaryAppend() {
	echo "Ais Binary IO Append..."
	./aisio --append "$file" -bool true -byte 255 -sbyte -128 -short 32767 -ushort 65535 -int 2147483647 -uint 4294967295 -long 9223372036854775807 -ulong 18446744073709551615 -float 3.1415927 -double 3.141592653589793 -bytes "This is Ais.IO Function Byte Array." -string "This is Ais.IO Function String."
}

BinaryInsert() {
	echo "Ais Binary IO Insert..."
	./aisio --insert "$file" -bool true 0 -byte 255 0 -sbyte -128 0 -short 32767 0 -ushort 65535 0 -int 2147483647 0 -uint 4294967295 0 -long 9223372036854775807 0 -ulong 18446744073709551615 0 -float 3.1415927 0 -double 3.141592653589793 0 -bytes "This is Ais.IO Function Byte Array." 0 -string "This is Ais.IO Function String." 0
}

BinaryReadAll() {
	echo "Ais Binary IO Read all..."
	./aisio --read-all "$file"
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
	./aisio --remove-index "$file" "$index_list"
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
	./aisio -hash -md5 -in "This is HASH-MD5 by the Hash libary." -salt "This is HASH-MD5 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_MD5_SHA1() {
	./aisio -hash -md5-sha1 -in "This is HASH-MD5-SHA1 by the Hash libary." -salt "This is HASH-MD5-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA1() {
	./aisio -hash -sha1 -in "This is HASH-SHA1 by the Hash libary." -salt "This is HASH-SHA1 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_224() {
	./aisio -hash -sha2-224 -in "This is HASH-SHA2-224 by the Hash libary." -salt "This is HASH-SHA2-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_256() {
	./aisio -hash -sha2-256 -in "This is HASH-SHA2-256 by the Hash libary." -salt "This is HASH-SHA2-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_384() {
	./aisio -hash -sha2-384 -in "This is HASH-SHA2-384 by the Hash libary." -salt "This is HASH-SHA2-384 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512() {
	./aisio -hash -sha2-512 -in "This is HASH-SHA2-512 by the Hash libary." -salt "This is HASH-SHA2-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512_224() {
	./aisio -hash -sha2-512-224 -in "This is HASH-SHA2-512-224 by the Hash libary." -salt "This is HASH-SHA2-512-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA2_512_256() {
	./aisio -hash -sha2-512-256 -in "This is HASH-SHA2-512-256 by the Hash libary." -salt "This is HASH-SHA2-512-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_224() {
	./aisio -hash -sha3-224 -in "This is HASH-SHA3-224 by the Hash libary." -salt "This is HASH-SHA3-224 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_256() {
	./aisio -hash -sha3-256 -in "This is HASH-SHA3-256 by the Hash libary." -salt "This is HASH-SHA3-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_384() {
	./aisio -hash -sha3-384 -in "This is HASH-SHA3-384 by the Hash libary." -salt "This is HASH-SHA3-384 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_512() {
	./aisio -hash -sha3-512 -in "This is HASH-SHA3-512 by the Hash libary." -salt "This is HASH-SHA3-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SHA3_KE_128() {
	./aisio -hash -sha3-ke-128 -in "This is HASH-SHA3-KE-128 by the Hash libary." -salt "This is HASH-SHA3-KE-128 Salt by the Hash." -length 16 -fir -mid -las -out "$BASE"
} 

HASH_SHA3_KE_256() {
	./aisio -hash -sha3-ke-256 -in "This is HASH-SHA3-KE-256 by the Hash libary." -salt "This is HASH-SHA3-KE-256 Salt by the Hash." -length 32 -fir -mid -las -out "$BASE"
} 

HASH_BLAKE2S_256() {
	./aisio -hash -blake2s-256 -in "This is HASH-BLAKE2S-256 by the Hash libary." -salt "This is HASH-BLAKE2S-256 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_BLAKE2B_512() {
	./aisio -hash -blake2b-512 -in "This is HASH-BLAKE2B-512 by the Hash libary." -salt "This is HASH-BLAKE2B-512 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_SM3() {
	./aisio -hash -sm3 -in "This is HASH-SM3 by the Hash libary." -salt "This is HASH-SM3 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

HASH_RIPEMD160() {
	./aisio -hash -sm3 -in "This is HASH-SM3 by the Hash libary." -salt "This is HASH-RIPEMD160 Salt by the Hash." -fir -mid -las -out "$BASE"
} 

