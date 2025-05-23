#!/bin/bash
source ./Aisio-shell-function.sh

mode=""
iterations=1
encoder="-e"

# Choice Settings...
mode=$(whiptail --title "Encode/Decode or Encrypt/Decrypt" --menu "Choice:" 15 40 4 \
	"1" "Encode or Encrypt" \
	"2" "Decode or Decrypt" \
	"3" "Signed" \
	"4" "Verify" \
	3>&1 1>&2 2>&3)

case $mode in
	1)
		encoder="-e"
		;;
	2)
		encoder="-d"
		;;
	3)
		encoder='-s'
		;;
	4)
		encoder='-v'
		;;
	*)
		exit 1
		;;
esac

iterations=$(whiptail --title "Set Loop Count" --inputbox "Choice your loop count (Default Count 1):" 10 40 1 3>&1 1>&2 2>&3)
if ! [[ $iterations =~ ^[0-9]+$ ]]; then
	exit 1
fi
index_list=$(seq 0 $((iterations-1)) | tr '\n' ' ')

CHOICE=$(whiptail --title "Aisio Shell Function Menu" --menu "Choice function:" 25 60 16 \
	"01" "Binary IO Write" \
	"02" "Binary IO Append" \
	"03" "Binary IO Insert" \
	"04" "Binary IO Read All" \
	"05" "Binary IO Indexes" \
	"06" "Binary IO Remove" \
	"07" "Binary IO Remove Index" \
	"08" "Binary IO Read Index" \
	"09" "Base 10 Encode/Decode" \
	"10" "Base 16 Encode/Decode" \
	"11" "Base 32 Encode/Decode" \
	"12" "Base 58 Encode/Decode" \
	"13" "Base 62 Encode/Decode" \
	"14" "Base 64 Encode/Decode" \
	"15" "Base 85 Encode/Decode" \
	"16" "Base 91 Encode/Decode" \
	"17" "Generate Random Key/Bytes" \
	"18" "Import Key/Bytes" \
	"19" "Aes ctr Encrypt/Decrypt" \
	"20" "Aes cbc Encrypt/Decrypt" \
	"21" "Aes cfb Encrypt/Decrypt" \
	"22" "Aes ofb Encrypt/Decrypt" \
	"23" "Aes ecb Encrypt/Decrypt" \
	"24" "Aes gcm Encrypt/Decrypt" \
	"25" "Aes ccm Encrypt/Decrypt" \
	"26" "Aes xts Encrypt/Decrypt" \
	"27" "Aes ocb Encrypt/Decrypt" \
	"28" "Aes wrap Encrypt/Decrypt" \
	"29" "Des cbc Encrypt/Decrypt" \
	"30" "Des cfb Encrypt/Decrypt" \
	"31" "Des ofb Encrypt/Decrypt" \
	"32" "Des ecb Encrypt/Decrypt" \
	"33" "Des wrap Encrypt/Decrypt" \
	"34" "Hash MD5 Calculation"\
	"35" "Hash MD5 SHA1 Calculation"\
	"36" "Hash SHA1 Calculation"\
	"37" "Hash SHA2 224 Calculation"\
	"38" "Hash SHA2 256 Calculation"\
	"39" "Hash SHA2 384 Calculation"\
	"40" "Hash SHA2 512 Calculation"\
	"41" "Hash SHA2 512 224 Calculation"\
	"42" "Hash SHA2 512 256 Calculation"\
	"43" "Hash SHA3 224 Calculation"\
	"44" "Hash SHA3 256 Calculation"\
	"45" "Hash SHA3 384 Calculation"\
	"46" "Hash SHA3 512 Calculation"\
	"47" "Hash SHA3 KE 128 Calculation"\
	"48" "Hash SHA3 KE 256 Calculation"\
	"49" "Hash BLAKE2S 256 Calculation"\
	"50" "Hash BLAKE2B 512 Calculation"\
	"51" "Hash SM3 Calculation"\
	"52" "Hash RIPEMD160 Calculation"\
	"53" "Dsa Generate Parameters" \
	"54" "Dsa Generate PEM Keys" \
	"55" "Dsa Generate DER Keys" \
	"56" "Dsa Export Parameters" \
	"57" "Dsa Export PEM Keys" \
	"58" "Dsa Export DER Keys" \
	"59" "Dsa Extract PEM Public Key" \
	"60" "Dsa Extract DER Public Key" \
	"61" "Dsa Extract PEM Parameters" \
	"62" "Dsa Extract DER Parameters" \
	"63" "Dsa Extract PEM Keys" \
	"64" "Dsa Extract DER Keys" \
	"65" "Dsa Check PEM Keys" \
	"66" "Dsa Check DER Keys" \
	"67" "Dsa Digital PEM" \
	"68" "Dsa Digital DER" \
	"69" "Rsa Generate Parameters" \
	"70" "Rsa Generate PEM Keys" \
	"71" "Rsa Generate DER Keys" \
	"72" "Rsa Export Parameters" \
	"73" "Rsa Export PEM Keys" \
	"74" "Rsa Export DER Keys" \
	"75" "Rsa Extract PEM Public Key" \
	"76" "Rsa Extract DER Public Key" \
	"77" "Rsa Check PEM Keys" \
	"78" "Rsa Check DER Keys" \
	"79" "Rsa Cryption PEM" \
	"80" "Rsa Cryption DER" \
	"81" "Rsa Digital PEM" \
	"82" "Rsa Digital DER" \
	"83" "Exit" 3>&1 1>&2 2>&3)

start_time=$(date +%s%N)
for ((i=1; i<=iterations; i++)); do
	echo "Iteration $i/$iterations"
	case $CHOICE in
		01)
			BinaryWrite
			;;
		02)
			BinaryAppend
			;;
		03)
			BinaryInsert
			;;
		04)
			BinaryReadAll
			;;
		05)
			BinaryIndexes
			;;
		06)
			BinaryRemove
			;;
		07)
			BinaryRemoveIndex
			break
			;;
		08)
			BinaryReadIndex
			break
			;;
		09)
			BASE_10
			;;
		10)
			BASE_16
			;;
		11)
			BASE_32
			;;
		12)
			BASE_58
			;;
		13)
			BASE_62
			;;	
		14)
			BASE_64
			;;
		15)
			BASE_85
			;;
		16)
			BASE_91
			;;	
		17)
			Generate
			;;
		18)
			Import
			;;
		19)
			AES_CTR
			;;
		20)
			AES_CBC
			;;
		21)
			AES_CFB
			;;
		22)
			AES_OFB
			;;
		23)
			AES_ECB
			;;
		24)
			AES_GCM
			;;
		25)
			AES_CCM
			;;
		26)
			AES_XTS
			;;
		27)
			AES_OCB
			;;
		28)
			AES_WRAP
			;;
		29)
			DES_CBC
			;;
		30)
			DES_CFB
			;;
		31)
			DES_OFB
			;;
		32)
			DES_ECB
			;;
		33)
			DES_WRAP
			;;
		34)
			HASH_MD5
			;;
		35)
			HASH_MD5_SHA1
			;;
		36)
			HASH_SHA1
			;;
		37)
			HASH_SHA2_224
			;;
		38)
			HASH_SHA2_256
			;;
		39)
			HASH_SHA2_384
			;;
		40)
			HASH_SHA2_512
			;;
		41)
			HASH_SHA2_512_224
			;;
		42)
			HASH_SHA2_512_256
			;;
		43)
			HASH_SHA3_224
			;;
		44)
			HASH_SHA3_256
			;;
		45)
			HASH_SHA3_384
			;;
		46)
			HASH_SHA3_512
			;;
		47)
			HASH_SHA3_KE_128
			;;
		48)
			HASH_SHA3_KE_256
			;;
		49)
			HASH_BLAKE2S_256
			;;
		50)
			HASH_BLAKE2B_512
			;;
		51)
			HASH_SM3
			;;
		52)
			HASH_RIPEMD160
			;;
		53)
			DSA_Generate_Parameters
			;;
		54)
			DSA_Generate_Keys_PEM
			;;
		55)
			DSA_Generate_Keys_DER
			;;
		56)
			DSA_Export_Parameters
			;;
		57)
			DSA_Export_Keys_PEM
			;;
		58)
			DSA_Export_Keys_DER
			;;
		59)
			DSA_Extract_Public_Key_PEM
			;;
		60)
			DSA_Extract_Public_Key_DER
			;;
		61)
			DSA_Extract_Parameters_PEM
			;;
		62)
			DSA_Extract_Parameters_DER
			;;
		63)
			DSA_Extract_Keys_PEM
			;;
		64)
			DSA_Extract_Keys_DER
			;;
		65)
			DSA_Check_Keys_PEM
			;;
		66)
			DSA_Check_Keys_DER
			;;
		67)
			DSA_Digital_PEM
			;;
		68)
			DSA_Digital_DER
			;;
		69)
			RSA_Generate_Parameters
			;;
		70)
			RSA_Generate_Keys_PEM
			;;
		71)
			RSA_Generate_Keys_DER
			;;
		72)
			RSA_Export_Parameters
			;;
		73)
			RSA_Export_Keys_PEM
			;;
		74)
			RSA_Export_Keys_DER
			;;
		75)
			RSA_Extract_Public_Key_PEM
			;;
		76)
			RSA_Extract_Public_Key_DER
			;;
		77)
			RSA_Check_Keys_PEM
			;;
		78)
			RSA_Check_Keys_DER
			;;
		79)
			RSA_Cryption_PEM
			;;
		80)
			RSA_Cryption_DER
			;;
		81)
			RSA_Digital_PEM
			;;
		82)
			RSA_Digital_DER
			;;
		83)
			echo "Exit..."
			exit 0
			;;
		*)
			exit 1
			;;
	esac
done
end_time=$(date +%s%N)
elapsed_time=$((end_time - start_time))
elapsed_time_sec=$(echo "scale=6; $elapsed_time / 1000000000" | bc)
printf "Execution time: %.6f seconds\n" "$elapsed_time_sec"
