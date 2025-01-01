#!/bin/bash
source ./Aisio-shell-function.sh

operation=""
mode=""
file="test.bin"
iterations=1
encoder="-e"


# Cryptography Settings...
BASE="-base16"

# Aes Settings...
AES_KEY="Key length must be 128, 192, 256"
AES_IV="IvMustBe128Size."
AES_TAG="TagMustBe128Size"
AES_AAD="Additional Authenticated Data (AAD) can be of any length"
AES_KEY2="Secondary Key for AES-XTS Tweak."
AES_TWEAK="SectorNumber0001"
AES_COUNTER=1

AES_GCM_TAG="73DD32019CD29E7251D17128DE27FFDD"
AES_CCM_TAG="DB9A881B8A159B079F826BD043A4F8C9"
AES_OCB_TAG="F7F64A75E6575C9093E12AB272CBF024"
AES_NONCE="Nonce12bytes"
AES_KEK="This is AES WRAP, 128, 192, 256."

# Des Settings...
DES_KEY="Key Must Be 128,192 Size"
DES_IV="Iv8Bytes"
DES_KEK="WRAP Key 128 192 by DES."

# Choice Settings...
mode=$(whiptail --title "Encode/Decode or Encrypt/Decrypt" --menu "Choice:" 15 40 2 \
    "1" "Encode or Encrypt" \
    "2" "Decode or Decrypt" 3>&1 1>&2 2>&3)

if [[ $mode == "1" ]]; then
    encoder="-e"
elif [[ $mode == "2" ]]; then
    encoder="-d"
else
    echo "Invalid option!"
    exit 1
fi

iterations=$(whiptail --title "Set Loop Count" --inputbox "Choice your loop count (Default Count 1):" 10 40 1 3>&1 1>&2 2>&3)
if ! [[ $iterations =~ ^[0-9]+$ ]]; then
    echo "Invalid option!"
    exit 1
fi

CHOICE=$(whiptail --title "Aisio Shell Function Menu" --menu "Choice function:" 25 60 16 \
	"01" "Binary IO Write" \
	"02" "Binary IO Append" \
	"03" "Binary IO Insert" \
	"04" "Binary IO Read All" \
	"05" "Binary IO Indexes" \
	"06" "Binary IO Remove" \
	"07" "Binary IO Remove Index" \
	"08" "Base 16 Encode/Decode" \
	"09" "Base 32 Encode/Decode" \
	"10" "Base 64 Encode/Decode" \
	"11" "Base 85 Encode/Decode" \
	"12" "Aes ctr Encrypt/Decrypt" \
	"13" "Aes cbc Encrypt/Decrypt" \
	"14" "Aes cfb Encrypt/Decrypt" \
	"15" "Aes ofb Encrypt/Decrypt" \
	"16" "Aes ecb Encrypt/Decrypt" \
	"17" "Aes gcm Encrypt/Decrypt" \
	"18" "Aes ccm Encrypt/Decrypt" \
	"19" "Aes xts Encrypt/Decrypt" \
	"20" "Aes ocb Encrypt/Decrypt" \
	"21" "Aes wrap Encrypt/Decrypt" \
	"22" "Des cbc Encrypt/Decrypt" \
	"23" "Des cfb Encrypt/Decrypt" \
	"24" "Des ofb Encrypt/Decrypt" \
	"25" "Des ecb Encrypt/Decrypt" \
	"26" "Des wrap Encrypt/Decrypt" \
	"27" "Hash MD5 Calculation"\
	"28" "Hash MD5 SHA1 Calculation"\
	"29" "Hash SHA1 Calculation"\
	"30" "Hash SHA2 224 Calculation"\
	"31" "Hash SHA2 256 Calculation"\
	"32" "Hash SHA2 384 Calculation"\
	"33" "Hash SHA2 512 Calculation"\
	"34" "Hash SHA2 512 224 Calculation"\
	"35" "Hash SHA2 512 256 Calculation"\
	"36" "Hash SHA3 224 Calculation"\
	"37" "Hash SHA3 256 Calculation"\
	"38" "Hash SHA3 384 Calculation"\
	"39" "Hash SHA3 512 Calculation"\
	"40" "Hash SHA3 KE 128 Calculation"\
	"41" "Hash SHA3 KE 256 Calculation"\
	"42" "Hash BLAKE2S 256 Calculation"\
	"43" "Hash BLAKE2B 512 Calculation"\
	"44" "Hash SM3 Calculation"\
	"45" "Hash RIPEMD160 Calculation"\
        "46" "Exit" 3>&1 1>&2 2>&3)

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
			;;
		08)
			BASE_16
			;;
		09)
			BASE_32
			;;
		10)
			BASE_64
			;;
		11)
			BASE_85
			;;
		12)
			AES_CTR
			;;
		13)
			AES_CBC
			;;
		14)
			AES_CFB
			;;
		15)
			AES_OFB
			;;
		16)
			AES_ECB
			;;
		17)
			AES_GCM
			;;
		18)
			AES_CCM
			;;
		19)
			AES_XTS
			;;
		20)
			AES_OCB
			;;
		21)
			AES_WRAP
			;;
		22)
			DES_CBC
			;;
		23)
			DES_CFB
			;;
		24)
			DES_OFB
			;;
		25)
			DES_ECB
			;;
		26)
			DES_WRAP
			;;
		27)
			HASH_MD5
			;;
		28)
			HASH_MD5_SHA1
			;;
		29)
			HASH_SHA1
			;;
		30)
			HASH_SHA2_224
			;;
		31)
			HASH_SHA2_256
			;;
		32)
			HASH_SHA2_384
			;;
		33)
			HASH_SHA2_512
			;;
		34)
			HASH_SHA2_512_224
			;;
		35)
			HASH_SHA2_512_256
			;;
		36)
			HASH_SHA3_224
			;;
		37)
			HASH_SHA3_256
			;;
		38)
			HASH_SHA3_384
			;;
		39)
			HASH_SHA3_512
			;;
		40)
			HASH_SHA3_KE_128
			;;
		41)
			HASH_SHA3_KE_256
			;;
		42)
			HASH_BLAKE2S_256
			;;
		43)
			HASH_BLAKE2B_512
			;;
		44)
			HASH_SM3
			;;
		45)
			HASH_RIPEMD160
			;;
		46)
			echo "Exit..."
			exit 0
			;;
		*)
			echo "Invalid option!"
			exit 1
			;;
	esac
done
end_time=$(date +%s%N)
elapsed_time=$((end_time - start_time))
elapsed_time_sec=$(echo "scale=6; $elapsed_time / 1000000000" | bc)
printf "Execution time: %.6f seconds\n" "$elapsed_time_sec"
