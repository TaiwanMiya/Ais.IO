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
	"12" "Generate Random Key/Bytes" \
	"13" "Import Key/Bytes" \
	"14" "Aes ctr Encrypt/Decrypt" \
	"15" "Aes cbc Encrypt/Decrypt" \
	"16" "Aes cfb Encrypt/Decrypt" \
	"17" "Aes ofb Encrypt/Decrypt" \
	"18" "Aes ecb Encrypt/Decrypt" \
	"19" "Aes gcm Encrypt/Decrypt" \
	"20" "Aes ccm Encrypt/Decrypt" \
	"21" "Aes xts Encrypt/Decrypt" \
	"22" "Aes ocb Encrypt/Decrypt" \
	"23" "Aes wrap Encrypt/Decrypt" \
	"24" "Des cbc Encrypt/Decrypt" \
	"25" "Des cfb Encrypt/Decrypt" \
	"26" "Des ofb Encrypt/Decrypt" \
	"27" "Des ecb Encrypt/Decrypt" \
	"28" "Des wrap Encrypt/Decrypt" \
	"29" "Hash MD5 Calculation"\
	"30" "Hash MD5 SHA1 Calculation"\
	"31" "Hash SHA1 Calculation"\
	"32" "Hash SHA2 224 Calculation"\
	"33" "Hash SHA2 256 Calculation"\
	"34" "Hash SHA2 384 Calculation"\
	"35" "Hash SHA2 512 Calculation"\
	"36" "Hash SHA2 512 224 Calculation"\
	"37" "Hash SHA2 512 256 Calculation"\
	"38" "Hash SHA3 224 Calculation"\
	"39" "Hash SHA3 256 Calculation"\
	"40" "Hash SHA3 384 Calculation"\
	"41" "Hash SHA3 512 Calculation"\
	"42" "Hash SHA3 KE 128 Calculation"\
	"43" "Hash SHA3 KE 256 Calculation"\
	"44" "Hash BLAKE2S 256 Calculation"\
	"45" "Hash BLAKE2B 512 Calculation"\
	"46" "Hash SM3 Calculation"\
	"47" "Hash RIPEMD160 Calculation"\
        "48" "Exit" 3>&1 1>&2 2>&3)

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
			Generate
			;;
		13)
			Import
			;;
		14)
			AES_CTR
			;;
		15)
			AES_CBC
			;;
		16)
			AES_CFB
			;;
		17)
			AES_OFB
			;;
		18)
			AES_ECB
			;;
		19)
			AES_GCM
			;;
		20)
			AES_CCM
			;;
		21)
			AES_XTS
			;;
		22)
			AES_OCB
			;;
		23)
			AES_WRAP
			;;
		24)
			DES_CBC
			;;
		25)
			DES_CFB
			;;
		26)
			DES_OFB
			;;
		27)
			DES_ECB
			;;
		28)
			DES_WRAP
			;;
		29)
			HASH_MD5
			;;
		30)
			HASH_MD5_SHA1
			;;
		31)
			HASH_SHA1
			;;
		32)
			HASH_SHA2_224
			;;
		33)
			HASH_SHA2_256
			;;
		34)
			HASH_SHA2_384
			;;
		35)
			HASH_SHA2_512
			;;
		36)
			HASH_SHA2_512_224
			;;
		37)
			HASH_SHA2_512_256
			;;
		38)
			HASH_SHA3_224
			;;
		39)
			HASH_SHA3_256
			;;
		40)
			HASH_SHA3_384
			;;
		41)
			HASH_SHA3_512
			;;
		42)
			HASH_SHA3_KE_128
			;;
		43)
			HASH_SHA3_KE_256
			;;
		44)
			HASH_BLAKE2S_256
			;;
		45)
			HASH_BLAKE2B_512
			;;
		46)
			HASH_SM3
			;;
		47)
			HASH_RIPEMD160
			;;
		48)
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
