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

start_time=$(date +%s%N)

if [ "$#" -eq 0 ]; then
	Usage
fi

while [[ "$#" -gt 0 ]]; do
	case "$1" in
		-w|-a|-i|-r|-id|-rm|-rs)
			operation="$1"
			shift
			;;
		-b16|-b32|-b64|-b85)
			operation="$1"
			shift
			;;
		-aes|-des|-hash)
			operation="$1"
			shift
			;;
		-ctr|-cbc|-cfb|-ofb|-ecb|-gcm|-ccm|-xts|-ocb|-wrap)
			mode="$1"
			shift
			;;
		-md5|-md5-sha1|-sha1|-sha2-224|-sha2-256|-sha2-384|-sha2-512|-sha2-512-224|-sha2-512-256|-sha3-224|-sha3-256|-sha3-384|-sha3-512|-sha3-ke-128|-sha3-ke-256|-blake2s-256|-blake2b-512|-sm3|-ripemd160)
			mode="$1"
			shift
			;;
		-e|-d)
			encoder="$1"
			shift
			;;
		-f)
			file="$2"
			shift 2
			;;
		-n)
			iterations="$2"
			shift 2
			;;
		*)
			Usage
			;;
	esac
done
index_list=$(seq 0 $((iterations-1)) | tr '\n' ' ')

if [ -z "$operation" ]; then
	echo "Error: Operation is required."
	Usage
fi

for ((i=1; i<=iterations; i++)); do
	echo "Iteration $i/$iterations"
	case "$operation" in
		-w)
			BinaryWrite
			;;
		-a)
			BinaryAppend
			;;
		-i)
			BinaryInsert
			;;
		-r)
			BinaryReadAll
			;;
		-id)
			BinaryIndexes
			;;
		-rm)
			BinaryRemove
			;;
		-rs)
			BinaryRemoveIndex
			break
			;;
		-b16) 
			BASE_16
			;;
		-b32) 
			BASE_32
			;;
		-b64) 
			BASE_64
			;;
		-b85) 
			BASE_85
			;;
		-aes)
			case "$mode" in
				-ctr)
					AES_CTR
					;;
				-cbc)	
					AES_CBC
					;;
				-cfb)	
					AES_CFB
					;;
				-ofb)	
					AES_OFB
					;;
				-ecb)	
					AES_ECB
					;;
				-gcm)	
					AES_GCM
					;;
				-ccm)	
					AES_CCM
					;;
				-xts)	
					AES_XTS
					;;
				-ocb)	
					AES_OCB
					;;
				-wrap)	
					AES_WRAP
					;;
				*)
					;;
			esac
			;;
		-des)
			case "$mode" in
				-cbc)
					DES_CBC
					;;
				-cfb)
					DES_CFB
					;;
				-ofb)
					DES_OFB
					;;
				-ecb)
					DES_ECB
					;;
				-wrap)
					DES_WRAP
					;;
				*)
					;;
			esac
			;;
		-hash)
			case "$mode" in
				-md5)
					HASH_MD5
					;;
				-md5-sha1)
					HASH_MD5_SHA1
					;;
				-sha1)
					HASH_SHA1
					;;
				-sha2-224)
					HASH_SHA2_224
					;;
				-sha2-256)
					HASH_SHA2_256
					;;
				-sha2-384)
					HASH_SHA2_384
					;;
				-sha2-512)
					HASH_SHA2_512
					;;
				-sha2-512-224)
					HASH_SHA2_512_224
					;;
				-sha2-512-256)
					HASH_SHA2_512_256
					;;
				-sha3-224)
					HASH_SHA3_224
					;;
				-sha3-256)
					HASH_SHA3_256
					;;
				-sha3-384)
					HASH_SHA3_384
					;;
				-sha3-512)
					HASH_SHA3_512
					;;
				-sha3-ke-128)
					HASH_SHA3_KE_128
					;;
				-blake2s-256)
					HASH_BLAKE2S_256
					;;
				-blake2b-512)
					HASH_BLAKE2B_512
					;;
				-sm3)
					HASH_SM3
					;;
				-ripemd160)
					HASH_RIPEMD160
					;;
			esac
			;;
		*)
			Usage
			;;
	esac
done
end_time=$(date +%s%N)
elapsed_time=$((end_time - start_time))
elapsed_time_sec=$(echo "scale=6; $elapsed_time / 1000000000" | bc)
printf "Execution time: %.6f seconds\n" "$elapsed_time_sec"
