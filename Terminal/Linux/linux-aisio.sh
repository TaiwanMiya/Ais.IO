#!/bin/bash
source ./Aisio-shell-function.sh

operation=""
mode=""
asym_format=""
file="test.bin"
iterations=1
encoder="-e"
extract_type=""

start_time=$(date +%s%N)

if [ "$#" -eq 0 ]; then
	Usage
fi

while [[ "$#" -gt 0 ]]; do
	case "$1" in
		-w|-a|-i|-r|-id|-rm|-rs|-ri)
			operation="$1"
			shift
			;;
		-b10|-b16|-b32|-b58|-b62|-b64|-b85|-b91)
			operation="$1"
			shift
			;;
		-imp)
			operation="$1"
			shift
			;;
		-gen)
			if [ -z "$operation" ]; then
				operation="$1"
			else
				if [[ "$operation" == "-rsa" || "$operation" == "-dsa" ]]; then
					mode="$1"
				else
					operation="$1"
				fi
			fi
			shift
			;;
		-exp|-ext|-chk)
			mode="$1"
			shift
			;;
		-aes|-des|-hash|-rsa|-dsa)
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
		-pem|-der)
			asym_format="$1"
			shift
			;;
		-param|-key)
			if [ "$mode" == "-ext" ]; then
				extract_type="$1"
			else
				asym_format="$1"
			fi
			shift
			;;
		-e|-d)
			if [ -z "$operation" ]; then
				encoder="$1"
			else
				if [ "$operation" == "-rsa" ]; then
					mode="-crypt"
					encoder="$1"
				else
					encoder="$1"
				fi
			fi
			shift
			;;
		-s|-v)
			if [ -z "$operation" ]; then
				encoder="$1"
			else
				if [[ "$operation" == "-rsa" || "$operation" == "-dsa" ]]; then
					mode="-digital"
					encoder="$1"
				else
					encoder="$1"
				fi
			fi
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
		-ri)
			BinaryReadIndex
			break
			;;
		-b10) 
			BASE_10
			;;	
		-b16) 
			BASE_16
			;;
		-b32) 
			BASE_32
			;;
		-b58) 
			BASE_58
			;;
		-b62) 
			BASE_62
			;;		
		-b64) 
			BASE_64
			;;
		-b85) 
			BASE_85
			;;
		-b91) 
			BASE_91
			;;	
		-gen)
			Generate
			;;
		-imp)
			Import
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
				-sha3-ke-256)
					HASH_SHA3_KE_256
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
		-rsa)
			case "$mode" in
				-gen)
					case "$asym_format" in
						-pem)
							RSA_Generate_Keys_PEM
							;;
						-der)

							RSA_Generate_Keys_DER
							;;
						-param)
							RSA_Generate_Parameters
							;;
					esac
					;;
				-exp)
					case "$asym_format" in
						-pem)
							RSA_Export_Keys_PEM	
							;;
						-der)
							RSA_Export_Keys_DER
							;;
						-param)
							RSA_Export_Parameters
							;;
					esac
					;;
				-ext)
					case "$asym_format" in
						-pem)
							RSA_Extract_Public_Key_PEM	
							;;
						-der)
							RSA_Extract_Public_Key_DER
							;;
					esac
					;;
				-chk)
					case "$asym_format" in
						-pem)
							RSA_Check_Keys_PEM
							;;
						-der)
							RSA_Check_Keys_DER
							;;
					esac
					;;
				-crypt)
					case "$asym_format" in
						-pem)
							RSA_Cryption_PEM
							;;
						-der)
							RSA_Cryption_DER
							;;
					esac
					;;
				-digital)
					case "$asym_format" in
						-pem)
							RSA_Digital_PEM
							;;
						-der)
							RSA_Digital_DER
							;;
					esac
					;;
			esac
			;;
		-dsa)
			case "$mode" in
				-gen)
					case "$asym_format" in
						-pem)
							DSA_Generate_Keys_PEM
							;;
						-der)

							DSA_Generate_Keys_DER
							;;
						-param)
							DSA_Generate_Parameters
							;;
					esac
					;;
				-exp)
					case "$asym_format" in
						-pem)
							DSA_Export_Keys_PEM	
							;;
						-der)
							DSA_Export_Keys_DER
							;;
						-param)
							DSA_Export_Parameters
							;;
					esac
					;;
				-ext)
					case "$extract_type" in
						-param)
							case "$asym_format" in
								-pem)
									DSA_Extract_Parameters_PEM	
									;;
								-der)
									DSA_Extract_Parameters_DER
									;;
							esac
							;;
						-key)
							case "$asym_format" in
								-pem)
									DSA_Extract_Keys_PEM	
									;;
								-der)
									DSA_Extract_Keys_DER
									;;
							esac
							;;
						*)
							case "$asym_format" in
								-pem)
									DSA_Extract_Public_Key_PEM	
									;;
								-der)
									DSA_Extract_Public_Key_DER
									;;
							esac
							;;
					esac
					;;
				-chk)
					case "$asym_format" in
						-pem)
							DSA_Check_Keys_PEM
							;;
						-der)
							DSA_Check_Keys_DER
							;;
					esac
					;;
				-digital)
					case "$asym_format" in
						-pem)
							DSA_Digital_PEM
							;;
						-der)
							DSA_Digital_DER
							;;
					esac
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
