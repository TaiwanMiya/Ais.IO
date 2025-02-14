#include "pch.h"
#include "HashIO.h"

const EVP_MD* GetHashCrypter(HASH_TYPE type) {
	const EVP_MD* md = NULL;
	switch (type)
	{
	case HASH_TYPE::HASH_MD5: md = EVP_md5(); break;
	case HASH_TYPE::HASH_MD5_SHA1: md = EVP_md5_sha1(); break;
	case HASH_TYPE::HASH_SHA1: md = EVP_sha1(); break;
	case HASH_TYPE::HASH_SHA2_224: md = EVP_sha224(); break;
	case HASH_TYPE::HASH_SHA2_256: md = EVP_sha256(); break;
	case HASH_TYPE::HASH_SHA2_384: md = EVP_sha384(); break;
	case HASH_TYPE::HASH_SHA2_512: md = EVP_sha512(); break;
	case HASH_TYPE::HASH_SHA2_512_224: md = EVP_sha512_224(); break;
	case HASH_TYPE::HASH_SHA2_512_256: md = EVP_sha512_256(); break;
	case HASH_TYPE::HASH_SHA3_224: md = EVP_sha3_224(); break;
	case HASH_TYPE::HASH_SHA3_256: md = EVP_sha3_256(); break;
	case HASH_TYPE::HASH_SHA3_384: md = EVP_sha3_384(); break;
	case HASH_TYPE::HASH_SHA3_512: md = EVP_sha3_512(); break;
	case HASH_TYPE::HASH_SHA3_KE_128: md = EVP_shake128(); break;
	case HASH_TYPE::HASH_SHA3_KE_256: md = EVP_shake256(); break;
	case HASH_TYPE::HASH_BLAKE2S_256: md = EVP_blake2s256(); break;
	case HASH_TYPE::HASH_BLAKE2B_512: md = EVP_blake2b512(); break;
	case HASH_TYPE::HASH_SM3: md = EVP_sm3(); break;
	case HASH_TYPE::HASH_RIPEMD160: md = EVP_ripemd160(); break;
	default: break;
	}
	return md;
}

HASH_TYPE GetHashType(int nid) {
	const char* sig_alg = OBJ_nid2ln(nid);
	switch (nid) {
	case NID_md5WithRSAEncryption:
		return HASH_TYPE::HASH_MD5;
	case NID_sha1WithRSAEncryption:
		return HASH_TYPE::HASH_SHA1;
	case NID_sha224WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_224;
	case NID_sha256WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_256;
	case NID_sha384WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_384;
	case NID_sha512WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_512;
	case NID_sha512_224WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_512_224;
	case NID_sha512_256WithRSAEncryption:
		return HASH_TYPE::HASH_SHA2_512_256;
	case NID_RSA_SHA3_224:
		return HASH_TYPE::HASH_SHA3_224;
	case NID_RSA_SHA3_256:
		return HASH_TYPE::HASH_SHA3_256;
	case NID_RSA_SHA3_384:
		return HASH_TYPE::HASH_SHA3_384;
	case NID_RSA_SHA3_512:
		return HASH_TYPE::HASH_SHA3_512;
	case NID_ripemd160WithRSA:
		return HASH_TYPE::HASH_RIPEMD160;
	default:
		return HASH_TYPE::HASH_NULL;
	}
}

int Hash(HASH_STRUCTURE* hash) {
	ERR_clear_error();
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx)
		return handleErrors_symmetry("An error occurred during ctx generation.", ctx);

	const EVP_MD* md = GetHashCrypter(hash->TYPE);
	if (!md)
		return handleErrors_symmetry("Not supported by build.", ctx);

	if (1 != EVP_DigestInit_ex(ctx, md, NULL))
		return handleErrors_symmetry("Failed to initialize digest.", ctx);

	if ((hash->SEQUENCE & SALT_SEQUENCE::SALT_FIRST) && hash->SALT_LENGTH > 0) {
		if (1 != EVP_DigestUpdate(ctx, hash->SALT, hash->SALT_LENGTH))
			return handleErrors_symmetry("Failed to update digest with salt (first).", ctx);
	}

	if ((hash->SEQUENCE & SALT_SEQUENCE::SALT_MIDDLE) && hash->SALT_LENGTH > 0) {
		size_t mid = hash->INPUT_LENGTH / 2;

		if (1 != EVP_DigestUpdate(ctx, hash->INPUT, mid))
			return handleErrors_symmetry("Failed to update digest with input (first half).", ctx);

		if (1 != EVP_DigestUpdate(ctx, hash->SALT, hash->SALT_LENGTH))
			return handleErrors_symmetry("Failed to update digest with salt (middle).", ctx);
		
		if (1 != EVP_DigestUpdate(ctx, hash->INPUT + mid, hash->INPUT_LENGTH - mid))
			return handleErrors_symmetry("Failed to update digest with input (second half).", ctx);
	}
	else
		if (1 != EVP_DigestUpdate(ctx, hash->INPUT, hash->INPUT_LENGTH))
			return handleErrors_symmetry("Failed to update digest.", ctx);

	if ((hash->SEQUENCE & SALT_SEQUENCE::SALT_LAST) && hash->SALT_LENGTH > 0) {
		if (1 != EVP_DigestUpdate(ctx, hash->SALT, hash->SALT_LENGTH))
			return handleErrors_symmetry("Failed to update digest with salt (last).", ctx);
	}
	
	unsigned int length = 0;
	if (hash->TYPE != HASH_TYPE::HASH_SHA3_KE_128 && hash->TYPE != HASH_TYPE::HASH_SHA3_KE_256) {
		if (1 != EVP_DigestFinal_ex(ctx, hash->OUTPUT, &length))
			return handleErrors_symmetry("Failed to finalize digest.", ctx);
	}
	else {
		if (1 != EVP_DigestFinalXOF(ctx, hash->OUTPUT, hash->OUTPUT_LENGTH))
			return handleErrors_symmetry("Failed to finalize digest.", ctx);
		length = hash->OUTPUT_LENGTH;
	}

	EVP_MD_CTX_free(ctx);
	return static_cast<int>(length);
}

int GetHashLength(HASH_TYPE type) {
	switch (type) {
	case HASH_TYPE::HASH_MD5: return 128 / 8;				// 128 bits = 16 bytes
	case HASH_TYPE::HASH_MD5_SHA1: return (128 + 160) / 8;	// MD5 (128 bits) + SHA1 (160 bits) = 36 bytes
	case HASH_TYPE::HASH_SHA1: return 160 / 8;				// 160 bits = 20 bytes
	case HASH_TYPE::HASH_SHA2_224: return 224 / 8;			// 224 bits = 28 bytes
	case HASH_TYPE::HASH_SHA2_256: return 256 / 8;			// 256 bits = 32 bytes
	case HASH_TYPE::HASH_SHA2_384: return 384 / 8;			// 384 bits = 48 bytes
	case HASH_TYPE::HASH_SHA2_512: return 512 / 8;			// 512 bits = 64 bytes
	case HASH_TYPE::HASH_SHA2_512_224: return 224 / 8;		// 224 bits = 28 bytes
	case HASH_TYPE::HASH_SHA2_512_256: return 256 / 8;		// 256 bits = 32 bytes
	case HASH_TYPE::HASH_SHA3_224: return 224 / 8;			// 224 bits = 28 bytes
	case HASH_TYPE::HASH_SHA3_256: return 256 / 8;			// 256 bits = 32 bytes
	case HASH_TYPE::HASH_SHA3_384: return 384 / 8;			// 384 bits = 48 bytes
	case HASH_TYPE::HASH_SHA3_512: return 512 / 8;			// 512 bits = 64 bytes
	case HASH_TYPE::HASH_SHA3_KE_128: return -1;			// Variable length
	case HASH_TYPE::HASH_SHA3_KE_256: return -1;			// Variable length
	case HASH_TYPE::HASH_BLAKE2S_256: return 256 / 8;		// 256 bits = 32 bytes
	case HASH_TYPE::HASH_BLAKE2B_512: return 512 / 8;		// 512 bits = 64 bytes
	case HASH_TYPE::HASH_SM3: return 256 / 8;				// 256 bits = 32 bytes
	case HASH_TYPE::HASH_RIPEMD160: return 160 / 8;			// 160 bits = 20 bytes
	default: return 0;										// Unknown 0
	}
}