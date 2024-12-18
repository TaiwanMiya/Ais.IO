#include "pch.h"
#include "HashIO.h"

int HashMd5(HASH_MD5* hash) {
	ERR_clear_error();
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (!ctx)
		return handleErrors("An error occurred during ctx generation.", ctx);

	if (1 != EVP_DigestInit_ex(ctx, EVP_md5(), NULL))
		return handleErrors("Failed to initialize digest.", ctx);

	if (hash->SEQUENCE == SALT_SEQUENCE::SALT_FIRST && hash->SALT_LENGTH > 0) {
		if (1 != EVP_DigestUpdate(ctx, hash->SALT, hash->SALT_LENGTH))
			return handleErrors("Failed to update digest with salt.", ctx);
	}

	if (1 != EVP_DigestUpdate(ctx, hash->INPUT, hash->INPUT_LENGTH))
		return handleErrors("Failed to update digest.", ctx);

	if (hash->SEQUENCE == SALT_SEQUENCE::SALT_LAST && hash->SALT_LENGTH > 0) {
		if (1 != EVP_DigestUpdate(ctx, hash->SALT, hash->SALT_LENGTH))
			return handleErrors("Failed to update digest with salt.", ctx);
	}
	
	unsigned int length = 0;
	if (1 != EVP_DigestFinal_ex(ctx, hash->OUTPUT, &length))
		return handleErrors("Failed to finalize digest.", ctx);

	EVP_MD_CTX_free(ctx);
	return static_cast<int>(length);
}