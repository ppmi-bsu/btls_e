/*
*******************************************************************************
\file btls_belt_hash.c
\brief Подключение алгоритмов шифрования belt
*******************************************************************************
\author (С) Михаил Койпиш, http://apmi.bsu.by
\created 2013.08.14
\version 2013.10.21
*******************************************************************************
*/

#include "btls_belt.h"

#define BELT_HASH_SIZE		32
#define BELT_HASH_DATA_SIZE 1

static int belt_hash_init(EVP_MD_CTX *ctx);
static int belt_hash_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int belt_hash_final(EVP_MD_CTX *ctx, unsigned char *md);
static int belt_hash_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int belt_hash_cleanup(EVP_MD_CTX *ctx);

EVP_MD belt_hash = 
{
	NID_undef,
	NID_undef, 
	BELT_HASH_SIZE,
	EVP_MD_FLAG_PKEY_METHOD_SIGNATURE,  
	belt_hash_init,
	belt_hash_update,
	belt_hash_final,
	belt_hash_copy,
	belt_hash_cleanup,
	NULL,	
	NULL,	
	{NID_undef,NID_undef,0,0,0}, /*EVP_PKEY_xxx */
	BELT_HASH_DATA_SIZE,
	0, /* ctx_size (will be initialize in bind function) */
	NULL /* control function */
};

static int belt_hash_init(EVP_MD_CTX *ctx) 
{
	beltHashStart(ctx->md_data);
	return 1;
}

static int belt_hash_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
	beltHashStepH(data, count, ctx->md_data);
	return 1;
}


static int belt_hash_final(EVP_MD_CTX *ctx, unsigned char *md)
{
	beltHashStepG(md, ctx->md_data);
	return 1;
}

static int belt_hash_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
	memCopy(to->md_data,from->md_data, belt_hash.ctx_size);
	return 1;
}

static int belt_hash_cleanup(EVP_MD_CTX *ctx)
{
	memSetZero(ctx->md_data, belt_hash.ctx_size);
	return 1;
}
