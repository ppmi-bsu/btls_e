/*
*******************************************************************************
\file btls_belt_mac.c
\brief Подключение алгоритмов имитозащиты belt
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.06.18
\version 2013.10.21
*******************************************************************************
*/

#include "btls_belt.h"
#include "btls_err.h"
#include "btls_utl.h"

#include <openssl/x509v3.h> /*For string_to_hex */

/* Init functions which set specific parameters */
static int belt_mac_init(EVP_MD_CTX *ctx);
/* process block of data */
static int belt_mac_update(EVP_MD_CTX *ctx, const void *data, size_t count);
/* Return computed value */
static int belt_mac_final(EVP_MD_CTX *ctx, unsigned char *md);
/* Copies context */
static int belt_mac_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int belt_mac_cleanup(EVP_MD_CTX *ctx);
/* Control function, knows how to set MAC key.*/
static int belt_mac_control(EVP_MD_CTX *ctx, int type, int arg, void *ptr);

EVP_MD belt_mac = 
{
	NID_undef,
	NID_undef,
	BELT_MAC_SIZE,
	0,
	belt_mac_init,
	belt_mac_update,
	belt_mac_final,
	belt_mac_copy,
	belt_mac_cleanup,
	NULL,
	NULL,
	{0,0,0,0,0},
	BELT_BLOCK_SIZE,
	0, /* ctx_size (will be initialize in bind function) */
	belt_mac_control
};

/* Implementation of belt-mac mode */

static int belt_mac_init(EVP_MD_CTX *ctx) 
{
	/* initialization will be done after setting key */
	return 1;
}

static int belt_mac_update(EVP_MD_CTX *ctx, const void *data, size_t count) 
{
	beltMACStepA(data, count, ctx->md_data);
	return 1;
}

static int belt_mac_final(EVP_MD_CTX *ctx, unsigned char *md) 
{
	beltMACStepG(md, ctx->md_data);
	return 1;
}

static int belt_mac_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) 
{
	memCopy(to->md_data, from->md_data, beltMAC_keep());
	return 1;
}

static int belt_mac_cleanup(EVP_MD_CTX *ctx) 
{
	memSetZero(ctx->md_data, beltMAC_keep());
	return 1;
}

static int belt_mac_control(EVP_MD_CTX *ctx, int type, int arg, void *ptr) 
{
	switch (type) 
	{
	case EVP_MD_CTRL_KEY_LEN:
		*((unsigned int*) (ptr)) = BELT_KEY_SIZE;
		return 1;
	case EVP_MD_CTRL_SET_KEY:
		if (arg != BELT_KEY_SIZE) 
		{
			ERR_BTLS(BTLS_F_BELT_MAC_CTRL, BTLS_R_INVALID_CIPHER_KEY_LENGTH);
			return -1;
		}
		beltMACStart((const octet*) ptr, arg, ctx->md_data);
		return 1;
	default:
		ERR_BTLS(BTLS_F_BELT_MAC_CTRL, BTLS_R_UNSUPPORTED_CTRL_CMD);
		return -1;
	}
}
