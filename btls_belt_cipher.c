/*
*******************************************************************************
\file btls_belt_cipher.c
\brief Подключение алгоритмов шифрования belt
*******************************************************************************
\author (С) Олег Соловей, http://apmi.bsu.by
\created 2013.05.14
\version 2013.10.21
*******************************************************************************
*/

#include "btls_belt.h"
#include "btls_err.h"
//#include <rand/rand.h>

/* режим счетчика */
static int belt_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int belt_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl);
static int belt_ctr_cleanup(EVP_CIPHER_CTX *ctx);
/* общая для режимов ctr, ofb функция*/
static int belt_cipher_control(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);

/*
 *  Определение структуры для поточного алгоритма.
 *  В качестве поточного алгоритма будем использовать алгоритм шифрования в режиме счетчика
 *  (согласно криптонаборам btls)
 */
EVP_CIPHER belt_stream =
{
	NID_undef,
	1, /*block_size*/
	BELT_KEY_SIZE, /*key_size*/
	BELT_IV_SIZE, /*iv_len */
	EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY |
	EVP_CIPH_ALWAYS_CALL_INIT , /* Various flags */
	belt_ctr_init, /* init key */
	belt_ctr_cipher, /* encrypt/decrypt data */
	belt_ctr_cleanup, /* cleanup ctx */
	0, /* ctx_size (will be initialize in bind function) */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	belt_cipher_control, /* control function */
	NULL  /* application data */
};

/* Определение структуры для блочного алгоритма в режиме счетчика */
EVP_CIPHER belt_ctr =
{
	NID_undef,
	1, /*block_size*/
	BELT_KEY_SIZE, /*key_size*/
	BELT_IV_SIZE, /*iv_len */
	EVP_CIPH_CTR_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY |
	EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_NO_PADDING, /* Various flags */
	belt_ctr_init, /* init key */
	belt_ctr_cipher, /* encrypt/decrypt data */
	belt_ctr_cleanup, /* cleanup ctx */
	0, /* ctx_size (will be initialize in bind function) */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	belt_cipher_control, /* control function */
	NULL  /* application data */
};

/* режим гаммирования с обратной связью */
static int belt_cfb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int belt_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl);
static int belt_cfb_cleanup(EVP_CIPHER_CTX *ctx);

EVP_CIPHER belt_cfb =
{
	NID_undef,
	1, /*block_size*/
	BELT_KEY_SIZE, /*key_size*/
	BELT_IV_SIZE, /*iv_len */
	EVP_CIPH_CFB_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_RAND_KEY |
	EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_NO_PADDING, /* Various flags */
	belt_cfb_init, /* init key */
	belt_cfb_cipher, /* encrypt/decrypt data */
	belt_cfb_cleanup, /* cleanup ctx */
	0, /* ctx_size (will be initialize in bind function) */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	belt_cipher_control, /* control function */
	NULL  /* application data */
};

/* режим одновременного шифрования и имитозащиты данных */
static int belt_dwp_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
static int belt_dwp_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl);
static int belt_dwp_cleanup(EVP_CIPHER_CTX *ctx);
static int belt_dwp_control(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);

/* режим одновременного шифрования и имитозащиты данных будем определять как GCM */
EVP_CIPHER belt_dwp =
{
	NID_undef,
	1, /*block_size*/
	BELT_KEY_SIZE, /*key_size*/
	BELT_IV_SIZE, /*iv_len */
	EVP_CIPH_GCM_MODE | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_CUSTOM_IV |
		 EVP_CIPH_RAND_KEY | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_NO_PADDING, /* Various flags */
	belt_dwp_init, /* init key */
	belt_dwp_cipher, /* encrypt/decrypt data */
	belt_dwp_cleanup, /* cleanup ctx */
	0, /* ctx_size (will be initialize in bind function) */
	NULL, /* set asn1 params */
	NULL, /* get asn1 params */
	belt_dwp_control, /* control function */
	NULL  /* application data */
};

/* Implementation of belt-ctr */
static int belt_ctr_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if (ctx->app_data == NULL)
		ctx->app_data = ctx->cipher_data;

	if (iv) memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
	memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));

	if (key)
		beltCTRStart(key, EVP_CIPHER_CTX_key_length(ctx), ctx->iv, ctx->cipher_data);

	return 1;
}

static int belt_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl)
{
	memCopy(out, in, inl);
	if (ctx->encrypt)
	{
		beltCTRStepE(out, inl, ctx->cipher_data);
	}
	else
	{
		beltCTRStepD(out, inl, ctx->cipher_data);
	}
	return 1;
}

static int belt_ctr_cleanup(EVP_CIPHER_CTX *ctx)
{
	memSetZero(ctx->cipher_data, beltCTR_keep());
	ctx->app_data = NULL;
	return 1;
}

int belt_cipher_control(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	switch (type)
	{
	case EVP_CTRL_RAND_KEY:
		if (RAND_bytes((unsigned char *)ptr, EVP_CIPHER_CTX_key_length(ctx))<=0)
		{
			ERR_BTLS(BTLS_F_BELT_CIPHER_CONTROL, BTLS_R_RANDOM_GENERATOR_ERROR);
			return -1;
		}
		break;
/*	Аналогичный код скорее всего придется реализовать для belt
 *  при "полном" встраивании ...
 *
 * case EVP_CTRL_PBE_PRF_NID:
 *		if (ptr)
 *			*((int *)ptr)=  NID_id_HMACGostR3411_94;
 *		else
 *		{
 *			ERR_BTLS(BTLS_F_BELT_CTR_CONTROL, BTLS_R_NO_PARAMETERS_SET);
 *			return 0;
 *			}
 *		break;
 */
	default:
		ERR_BTLS(BTLS_F_BELT_CIPHER_CONTROL, BTLS_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
		return -1;
	}
	return 1;
}


/* Implementation of belt-cfb */
static int belt_cfb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if (ctx->app_data == NULL)
		ctx->app_data = ctx->cipher_data;

	if (iv) memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
	memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));

	if (key)
		beltCFBStart(key, EVP_CIPHER_CTX_key_length(ctx), ctx->iv, ctx->cipher_data);

	return 1;
}

static int belt_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl)
{
	memCopy(out, in, inl);
	if (ctx->encrypt)
	{
		beltCFBStepE(out, inl, ctx->cipher_data);
	}
	else
	{
		beltCFBStepD(out, inl, ctx->cipher_data);
	}
	return 1;
}

static int belt_cfb_cleanup(EVP_CIPHER_CTX *ctx)
{
	memSetZero(ctx->cipher_data, beltCFB_keep());
	ctx->app_data = NULL;
	return 1;
}


/* Implementation of belt-dwp mode */

static int belt_dwp_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
	if (ctx->app_data == NULL)
		ctx->app_data = ctx->cipher_data;

	if (iv) memcpy(ctx->oiv, iv, EVP_CIPHER_CTX_iv_length(ctx));
	memcpy(ctx->iv, ctx->oiv, EVP_CIPHER_CTX_iv_length(ctx));

	if (key)
		beltDWPStart(key, EVP_CIPHER_CTX_key_length(ctx), ctx->iv, ctx->cipher_data);

	return 1;
}

static int belt_dwp_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, unsigned int inl)
{
	unsigned char mac[BELT_MAC_SIZE];

	if (in)
	{ /* update */
		if (!out)
		{ /* обработка открытых данных */
			beltDWPStepI(in, inl, ctx->cipher_data); /* имитозащита */
		}
		else
		{ /* обработка критических данных */
			if (ctx->encrypt)
			{ /* зашифрование */
				memCopy(out, in, inl);
				beltDWPStepE(out, inl, ctx->cipher_data); /* зашифрование */
				beltDWPStepA(out, inl, ctx->cipher_data); /* подсчет имитовставки */
			}
			else
			{ /* расшифрование */
				memCopy(out, in, inl);
				beltDWPStepA(out, inl, ctx->cipher_data); /* подсчет имитовставки */
				beltDWPStepD(out, inl, ctx->cipher_data); /* расшифрование */
			}
		}
		return inl; /* возвращаем количество обработанных данных */
	}
	else
	{ /* finish */
		if (!ctx->encrypt)
		{ /* режим расшифрования */
			beltDWPStepG(mac, ctx->cipher_data);
			if (memCmp(mac, ctx->buf, BELT_MAC_SIZE) != 0)
				return -1;
		}
		else
		{ /* режим зашифрования */
			beltDWPStepG(ctx->buf, ctx->cipher_data);
		}
		return 0;
	}
}

static int belt_dwp_cleanup(EVP_CIPHER_CTX *ctx)
{
	memSetZero(ctx->cipher_data, beltDWP_keep());
	ctx->app_data = NULL;
	return 1;
}

static int belt_dwp_control(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	switch (type)
	{
	case EVP_CTRL_GCM_SET_TAG:
		if (arg != BELT_MAC_SIZE || c->encrypt)
		{
			ERR_BTLS(BTLS_F_BELT_DWP_CONTROL, BTLS_R_INVALID_CIPHER_PARAMS);
			return -1;
		}
		memCopy(c->buf, ptr, arg);
		break;

	case EVP_CTRL_GCM_GET_TAG:
		if (arg != BELT_MAC_SIZE || !c->encrypt )
		{
			ERR_BTLS(BTLS_F_BELT_DWP_CONTROL, BTLS_R_INVALID_CIPHER_PARAMS);
			return -1;
		}
		memCopy(ptr, c->buf, arg);
		break;

	case EVP_CTRL_RAND_KEY:
		if (RAND_bytes((unsigned char *)ptr, BELT_KEY_SIZE)<=0)
		{
			ERR_BTLS(BTLS_F_BELT_DWP_CONTROL, BTLS_R_RANDOM_GENERATOR_ERROR);
			return -1;
		}
		break;
/*	Аналогичный код скорее всего придется реализовать для belt
 *  при "полном" встраивании ...
 *
*	case EVP_CTRL_PBE_PRF_NID:
 *		if (ptr)
 *			*((int *)ptr)=  NID_id_HMACGostR3411_94;
 *		else
 *		{
 *			ERR_BTLS(BTLS_F_BELT_CTR_CONTROL, BTLS_R_NO_PARAMETERS_SET);
 *			return 0;
 *			}
 *		break;
 *
 *	case EVP_CTRL_AEAD_SET_MAC_KEY:
 *  ...
 *	case case EVP_CTRL_AEAD_TLS1_AAD:
 *  ...
 */
	default:
		ERR_BTLS(BTLS_F_BELT_DWP_CONTROL, BTLS_R_UNSUPPORTED_CIPHER_CTL_COMMAND);
		return -1;
	}
	return 1;
}


