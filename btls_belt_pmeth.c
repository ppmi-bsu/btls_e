/*
*******************************************************************************
\file btls_belt_pmeth.c
\brief Форматы данных для алгоритмов belt
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.07.01
\version 2013.09.26
*******************************************************************************
*/

#include <ctype.h>
#include "btls_belt.h"
#include "btls_oids.h"
#include "btls_utl.h"
#include "btls_err.h"

static int pkey_belt_mac_init(EVP_PKEY_CTX *ctx);
static void pkey_belt_mac_cleanup(EVP_PKEY_CTX *ctx);
static int pkey_belt_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int pkey_belt_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static int pkey_belt_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);
static int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);

/* Implementation */

static int pkey_belt_mac_init(EVP_PKEY_CTX *ctx) 
{
	struct belt_mac_pmeth_data *data = NULL;

	data = (struct belt_mac_pmeth_data*) OPENSSL_malloc(sizeof(struct belt_mac_pmeth_data));
	if (!data) 
	{
		ERR_BTLS(BTLS_F_PKEY_BELT_MAC_INIT, BTLS_R_MALLOC_FAILURE);
		return 0;
	}
	memSetZero(data, sizeof(struct belt_mac_pmeth_data));
	EVP_PKEY_CTX_set_data(ctx, data);
	return 1;
}

static void pkey_belt_mac_cleanup(EVP_PKEY_CTX *ctx) 
{
	struct belt_mac_pmeth_data *data;

	data = (struct belt_mac_pmeth_data*) EVP_PKEY_CTX_get_data(ctx);
	OPENSSL_cleanse(data, sizeof(struct belt_mac_pmeth_data));
	OPENSSL_free(data);
	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int pkey_belt_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) 
{
	struct belt_mac_pmeth_data *dst_data, *src_data;

	if (!pkey_belt_mac_init(dst)) 
	{
		ERR_BTLS(BTLS_F_PKEY_BELT_MAC_COPY, BTLS_R_MALLOC_FAILURE);
		return 0;
	}

	src_data = (struct belt_mac_pmeth_data *) EVP_PKEY_CTX_get_data(src);
	dst_data = (struct belt_mac_pmeth_data *) EVP_PKEY_CTX_get_data(dst);
	*dst_data = *src_data;

	return 1;
}

static int pkey_belt_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) 
{
	struct belt_mac_pmeth_data *data;
	unsigned char *keydata = NULL;

	data = (struct belt_mac_pmeth_data *) EVP_PKEY_CTX_get_data(ctx);
	if (!data->key_set) 
	{
		ERR_BTLS(BTLS_F_PKEY_BELT_MAC_KEYGEN, BTLS_R_KEY_IS_NOT_INITALIZED);
		return 0;
	}
	keydata = (unsigned char *) OPENSSL_malloc(BELT_KEY_SIZE);
	if (!keydata)
	{
		ERR_BTLS(BTLS_F_PKEY_BELT_MAC_KEYGEN, BTLS_R_MALLOC_FAILURE);
		return 0;
	}
	memCopy(keydata, data->key, BELT_KEY_SIZE);
	if (EVP_PKEY_assign(pkey, belt_mac.type, keydata) <= 0)
		return 0;
	else
		return 1;
}

static int pkey_belt_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) 
{
	return 1;
}

static int pkey_belt_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) 
{
	unsigned int tmpsiglen; 
	int ret;

	tmpsiglen = *siglen; 

	if (!sig) 
	{
		*siglen = BELT_MAC_SIZE;
		return 1;
	}
	ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
	*siglen = tmpsiglen;
	return ret;
}

static int pkey_belt_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	struct belt_mac_pmeth_data *data;
	EVP_MD_CTX *mctx;
	EVP_PKEY *pkey;
	void *key;

	data = (struct belt_mac_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);

	switch (type)
	{
		case EVP_PKEY_CTRL_MD:
		{
			if (EVP_MD_type((const EVP_MD *)p2) != belt_mac_nid)
			{
				ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL, BTLS_R_INVALID_DIGEST_TYPE);
				return 0;
			}
			data->md = (EVP_MD *)p2;
			return 1;
		}
		break;

		case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
		case EVP_PKEY_CTRL_PKCS7_DECRYPT:
		case EVP_PKEY_CTRL_PKCS7_SIGN:
			return 1;
		case EVP_PKEY_CTRL_SET_MAC_KEY:
			if (p1 != BELT_KEY_SIZE)
			{
				ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL, BTLS_R_INVALID_CIPHER_PARAMS);
				return 0;
			}
			memcpy(data->key,p2,BELT_KEY_SIZE);
			data->key_set = 1;
			return 1;
		case EVP_PKEY_CTRL_DIGESTINIT:
		{
			mctx = (EVP_MD_CTX *) p2;
			if (!data->key_set)
			{
				pkey = EVP_PKEY_CTX_get0_pkey(ctx);
				if (!pkey)
				{
					ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL, BTLS_R_MAC_KEY_NOT_SET);
					return 0;
				}
				key = EVP_PKEY_get0(pkey);
				if (!key)
				{
					ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL, BTLS_R_MAC_KEY_NOT_SET);
					return 0;
				}
			} 
			else 
			{
				key = &(data->key);
			}
			return mctx->digest->md_ctrl(mctx, EVP_MD_CTRL_SET_KEY, BELT_KEY_SIZE, key);
		}
	}
	return -2;
}

static int pkey_belt_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	long keylen;
	int ret;
	unsigned char *keybuf;

	
	if (!strcmp(type, "key"))
	{
		if (strlen(value) != BELT_KEY_SIZE)
		{
				ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL_STR, BTLS_R_INVALID_MAC_KEY_LENGTH);
				return 0;
		}
		return pkey_belt_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, BELT_KEY_SIZE, (char *)value);
	}
	if (!strcmp(type, "hexkey"))
	{
		keybuf = string_to_hex(value, &keylen);
		if (keylen != BELT_KEY_SIZE)
		{
			ERR_BTLS(BTLS_F_PKEY_BELT_MAC_CTRL_STR, BTLS_R_INVALID_MAC_KEY_LENGTH);
			OPENSSL_free(keybuf);
			return 0;
		}
		ret = pkey_belt_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, BELT_KEY_SIZE, keybuf);
		OPENSSL_free(keybuf);
		return ret;
	}
	return -2;
}

int register_pmeth_belt(int id, EVP_PKEY_METHOD **pmeth, int flags) 
{
	*pmeth = EVP_PKEY_meth_new(id, flags);
	if (!*pmeth) return 0;

	if (id == belt_mac.type) 
	{
		EVP_PKEY_meth_set_ctrl(*pmeth, pkey_belt_mac_ctrl, pkey_belt_mac_ctrl_str);
		EVP_PKEY_meth_set_signctx(*pmeth, pkey_belt_mac_signctx_init, pkey_belt_mac_signctx);
		EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_belt_mac_keygen);
		EVP_PKEY_meth_set_init(*pmeth, pkey_belt_mac_init);
		EVP_PKEY_meth_set_cleanup(*pmeth, pkey_belt_mac_cleanup);
		EVP_PKEY_meth_set_copy(*pmeth, pkey_belt_mac_copy);
		return 1;
	} 
	else 
	{
		EVP_PKEY_meth_free(*pmeth);
		return 0;
	}
}
