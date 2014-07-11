/*
*******************************************************************************
\file btls_bign_pmeth.c
\brief Управление ключами алгоритмов bign
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.06.21
\version 2013.10.21
*******************************************************************************
*/

#include <ctype.h>
#include "btls_bign.h"
#include "btls_oids.h"
#include "btls_utl.h"

static int init_rng_stack(void *rng_stack)
{
	unsigned char *buf = NULL;

	buf = (unsigned char *) OPENSSL_malloc(64);
	if (!buf) return 0;

	if (RAND_bytes(buf, 64) <= 0) return 0;

	brngCTRStart(buf, buf+32, rng_stack);

	OPENSSL_cleanse(buf, 64);
	OPENSSL_free(buf);

	return 1;
}

/* Allocates new bign_pmeth_data structure and assigns it as data */
static int pkey_bign_init(EVP_PKEY_CTX *ctx)
{
	struct bign_pmeth_data *data = NULL;
	struct bign_key_data *bign_key;
	int base_id;
	EVP_PKEY *pkey;

	data = (struct bign_pmeth_data *) OPENSSL_malloc(sizeof(struct bign_pmeth_data));
	if (!data) return 0;
	memSetZero(data, sizeof(struct bign_pmeth_data));

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);

	if (pkey && EVP_PKEY_get0(pkey))
	{
		base_id = EVP_PKEY_base_id(pkey);
		if (base_id == bign_pubkey_nid)
		{
			bign_key = (struct bign_key_data*) EVP_PKEY_get0(pkey);
			data->param_nid = bign_key->param_nid;
		}
		else
		{
			return 0;
		}
	}

	data->param_nid = bign_prm1_nid;
	data->rng_stack = (unsigned char*) OPENSSL_malloc(brngCTR_keep());
	if (!data->rng_stack) return 0;
	if (!init_rng_stack(data->rng_stack)) return 0;

	EVP_PKEY_CTX_set_data(ctx, data);
	return 1;
}

/* Copies contents of bign_pmeth_data structure */
static int pkey_bign_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	struct bign_pmeth_data *dst_data, *src_data;
	unsigned char *pstack;

	if (!pkey_bign_init(dst))
	{
		return 0;
	}
	src_data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(src);
	dst_data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(dst);

	if (src_data->rng_stack)
		pstack = dst_data->rng_stack;

	*dst_data = *src_data;

	if (src_data->rng_stack)
		dst_data->rng_stack = pstack;

	return 1;
}

/* Frees up bign_pmeth_data structure */
static void pkey_bign_cleanup(EVP_PKEY_CTX *ctx)
{
	struct bign_pmeth_data *data;

	data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(ctx);
	if (!data) return;

	if (data->rng_stack)
	{
		OPENSSL_cleanse(data->rng_stack, brngCTR_keep());
		OPENSSL_free(data->rng_stack);
		data->rng_stack = NULL;
	}

	memSetZero(data, sizeof(struct bign_pmeth_data));
	OPENSSL_free(data);
	EVP_PKEY_CTX_set_data(ctx, NULL);
}

/* --------------------- control functions  ------------------------------*/
static int pkey_bign_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	struct bign_pmeth_data *pctx;

	pctx = (struct bign_pmeth_data*) EVP_PKEY_CTX_get_data(ctx);

	switch (type)
	{
	case EVP_PKEY_CTRL_MD:
		if (EVP_MD_type((const EVP_MD *) p2) != belt_hash.type)
		{
			return 0;
		}
		pctx->md = (EVP_MD *) p2;
		return 1;

	case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
	case EVP_PKEY_CTRL_PKCS7_DECRYPT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_DIGESTINIT:
#ifndef OPENSSL_NO_CMS
	case EVP_PKEY_CTRL_CMS_ENCRYPT:
	case EVP_PKEY_CTRL_CMS_DECRYPT:
	case EVP_PKEY_CTRL_CMS_SIGN:
#endif
		return 1;

	case EVP_PKEY_CTRL_BIGN_PARAMSET:
		pctx->param_nid = p1;
		return 1;
	case EVP_PKEY_CTRL_SET_IV:
		return 1;
	case EVP_PKEY_CTRL_PEER_KEY:
		if (p1 == 0 || p1 == 1) /* call from EVP_PKEY_derive_set_peer */
			return 1;
		if (p1 == 2) /* TLS: peer key used? */
			return pctx->peer_key_used;
		if (p1 == 3) /* TLS: peer key used! */
			return (pctx->peer_key_used = 1);
		return -2;
	}

	return -2;
}

static int pkey_bign_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value)
{
	int param_nid = 0;

	if (!strcmp(type, param_ctrl_string))
	{
		if (!value)
		{
			return 0;
		}
		if (strlen(value) == 1)
		{
			switch (toupper((unsigned char) value[0]))
			{
			case 'A':
				param_nid = bign_prm1_nid;
				break;
			default:
				return 0;
			}
		}
		return pkey_bign_ctrl(ctx, EVP_PKEY_CTRL_BIGN_PARAMSET, param_nid, NULL);
	}
	return -2;
}

/* --------------------- key generation  --------------------------------*/

static int pkey_bign_paramgen_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

int fill_bign_params(struct bign_key_data *key_data, int params_nid)
{
	char * param_oid;
	int status;

	param_oid = NULL;
	key_data->param_nid = params_nid;
	if (key_data->param_nid == bign_prm1_nid)
		param_oid = OID_bign_prm1;

	status = bignStdParams(&key_data->params, param_oid);
	if (status != ERR_OK)  return 0;

	return 1;
}

static int pkey_bign_set_params(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	struct bign_pmeth_data *data = NULL;
	struct bign_key_data *key_data = NULL;

	data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(ctx);
	if (!data) return 0;

	key_data = (struct bign_key_data *) OPENSSL_malloc(sizeof(struct bign_key_data));
	if (!key_data) return 0;
	memSetZero(key_data, sizeof(struct bign_key_data));

	if (data->param_nid == NID_undef)
	{
		data->param_nid = bign_prm1_nid;
	}
	if (!fill_bign_params(key_data, data->param_nid))
	{
		OPENSSL_free(key_data);
		EVP_PKEY_CTX_set_data(ctx, NULL);
		return 0;
	}

	if (EVP_PKEY_assign(pkey, bign_pubkey_nid, key_data) <= 0)
		return 0;
	else
		return 1;
}

/* Generates BIGN key and assigns it using specified type */
static int pkey_bign_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	struct bign_pmeth_data *data;
	struct bign_key_data *key_data;
	int status;

	if (!pkey_bign_set_params(ctx, pkey))
	{
		return 0;
	}

	key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);
	if (!key_data) return 0;

	key_data->privKey = (octet*) OPENSSL_malloc(key_data->params.l / 4);
	key_data->pubKey = (octet*) OPENSSL_malloc(key_data->params.l / 2);

	if (!key_data->privKey || !key_data->pubKey) return 0;

	data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(ctx);

	status = bignGenKeypair(key_data->privKey, key_data->pubKey,
			&key_data->params, brngCTRStepR, data->rng_stack);

	return (status == ERR_OK) ? 1 : 0;
}

/* ----------- sign/verify callbacks --------------------------------------*/
static octet _belt_hash_der[] = {0x06, 0x09, 0x2A, 0x70, 0x00, 0x02, 0x00, 0x22, 0x65, 0x1F, 0x51};
static size_t _belt_oid_len = sizeof(_belt_hash_der);

static int pkey_bign_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
		size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
	struct bign_pmeth_data *data;
	struct bign_key_data *key_data;
	int status;

	key_data = (struct bign_key_data *) EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
	if (tbs_len != (key_data->params.l / 4))
	{
		return 0;
	}
	if (!siglen)
	{
		return 0;
	}
	*siglen = key_data->params.l * 3 / 8;;
	if (!sig)
	{
		return 1;
	}

	data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(ctx);

	status = bignSign(sig, &key_data->params, _belt_hash_der, _belt_oid_len, tbs, key_data->privKey, brngCTRStepR, data->rng_stack);
	return (status == ERR_OK) ? 1 : 0;
}

static int pkey_bign_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
		size_t siglen, const unsigned char *tbs, size_t tbs_len)
{
	int ok;
	struct bign_key_data *key_data;
	err_t ret;
	EVP_PKEY* pkey;
	ok = 0;
	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey)
	{
		key_data = (struct bign_key_data *) EVP_PKEY_get0(pkey);
		ret = bignVerify(&key_data->params, _belt_hash_der, _belt_oid_len, tbs, sig, key_data->pubKey);
		ok = (ret == ERR_OK) ? 1 : 0;
	}
	return ok;
}

/* ------------- encrypt init -------------------------------------*/
static int pkey_bign_encrypt_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int pkey_bign_encrypt(EVP_PKEY_CTX *pctx, unsigned char *out, size_t *out_len,
	const unsigned char *key, size_t key_len)
{
	struct bign_pmeth_data *data;
	EVP_PKEY *pubk;
	struct bign_key_data * key_data;
	int status;

	if (key_len < 16) return 0;
	if (!out_len) return 0;

	pubk = EVP_PKEY_CTX_get0_pkey(pctx);
	if (!pubk) return 0;

	key_data = (struct bign_key_data *) EVP_PKEY_get0(pubk);
	if (!key_data) return 0;

	data = (struct bign_pmeth_data *) EVP_PKEY_CTX_get_data(pctx);
	if (!data) return 0;

	*out_len = key_len + 16 + key_data->params.l / 4;
	if (!out) return 1; // return size of token

	status = bignKeyWrap(out, &key_data->params, key, key_len, NULL, key_data->pubKey, brngCTRStepR, data->rng_stack);

	return (status == ERR_OK) ? 1 : 0;
}

static int pkey_bign_decrypt(EVP_PKEY_CTX *pctx, unsigned char *key,
		size_t * key_len, const unsigned char *in, size_t in_len)
{
	EVP_PKEY *priv;
	struct bign_key_data *key_data;
	int status;

	if (!key_len) return 0;

	priv = EVP_PKEY_CTX_get0_pkey(pctx);
	if (!priv) return 0;

	key_data = (struct bign_key_data*) EVP_PKEY_get0(priv);
	if (!key_data) return 0;

	if (in_len < 16 + 16 + key_data->params.l / 4) return 0;

	*key_len = in_len - 16 - key_data->params.l / 4;
	if (!key) return 1; // return size of key

	status = bignKeyUnwrap(key, &key_data->params, in, in_len, NULL, key_data->privKey);
	return (status == ERR_OK) ? 1 : 0;
}

int register_pmeth_bign(int id, EVP_PKEY_METHOD **pmeth, int flags)
{
	*pmeth = EVP_PKEY_meth_new(id, flags);

	if (!*pmeth)
	{
		return 0;
	}

	if (id == bign_pubkey_nid)
	{
		EVP_PKEY_meth_set_ctrl(*pmeth, pkey_bign_ctrl, pkey_bign_ctrl_str);
		EVP_PKEY_meth_set_sign(*pmeth, NULL, pkey_bign_sign);
		EVP_PKEY_meth_set_verify(*pmeth, NULL, pkey_bign_verify);

		EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_bign_keygen);

		EVP_PKEY_meth_set_encrypt(*pmeth, pkey_bign_encrypt_init, pkey_bign_encrypt);
		EVP_PKEY_meth_set_decrypt(*pmeth, NULL, pkey_bign_decrypt);

		EVP_PKEY_meth_set_paramgen(*pmeth, pkey_bign_paramgen_init, pkey_bign_set_params);
	}
	else
	{
		return 0;
	}

	EVP_PKEY_meth_set_init(*pmeth, pkey_bign_init);
	EVP_PKEY_meth_set_cleanup(*pmeth, pkey_bign_cleanup);
	EVP_PKEY_meth_set_copy(*pmeth, pkey_bign_copy);

	return 1;
}
