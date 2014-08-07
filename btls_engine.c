﻿/*
*******************************************************************************
\file btls_engine.c
\brief Подключение встраиваемого модуля (энжайна) btls
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.07.24
\version 2013.10.29
*******************************************************************************
*/
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

#include "btls_belt.h"
#include "btls_bign.h"
#include "btls_oids.h"
#include "btls_utl.h"
#include "btls_err.h"
#include "btls_engine.h"

#define SSL_CIPHER_SET_DYNAMIC

#ifdef SSL_CIPHER_SET_DYNAMIC
#include <openssl/ssl.h>
#include "ssl_spec.h"

#endif

static const char *engine_btls_id = "btls_e";
static const char *engine_btls_name = "BTLS_E Engine [belt + bign support]";

/*
*******************************************************************************
Идентификаторы
*******************************************************************************
*/

int belt_stream_nid = NID_undef;
int belt_ctr_nid = NID_undef;
int belt_cfb_nid = NID_undef;
int belt_dwp_nid = NID_undef;
int belt_hash_nid = NID_undef;
int belt_mac_nid = NID_undef;

int bign_prm1_nid = NID_undef;
int bign_pubkey_nid = NID_undef;
int bign_primefield_nid = NID_undef;
int bign_with_hbelt_nid = NID_undef;

int belt_digest_nids[] = {NID_undef, NID_undef};
int belt_cipher_nids[] = {NID_undef, NID_undef, NID_undef, NID_undef};
int meth_nids[] = {NID_undef, NID_undef};

#define REGISTER_NID(var, alg) tmpnid = OBJ_ln2nid(LN_##alg);\
	var = (tmpnid == NID_undef)?\
		OBJ_create(OID_##alg, BUF_strdup(SN_##alg) , BUF_strdup(LN_##alg)) : tmpnid;\
	if (var == NID_undef) { goto err;}

static int register_NIDs()
{
	int tmpnid;

	REGISTER_NID(belt_stream_nid, belt_stream)
	REGISTER_NID(belt_ctr_nid, belt_ctr)
	REGISTER_NID(belt_cfb_nid, belt_cfb)
	REGISTER_NID(belt_dwp_nid, belt_dwp)
	REGISTER_NID(belt_mac_nid, belt_mac)
	REGISTER_NID(belt_hash_nid, belt_hash)
	REGISTER_NID(bign_prm1_nid, bign_prm1)
	REGISTER_NID(bign_primefield_nid, bign_primefield)
	REGISTER_NID(bign_pubkey_nid, bign_pubkey)
	REGISTER_NID(bign_with_hbelt_nid, bign_with_hbelt)

	if (!OBJ_add_sigid(bign_with_hbelt_nid, belt_hash_nid, bign_pubkey_nid))
		goto err;

	belt_digest_nids[0] = belt_hash_nid;
	belt_digest_nids[1] = belt_mac_nid;

	belt_cipher_nids[0] = belt_stream_nid;
	belt_cipher_nids[1] = belt_ctr_nid;
	belt_cipher_nids[2] = belt_cfb_nid;
	belt_cipher_nids[3] = belt_dwp_nid;

	meth_nids[0] = belt_mac_nid;
	meth_nids[1] = bign_pubkey_nid;

	return 1;

err:
	belt_stream_nid = NID_undef;
	belt_ctr_nid = NID_undef;
	belt_cfb_nid = NID_undef;
	belt_dwp_nid = NID_undef;
	belt_hash_nid = NID_undef;
	belt_mac_nid = NID_undef;
	bign_prm1_nid = NID_undef;
	bign_primefield_nid = NID_undef;
	bign_pubkey_nid = NID_undef;
	bign_with_hbelt_nid = NID_undef;

	return 0;
}

/*
*******************************************************************************
Структуры EVP_PKEY_XXX
*******************************************************************************
*/

EVP_PKEY_METHOD *belt_mac_pmeth = NULL;
EVP_PKEY_METHOD *bign_pmeth = NULL;
EVP_PKEY_ASN1_METHOD *belt_mac_ameth = NULL;
EVP_PKEY_ASN1_METHOD *bign_ameth = NULL;


#ifdef SSL_CIPHER_SET_DYNAMIC
/*
*******************************************************************************
Структуры SSL_CIPHER
*******************************************************************************
*/

static ENC_SPEC enc_spec_BELT_CTR = { { 0 }, "BELT-CTR", NULL, &belt_ctr, 0 };


static MAC_SPEC mac_spec_GOST94 = { { 0 }, "BELT-MAC", NULL, &belt_mac, 0 };


AUTH_SPEC auth_spec_GOST;


static KEYEXCH_SPEC kex_spec_CPGOST94 = { { 0 }, "GOST", NULL, 1,
	CPGOST_prepare_client_key_exchange, //prepare_client_key_exchange should be implemented
	NULL,
	NULL,
	CPGOST_parse_client_key_exchange,  //parse_client_key_exchange should be implemented 1st
	CPGOST94_cert_cipher_compat_p
};

static PRF_SPEC prf_spec_GOST = {
	{ 0 },
	"GOST PRF",
	NULL,
	gost_prf_func,
	0
};

#define TLS1_TXT_DH_WITH_BELT_128_SHA256 "GOST94-GOST89-GOST89"
#define TLS1_CK_DH_WITH_BELT_128_SHA256 0x3000080
/* Bits for algorithm_mkey (key exchange algorithm) */
#define SSL_kBELT       0x00000800L /* BELT key exchange */
/* Bits for algorithm_auth (server authentication) */
#define SSL_aBELT 	    0x00000800L /* BELT signature auth */
/* Bits for algorithm_enc (symmetric encryption) */
#define SSL_eBELTCNT		0x00008000L
/* Bits for algorithm_mac (symmetric authentication) */
#define SSL_BELTMAC     0x00000080L
/* Bits for algorithm_ssl (protocol version) */
#define SSL_TLSV1_2		0x00000004L
/* Bits for algorithm2 (handshake digests and other extra flags) */

#define SSL_HANDSHAKE_MAC_BELT 0x200

#define TLS1_PRF_DGST_SHIFT 10
#define TLS1_PRF_BELT (SSL_HANDSHAKE_MAC_BELT << TLS1_PRF_DGST_SHIFT)
#define TLS1_STREAM_MAC 0x04


static SSL_CIPHER tls_gost341094_with_gost28147_ofb_gost28147 =
	{
    1,
    TLS1_TXT_DH_WITH_BELT_128_SHA256,
    TLS1_CK_DH_WITH_BELT_128_SHA256,
    SSL_kBELT,
    SSL_aBELT,
    SSL_eBELTCNT,
    SSL_BELTMAC,
    SSL_TLSV1_2,
    SSL_NOT_EXP|SSL_HIGH,
    SSL_HANDSHAKE_MAC_BELT|TLS1_PRF_BELT|TLS1_STREAM_MAC,
    256,
    256
};
static SSL_CIPHER_SPEC tls_gost341094_with_gost28147_ofb_gost28147_spec =
{
	1,
	//"TLS_GOST341094_WITH_GOST28147_OFB_GOST28147",
	"GOST94-GOST89-GOST89",
	0x03000080,
	0x02000000L,
	&kex_spec_CPGOST94,
	&auth_spec_GOST,
	&prf_spec_GOST,
	&enc_spec_BELT_CTR,
	&mac_spec_GOST94,
	{NID_undef, NID_undef}, //NID_gost
	SSL_NOT_EXP|SSL_HIGH,
	0,
	256,
	256,
	SSL_ALL_STRENGTHS
};

static int init_gost_ssl_cipher_spec(void)
{

	if (!SSL_register_enc_spec(&enc_spec_BELT_CTR)) goto end;
	if (!SSL_register_mac_spec(&mac_spec_GOST94)) goto end;
	if (!SSL_register_prf_spec(&prf_spec_GOST)) goto end;
	kex_spec_CPGOST94.mask.mask = 0x00000004L; /* SSL_kDHd */
	/* clone and modify auth_spec_DSS */
//	auth_spec_GOST = *SSL_auth_spec_DSS();
	auth_spec_GOST.md_nid[0] = belt_hash.type;//digest_gost.type;
	auth_spec_GOST.cert_verify_dgst_len = 32;//digest_gost.md_size;
	auth_spec_GOST.get_and_verify_server_params = GOST_verify_server_params;
	auth_spec_GOST.authenticate_server_params = GOST_sign_server_params;
/*	if (!SSL_register_auth_spec(&auth_spec_GOST)) goto end */

	tls_gost341094_with_gost28147_ofb_gost28147_spec.finished_md_nid[0] = belt_ctr_nid;//NID_digest_GOST;
	if (!tls1_register_cipher_suite(&tls_gost341094_with_gost28147_ofb_gost28147_spec)) goto end;
		return 1;
end:
		return 0;
}




#endif // SSL_CIPHER_SET_DYNAMIC
/*
*******************************************************************************
Callbacks
*******************************************************************************
*/

static int belt_ciphers(ENGINE * e, const EVP_CIPHER ** cipher, const int ** nids, int nid)
{
	if (cipher == NULL)
	{
		*nids = belt_cipher_nids;
		return sizeof(belt_cipher_nids) / sizeof(belt_cipher_nids[0]);
	}

	if (nid == belt_stream_nid)
		*cipher = &belt_stream;
	else if (nid == belt_ctr_nid)
		*cipher = &belt_ctr;
	else if (nid == belt_cfb_nid)
		*cipher = &belt_cfb;
	else if (nid == belt_dwp_nid)
		*cipher = &belt_dwp;
	else
		return 0;

	return 1;
}

static int belt_digest(ENGINE * engine, const EVP_MD ** evp_md, const int ** nids, int nid)
{
	if (evp_md == NULL)
	{
		*nids = belt_digest_nids;
		return sizeof(belt_digest_nids) / sizeof(belt_digest_nids[0]);
	}

	if (nid == belt_hash_nid)
			*evp_md = &belt_hash;
	else if (nid == belt_mac_nid)
		*evp_md = &belt_mac;
	else
		return 0;

	return 1;
}

static int belt_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid)
{
	if (!pmeth)
	{
		*nids = meth_nids;
		return sizeof(meth_nids) / sizeof(meth_nids[0]);
	}

	*pmeth = NULL;
	if (nid == belt_mac_nid)
		*pmeth = belt_mac_pmeth;
	else if (nid == bign_pubkey_nid)
		*pmeth = bign_pmeth;
	else
		return 0;

	return 1;
}

static int belt_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid)
{
	if (!ameth)
	{
		*nids = meth_nids;
		return sizeof(meth_nids) / sizeof(meth_nids[0]);
	}

	*ameth = NULL;
	if (nid == belt_mac_nid)
		*ameth = belt_mac_ameth;
	else if (nid == bign_pubkey_nid)
		*ameth = bign_ameth;
	else
		return 0;

	return 1;
}

static int add()
{
	if (!EVP_add_digest(&belt_hash))
	{
		return 0;
	}
	if (!EVP_add_digest(&belt_mac))
	{
		return 0;
	}
	if (!EVP_add_cipher(&belt_stream))
	{
		return 0;
	}
	if (!EVP_add_cipher(&belt_cfb))
	{
		return 0;
	}
	if (!EVP_add_cipher(&belt_ctr))
	{
		return 0;
	}
	if (!EVP_add_cipher(&belt_dwp))
	{
		return 0;
	}
	return 1;
}

const ENGINE_CMD_DEFN btls_cmds[]= {{0,NULL,NULL,0}};

int btls_control_func(ENGINE *e,int cmd,long i, void *p, void (*f)(void))
{
	return 1;
}

static int btls_engine_init(ENGINE *e)
{
	return 1;
}

static int btls_engine_finish(ENGINE *e)
{
	return 1;
}

static int btls_engine_destroy(ENGINE *e)
{
	belt_mac_pmeth = NULL;
	bign_pmeth = NULL;
	belt_mac_ameth = NULL;
	bign_ameth = NULL;
	return 1;
}


static int bind_btls(ENGINE * e, const char *id)
{
	if (id && strcmp(id, engine_btls_id))
		return 0;

	if (bign_ameth)
	{
		printf("btls-engine already loaded\n");
		return 0;
	}

	if (!register_NIDs()) {
		printf("nids register error\n");
		return 0;
	}

	// Set up NIDs and context-sizes
	belt_stream.nid = belt_stream_nid;
	belt_stream.ctx_size = beltCTR_keep();

	belt_cfb.nid = belt_cfb_nid;
	belt_cfb.ctx_size = beltCFB_keep();

	belt_ctr.nid = belt_ctr_nid;
	belt_ctr.ctx_size = beltCTR_keep();

	belt_dwp.nid = belt_dwp_nid;
	belt_dwp.ctx_size = beltDWP_keep();

	belt_hash.type = belt_hash_nid;
	belt_hash.ctx_size = beltHash_keep();

	belt_mac.type = belt_mac_nid;
	belt_mac.ctx_size = beltMAC_keep();

	belt_hash.pkey_type = bign_pubkey_nid;

	if (!ENGINE_set_id(e, engine_btls_id))
	{
		printf("ENGINE_set_id failed\n");
		return 0;
	}
	if (!ENGINE_set_name(e, engine_btls_name))
	{
		printf("ENGINE_set_name failed\n");
		return 0;
	}
	if (!ENGINE_set_digests(e, belt_digest))
	{
		printf("ENGINE_set_digests failed\n");
		return 0;
	}
	if (!ENGINE_set_ciphers(e, belt_ciphers))
	{
		printf("ENGINE_set_ciphers failed\n");
		return 0;
	}
	if (!ENGINE_set_pkey_meths(e, belt_pkey_meths))
	{
		printf("ENGINE_set_pkey_meths failed\n");
		return 0;
	}
	if (!ENGINE_set_pkey_asn1_meths(e, belt_pkey_asn1_meths))
	{
		printf("ENGINE_set_pkey_asn1_meths failed\n");
		return 0;
	}

	if (!register_ameth_belt(belt_mac.type, &belt_mac_ameth, SN_belt_mac, LN_belt_mac))
	{
		printf("register_ameth_belt for MAC failed\n");
		return 0;
	}
	if (!register_pmeth_belt(belt_mac.type, &belt_mac_pmeth, 0))
	{
		printf("register_pmeth_belt for MAC failed\n");
		return 0;
	}
	if (!register_ameth_bign(bign_pubkey_nid, &bign_ameth, SN_bign_pubkey, LN_bign_pubkey))
	{
		printf("register_ameth_bign failed\n");
		return 0;
	}
	if (!register_pmeth_bign(bign_pubkey_nid, &bign_pmeth, 0))
	{
		printf("register_pmeth_bign failed\n");
		return 0;
	}

	/* Control function and commands */
	if (!ENGINE_set_cmd_defns(e, btls_cmds))
	{
		fprintf(stderr,"ENGINE_set_cmd_defns failed\n");
		return 0;
	}
	if (!ENGINE_set_ctrl_function(e, btls_control_func))
	{
		fprintf(stderr,"ENGINE_set_ctrl_func failed\n");
		return 0;
	}
	if ( ! ENGINE_set_destroy_function(e, btls_engine_destroy)
		|| ! ENGINE_set_init_function(e, btls_engine_init)
		|| ! ENGINE_set_finish_function(e, btls_engine_finish))
	{
		return 0;
	}

	/* Register and add algorithms */
	if (!ENGINE_register_ciphers(e) ||
		!ENGINE_register_digests(e) ||
		!ENGINE_register_pkey_meths(e) ||
		!EVP_add_digest(&belt_hash) ||
		!EVP_add_digest(&belt_mac) ||
		!EVP_add_cipher(&belt_stream) ||
		!EVP_add_cipher(&belt_cfb) ||
		!EVP_add_cipher(&belt_ctr) ||
		!EVP_add_cipher(&belt_dwp))
	{
		printf("ENGINE register / EVP_add failed\n");
		return 0;
	}
#ifdef SSL_CIPHER_SET_DYNAMIC
    if (! init_gost_ssl_cipher_spec()) return 0;
#endif
	ERR_load_BTLS_strings();
	return 1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
IMPLEMENT_DYNAMIC_BIND_FN(bind_btls)
IMPLEMENT_DYNAMIC_CHECK_FN()
#endif  /* ndef OPENSSL_NO_DYNAMIC_ENGINE */

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
static ENGINE *engine_btls(void)
{
	ENGINE *ret = ENGINE_new();
	if (!ret)
		return NULL;
	if (!bind_btls(ret, engine_btls_id))
	{
		ENGINE_free(ret);
		return NULL;
	}
	return ret;
}

void ENGINE_load_btls(void)
{
	ENGINE *toadd;
	if (bign_ameth)
		return;
	toadd = engine_btls();
	if (!toadd)
		return;
	ENGINE_add(toadd);
	ENGINE_free(toadd);
	ERR_clear_error();
}

#endif	/* ndef OPENSSL_NO_DYNAMIC_ENGINE */
