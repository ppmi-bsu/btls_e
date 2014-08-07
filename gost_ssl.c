/**********************************************************************
 *                            gost_ssl.c                              *
 *             Copyright (c) 2005-2006 Cryptocom LTD                  *
 *         This file is distributed under same license as OpenSSL     *
 *                                                                    *
 *      SSL key exchange functions for GOST algorithms                *
 *          Requires OpenSSL 0.9.8 for compilation                    *
 **********************************************************************/
/* Returns 1 if two passed EVP_PKEYs have identical algorithms and
 * paramsets and 0 otherwise. Works only for GOST algorithms
 */
#include <openssl/evp.h>
#include "ssl_spec.h"
#include <openssl/rand.h>
#include <openssl/x509.h>
//#include "impl.h"
//#include "gost_keytrans.h"
//#include "e_gost_err.h"
/*
int same_alg_str(const EVP_PKEY *pubk, const EVP_PKEY *priv) {
	if (pubk->asymmetric->nid != priv->asymmetric->nid) return 0;
	if (pubk->asymmetric->nid == get_NID_sign_GOST2001()) {
		const EC_GROUP *priv_group = EC_KEY_get0_group(GET_ECKEY(priv));
		const EC_GROUP *pub_group  = EC_KEY_get0_group(GET_ECKEY(pubk));
		return (EC_GROUP_get_curve_name(priv_group)==EC_GROUP_get_curve_name(pub_group));

	} else if (pubk->asymmetric->nid == get_NID_sign_GOST()) {
		return !BN_cmp(pubk->pkey.dsa->q,priv->pkey.dsa->q);
	} else {
		/// Unknown asymmetric algorithm
		OPENSSL_assert(0);
	}
	return 0;
}*/
/*
 * Copies parameters from src to dest EVP_PKEY. Works only for GOST.
 */
/*
void copy_key_params(EVP_PKEY *dest, const EVP_PKEY *src) {
	OPENSSL_assert(dest->asymmetric->nid == src->asymmetric->nid);

	if (dest->asymmetric->nid == get_NID_sign_GOST2001()) {
		fill_GOST2001_params(dest->pkey.dsa,
			EC_GROUP_get_curve_name(EC_KEY_get0_group(GET_ECKEY(src))));

	} else {
		dest->pkey.dsa->p = BN_dup(src->pkey.dsa->p);
		dest->pkey.dsa->q = BN_dup(src->pkey.dsa->q);
		dest->pkey.dsa->g = BN_dup(src->pkey.dsa->g);
	}

}*/



int CPGOST_prepare_client_key_exchange (SSL *s, unsigned char *p)
{
	int ret = -1;
	int buf_len = 32;
	unsigned int hsize=32;
	unsigned char buf[32], hashval[32];
	EVP_PKEY *pubk = get_sess_cert_pubkey(s);
	GOST_CLIENT_KEY_EXCHANGE_PARAMS *gpar = NULL;
	GOST_KEY_TRANSPORT* gkt = NULL;
	EVP_MD_CTX *digest;

	/* Generate 32 random bytes*/
	RAND_pseudo_bytes(buf, buf_len);
	/* Hash client random and server random */
	digest = EVP_MD_CTX_create();
	if (!digest) {
		goto cleanup;
	}
	EVP_DigestInit(digest,EVP_get_digestbyname("md_gost94"));
	EVP_DigestUpdate(digest,s->s3->client_random,SSL3_RANDOM_SIZE);
	EVP_DigestUpdate(digest,s->s3->server_random,SSL3_RANDOM_SIZE);
	EVP_DigestFinal_ex(digest,hashval,&hsize);
	EVP_MD_CTX_destroy(digest);

	if (EVP_PKEY_get_save_type(pubk) == get_NID_sign_GOST2001()) {
		if ((gkt = make_rfc4490_keytransport_2001(pubk,buf,32,hashval,8,"cp_cipher_param_a"))==NULL) {

			goto cleanup;
		}
	} else if (EVP_PKEY_get_save_type(pubk) == get_NID_sign_GOST()) {
		if ((gkt = make_rfc4490_keytransport_94(pubk,buf,32,hashval,8,"cp_cipher_param_a"))==NULL) {
			goto cleanup;
		}
	}	 else {
			GOSTerr("GOST_F_CPGOST_PREPARE_CLIENT_KEY_EXCHANGE",
				"GOST_R_ALGORITHM_IS_NOT_SUPPORTED_FOR_THIS_CIPHERSUITE");
			goto cleanup;
	}
	gpar = GOST_CLIENT_KEY_EXCHANGE_PARAMS_new();
	GOST_KEY_TRANSPORT_free(gpar->gkt);
	gpar->gkt = gkt;
	ret = i2d_GOST_CLIENT_KEY_EXCHANGE_PARAMS(gpar,&p);
	s->session->master_key_length=GenerateMasterSecret(s,
			s->session->master_key,buf,buf_len);
cleanup:
	EVP_PKEY_free(pubk);
	GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar);
	return ret;
}

int CPGOST_parse_client_key_exchange (SSL *s, unsigned char *data, long msg_len)
{

	GOST_CLIENT_KEY_EXCHANGE_PARAMS *gpar = NULL;
	EVP_PKEY *priv= get_sess_DSA_privkey(s);
	unsigned char key_buf[32];
	unsigned char *tmp = data;
	int key_buf_len =32;

	gpar=d2i_GOST_CLIENT_KEY_EXCHANGE_PARAMS(NULL,
				(const unsigned char **)&tmp, msg_len);

	if ( !gpar )
	{
		GOSTerr (GOST_F_CPGOST_PARSE_CLIENT_KEY_EXCHANGE,
			GOST_R_ERROR_UNPACKING_ASN1_STRUCTURE);
		return -1;
	}
	s->client_cert_used_for_exchange =0;
	if (s->session->peer && !gpar->gkt->key_agreement_info->ephem_key) {
		s->client_cert_used_for_exchange = 1;
		{
			EVP_PKEY *peer_key = X509_get_pubkey(s->session->peer);
			if (!peer_key) {
				GOSTerr(GOST_F_CPGOST_PARSE_CLIENT_KEY_EXCHANGE,
					GOST_R_KEY_IS_NOT_INITIALIZED);
					return -1;
			}

		X509_PUBKEY_set(&(gpar->gkt->key_agreement_info->ephem_key),peer_key);
		EVP_PKEY_free (peer_key);
		}

	}
	if (!gpar->gkt->key_agreement_info->ephem_key) {
		GOSTerr(GOST_F_CPGOST_PARSE_CLIENT_KEY_EXCHANGE,
			GOST_R_MISSING_EXCHANGE_KEY);
        GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar); // PIT
		return -1;
	}

	if (EVP_PKEY_get_save_type(priv) == get_NID_sign_GOST2001()) {
		if (decrypt_rfc4490_shared_key_2001(priv,gpar->gkt,key_buf,key_buf_len)<=0)
		{
			GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar);
			return -1;
		}
	} else if (EVP_PKEY_get_save_type(priv) == get_NID_sign_GOST()) {
		if (decrypt_rfc4490_shared_key_94(priv,gpar->gkt,key_buf,key_buf_len)<=0)
		{
			if (gpar)
			GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar);
			return -1;
		}

	} else {
			GOSTerr(GOST_F_CPGOST_PARSE_CLIENT_KEY_EXCHANGE,
				GOST_R_ALGORITHM_IS_NOT_SUPPORTED_FOR_THIS_CIPHERSUITE);
			GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar);
			return -1;
	}
	s->session->master_key_length= GenerateMasterSecret(s,
			s->session->master_key,key_buf,key_buf_len);

	GOST_CLIENT_KEY_EXCHANGE_PARAMS_free(gpar);
	return 1;
}

long GOST_verify_server_params (SSL *s, unsigned char *buf, long restlen)
	{
	return DSA_like_verify_server_params(s, buf, restlen, auth_spec_GOST.get_peer_pubkey(s), &digest_gost);
	}

int GOST_sign_server_params (SSL *s, unsigned char *param,
									int param_len, unsigned char *buf)
	{
	return DSA_like_sign_server_params(s, param, param_len, buf, EVP_PKEY_DSA,
									   &digest_gost);
	}


int CPGOST_cert_cipher_compat_p(X509 *cert,SSL_CIPHER_SPEC *c)
	{
	EVP_PKEY *key = X509_get_pubkey(cert);
	int algtype;
	if (!key) {
		GOSTerr(GOST_F_CPGOST_CERT_CIPHER_COMPAT_P,
			GOST_R_KEY_IS_NOT_INITIALIZED);
		return 0;
	}
	algtype = EVP_PKEY_get_save_type(key);
	EVP_PKEY_free(key);
	if (algtype == get_NID_sign_GOST2001())
		{
		 return 1;
		}
		else
		{
		return 0;
		}
	}


int CPGOST94_cert_cipher_compat_p(X509 *cert,SSL_CIPHER_SPEC *c)
	{
	EVP_PKEY *key = X509_get_pubkey(cert);
	int algtype;
	if (key == NULL)
	{
		GOSTerr(GOST_F_CPGOST94_CERT_CIPHER_COMPAT_P,
			GOST_R_KEY_IS_NOT_INITIALIZED);
		return 0;
	}
	algtype = EVP_PKEY_get_save_type(key);
	EVP_PKEY_free(key);
	if (algtype == get_NID_sign_GOST())
		{
		 return 1;
		}
		else
		{
		return 0;
		}
	}

void gost_prf_func(SSL *s, unsigned char *label, int label_len,
		const unsigned char *sec, int slen, unsigned char *out,
		unsigned char *tmp, int olen)
{

	const EVP_MD *md = EVP_get_digestbyname("md_gost94");
	HMAC_CTX ctx1,ctx2;
	int chunk,j;
	unsigned char A1[EVP_MAX_MD_SIZE];
	unsigned int A1_len;

	chunk = EVP_MD_size(md);
	HMAC_CTX_init(&ctx1);
	HMAC_CTX_init(&ctx2);
	HMAC_Init_ex(&ctx1,sec,slen,md,NULL);
	HMAC_Init_ex(&ctx2,sec,slen,md,NULL);
	HMAC_Update(&ctx1,label,label_len);
	HMAC_Final(&ctx1,A1,&A1_len);


	for (;;)
	{
		HMAC_Init_ex(&ctx1,NULL,0,NULL,NULL);
		HMAC_Init_ex(&ctx2,NULL,0,NULL,NULL);
		HMAC_Update(&ctx1,A1,A1_len);
		HMAC_Update(&ctx2,A1,A1_len);
		HMAC_Update(&ctx1,label,label_len);
		if (olen > chunk)
		{
			HMAC_Final(&ctx1,out,&j);
			out +=j;
			olen -=j;
			HMAC_Final(&ctx2,A1,&A1_len);
		} else {
			HMAC_Final(&ctx1,A1,&A1_len);
			memcpy(out,A1,olen);
			break;
		}
	}
	HMAC_CTX_cleanup(&ctx1);
	HMAC_CTX_cleanup(&ctx2);
	OPENSSL_cleanse(A1,sizeof(A1));
}
