/*!
*******************************************************************************
\file btls_bign.h
\brief Определения для алгоритмов СТБ 34.101.45 (bign)
*//****************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#ifndef __BTLS_BIGN_H
#define __BTLS_BIGN_H

#include <openssl/asn1t.h>
#include "btls_belt.h"
#include "btls_utl.h"
#include "../bee2/crypto/bign.h"

#define BIGN_PRIVKEY_SIZE  32
#define BIGN_PUBKEY_SIZE   64
#define BIGN_SIGN_SIZE     48

#define EVP_PKEY_CTRL_BIGN_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#define param_ctrl_string "paramset"

struct bign_pmeth_data 
{
	int param_nid; /* Should be set whenever parameters are filled */
	EVP_MD *md;
	int peer_key_used; 
	int key_set;
	unsigned char *rng_stack;
};

struct bign_key_data 
{
	bign_params params;
	int param_nid;
	octet *privKey;
	octet *pubKey;
};

#define id_bign_pubkey bign_pubkey_nid
#define id_bign_curve256v1 bign_prm1_nid
//extern int id_bign_curve384v1;
//extern int id_bign_curve512v1;
#define id_bign_primefield  bign_primefield_nid
#define id_bign_with_hbelt bign_with_hbelt_nid

typedef struct bign_key_data bign_key;

/* method registration */
int register_pmeth_bign(int id, EVP_PKEY_METHOD **pmeth, int flags);
int register_ameth_bign(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info);

int fill_bign_params(struct bign_key_data *key_data, int params_nid);

int bign_get_params_name(const bign_params* params);
int bign_i2d_params(unsigned char** out, const bign_key* key);
int bign_d2i_params(bign_key* key, const unsigned char** in, long len);

#endif /* __BTLS_BIGN_H */
