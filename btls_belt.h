/*!
*******************************************************************************
\file btls_belt.h
\brief Определения для алгоритмов СТБ 34.101.31 (belt)
*//****************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#ifndef __BTLS_BELT_H
#define __BTLS_BELT_H

#include <stddef.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#include "../bee2/belt.h"
#include "../bee2/brng.h"
#include "../bee2/defs.h"
#include "../bee2/err.h"

#include "btls_mem.h"

#define BELT_BLOCK_SIZE 16
#define BELT_IV_SIZE	BELT_BLOCK_SIZE
#define BELT_KEY_SIZE	32
#define BELT_MAC_SIZE	8

/* Ctrls to set belt-mac key */
#define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3) 
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4) 

struct belt_mac_pmeth_data 
{
	int key_set;
	EVP_MD *md;
	unsigned char key[BELT_KEY_SIZE];
};

/* method registration */
int register_pmeth_belt(int id, EVP_PKEY_METHOD **pmeth, int flags);
int register_ameth_belt(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info);

extern EVP_MD belt_hash;
extern EVP_MD belt_mac;
extern EVP_CIPHER belt_stream;
extern EVP_CIPHER belt_cfb;
extern EVP_CIPHER belt_ctr;
extern EVP_CIPHER belt_dwp;

#endif /* __BTLS_BELT_H */
