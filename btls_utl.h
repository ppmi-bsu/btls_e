/*!
*******************************************************************************
\file btls_utl.h
\brief Определения для встраиваемого модуля btls 
*//****************************************************************************
\author (С) Олег Соловей, http://apmi.bsu.by
\created 2013.05.14
\version 2013.10.22
*******************************************************************************
*/
#ifndef __BTLS_UTL_H
#define __BTLS_UTL_H

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <asn1/asn1_locl.h>
#include <x509v3/x509v3.h>

extern int belt_stream_nid;
extern int belt_ctr_nid;
extern int belt_cfb_nid;
extern int belt_dwp_nid;
extern int belt_hash_nid;
extern int belt_mac_nid;

extern int bign_with_hbelt_nid;
extern int bign_pubkey_nid;
extern int bign_prm1_nid;
extern int bign_primefield_nid;

extern EVP_PKEY_METHOD *belt_mac_pmeth;
extern EVP_PKEY_METHOD *bign_pmeth;
extern EVP_PKEY_ASN1_METHOD *belt_mac_ameth;
extern EVP_PKEY_ASN1_METHOD *bign_ameth;

#endif /* __BTLS_UTL_H */

