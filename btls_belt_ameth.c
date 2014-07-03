/*
*******************************************************************************
\file btls_belt_ameth.c
\brief Форматы данных для алгоритмов belt
*******************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.07.01
\version 2013.09.26
*******************************************************************************
*/
#include "btls_belt.h"

static void mackey_free_belt(EVP_PKEY *pk) 
{
	if (pk->pkey.ptr) 
	{
		OPENSSL_free(pk->pkey.ptr);
		pk->pkey.ptr = NULL;
	}
}

static int mac_ctrl_belt(EVP_PKEY *pkey, int op, long arg1, void *arg2) 
{
	switch (op) 
	{
	case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
		*(int *) arg2 = belt_mac.type;
		return 2;
	}
	return -2;
}

int register_ameth_belt(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info) 
{
	*ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
	if (!*ameth) return 0;

	if (nid == belt_mac.type) 
	{
		EVP_PKEY_asn1_set_free(*ameth, mackey_free_belt);
		EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_belt);
	}
	else
	{
		EVP_PKEY_asn1_free(*ameth);
		return 0;
	}

	return 1;
}