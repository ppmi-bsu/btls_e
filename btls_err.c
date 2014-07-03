/*
*******************************************************************************
\file btls_err.c
\brief Управление ошибками
*******************************************************************************
\author (С) Олег Соловей, http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#include <stdio.h>
#include <openssl/err.h>
#include "btls_err.h"

#define BTLS_LIB_NAME "btls engine"

/* BEGIN ERROR CODES */
#ifndef OPENSSL_NO_ERR

#define ERR_FUNC(func) ERR_PACK(0,func,0)
#define ERR_REASON(reason) ERR_PACK(0,0,reason)

static ERR_STRING_DATA BTLS_str_functs[]= {
{ERR_FUNC(BTLS_F_BELT_MAC_CTRL),	 		"BELT_MAC_CTRL"},
{ERR_FUNC(BTLS_F_PKEY_BELT_MAC_INIT),	 	"PKEY_BELT_MAC_INIT"},
{ERR_FUNC(BTLS_F_PKEY_BELT_MAC_COPY),		"BELT_MAC_COPY"},
{ERR_FUNC(BTLS_F_PKEY_BELT_MAC_KEYGEN),		"BELT_MAC_KEYGEN"},
{ERR_FUNC(BTLS_F_BIND_BTLS),				"BIND_BTLS"},
{ERR_FUNC(BTLS_F_BELT_CIPHER_CONTROL),		"BTLS_F_BELT_CIPHER_CONTROL"},
{ERR_FUNC(BTLS_F_BELT_DWP_CONTROL),			"BTLS_F_BELT_DWP_CONTROL"},
{ERR_FUNC(BTLS_F_EVP_PKEY_assign),		"BTLS_F_EVP_PKEY_assign"},
{ERR_FUNC(BTLS_F_PKEY_BELT_MAC_CTRL),		"BTLS_F_PKEY_BELT_MAC_CTRL"},
{ERR_FUNC(BTLS_F_PKEY_BELT_MAC_CTRL_STR),	"BTLS_F_PKEY_BELT_MAC_CTRL_STR"},
{ERR_FUNC(BTLS_F_DECODE_BIGN_ALGOR_PARAMS),  "BTLS_F_DECODE_BIGN_ALGOR_PARAMS"},
{ERR_FUNC(BTLS_F_ENCODE_BIGN_ALGOR_PARAMS), "BTLS_F_ENCODE_BIGN_ALGOR_PARAMS"},
{ERR_FUNC(BTLS_F_PRIV_DECODE_BIGN),			"BTLS_F_PRIV_DECODE_BIGN"},
{ERR_FUNC(BTLS_F_PRIV_ENCODE_BIGN),			"BTLS_F_PRIV_ENCODE_BIGN"},
{ERR_FUNC(BTLS_F_PARAM_COPY_BIGN),			"BTLS_F_PARAM_COPY_BIGN"},
{ERR_FUNC(BTLS_F_BIGN_SET_PRIV_KEY),		"BTLS_F_BIGN_SET_PRIV_KEY"},
{ERR_FUNC(BTLS_F_BIGN_PARAM_DECODE),		"BTLS_F_BIGN_PARAM_DECODE"},
{ERR_FUNC(BTLS_F_PUB_DECODE_BIGN),			"BTLS_F_PUB_DECODE_BIGN"},
{ERR_FUNC(BTLS_F_PUB_ENCODE_BIGN),			"BTLS_F_PUB_ENCODE_BIGN"},
{0,NULL}};

static ERR_STRING_DATA BTLS_str_reasons[]= {
{ERR_REASON(BTLS_R_BAD_KEY_PARAMETERS_FORMAT),"bad key parameters format"},
{ERR_REASON(BTLS_R_BAD_PKEY_PARAMETERS_FORMAT),"bad pkey parameters format"},
{ERR_REASON(BTLS_R_CANNOT_PACK_EPHEMERAL_KEY),"cannot pack ephemeral key"},
{ERR_REASON(BTLS_R_CTRL_CALL_FAILED)     ,"ctrl call failed"},
{ERR_REASON(BTLS_R_ERROR_COMPUTING_SHARED_KEY),"error computing shared key"},
{ERR_REASON(BTLS_R_ERROR_PACKING_KEY_TRANSPORT_INFO),"error packing key transport info"},
{ERR_REASON(BTLS_R_ERROR_PARSING_KEY_TRANSPORT_INFO),"error parsing key transport info"},
{ERR_REASON(BTLS_R_INCOMPATIBLE_ALGORITHMS),"incompatible algorithms"},
{ERR_REASON(BTLS_R_INCOMPATIBLE_PEER_KEY),"incompatible peer key"},
{ERR_REASON(BTLS_R_INVALID_CIPHER_PARAMS),"invalid cipher params"},
{ERR_REASON(BTLS_R_INVALID_CIPHER_PARAM_OID),"invalid cipher param oid"},
{ERR_REASON(BTLS_R_INVALID_DIGEST_TYPE)  ,"invalid digest type"},
{ERR_REASON(BTLS_R_INVALID_BTLS94_PARMSET),"invalid gost94 parmset"},
{ERR_REASON(BTLS_R_INVALID_IV_LENGTH)    ,"invalid iv length"},
{ERR_REASON(BTLS_R_INVALID_MAC_KEY_LENGTH),"invalid mac key length"},
{ERR_REASON(BTLS_R_INVALID_CIPHER_KEY_LENGTH), "invalid cipher key length"},
{ERR_REASON(BTLS_R_INVALID_PARAMSET)     ,"invalid paramset"},
{ERR_REASON(BTLS_R_KEY_IS_NOT_INITALIZED),"key is not initalized"},
{ERR_REASON(BTLS_R_KEY_PARAMETERS_MISSING),"key parameters missing"},
{ERR_REASON(BTLS_R_MAC_KEY_NOT_SET)      ,"mac key not set"},
{ERR_REASON(BTLS_R_MALLOC_FAILURE)       ,"malloc failure"},
{ERR_REASON(BTLS_R_NO_MEMORY)            ,"no memory"},
{ERR_REASON(BTLS_R_NO_PARAMETERS_SET)    ,"no parameters set"},
{ERR_REASON(BTLS_R_NO_PEER_KEY)          ,"no peer key"},
{ERR_REASON(BTLS_R_NO_PRIVATE_PART_OF_NON_EPHEMERAL_KEYPAIR),"no private part of non ephemeral keypair"},
{ERR_REASON(BTLS_R_PUBLIC_KEY_UNDEFINED) ,"public key undefined"},
{ERR_REASON(BTLS_R_RANDOM_GENERATOR_ERROR),"random generator error"},
{ERR_REASON(BTLS_R_RANDOM_GENERATOR_FAILURE),"random generator failure"},
{ERR_REASON(BTLS_R_RANDOM_NUMBER_GENERATOR_FAILED),"random number generator failed"},
{ERR_REASON(BTLS_R_SIGNATURE_MISMATCH)   ,"signature mismatch"},
{ERR_REASON(BTLS_R_SIGNATURE_PARTS_GREATER_THAN_Q),"signature parts greater than q"},
{ERR_REASON(BTLS_R_UKM_NOT_SET)          ,"ukm not set"},
{ERR_REASON(BTLS_R_UNSUPPORTED_CIPHER_CTL_COMMAND),"unsupported cipher ctl command"},
{ERR_REASON(BTLS_R_UNSUPPORTED_PARAMETER_SET),"unsupported parameter set"},
{ERR_REASON(BTLS_R_UNSUPPORTED_CTRL_CMD), "unsupported control function mode"},
{ERR_REASON(BTLS_R_REGISTER_ERR), "register nid error"},
{ERR_REASON(BTLS_R_DECODE_ERR), "decode error"},
{ERR_REASON(BTLS_R_ENCODE_ERR), "encode error"},
{0,NULL}};
#endif

#ifdef BTLS_LIB_NAME
static ERR_STRING_DATA BTLS_lib_name[]= {
	{0,BTLS_LIB_NAME},
	{0,NULL}};
#endif

static int BTLS_lib_error_code = 0;
static int BTLS_error_init = 1;

void ERR_load_BTLS_strings(void)
{
	if (BTLS_lib_error_code == 0)
		BTLS_lib_error_code = ERR_get_next_error_library();

	if (BTLS_error_init)
	{
		BTLS_error_init = 0;
#ifndef OPENSSL_NO_ERR
		ERR_load_strings(BTLS_lib_error_code, BTLS_str_functs);
		ERR_load_strings(BTLS_lib_error_code, BTLS_str_reasons);
#endif

#ifdef BTLS_LIB_NAME
		BTLS_lib_name->error = ERR_PACK(BTLS_lib_error_code,0,0);
		ERR_load_strings(0, BTLS_lib_name);
#endif
	}
}

void ERR_unload_BTLS_strings(void)
{
	if (BTLS_error_init == 0)
	{
#ifndef OPENSSL_NO_ERR
		ERR_unload_strings(BTLS_lib_error_code, BTLS_str_functs);
		ERR_unload_strings(BTLS_lib_error_code, BTLS_str_reasons);
#endif

#ifdef BTLS_LIB_NAME
		ERR_unload_strings(0, BTLS_lib_name);
#endif
		BTLS_error_init=1;
	}
}

void ERR_BTLS_error(int function, int reason, char *file, int line)
{
	if (BTLS_lib_error_code == 0)
		BTLS_lib_error_code = ERR_get_next_error_library();
	ERR_PUT_error(BTLS_lib_error_code, function, reason, file, line);
}
