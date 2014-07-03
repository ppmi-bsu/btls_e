/*!
*******************************************************************************
\file btls_err.h
\brief Определение кодов ошибок и функций обработки ошибок
*//****************************************************************************
\author (С) Олег Соловей http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#ifndef BTLS_ERR_H
#define BTLS_ERR_H

#ifdef  __cplusplus
extern "C" {
#endif

void ERR_load_BTLS_strings(void);
void ERR_unload_BTLS_strings(void);
void ERR_BTLS_error(int function, int reason, char *file, int line);
#define ERR_BTLS(f,r) ERR_BTLS_error((f),(r),__FILE__,__LINE__)

/* Error codes for the BTLS functions. */

/* Function codes. */
#define BTLS_F_BELT_MAC_CTRL							200
#define BTLS_F_PKEY_BELT_MAC_INIT						201
#define BTLS_F_PKEY_BELT_MAC_COPY						202
#define BTLS_F_PKEY_BELT_MAC_KEYGEN						203
#define BTLS_F_BIND_BTLS								204
#define BTLS_F_BELT_CIPHER_CONTROL						205
#define BTLS_F_BELT_DWP_CONTROL							206
#define BTLS_F_EVP_PKEY_assign							207
#define BTLS_F_PKEY_BELT_MAC_CTRL						208
#define BTLS_F_PKEY_BELT_MAC_CTRL_STR					209
#define BTLS_F_DECODE_BIGN_ALGOR_PARAMS					210
#define BTLS_F_ENCODE_BIGN_ALGOR_PARAMS					211
#define BTLS_F_PRIV_DECODE_BIGN							212
#define BTLS_F_PRIV_ENCODE_BIGN							213
#define BTLS_F_PARAM_COPY_BIGN							214
#define BTLS_F_BIGN_SET_PRIV_KEY						215
#define BTLS_F_BIGN_PARAM_DECODE						216
#define BTLS_F_PUB_DECODE_BIGN							217
#define BTLS_F_PUB_ENCODE_BIGN							218
#define BTLS_F_BIGN_PUB_ENCODE							219
#define BTLS_F_BIGN_PUB_DECODE							220
#define BTLS_F_BIGN_PARAM2TYPE							221
#define BTLS_F_BIGN_TYPE2PARAM							222

/* Reason codes. */
#define BTLS_R_BAD_KEY_PARAMETERS_FORMAT				200
#define BTLS_R_BAD_PKEY_PARAMETERS_FORMAT				201
#define BTLS_R_CANNOT_PACK_EPHEMERAL_KEY				202
#define BTLS_R_CTRL_CALL_FAILED							203
#define BTLS_R_ERROR_COMPUTING_SHARED_KEY				204
#define BTLS_R_ERROR_PACKING_KEY_TRANSPORT_INFO			205
#define BTLS_R_ERROR_PARSING_KEY_TRANSPORT_INFO			206
#define BTLS_R_INCOMPATIBLE_ALGORITHMS					207
#define BTLS_R_INCOMPATIBLE_PEER_KEY					208
#define BTLS_R_INVALID_CIPHER_PARAMS					209
#define BTLS_R_INVALID_CIPHER_PARAM_OID					210
#define BTLS_R_INVALID_DIGEST_TYPE						211
#define BTLS_R_INVALID_BTLS94_PARMSET					212
#define BTLS_R_INVALID_IV_LENGTH						213
#define BTLS_R_INVALID_MAC_KEY_LENGTH					214
#define BTLS_R_INVALID_CIPHER_KEY_LENGTH				215
#define BTLS_R_INVALID_PARAMSET							216
#define BTLS_R_KEY_IS_NOT_INITALIZED					217
#define BTLS_R_KEY_PARAMETERS_MISSING					219
#define BTLS_R_MAC_KEY_NOT_SET							220
#define BTLS_R_MALLOC_FAILURE							221
#define BTLS_R_NO_MEMORY								222
#define BTLS_R_NO_PARAMETERS_SET						223
#define BTLS_R_NO_PEER_KEY								224
#define BTLS_R_NO_PRIVATE_PART_OF_NON_EPHEMERAL_KEYPAIR	225
#define BTLS_R_PUBLIC_KEY_UNDEFINED						226
#define BTLS_R_RANDOM_GENERATOR_ERROR					227
#define BTLS_R_RANDOM_GENERATOR_FAILURE					228
#define BTLS_R_RANDOM_NUMBER_GENERATOR_FAILED			229
#define BTLS_R_SIGNATURE_MISMATCH						230
#define BTLS_R_SIGNATURE_PARTS_GREATER_THAN_Q			231
#define BTLS_R_UKM_NOT_SET								233
#define BTLS_R_UNSUPPORTED_CIPHER_CTL_COMMAND			234
#define BTLS_R_UNSUPPORTED_PARAMETER_SET				235
#define BTLS_R_UNSUPPORTED_CTRL_CMD						236
#define BTLS_R_REGISTER_ERR								237
#define BTLS_R_DECODE_ERR								238
#define BTLS_R_ENCODE_ERR								239

#ifdef  __cplusplus
}
#endif
#endif
