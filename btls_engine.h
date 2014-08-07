/*!
*******************************************************************************
\file btls_engine.h
\brief Определения для встраиваемого модуля (энжайна) btls
*//****************************************************************************
\author (С) Олег Соловей, Денис Веремейчик, http://apmi.bsu.by
\created 2013.08.01
\version 2013.08.30
*******************************************************************************
*/

#ifndef __BTLS_ENG_H
#define __BTLS_ENG_H

#ifdef __cplusplus
extern "C" {
#endif

#define ENGINE_NAME "btls_e"

#undef OPENSSL_NO_DYNAMIC_ENGINE

#ifdef OPENSSL_NO_DYNAMIC_ENGINE
void ENGINE_load_btls(void);
#endif	/* OPENSSL_NO_DYNAMIC_ENGINE */
#include "ssl_spec.h"

/// TEMP functions
int CPGOST_prepare_client_key_exchange (SSL *s, unsigned char *p);
int CPGOST_parse_client_key_exchange (SSL *s, unsigned char *data, long msg_len);
int CPGOST_cert_cipher_compat_p(X509 *cert,SSL_CIPHER_SPEC *c);
int CPGOST94_cert_cipher_compat_p(X509 *cert,SSL_CIPHER_SPEC *c);
int GOST_sign_server_params (SSL *s, unsigned char *param,
									int param_len, unsigned char *buf);
long GOST_verify_server_params (SSL *s, unsigned char *buf, long restlen);
void gost_prf_func(SSL *s, unsigned char *label, int label_len,
		const unsigned char *sec, int slen, unsigned char *out,
		unsigned char *tmp, int olen);
/// Temp functions
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BTLS_ENG_H */
