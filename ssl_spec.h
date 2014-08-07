#ifndef SSL_SPEC_H_INCLUDED
#define SSL_SPEC_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/ssl.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Export and cipher strength information. For each cipher we have to decide
 * whether it is exportable or not. This information is likely to change
 * over time, since the export control rules are no static technical issue.
 *
 * Independent of the export flag the cipher strength is sorted into classes.
 * SSL_EXP40 was denoting the 40bit US export limit of past times, which now
 * is at 56bit (SSL_EXP56). If the exportable cipher class is going to change
 * again (eg. to 64bit) the use of "SSL_EXP*" becomes blurred even more,
 * since SSL_EXP64 could be similar to SSL_LOW.
 * For this reason SSL_MICRO and SSL_MINI macros are included to widen the
 * namespace of SSL_LOW-SSL_HIGH to lower values. As development of speed
 * and ciphers goes, another extension to SSL_SUPER and/or SSL_ULTRA would
 * be possible.
 */
#define SSL_EXP_MASK		0x00000003L
#define SSL_NOT_EXP		0x00000001L
#define SSL_EXPORT		0x00000002L

#define SSL_STRONG_MASK		0x000000fcL
#define SSL_STRONG_NONE		0x00000004L
#define SSL_EXP40		0x00000008L
#define SSL_MICRO		(SSL_EXP40)
#define SSL_EXP56		0x00000010L
#define SSL_MINI		(SSL_EXP56)
#define SSL_LOW			0x00000020L
#define SSL_MEDIUM		0x00000040L
#define SSL_HIGH		0x00000080L

#define SSL_ALL_STRENGTHS	(SSL_EXP_MASK|SSL_STRONG_MASK)
/* we have used 000000ff - 24 bits left to go */

typedef struct algor_mask
	{
	unsigned long mask;
	} ALGOR_MASK;
typedef const ALGOR_MASK *CP_ALGOR_MASK;

#define ALGOR_MASK_set_and(mask0, mask1) (mask0).mask &= (mask1).mask
#define ALGOR_MASK_set_or(mask0, mask1) (mask0).mask |= (mask1).mask
#define ALGOR_MASK_invert(mask0) (mask0).mask = ~(mask0).mask
#define ALGOR_MASK_set_zero(mask0) (mask0).mask = 0
#define ALGOR_MASK_is_zero(mask0) ((mask0).mask == 0)
#define ALGOR_MASK_intersect(mask0, mask1) ((mask0).mask & (mask1).mask)
#define ALGOR_MASK_equal(mask0, mask1) ((mask0).mask == (mask1).mask)

#define SSL_MAX_NUM_FINISHED_DIGESTS 2
#define SSL_MAX_NUM_CERT_VERIFY_DIGESTS 2

typedef struct ssl_cipher_spec_st SSL_CIPHER_SPEC;

struct keyexch_spec_st
	{
	ALGOR_MASK mask;
	/*Family name*/
	const char *name;

	/* Returns concrete name depending on set of params. */
	const char *(*get_name) (const SSL_CIPHER_SPEC *cipher);
	int available; /* For built-in specs we define it depending on preprocessor definitions*/
	/*	int dtls1_send_client_key_exchange(SSL *s); */
	/*  int ssl3_send_client_key_exchange(SSL *s); */
	/* Prepares client key exchange and generates master secret, returns used length or (-1) on error.*/
	int (*prepare_client_key_exchange) (SSL *s, unsigned char *p);
	/* int dtls1_send_server_key_exchange(SSL *s); */
	/* int ssl3_send_server_key_exchange(SSL *s); */
	/* places ServerParams into data if it is not NULL; returns used/needed length, -1 on error */
	int (*make_server_params) (SSL *s, unsigned char *data);

	/*	int ssl3_get_key_exchange(SSL *s); */
	/* returns parsed len or (-1) on error*/
	int (*parse_server_params) (SSL *s, const unsigned char *data, int maxlen);
	/* int ssl3_get_client_key_exchange(SSL *s); */
	int (*parse_client_key_exchange) (SSL *s, unsigned char *data, long msg_len);
#if 0
	int dtls1_accept(SSL *s); /*FIXME is it necessary? */

	int ssl3_check_cert_and_algorithm(SSL *s);
	int ssl3_accept(SSL *s); /*FIXME is it necessary? */

#endif
	/* This function is called, if it is defined, for each certificate
	 * loaded into server context, which has private key
	 * It should return 1 if this certificate can be used with this
	 * ciphersuite.
	 */
	int (*ssl_cert_cipher_compat_p)(X509 *c, SSL_CIPHER_SPEC *cipher);  /*FIXME need refactoring*/
	};

struct auth_spec_st
	{
	ALGOR_MASK mask;

	/* NID(s) of digest(s) for CertificateVerify, need to calculate from the beginning */
	int md_nid[SSL_MAX_NUM_CERT_VERIFY_DIGESTS];
	/* Length of a buffer for CertificateVerify digest */
	unsigned int cert_verify_dgst_len;

	/*Family name*/
	const char *name;

	/* Returns concrete name depending on set of params. */
	const char *(*get_name) (const SSL_CIPHER_SPEC *cipher);
	int available; /* For built-in specs we define it depending on preprocessor definitions*/
	EVP_PKEY * (*get_peer_pubkey) (SSL *s);
	long (*get_and_verify_server_params) (SSL *s, unsigned char *buf, long siglen);	/* returns number of bytes rest */
	int (*authenticate_server_params) (SSL *s, unsigned char *param, int param_len, unsigned char *buf); /* places params and authenticator to buffer for ServerKeyExchange, if it is not NULL; returns full used/needed length */
#if 0
	/* int ssl3_check_cert_and_algorithm(SSL *s); */
	int certificate_requirements; /* 0 for aNULL, aDH, aKRB5,
			EVP_PK_RSA|EVP_PKT_SIGN for aRSA
			EVP_PK_DSA|EVP_PKT_SIGN for aDSS*/

	/* int dtls1_send_server_key_exchange(SSL *s); */
	/* int ssl3_send_server_key_exchange(SSL *s); */
	long (*sign_server_key_exchange) (SSL *s); /* extends s->init_buffer, returns resulting length */

	/* int ssl3_get_key_exchange_1(SSL *s); */
	/* int ssl3_get_key_exchange_2(SSL *s); */
	/* int ssl3_get_key_exchange_3(SSL *s); */
	/*FIXME aFZA is not supported, aNULL is processed in it's own case*/
	EVP_PKEY * (*get_peer_pubkey) (SSL *s);

	int ssl_cert_cipher_compat_p_1(CERT *c, SSL_CIPHER *cipher);  /*FIXME need refactoring*/
	int ssl_cert_cipher_compat_p_2(CERT *c, SSL_CIPHER *cipher);  /*FIXME need refactoring*/
	int check_srvr_ecc_cert_and_alg(X509 *x, SSL_CIPHER *cs);
	X509 *ssl_get_server_send_cert(SSL *s);
	EVP_PKEY *ssl_get_sign_pkey(SSL *s,SSL_CIPHER *cipher);
#endif

	};

struct prf_spec_st {
	ALGOR_MASK mask;
	/*Family name*/
	const char *name;

	/* Returns concrete name depending on set of params. */
	const char *(*get_name) (const SSL_CIPHER_SPEC *cipher);
	void (*PRF)(SSL *s, unsigned char *label, int label_len,
		     const unsigned char *sec, int slen, unsigned char *out,
		     unsigned char *tmp, int olen);
	unsigned int flags;
};

typedef struct keyexch_spec_st KEYEXCH_SPEC;
typedef struct auth_spec_st AUTH_SPEC;
typedef struct prf_spec_st PRF_SPEC;
typedef struct enc_spec_st ENC_SPEC;
typedef struct mac_spec_st MAC_SPEC;

///* used to hold info on the particular ciphers used */
//struct ssl_cipher_st
//{
//int valid;
//const char *name;	/* text name */
//unsigned long id;	/* id, 4 bytes, first is version */
//
///* changed in 0.9.9: these four used to be portions of a single value 'algorithms' */
//unsigned long algorithm_mkey;	/* key exchange algorithm */
//unsigned long algorithm_auth;	/* server authentication */
//unsigned long algorithm_enc;	/* symmetric encryption */
//unsigned long algorithm_mac;	/* symmetric authentication */
//unsigned long algorithm_ssl;	/* (major) protocol version */
//
//unsigned long algo_strength;	/* strength and export flags */
//unsigned long algorithm2;	/* Extra flags */
//int strength_bits;	/* Number of bits really used */
//int alg_bits;	/* Number of bits for algorithm */
//};



/* used to hold info on the particular ciphers used */
 typedef struct ssl_cipher_spec_st {
 	int valid;
 	const char *name;		/* text name */
 	unsigned long id;		/* id, 4 bytes, first is version */
	unsigned long protocol; /* what protocol version is used */
	const KEYEXCH_SPEC *kex_spec; /* Key exchange spec */
	const AUTH_SPEC *auth_spec; /* Authentication spec */
	const PRF_SPEC *prf_spec; /* PRF spec*/
	const ENC_SPEC *enc_spec; /* Encryption algorithm spec */
	const MAC_SPEC *mac_spec;			/* MAC algorithm spec */
	int finished_md_nid[SSL_MAX_NUM_FINISHED_DIGESTS]; /* NID(s) of digest(s)
														* for PRF input in
														* Finished message */
 	unsigned long algo_strength;	/* strength and export flags */
 	unsigned long algorithm2;	/* Extra flags */
 	int strength_bits;		/* Number of bits really used */
 	int alg_bits;			/* Number of bits for algorithm */
 	};

typedef struct handshake_spec_st {
	KEYEXCH_SPEC * kex_spec;
	AUTH_SPEC * auth_spec;

	int handshake_omits_cert; /*PSK, KRB5, aNULL*/
	int tmp_data_type; /* RSA, DH, ECDH ... */

#if 0
	CERT_PKEY (* get_corresponding_cert )(SSL *s);

#endif

	/* Checks whether peer cert is compatible with combination of KEX_SPEC and
	 * AUTH_SPEC. This callback is used in check_srvr_ecc_cert_and_alg() and
	 * ssl3_check_cert_and_algorithm() */
	int (*is_cert_compatible)(SSL *s);

} HANDSHAKE_SPEC;

#define ENC_SPEC_NEED_EMPTY_FRAGMENTS 0x01
struct enc_spec_st
{
	ALGOR_MASK mask;
	/*Family name*/
	const char *name;

	/* Returns concrete name depending on set of params. */
	const char *(*get_name)(const SSL_CIPHER_SPEC *cipher);
	const EVP_CIPHER *cipher;

	/*Should be 0 for RC4 && eNULL, 1 otherwise
	 *It is used in ssl3_setup_key_block() and tls1_setup_key_block() */
	unsigned int flags;

	/* In ssl3_get_client_hello() we compare cipher mask with SSL_eNULL
	 * It seems we don't need separate callback for it.*/
};

#define MAC_SPEC_STREAM_MAC 0x01
struct mac_spec_st
{
	ALGOR_MASK mask;
	/*Family name*/
	const char *name;
	/* Returns concrete name depending on set of params. */
	const char *(*get_name) (const SSL_CIPHER_SPEC *cipher);
	const EVP_MD *md;
	unsigned int flags;
};

long DSA_like_verify_server_params (SSL *s, unsigned char *buf, long restlen,
									EVP_PKEY *pkey, const EVP_MD *md);
int DSA_like_sign_server_params (SSL *s, unsigned char *param, int param_len,
								 unsigned char *buf, int pkey_type, const EVP_MD *md);

#define SSL_CIPHER_add(cs) sk_SSL_CIPHER_push(cipher_suites, (cs))
SSL_CIPHER_SPEC * SSL_CIPHER_by_id (const STACK_OF(SSL_CIPHER_SPEC) *cipher_suites, unsigned long id);

int tls1_register_cipher_suite (SSL_CIPHER_SPEC *cipher);
int tls1_unregister_cipher_suite (SSL_CIPHER_SPEC *cipher);

#ifdef __cplusplus
}
#endif

#endif // SSL_SPEC_H_INCLUDED
