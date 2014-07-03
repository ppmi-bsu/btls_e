/*
*******************************************************************************
\file btls_bign_asn1.c
\brief Структуры АСН.1, описывающие параметры и ключи bign
*******************************************************************************
\author (С) Сергей Агиевич, http://apmi.bsu.by
\comment Адаптация модуля openssl/crypto/ec/ec_asn1 [автор Nils Larsch]
\created 2013.11.01
\version 2014.04.04
*******************************************************************************
*/
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "bee2evp_err.h"
#include "btls_bign.h"
#include "../bee2/mem.h"

/*
*******************************************************************************
Реализована поддержка следующих структур ASN.1, описанных 
в СТБ 34.101.45 [приложение Д]:

  AlgorithmIdentifier ::= SEQUENCE {
    algorithm   OBJECT IDENTIFIER,
    parameters  ANY DEFINED BY algorithm OPTIONAL
  }

  DomainParameters ::= CHOICE {
    specified  ECParameters,
    named      OBJECT IDENTIFIER,
    implicit   NULL
  }

  ECParameters ::= SEQUENCE {
    version  INTEGER {ecpVer1(1)} (ecpVer1),
    fieldID  FieldID,
    curve    Curve,
    base     OCTET STRING (SIZE(32|48|64)),
    order    INTEGER,
    cofactor INTEGER (1) OPTIONAL
  }

  FieldID ::= SEQUENCE {
    fieldType   OBJECT IDENTIFIER (bign-primefield),
    parameters  INTEGER
  } 

  Curve ::= SEQUENCE {
    a     OCTET STRING (SIZE(32|48|64)),
    b     OCTET STRING (SIZE(32|48|64)),
    seed  BIT STRING (SIZE(64))
  }

  PublicKey ::= BIT STRING (SIZE(512|768|1024))

  SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm         AlgorithmIdentifier,
    subjectPublicKey  PublicKey
  }

Дополнительно поддерживается описание личного ключа, заданное в СТБ П 34.101.45
и соответствующее стандартам SEC 1:

  PrivateKey ::= SEQUENCE {
    privateKey  OCTET STRING (SIZE(32|48|64)),
    parameters  DomainParameters OPTIONAL,
    publicKey   BIT STRING (SIZE(512|768|1024)) OPTIONAL 
  }

*******************************************************************************
*/

typedef struct
{
	ASN1_OBJECT* fieldType;
	ASN1_INTEGER* prime;
} BIGN_FIELDID;

typedef struct
{
	ASN1_OCTET_STRING* a;
	ASN1_OCTET_STRING* b;
	ASN1_BIT_STRING* seed;
} BIGN_CURVE;

typedef struct
{
	long version;
	BIGN_FIELDID* fieldID;
	BIGN_CURVE* curve;
	ASN1_OCTET_STRING* base;
	ASN1_INTEGER* order;
	ASN1_INTEGER* cofactor;
} BIGN_ECPARAMS;

typedef struct
{
	int	type;
	union {
		ASN1_OBJECT* named;
		BIGN_ECPARAMS* specified;
		ASN1_NULL* implicit;
	} value;
} BIGN_DOMAINPARAMS;

typedef struct 
{
	long version;
	ASN1_OCTET_STRING* privateKey;
    BIGN_DOMAINPARAMS* parameters;
	ASN1_BIT_STRING* publicKey;
} BIGN_PRIVATEKEY;

ASN1_SEQUENCE(BIGN_FIELDID) = 
{
	ASN1_SIMPLE(BIGN_FIELDID, fieldType, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_FIELDID, prime, ASN1_INTEGER)
} 
ASN1_SEQUENCE_END(BIGN_FIELDID)

ASN1_SEQUENCE(BIGN_CURVE) = 
{
	ASN1_SIMPLE(BIGN_CURVE, a, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_CURVE, b, ASN1_OCTET_STRING),
	ASN1_OPT(BIGN_CURVE, seed, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(BIGN_CURVE)

ASN1_SEQUENCE(BIGN_ECPARAMS) = 
{
	ASN1_SIMPLE(BIGN_ECPARAMS, version, LONG),
	ASN1_SIMPLE(BIGN_ECPARAMS, fieldID, BIGN_FIELDID),
	ASN1_SIMPLE(BIGN_ECPARAMS, curve, BIGN_CURVE),
	ASN1_SIMPLE(BIGN_ECPARAMS, base, ASN1_OCTET_STRING),
	ASN1_SIMPLE(BIGN_ECPARAMS, order, ASN1_INTEGER),
	ASN1_OPT(BIGN_ECPARAMS, cofactor, ASN1_INTEGER) 
} ASN1_SEQUENCE_END(BIGN_ECPARAMS)

DECLARE_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(BIGN_ECPARAMS)

ASN1_CHOICE(BIGN_DOMAINPARAMS) = 
{
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.named, ASN1_OBJECT),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.specified, BIGN_ECPARAMS),
	ASN1_SIMPLE(BIGN_DOMAINPARAMS, value.implicit, ASN1_NULL)
} ASN1_CHOICE_END(BIGN_DOMAINPARAMS)

DECLARE_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(BIGN_DOMAINPARAMS, BIGN_DOMAINPARAMS)
IMPLEMENT_ASN1_FUNCTIONS_const(BIGN_DOMAINPARAMS)

ASN1_SEQUENCE(BIGN_PRIVATEKEY) = {
	ASN1_SIMPLE(BIGN_PRIVATEKEY, version, LONG),
	ASN1_SIMPLE(BIGN_PRIVATEKEY, privateKey, ASN1_OCTET_STRING),
	ASN1_EXP_OPT(BIGN_PRIVATEKEY, parameters, BIGN_DOMAINPARAMS, 0),
	ASN1_EXP_OPT(BIGN_PRIVATEKEY, publicKey, ASN1_BIT_STRING, 1)
} ASN1_SEQUENCE_END(BIGN_PRIVATEKEY)

DECLARE_ASN1_FUNCTIONS_const(BIGN_PRIVATEKEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_const(BIGN_PRIVATEKEY, BIGN_PRIVATEKEY)
IMPLEMENT_ASN1_FUNCTIONS_const(BIGN_PRIVATEKEY)

/*
*******************************************************************************
Расширение модуля bee2/bign

\pre Параметры функции bign_cmp_params() корректны. Поэтому можно сравнивать 
только тройки (p, a, b) [все остальные поля определяются по этой тройке].
*******************************************************************************
*/

static int bign_cmp_params(const bign_params* params1, 
	const bign_params* params2)
{
	return (params1 && params2 && 
		params1->l <= 256 && params1->l == params2->l &&
		memCmp(params1->p, params2->p, params1->l / 4) == 0 &&
		memCmp(params1->a, params2->a, params1->l / 4) == 0 &&
		memCmp(params1->b, params2->b, params1->l / 4) == 0);
}

int bign_get_params_name(const bign_params* params)
{
	bign_params std;

	if (!params)
		return 0;
	if (bignStdParams(&std, "1.2.112.0.2.0.34.101.45.3.1") != ERR_SUCCESS)
		return 0;
	if (bign_cmp_params(params, &std))
		return id_bign_curve256v1;
	/*if (bignStdParams(&std, "1.2.112.0.2.0.34.101.45.3.2") != ERR_SUCCESS)
		return 0;
	if (bign_cmp_params(params, &std))
		return id_bign_curve384v1;
	if (bignStdParams(&std, "1.2.112.0.2.0.34.101.45.3.3") != ERR_SUCCESS)
		return 0;
	if (bign_cmp_params(params, &std))
		return id_bign_curve512v1;*/
	return 0;
}

int bign_params_by_name(bign_params* params, int nid)
{
	char* oid = NULL;

	if (!params)
		return 0;
	if (nid == id_bign_curve256v1)
		oid = "1.2.112.0.2.0.34.101.45.3.1";
	/*else if (nid == id_bign_curve384v1)
		oid = "1.2.112.0.2.0.34.101.45.3.2";
	else if (nid == id_bign_curve512v1)
		oid = "1.2.112.0.2.0.34.101.45.3.3";*/
	else
		return 0;
	return bignStdParams(params, oid) == ERR_SUCCESS;
}

/*
*******************************************************************************
Запись параметров bign_params в структуры ASN1
*******************************************************************************
*/

static int bign_asn1_params2fieldid(BIGN_FIELDID* field, 
	const bign_params* params)
{
	int ok = 0;
	BIGNUM* p = NULL;
	octet rev[64];
	// минимальный входной контроль
	if (!params || !field)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2FIELDID, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// подготовить field
	if (field->fieldType)
		ASN1_OBJECT_free(field->fieldType);
	if (field->prime)
		ASN1_INTEGER_free(field->prime);
	// установить fieldType
	if (!(field->fieldType = OBJ_nid2obj(id_bign_primefield)))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2FIELDID, ERR_R_OBJ_LIB);
		goto err;
	}
	// установить prime
	memCopy(rev, params->p, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(p = BN_new()) || !BN_bin2bn(rev, params->l / 4, p))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2FIELDID, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	field->prime = BN_to_ASN1_INTEGER(p, NULL);
	if (!field->prime)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2FIELDID, ERR_R_ASN1_LIB);
		goto err;
	}
	ok = 1;
	// выход
err:
	p ? OPENSSL_free(p) : 0;
	memSetZero(rev, sizeof(rev));
	return ok;
}

static int bign_asn1_params2curve(BIGN_CURVE* curve, const bign_params* params)
{
	// входной контроль
	if (!params || !curve || !curve->a || !curve->b)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2CURVE, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}

	// установить a и b
	if (!M_ASN1_OCTET_STRING_set(curve->a, params->a, params->l / 4) ||
	    !M_ASN1_OCTET_STRING_set(curve->b, params->b, params->l / 4))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2CURVE, ERR_R_ASN1_LIB);
		return 0;
	}

	// установить seed (optional)
	if (!curve->seed && !(curve->seed = ASN1_BIT_STRING_new()))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2CURVE, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	curve->seed->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 7);
	curve->seed->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	if (!ASN1_BIT_STRING_set(curve->seed, (unsigned char*)params->seed, 8))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2CURVE, ERR_R_ASN1_LIB);
		return 0;
	}
	return 1;
}

static BIGN_ECPARAMS* bign_asn1_params2ecp(BIGN_ECPARAMS* ecp, 
	const bign_params* params)
{
	int	ok = 0;
	BIGN_ECPARAMS* ret = ecp;
	BIGNUM* order = NULL;
	octet rev[64];
	// входной контроль
	if (!params)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// подготовить возврат
	if (!ret && !(ret = BIGN_ECPARAMS_new()))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	// установить версию (всегда 1)
	ret->version = (long)1;
	// установить fieldID
	if (!bign_asn1_params2fieldid(ret->fieldID, params))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_EC_LIB);
		goto err;
	}
	// установить кривую
	if (!bign_asn1_params2curve(ret->curve, params))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_EC_LIB);
		goto err;
	}
	
	// установить базовую точку
	if (!M_ASN1_OCTET_STRING_set(ret->base, params->yG, params->l / 4))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_ASN1_LIB);
		goto err;
	}
	// установить порядок
	memCopy(rev, params->q, params->l / 4);
	memRev(rev, params->l / 4);
	if (!(order = BN_new()) || !BN_bin2bn(rev, params->l / 4, order))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	ret->order = BN_to_ASN1_INTEGER(order, NULL);
	if (!ret->order)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_ASN1_LIB);
		goto err;
	}
	// установить кофактор (optional, всегда 1)
	//if (!ASN1_INTEGER_set(ret->cofactor, (long)1))
	//{
	//	BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2ECP, ERR_R_ASN1_LIB);
	//	goto err;
	//}
	ok = 1;

err:	
	if (!ok)
	{
		if (ret && !ecp)
			BIGN_ECPARAMS_free(ret);
		ret = NULL;
	}
	order ? BN_free(order) : 0;
	memSetZero(rev, sizeof(rev));
	return ret;
}

BIGN_DOMAINPARAMS* bign_asn1_params2dp(BIGN_DOMAINPARAMS* dp, 
	const bign_params* params)
{
	int ok = 1, nid;
	BIGN_DOMAINPARAMS* ret = dp;
	// входной контроль
	if (!params)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2DP, ERR_R_PASSED_NULL_PARAMETER);
		return NULL;
	}
	// подготовка возврата
	if (ret)
	{
		if (ret->type == 0 && ret->value.named)
			ASN1_OBJECT_free(ret->value.named);
		else if (ret->type == 1 && ret->value.specified)
			BIGN_ECPARAMS_free(ret->value.specified);
	}
	else if (!(ret = BIGN_DOMAINPARAMS_new()))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMS2DP, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	// стандартные параметры?
	if ((nid = bign_get_params_name(params)))
	{
		ret->type = 0;
		if (!(ret->value.named = OBJ_nid2obj(nid)))
			ok = 0;
	}
	// обшие параметры
	else
	{	
		ret->type = 1;
		if (!(ret->value.specified = bign_asn1_params2ecp(NULL, params)))
			ok = 0;
	}
	if (!ok)
	{
		BIGN_DOMAINPARAMS_free(ret);
		return NULL;
	}
	return ret;
}

/*
*******************************************************************************
Чтение параметров bign_params из структур ASN1
*******************************************************************************
*/

static int bign_asn1_ecp2params(bign_params* params, const BIGN_ECPARAMS* ecp)
{
	int ok = 0;
	BIGNUM* p = NULL;
	// входной контроль
	if (!params || !ecp)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	memSetZero(params, sizeof(bign_params));
	// разобрать описание поля GF(p)
	if (!ecp->fieldID || 
		!ecp->fieldID->fieldType || 
		OBJ_obj2nid(ecp->fieldID->fieldType) != id_bign_primefield ||
		!ecp->fieldID->prime)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2GROUP, BEE2EVP_R_ASN1_ERROR);
		goto err;
	}
	p = ASN1_INTEGER_to_BN(ecp->fieldID->prime, NULL);
	if (!p)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, ERR_R_ASN1_LIB);
		goto err;
	}
	if (BN_is_negative(p) || BN_is_zero(p) ||
		(params->l = (size_t)BN_num_bits(p)) != 256 && 
			params->l != 384 && params->l != 512)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMETERS2GROUP, 
			BEE2EVP_R_INVALID_FIELD);
		goto err;
	}
	params->l /= 2;
	// загрузить p
	if (!BN_bn2bin(p, params->p))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
		goto err;
	}
	memRev(params->p, params->l / 4);
	// загрузить a и b
	if (!ecp->curve || 
		!ecp->curve->a || !ecp->curve->a->data || 
		!ecp->curve->b || !ecp->curve->b->data ||
		ecp->curve->a->length != params->l / 4 ||
		ecp->curve->b->length != params->l / 4)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, BEE2EVP_R_ASN1_ERROR);
		goto err;
	}
	memCopy(params->a, ecp->curve->a->data, params->l / 4);
	memCopy(params->b, ecp->curve->b->data, params->l / 4);
	// загрузить seed (optional)
	if (ecp->curve->seed)
	{
		if (ecp->curve->seed->length != 8)
		{
			BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, BEE2EVP_R_ASN1_ERROR);
			goto err;
		}
		memCopy(params->seed, ecp->curve->seed->data, 8);
	}
	// загрузить base
	if (!ecp->base || !ecp->base->data || ecp->base->length != params->l / 4)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, BEE2EVP_R_ASN1_ERROR);
		goto err;
	}
	memCopy(params->yG, ecp->base->data, params->l / 4);
	// загрузить order
	if ((p = ASN1_INTEGER_to_BN(ecp->order, p)) == NULL)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, ERR_R_ASN1_LIB);
		goto err;
	}
	if (BN_is_negative(p) || BN_is_zero(p) || 
		BN_num_bits(p) != (int)params->l * 2)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, 
			BEE2EVP_R_INVALID_GROUP_ORDER);
		goto err;
	}
	if (!BN_bn2bin(p, params->q))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PARAMETERS2GROUP, ERR_R_BN_LIB);
		goto err;
	}
	memRev(params->q, params->l / 4);
	// загрузить cofactor (optional)
	if (ecp->cofactor)
	{
		if (!(p = ASN1_INTEGER_to_BN(ecp->cofactor, p)) ||
			!BN_is_one(p))
		{
			BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_ECP2PARAMS, ERR_R_ASN1_LIB);
			goto err;
		}
	}
	ok = 1;

err:
	p ? BN_free(p) : 0;
	return ok;
}

static int bign_asn1_dp2params(bign_params* params, 
	const BIGN_DOMAINPARAMS* dp)
{
	// входной контроль
	if (!params || !dp)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_DP2PARAMS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// стандартные параметры?
	if (dp->type == 0)
	{ 
		if (!bign_params_by_name(params, OBJ_obj2nid(dp->value.named)))
		{
			BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_DP2PARAMS, 
				BEE2EVP_R_PARAMS_NEW_BY_NAME_FAILURE);
			return 0;
		}
	}
	// общие параметры?
	else if (dp->type == 1)
	{ 
		if (!bign_asn1_ecp2params(params, dp->value.specified))
		{
			BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PKPARAMETERS2GROUP, ERR_R_EC_LIB);
			return 0;
		}
	}
	// наследованные параметры?
	else if (dp->type == 2)
	{ 
		return 0;
	}
	// неверные параметры?
	else
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_ASN1_PKPARAMETERS2GROUP, 
			BEE2EVP_R_ASN1_ERROR);
		return 0;
	}
	return 1;
}

/*
*******************************************************************************
Кодирование и декодирование параметров, вложенных в bign_key

\remark Параметры задаются типом DomainParameters [BIGN_DOMAINPARAMS]
*******************************************************************************
*/
int bign_d2i_params(bign_key* key, const unsigned char** in, long len)
{
	BIGN_DOMAINPARAMS* dp;
	// входной контроль
	if (!key)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_D2I_DOMAINPARAMS, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// декодировать в dp
	if (!(dp = d2i_BIGN_DOMAINPARAMS(NULL, in, len)))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_D2I_DOMAINPARAMS, 
			BEE2EVP_R_D2I_PARAMS_FAILURE);
		BIGN_DOMAINPARAMS_free(dp);
		return 0;
	}
	// разобрать dp
	if (!bign_asn1_dp2params(&key->params, dp))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_D2I_DOMAINPARAMS, 
			BEE2EVP_R_DP2PARAMS_FAILURE);
		BIGN_DOMAINPARAMS_free(dp);
		return 0; 
	}
	BIGN_DOMAINPARAMS_free(dp);
	return 1;
}

int bign_i2d_params(unsigned char** out, const bign_key* key)
{
	int ret = 0;
	BIGN_DOMAINPARAMS* dp;
	// входной контроль
	if (!key)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_I2D_DOMAINPARAMS, 
			ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// преобразовать в стандартную структуру
	if (!(dp = bign_asn1_params2dp(NULL, &key->params)))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_I2D_DOMAINPARAMS, 
			BEE2EVP_R_PARAMS2DP_FAILURE);
		return 0;
	}
	if (!(ret = i2d_BIGN_DOMAINPARAMS(dp, out)))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_I2D_DOMAINPARAMS, 
			BEE2EVP_R_I2D_PARAMS_FAILURE);
		BIGN_DOMAINPARAMS_free(dp);
		return 0;
	}	
	BIGN_DOMAINPARAMS_free(dp);
	return ret;
}

/*
*******************************************************************************
Кодирование и декодирование открытого ключа, вложенных в структуру bign_key

\remark Открытый ключ задается типом PublicKey ::= BIT STRING
*******************************************************************************
*/
int bign_o2i_pubkey(bign_key* key, const unsigned char* in, long len)
{
	// входной контроль
	if (!key || !in)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_O2I_PUBKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	if (len != key->params.l / 2)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_O2I_PUBKEY, BEE2EVP_R_INVALID_PUBKEY);
		return 0;
	}
	// сохранить ключ
	memCopy(key->pubKey, in, len);
	return 1;
}

int bign_i2o_pubkey(unsigned char** out, const bign_key* key)
{
	int ret;
	// входной контроль
	if (!key)
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_I2O_PUBKEY, ERR_R_PASSED_NULL_PARAMETER);
		return 0;
	}
	// длина ключа в октетах
	ret = key->params.l / 2;
	if (!out)
		return ret;
	// подготовить буфер
	if (!*out && !(*out = OPENSSL_malloc(ret)))
	{
		BEE2EVPerr(BEE2EVP_F_BIGN_I2O_PUBKEY, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	// возвратить ключ
	memCopy(*out, key->pubKey, ret);
	return ret;
}
