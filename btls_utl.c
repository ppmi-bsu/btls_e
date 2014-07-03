/*
*******************************************************************************
\file btls_utl.c
\brief Вспомогательные функции
*******************************************************************************
\author (С) Олег Соловей, Николай Шенец http://apmi.bsu.by
\created 2013.08.01
\version 2013.09.26
*******************************************************************************
*/

#include "btls_utl.h"
#include "btls_err.h"

ASN1_OBJECT* btls_c2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, long len)
{
	ASN1_OBJECT *ret=NULL;
	const unsigned char *p;
	unsigned char *data;
	int i;
	/* Sanity check OID encoding: can't have leading 0x80 in
	 * subidentifiers, see: X.690 8.19.2
	 */
	for (i = 0, p = *pp; i < len; i++, p++)
		{
		if (*p == 0x80 && (!i || !(p[-1] & 0x80)))
			{
			return NULL;
			}
		}

	/* only the ASN1_OBJECTs from the 'table' will have values
	 * for ->sn or ->ln */
	if ((a == NULL) || ((*a) == NULL))
		{
		if ((ret=ASN1_OBJECT_new()) == NULL) return(NULL);
		}
	else	ret=(*a);

	p= *pp;
	/* detach data from object */
	data = (unsigned char *)ret->data;
	ret->data = NULL;
	/* once detached we can change it */
	if ((data == NULL) || (ret->length < len))
		{
		ret->length=0;
		if (data != NULL) OPENSSL_free(data);
		data=(unsigned char *)OPENSSL_malloc(len ? (int)len : 1);
		if (data == NULL)
			{ i=ERR_R_MALLOC_FAILURE; 
				if ((ret != NULL) && ((a == NULL) || (*a != ret)))
				ASN1_OBJECT_free(ret);
				return(NULL);}
		}
	memcpy(data,p,(int)len);
	/* reattach data to object, after which it remains const */
	ret->data  =data;
	ret->length=(int)len;
	/* ret->flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic */
	p+=len;

	if (a != NULL) (*a)=ret;
	*pp=p;
	return(ret);
}

ASN1_OBJECT* btls_d2i_ASN1_OBJECT(ASN1_OBJECT **a, const unsigned char **pp, long length)
{
	const unsigned char *p;
	long len;
	int tag,xclass;
	int inf,i;
	ASN1_OBJECT *ret = NULL;
	p= *pp;
	inf=ASN1_get_object(&p,&len,&tag,&xclass,length);
	if (inf & 0x80)
		{
		i=ASN1_R_BAD_OBJECT_HEADER;
		return(NULL);
		}

	if (tag != V_ASN1_OBJECT)
		{
		i=ASN1_R_EXPECTING_AN_OBJECT;
		return(NULL);
		}
	ret = btls_c2i_ASN1_OBJECT(a, &p, len);
	if(ret) *pp = p;
	return ret;
}

int btls_change_obj_data(ASN1_OBJECT **a, const char* pp)
{
	int res = 1;
	unsigned char *buf;
	unsigned char *p;
	const unsigned char *cp;
	int i, j;

	i=a2d_ASN1_OBJECT(NULL,0, pp,-1);
	if (i <= 0) {
		/* Don't clear the error */
		/*ERR_clear_error();*/
		return 0;
	}
	/* Work out total size */
	j = ASN1_object_size(0,i,V_ASN1_OBJECT);

	if((buf=(unsigned char *)OPENSSL_malloc(j)) == NULL) return 0;

	p = buf;
	/* Write out tag+length */
	ASN1_put_object(&p,0,i,V_ASN1_OBJECT,V_ASN1_UNIVERSAL);
	/* Write out contents */
	a2d_ASN1_OBJECT(p,i,pp,-1);

	cp=buf;
	(*a)=btls_d2i_ASN1_OBJECT(a,&cp,j);
	OPENSSL_free(buf);

	return 1;
}
