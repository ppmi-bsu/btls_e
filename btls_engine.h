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

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BTLS_ENG_H */