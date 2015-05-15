/*
 * OCSP responder
 * by Massimiliano Pala (madwolf@openca.org)
 * OpenCA project 2001
 *
 * Copyright (c) 2001 The OpenCA Project.  All rights reserved.
 *
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

/* Functions prototypes*/

#ifndef _OCSPD_CRL_H
#define _OCSPD_CRL_H

int ocspd_load_ca_crl ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf );
int ocspd_reload_crls ( OCSPD_CONFIG *conf );
int check_crl ( PKI_X509_CRL *x_crl, PKI_X509_CERT *x_cacert, PKI_RWLOCK *single_crl_lock, OCSPD_CONFIG *conf );
int check_crl_validity ( CRL_DATA *crl_data, PKI_RWLOCK *lock, OCSPD_CONFIG *conf, char *ca_id );
char * get_crl_status_info ( int status );
void force_crl_reload ( int sig );


#endif
