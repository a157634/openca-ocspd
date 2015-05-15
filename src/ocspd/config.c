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

#include "general.h"
#include <sys/stat.h>


/* Internal data structure */
typedef struct {
	const char *name;
	unsigned long flag;
	unsigned long mask;
} NAME_EX_TBL;

 
/* External imported variables */
extern OCSPD_CONFIG * ocspd_conf;

/* Functions */
static int OCSPD_EVP_MD_STACK_add_md(STACK_OF(EVP_MD) **mds, const EVP_MD *md)
{
	if (!mds)
		return 0;

	/* Create new md stack if necessary. */
	if (!*mds && !(*mds = sk_EVP_MD_new_null()))
		return 0;

	/* Add the shared md, no copy needed. */
	if (!sk_EVP_MD_push(*mds, (EVP_MD *)md))
		return 0;

	return 1;
}

static int set_table_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL *in_tbl)
{
  char c;
  const NAME_EX_TBL *ptbl;
  c = arg[0];

  if(c == '-') {
    c = 0;
    arg++;
  } else if (c == '+') {
    c = 1;
    arg++;
  } else c = 1;

  for(ptbl = in_tbl; ptbl->name; ptbl++) {
    if(!strcasecmp(arg, ptbl->name)) {
      *flags &= ~ptbl->mask;
      if(c) *flags |= ptbl->flag;
      else *flags &= ~ptbl->flag;
      return 1;
    }
  }
  return 0;
}

static int set_multi_opts(unsigned long *flags, const char *arg, const NAME_EX_TBL *in_tbl)
{
  STACK_OF(CONF_VALUE) *vals;
  CONF_VALUE *val;
  int i, ret = 1;
  if(!arg) return 0;
  vals = X509V3_parse_list(arg);
  for (i = 0; i < sk_CONF_VALUE_num(vals); i++) {
    val = sk_CONF_VALUE_value(vals, i);
    if (!set_table_opts(flags, val->name, in_tbl))
      ret = 0;
  }
  sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
  return ret;
}

static int set_name_ex(unsigned long *flags, const char *arg)
{ 
  static const NAME_EX_TBL ex_tbl[] = {
    { "esc_2253", ASN1_STRFLGS_ESC_2253, 0},
    { "esc_ctrl", ASN1_STRFLGS_ESC_CTRL, 0},
    { "esc_msb", ASN1_STRFLGS_ESC_MSB, 0},
    { "use_quote", ASN1_STRFLGS_ESC_QUOTE, 0},
    { "utf8", ASN1_STRFLGS_UTF8_CONVERT, 0},
    { "ignore_type", ASN1_STRFLGS_IGNORE_TYPE, 0},
    { "show_type", ASN1_STRFLGS_SHOW_TYPE, 0},
    { "dump_all", ASN1_STRFLGS_DUMP_ALL, 0},
    { "dump_nostr", ASN1_STRFLGS_DUMP_UNKNOWN, 0},
    { "dump_der", ASN1_STRFLGS_DUMP_DER, 0},
    { "compat", XN_FLAG_COMPAT, 0xffffffffL},
    { "sep_comma_plus", XN_FLAG_SEP_COMMA_PLUS, XN_FLAG_SEP_MASK},
    { "sep_comma_plus_space", XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK},
    { "sep_semi_plus_space", XN_FLAG_SEP_SPLUS_SPC, XN_FLAG_SEP_MASK},
    { "sep_multiline", XN_FLAG_SEP_MULTILINE, XN_FLAG_SEP_MASK},
    { "dn_rev", XN_FLAG_DN_REV, 0},
    { "nofname", XN_FLAG_FN_NONE, XN_FLAG_FN_MASK},
    { "sname", XN_FLAG_FN_SN, XN_FLAG_FN_MASK},
    { "lname", XN_FLAG_FN_LN, XN_FLAG_FN_MASK},
    { "align", XN_FLAG_FN_ALIGN, 0},
    { "oid", XN_FLAG_FN_OID, XN_FLAG_FN_MASK},
    { "space_eq", XN_FLAG_SPC_EQ, 0},
    { "dump_unknown", XN_FLAG_DUMP_UNKNOWN_FIELDS, 0},
    { "RFC2253", XN_FLAG_RFC2253, 0xffffffffL},
    { "oneline", XN_FLAG_ONELINE, 0xffffffffL},
    { "multiline", XN_FLAG_MULTILINE, 0xffffffffL},
    { "ca_default", XN_FLAG_MULTILINE, 0xffffffffL},
    { NULL, 0, 0}
  };
  return set_multi_opts(flags, arg, ex_tbl);
}

static int parse_stats_items(char *items, unsigned long *item_flags, char *base_url, URL **log_stats_url)
{
	char *column;
	char *next;
	LOG_STATS_ITEM_TBL *tbl;
	LOG_STATS_ITEM_TBL *tbl_cpy = NULL;
	BIO   *membio = NULL;
	int   ret = 1;
	long  len = 0;


  // copy original ocsp_stats_item_tbl due to static const definition
  // we need this to modify the entry element for ordering the occurence of the logStatsItems
  if( (tbl_cpy = PKI_Malloc(sizeof(ocsp_stats_item_tbl))) == NULL)
	{
		PKI_log_err("Memory allocation error!");
		return(ret);
	}
  memcpy(tbl_cpy, ocsp_stats_item_tbl, sizeof(ocsp_stats_item_tbl));


	if( (membio = BIO_new(BIO_s_mem())) == NULL)
	{
		PKI_log_err("Memory allocation error!");
		goto end;
	}

	if(BIO_printf(membio, "%s?", base_url) <= 0)
	{
		PKI_log_err ("BIO_printf(logStatsUrl) failed!\n");
		goto end;
	}

	*item_flags = 0;

	while(*items)
	{
		if( (next = strchr(items, ',')) != NULL)
			*next++ = 0;
		
		if( (column = strchr(items, '=')) != NULL)
		{
			*column++ = 0;
			if(*column == '\0')
				column = NULL;
		}

		for(tbl = tbl_cpy; tbl->name; tbl++)
		{
			if(strcmp_nocase(items, tbl->name) == 0)
			{
				if(column)
					tbl->entry = column;
				else
					tbl->entry = tbl->column;;

				*item_flags |= tbl->flag;

				break;
			}
		}
		items = next;

		if(items == NULL)
			break;
	}

  // temporary usage of len to indicate the number of items
	for(tbl = tbl_cpy; tbl->name; tbl++)
	{
		if(*item_flags & tbl->flag)
		{
			if(BIO_printf(membio, "%s%s", len++ ? ",":"", tbl->entry) <= 0)
			{
				PKI_log_err ("BIO_printf(column) failed!\n");
				goto end;
			}
		}
	}

	if(BIO_write(membio, "\x0", 1) <= 0)
	{
		PKI_log_err ("BIO_write() failed!\n");
		goto end;
	}

	if( (len = BIO_get_mem_data(membio, &column) ) <= 0)
	{
		PKI_log_err ( "BIO_get_mem_data() failed");
		goto end;
	}

	if ((*log_stats_url = URL_new ( column )) == NULL)
	{
		PKI_log_err ( "logStatsUrl not parsable (%s)", column );
		goto end;
	}

	PKI_log_debug("logStatsUrl: %s", column);

	ret = 0;

end:
	if(membio) BIO_free(membio);
  if(tbl_cpy) PKI_Free(tbl_cpy);
	return(ret);
}

OCSPD_CONFIG * OCSPD_load_config(char *configfile)
{
	OCSPD_CONFIG *h = NULL;
	PKI_CONFIG *cnf = NULL;
	PKI_CONFIG_STACK *ca_config_stack = NULL;

	char *tmp_s = NULL;
	char *tmp_s2 = NULL;

	int i;

	/* Check for the environment variable PRQP_CONF */
	if (configfile == NULL) configfile = getenv("OCSPD_CONF");

	/* If not, check for the default CONFIG_FILE */
	if (configfile == NULL) configfile = CONFIG_FILE;

	if( !configfile ) {
		/* No config file is available */
		PKI_log(PKI_LOG_ERR, "No config file provided!");
		return (NULL);
	}

	/* Load the config file */
	if(( cnf = PKI_CONFIG_load ( configfile )) == NULL ) {
		PKI_log( PKI_LOG_ERR, "Can not load config file [%s]!",
			configfile );
		return (NULL);
	}
	if(( h = (OCSPD_CONFIG *)PKI_Malloc(sizeof(OCSPD_CONFIG))) == NULL) {
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto err;
	}

	/* Set the group and user string to NULL */
	h->user = NULL;
	h->group = NULL;

	/* Set the PRQPD verbose status */
	h->verbose   = 0;
	h->debug     = 0;
	h->nthreads  = 5;
	h->http_proto = strdup("1.0");
	h->max_timeout_secs = 5;

	h->crl_auto_reload = 3600;
	h->crl_reload_expired = 1;
	h->crl_check_validity = 600;

	/* Copy the config filename so that it could be re-loaded on SIGHUP */
	h->cnf_filename = strdup( configfile );

	/* Initialize the COND variables and MUTEXES */
	for( i = 0; i < sizeof ( h->mutexes ) / sizeof( PKI_MUTEX ); i++ )
	{
		PKI_MUTEX_init ( &h->mutexes[i] );
	}

	for( i = 0; i < sizeof ( h->condVars ) / sizeof( PKI_COND ); i++)
	{
		PKI_COND_init ( &h->condVars[i] );
	}

	//PKI_RWLOCK_init ( &h->crl_lock );

	/* responderName */
	if (( tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/responderName")) != NULL)
	{
		h->responder_name = tmp_s;
	}

	/* Token Initialization */
	if (( tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/pkiConfigDir")) == NULL)
	{
		PKI_log_err("Missing pkiConfigDir in configuration!");
		goto err;
	}
	else 
	{
		if ((tmp_s2 = PKI_CONFIG_get_value( cnf, "/serverConfig/general/token" )) != NULL)
		{
			h->token_name = strdup( tmp_s2 );
			h->token_config_dir = strdup ( tmp_s );

			if ((h->token = PKI_TOKEN_new_null()) == NULL)
			{
				PKI_log( PKI_LOG_ERR, "Memory error for new token");
				PKI_Free(tmp_s);
				goto err;
			}

			PKI_Free(tmp_s2);
		}
		else
		{
			PKI_log_err("No General Token provided in configuration.");

			PKI_Free(tmp_s);
			goto err;
		}

		PKI_Free(tmp_s);
	}

	/* Thread configuration */
	if((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/general/spawnThreads")) != NULL)
	{
		int t = 0;
		if((t = atoi( tmp_s )) > 0 ) h->nthreads = t;

		PKI_Free(tmp_s);
	}

	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/caConfigDir")) != NULL)
	{
		h->ca_config_dir = strdup(tmp_s);

		ca_config_stack = PKI_CONFIG_load_dir(h->ca_config_dir, NULL);
		if (ca_config_stack == NULL)
		{
			PKI_log( PKI_LOG_ERR, "Can't load caConfigDir (%s)", h->ca_config_dir);
			PKI_Free(tmp_s);

			goto err;
		}

		PKI_Free(tmp_s);
	}
	else
	{
		PKI_log( PKI_LOG_ERR, "/serverConfig/general/caConfigDir needed in conf!\n");
		goto err;
	}

	/* Pid File */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/pidFile")) != NULL )
	{
		h->pidfile = strdup(tmp_s);

		PKI_Free(tmp_s);
	}

	/* AutoReload timeout */
	if((tmp_s = PKI_CONFIG_get_value( cnf, 
		"/serverConfig/general/crlAutoReload")) != NULL)
	{
		h->crl_auto_reload = atoi(tmp_s);

		if( h->crl_auto_reload <= 0 )
		{
			h->crl_auto_reload = 0;
			PKI_log(PKI_LOG_INFO, "Auto Reload Disabled");
		}

		PKI_Free(tmp_s);
	}

	/* CRL validity check timeout */
	if((tmp_s = PKI_CONFIG_get_value( cnf, 
			"/serverConfig/general/crlCheckValidity")) != NULL )
	{
		h->crl_check_validity = atoi(tmp_s);
		if ( h->crl_check_validity <= 0 )
		{
			h->crl_check_validity = 0;
			PKI_log(PKI_LOG_INFO, "CRL check validity disabled");
		}

		PKI_Free(tmp_s);
	}

	/* ReloadExpired */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, 
				"/serverConfig/general/crlReloadExpired")) != NULL )
	{
		if (strncmp_nocase(tmp_s, "n", 1) == 0)
		{
			h->crl_reload_expired = 0;
			PKI_log(PKI_LOG_INFO, "Expired CRLs Reload Disabled");
		}

		PKI_Free(tmp_s);
	}

	/* CheckModificationTime */
	if((tmp_s = PKI_CONFIG_get_value( cnf, 
				"/serverConfig/general/crlCheckModificationTime")) != NULL ) {

		if (strncmp_nocase(tmp_s, "y", 1) == 0)
		{
			h->crl_check_mtime = 1;
			PKI_log(PKI_LOG_INFO, "CRL check of modification time enabled");
		}
		else
			PKI_log(PKI_LOG_INFO, "CRL check of modification time disabled");
		PKI_Free(tmp_s);
	}

	/* logStatsUrl */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/logStatsUrl")) != NULL)
	{
		/* logStatsItems */
		if ((tmp_s2 = PKI_CONFIG_get_value( cnf, "/serverConfig/general/logStatsItems")) != NULL)
		{
      if(parse_stats_items(tmp_s2, &(h->log_stats_flags), tmp_s, &(h->log_stats_url)) != 0)
			  PKI_log_err ( "logStatsItems not parsable. No statistics logging will be performed." );

			PKI_Free(tmp_s2);
		}
		PKI_Free(tmp_s);
	}

	/* Server Privileges */
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/security/user")) != NULL)
	{
		h->user = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/security/group" )) != NULL)
	{
		h->group = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/security/chrootDir" )) != NULL )
	{
		h->chroot_dir = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	/* Bind Address */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/bindAddress" )) == NULL)
	{
		// If not bindAddress, let's use the universal one
		tmp_s = strdup("http://0.0.0.0:2560");
	}

	if ((h->bindUrl = URL_new( tmp_s )) == NULL)
	{
		PKI_log( PKI_LOG_ERR, "Can't parse bindAddress (%s)", tmp_s );
		PKI_Free(tmp_s);

		goto err;
	}

	// We need to free the tmp_s
	PKI_Free(tmp_s);

	/* HTTP Version */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/httpProtocol")) != NULL)
	{
		if(h->http_proto) PKI_Free(h->http_proto);
		h->http_proto = strdup(tmp_s);
		PKI_Free(tmp_s);
	}

	/* Timeout for incoming connections */
	if((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/network/timeOut")) != NULL )
	{
		long t = 0;

		if ((t = atol( tmp_s )) > 0) h->max_timeout_secs = (unsigned int) t;
		PKI_Free(tmp_s);
	}

	/* Maximum Request Size */
	if((tmp_s = PKI_CONFIG_get_value( cnf,
				"/serverConfig/request/maxReqSize" )) == NULL ) {

		/* Fallback for old configuration files */
		tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/response/maxReqSize" );
	}

	if(tmp_s) {
		int t = 0;

		if((t = atoi( tmp_s )) > 0 ) {
			h->max_req_size = t;
		}
		PKI_Free(tmp_s);
	}

	// Default
	h->digest = PKI_DIGEST_ALG_SHA1;

	/* Digest algorithm to be used */
	if ((tmp_s = PKI_CONFIG_get_value(cnf, "/serverConfig/response/digestAlgorithm" )) != NULL)
	{
		h->digest = PKI_DIGEST_ALG_get_by_name( tmp_s );

		if (!h->digest) 
		{
			PKI_log_err("Can not parse response digest algorithm: %s", tmp_s);
			PKI_Free(tmp_s);
			goto err;
		}
		else PKI_log_debug("Selected response digest algorithm: %s", tmp_s);

		PKI_Free(tmp_s);
	}

	/* Signing Digest Algorithm to be used */
	if((tmp_s = PKI_CONFIG_get_value( cnf,
			"/serverConfig/response/signatureDigestAlgorithm" )) == NULL)
	{
		PKI_log_debug("No specific signature digest algorithm selected.");
		h->sigDigest = NULL;
	}
	else
	{
		h->sigDigest = PKI_DIGEST_ALG_get_by_name( tmp_s );

		if (!h->sigDigest) 
		{
			PKI_log_err("Can not parse signing digest algorithm: %s", tmp_s);
			PKI_Free(tmp_s);
			goto err;
		}
		else PKI_log_debug("Selected signature digest algorithm: %s", tmp_s);

		PKI_Free(tmp_s);
	}

	/* Digest algorithm used for building the issuerNameHash and issuerKeyHash */
	if((tmp_s = PKI_CONFIG_get_value( cnf,
			"/serverConfig/response/issuerHashDigestAlgorithm" )) != NULL )
	{
		EVP_MD *digest;
		char *p1, *p2;

		p1 = tmp_s;

		while( (p2 = strchr(p1, ',') ) != NULL)
		{
			*p2++ = 0;

			digest = PKI_DIGEST_ALG_get_by_name( p1 );
			if (!digest) 
			{
				PKI_log_err("Can not parse issuerHashDigestAlgorithm: %s", p1);
				goto err;
			}

			if(!OCSPD_EVP_MD_STACK_add_md(&(h->issuerHashDigest), digest))
			{
				PKI_log_err("Can not add issuerHashDigestAlgorithm");
				goto err;
			}

			PKI_log_debug("Selected issuerHashDigestAlgorithm: %s", p1);

			/* Skip possible spaces */
			while(*p2 == ' ')
        p2++;
			p1 = p2;
		}

		digest = PKI_DIGEST_ALG_get_by_name( p1 );
		if (!digest) 
		{
			PKI_log_err("Can not parse issuerHashDigestAlgorithm: %s", p1);
			goto err;
		}

		if(!OCSPD_EVP_MD_STACK_add_md(&(h->issuerHashDigest), digest))
		{
			PKI_log_err("Can not add issuerHashDigestAlgorithm: %s", p1);
			goto err;
		}

		PKI_log_debug("Selected issuerHashDigestAlgorithm: %s", p1);
		PKI_Free(tmp_s);
	}
	else
	{
		/* for backward compatibility we use the configured digestAlgorithm */
		if(!OCSPD_EVP_MD_STACK_add_md(&(h->issuerHashDigest), h->digest))
		{
			PKI_log_err("Can not add issuerHashDigestAlgorithm: %s", EVP_MD_name(PKI_DIGEST_ALG_DEFAULT));
			goto err;
		}

		PKI_log_debug("Selected issuerHashDigestAlgorithm: %s", EVP_MD_name(PKI_DIGEST_ALG_DEFAULT));
	}

	/* Now Parse the PRQP Response Section */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/response/validity/days" )) != NULL)
	{
		h->ndays = atoi(tmp_s);
		PKI_Free(tmp_s);
	}

	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/response/validity/mins" )) != NULL)
	{
		h->nmin = atoi(tmp_s);
		PKI_Free(tmp_s);
	}

	h->set_nextUpdate = h->ndays * 3600 + h->nmin * 60;

	/* Database Options */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/dbUrl")) != NULL)
	{
		if ((h->db_url = URL_new ( tmp_s )) == NULL)
		{
			PKI_log_err ( "Database Url not parsable (%s)", tmp_s );
			PKI_Free(tmp_s);
			goto err;
		}

		PKI_Free(tmp_s);
	}

	/* Database Persistant */
	if ((tmp_s = PKI_CONFIG_get_value( cnf, "/serverConfig/general/dbPersistant")) != NULL)
	{
		if (strncmp_nocase ( "n", tmp_s, 1 ) == 0 )
			h->db_persistant = 0;
		else 
			h->db_persistant = 1;

		PKI_Free(tmp_s);
	}

	/* Now we should load the CA configuration files and generate the
	   CERT_ID for the different CAs */
	if ((OCSPD_build_ca_list( h, ca_config_stack )) == PKI_ERR )
	{

		PKI_log(PKI_LOG_ERR, "Can not build CA list!");
		goto err;
	}

	if (ca_config_stack) PKI_STACK_CONFIG_free_all ( ca_config_stack );
	if( cnf ) PKI_CONFIG_free ( cnf );

	return ( h );

err:
	if( ca_config_stack ) PKI_STACK_CONFIG_free_all ( ca_config_stack );
	if( cnf ) PKI_CONFIG_free ( cnf );
	if( h ) {
		OCSPD_free_config(h);
		PKI_Free ( h );
	}

	return( NULL );
}

void OCSPD_free_ca_list(PKI_STACK *ca_list) {

	CA_LIST_ENTRY *ca = NULL;

	if(!ca_list) return;

	while ( (ca = PKI_STACK_pop ( ca_list ) ) ) {
		CA_LIST_ENTRY_free(ca);
	}

	PKI_STACK_free_all(ca_list);
}

void OCSPD_free_config(OCSPD_CONFIG *cnf) {

  int i;

	if(!cnf) return;

	if(cnf->cnf_filename)     PKI_Free(cnf->cnf_filename);
	if(cnf->responder_name)   PKI_Free(cnf->responder_name);
	if(cnf->token_name)       PKI_Free(cnf->token_name);
	if(cnf->token_config_dir) PKI_Free(cnf->token_config_dir);
	if(cnf->token)            PKI_TOKEN_free_void(cnf->token);
	if(cnf->ca_config_dir)    PKI_Free(cnf->ca_config_dir);
	if(cnf->pidfile)          PKI_Free(cnf->pidfile);
	if(cnf->user)             PKI_Free(cnf->user);
	if(cnf->group)            PKI_Free(cnf->group);
	if(cnf->chroot_dir)       PKI_Free(cnf->chroot_dir);
	if(cnf->bindUrl)          URL_free(cnf->bindUrl);
	if(cnf->http_proto)       PKI_Free(cnf->http_proto);
	if(cnf->db_url)           URL_free(cnf->db_url);
	if(cnf->log_stats_url)    URL_free(cnf->log_stats_url);
	if(cnf->ca_list)          OCSPD_free_ca_list(cnf->ca_list);
	if(cnf->threads_list)     PKI_Free(cnf->threads_list);
	if(cnf->issuerHashDigest) sk_EVP_MD_free(cnf->issuerHashDigest);

	for( i = 0; i < sizeof ( cnf->mutexes ) / sizeof( PKI_MUTEX ); i++ )
	{
		PKI_MUTEX_destroy ( &cnf->mutexes[i] );
	}
}
 
int OCSPD_build_ca_list ( OCSPD_CONFIG *handler,
			PKI_CONFIG_STACK *ca_conf_sk) {

	int i = 0;
	PKI_STACK *ca_list = NULL;

	PKI_log_debug("Building CA List");

	if ( !ca_conf_sk ) {
		PKI_log( PKI_LOG_ERR, "No stack of ca configs!");
		return ( PKI_ERR );
	}

	if((ca_list = PKI_STACK_new((void (*))CA_LIST_ENTRY_free)) == NULL ) {
		PKI_log_err ( "Memory Error");
	return ( PKI_ERR );
	}

	for (i = 0; i < PKI_STACK_CONFIG_elements( ca_conf_sk ); i++)
	{
		char *tmp_s = NULL;
		URL *tmp_url = NULL;
		PKI_X509_CERT *tmp_cert = NULL;

		CA_LIST_ENTRY *ca = NULL;
		PKI_CONFIG *cnf = NULL;

		/* Get the current Configuration file */
		cnf = PKI_STACK_CONFIG_get_num( ca_conf_sk, i );
		if (!cnf) continue;

		/* Get the CA cert from the cfg file itself */
		if((tmp_s = PKI_CONFIG_get_value( cnf, "/caConfig/caCertValue" )) == NULL )
		{
			tmp_s = PKI_CONFIG_get_value( cnf, "/caConfig/caCertUrl" );
			if( tmp_s == NULL )
			{
				PKI_log( PKI_LOG_ERR, "No CA cert url given" );
				continue;
			}

			/* Get the CA parsed url */
			if((tmp_url = URL_new( tmp_s )) == NULL )
			{
				/* Error, can not parse url data */
				PKI_log( PKI_LOG_ERR, "Can not parse CA cert url (%s)", tmp_s);
				PKI_Free(tmp_s);
				continue;
			}

			if((tmp_cert = PKI_X509_CERT_get_url(tmp_url, NULL, NULL ))== NULL)
			{
				PKI_log_err("Can not get CA cert from (%s)", tmp_url->url_s);
				URL_free (tmp_url);
				PKI_Free(tmp_s);
				continue;
			}
			PKI_Free(tmp_s);
		}
		else
		{
			PKI_X509_CERT_STACK *cc_sk = NULL;
			PKI_MEM *mm = NULL;

			if((mm = PKI_MEM_new_null()) == NULL )
			{
				PKI_Free(tmp_s);
				continue;
			}

			PKI_MEM_add ( mm, tmp_s, strlen(tmp_s));

			if((cc_sk=PKI_X509_CERT_STACK_get_mem(mm, NULL)) == NULL )
			{
				PKI_log_err ( "Can not parse cert from /caConfig/caCertValue");
				PKI_Free(tmp_s);

				continue;
			}

			if ((tmp_cert = PKI_STACK_X509_CERT_pop( cc_sk )) == NULL )
			{
				PKI_log_err ( "No elements on stack from /caConfig/caCertValue");

				PKI_STACK_X509_CERT_free_all(cc_sk);
				PKI_Free(tmp_s);

				continue;
			}

			PKI_STACK_X509_CERT_free ( cc_sk );
			PKI_Free(tmp_s);
		}

		/* OCSPD create the CA entry */
		if ((ca = CA_LIST_ENTRY_new()) == NULL )
		{
			PKI_log_err ( "CA List structure init error");

			/* remember to do THIS!!!! */
			if( tmp_url ) URL_free ( tmp_url );
			if( tmp_cert ) PKI_X509_CERT_free ( tmp_cert );

			continue;
		}

		ca->ca_cert = tmp_cert;
		tmp_cert = NULL;

		ca->ca_url = tmp_url;
		tmp_url = NULL;

		ca->ca_id = PKI_CONFIG_get_value( cnf, "/caConfig/name" );

		PKI_RWLOCK_init ( &ca->single_crl_lock );

		if( (ca->crl_data = PKI_Malloc(sizeof(CRL_DATA)) ) == NULL)
		{
			PKI_log_err ("PKI_Malloc(CRL_DATA) failed (%d bytes)\n", sizeof(CRL_DATA));
			return(-1);
		}

		ca->sk_cid = CA_ENTRY_CERTID_new_sk ( ca->ca_cert, handler->issuerHashDigest );
		if(ca->sk_cid == NULL) {
			PKI_log_err ( "Cannot build CA CertIDs");
			continue;
		}

		/* Get the CRL URL and the CRL itself */
		if((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/crlUrl")) == NULL)
		{
			PKI_STACK *cdp_sk = NULL;

			/* Now let's get it from PRQP */

			/* Now from the Certificate */
			
			if((cdp_sk = PKI_X509_CERT_get_cdp (ca->ca_cert)) ==NULL)
			{
				// No source for the CRL Distribution Point
				PKI_log_err ( "ERROR::Can not find the CDP for %s, skipping CA", ca->ca_id );

				CA_LIST_ENTRY_free ( ca );
				continue;
			}

			while ((tmp_s = PKI_STACK_pop ( cdp_sk )) != NULL)
			{
				if ((ca->crl_url = URL_new ( tmp_s )) == NULL )
				{
					PKI_log_err( "URL %s not in the right format!");
					CA_LIST_ENTRY_free ( ca );
					continue;
				}
				else if( tmp_s ) PKI_Free ( tmp_s );

				break;
			}
		}
		else
		{
			PKI_log_debug("Got CRL Url -> %s", tmp_s );

			if((ca->crl_url = URL_new ( tmp_s )) == NULL )
			{
				PKI_log_err ("Error Parsing CRL URL [%s] for CA [%s]", ca->ca_id, tmp_s);

				CA_LIST_ENTRY_free ( ca );
				PKI_Free(tmp_s);

				continue;
			}

			PKI_Free(tmp_s);
		}

		if(OCSPD_load_crl ( ca, handler ) == PKI_ERR )
		{
			PKI_log_err ( "Can not get CRL for %s", ca->ca_id);
			CA_LIST_ENTRY_free ( ca );

			continue;
		}

		/* If the Server has a Token to be used with this CA, let's
                   load it */
		if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/serverToken" )) == NULL)
		{
			/* No token in config, let's see if a specific cert
			   is configured */
			ca->token = NULL;

			if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/serverCertUrl" )) == NULL )
			{
				/* No cert is configured, we will use the defaults */
				ca->server_cert = NULL;
			}
			else
			{
				/* The Server's cert URL is found, let's load the certificate */
				if ((tmp_cert = PKI_X509_CERT_get ( tmp_s, NULL, NULL )) == NULL )
				{
					PKI_log_err("Can not get server's cert from %s!", tmp_s );

					CA_LIST_ENTRY_free ( ca );
					PKI_Free(tmp_s);

					continue;
				}
				else
				{
					ca->server_cert = tmp_cert;
				}

				PKI_Free(tmp_s);
			}
		}
		else
		{
			/* A Token for this CA is found - we do not load
 			   it to avoid problems with Thread Initialization */
			ca->server_cert = NULL;
			ca->token_name = tmp_s;
			ca->token = PKI_TOKEN_new_null();

			if ((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/pkiConfigDir" )) != NULL) {
				ca->token_config_dir = strdup( tmp_s );
				PKI_Free(tmp_s);
			}
			else
			{
				ca->token_config_dir = strdup(handler->token_config_dir);
			}
		}

		if((tmp_s = PKI_CONFIG_get_value ( cnf, "/caConfig/caCompromised" )) == NULL) {
			ca->compromised = 0;
		}
		else
		{
			ca->compromised = atoi(tmp_s);
			PKI_Free(tmp_s);
		}

		/* checkIssuedByCA */
		if((tmp_s = PKI_CONFIG_get_value( cnf, 
					"/caConfig/checkIssuedByCA")) != NULL ) {

			int n, m;

			if (strncmp_nocase(tmp_s, "y", 1) == 0) {
				ca->check_issued_by_ca = 1;
				PKI_log(PKI_LOG_INFO, "Check - 'if the requested certificates were issued by our configured CA' - is enabled");
			}
			else
				PKI_log(PKI_LOG_INFO, "Check - 'if the requested certificates were issued by our configured CA' - is disabled");
			PKI_Free ( tmp_s );

			/* Database Options */
			if((tmp_s = PKI_CONFIG_get_value( cnf, "/caConfig/dbUrl")) != NULL ) {
				if((ca->db_url = URL_new ( tmp_s )) == NULL ) {
					PKI_log_err ( "Database Url not parsable (%s)", tmp_s );
					CA_LIST_ENTRY_free ( ca );
					PKI_Free(tmp_s);
					continue;
				}
				PKI_Free(tmp_s);
			}

			/* fingerprint hash algorithm */
			if((tmp_s = PKI_CONFIG_get_value( cnf, 
					"/caConfig/CAfingerprintHashAlgo")) == NULL ) {
				if( (tmp_s = strdup((const char *)"SHA1") ) == NULL) {
					PKI_log_err ( "Cannot create CAfingerprintHashAlgo" );
					CA_LIST_ENTRY_free ( ca );
					continue;
				}
			}

			/* calculate CA fingerprint */
			ca->ca_cert_digest = PKI_X509_CERT_fingerprint_by_name(ca->ca_cert, tmp_s);
			PKI_Free(tmp_s);

			if(ca->ca_cert_digest == NULL) {
				PKI_log_err ( "Cannot generate fingerprint for CA certificate for CA [%s]", ca->ca_id);
				CA_LIST_ENTRY_free ( ca );
				continue;
			}

			/* convert to string value */
			for(n = 0, m = 0; n < ca->ca_cert_digest->size; n++) {
				ca->ca_cert_digest_str[m]  = (char) ((ca->ca_cert_digest->digest[n] & 0xf0) >> 4);
				if(ca->ca_cert_digest_str[m] < 10)
					ca->ca_cert_digest_str[m] = (char) ((int) ca->ca_cert_digest_str[m] + 0x30);
				else
					ca->ca_cert_digest_str[m] = (char) ((int) ca->ca_cert_digest_str[m] + 0x57);
				m++;

				ca->ca_cert_digest_str[m]  = (char) (ca->ca_cert_digest->digest[n] & 0x0f);
				if(ca->ca_cert_digest_str[m] < 10)
					ca->ca_cert_digest_str[m] = (char) ((int) ca->ca_cert_digest_str[m] + 0x30);
				else
					ca->ca_cert_digest_str[m] = (char) ((int) ca->ca_cert_digest_str[m] + 0x57);
				m++;
			}
			ca->ca_cert_digest_str[m] = 0;

			/* Issuer DN Options */
			if((tmp_s = PKI_CONFIG_get_value( cnf, "/caConfig/issuerNameOptions")) != NULL ) {
				if(!set_name_ex(&ca->issuer_dn_nmflag, tmp_s)) {
					PKI_log_err ( "Issuer DN options not parsable (%s)", tmp_s );
					CA_LIST_ENTRY_free ( ca );
					PKI_Free(tmp_s);
					continue;
				}
				PKI_Free(tmp_s);
			}
			else {
				(void)set_name_ex(&ca->issuer_dn_nmflag, 
					"esc_2253,esc_ctrl,esc_msb,utf8,dump_nostr,dump_unknown,dump_der,sep_comma_plus,sname");
			}

			ca->db_column_ca_fingerprint = PKI_CONFIG_get_value ( cnf, 
					"/caConfig/dbColumnNameCaFingerprint" );

			ca->db_column_issuer_name_hash = PKI_CONFIG_get_value ( cnf, 
					"/caConfig/dbColumnNameIssuerNameHash" );

			ca->db_column_serial_number = PKI_CONFIG_get_value ( cnf, 
					"/caConfig/dbColumnNameSerialNumber" );

			ca->db_column_issuer_dn = PKI_CONFIG_get_value ( cnf, 
					"/caConfig/dbColumnNameIssuerDN" );
		}

		/* Responder Id Type */
		if ((tmp_s = PKI_CONFIG_get_value(cnf, "/caConfig/responderIdType")) != NULL)
		{
			if (strncmp_nocase(tmp_s, "keyid", 5) == 0) 
			{
				ca->response_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_KEYID;
			}
			else if (strncmp_nocase(tmp_s, "name", 4) == 0)
			{
				ca->response_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;
			}
			else
			{
				PKI_log_err("Can not parse responderIdType: %s (allowed 'keyid' or 'name')", tmp_s);
				exit(1);
			}

			PKI_Free(tmp_s);
		}
		else
		{
			// Default Value
			ca->response_id_type = PKI_X509_OCSP_RESPID_TYPE_BY_NAME;
		}

		// Now let's add the CA_LIST_ENTRY to the list of configured CAs
		PKI_STACK_push ( ca_list, ca );

	}

	handler->ca_list = ca_list;

	return ( PKI_OK );
}


int OCSPD_load_crl ( CA_LIST_ENTRY *ca, OCSPD_CONFIG *conf ) {

	int ret = 0;

	if( !ca ) return PKI_ERR;

	if( !ca->crl_url ) {
		PKI_log_err ("CRL URL is empty (%s)!", ca->ca_id );
		return PKI_ERR;
	}

	if ( ca->crl_data->crl ) PKI_X509_CRL_free ( ca->crl_data->crl );

	if (( ca->crl_data->crl = PKI_X509_CRL_get_url ( ca->crl_url, 
						NULL, NULL )) == NULL ) {
		PKI_log_err ("Failed loading CRL for %s", ca->ca_id );
		return PKI_ERR;
	}

	if(conf->crl_check_mtime) {
		struct stat st;

		if(stat(ca->crl_url->addr, &st) == -1) {
			PKI_log_err ("Cannot access CRL %s (%s)", 
				ca->crl_url->addr, strerror(errno) );
		}
		else
			ca->crl_data->mtime = st.st_mtime;
	}
  
	/* Let's check the CRL against the CA certificate */
	if( (ret = check_crl( ca->crl_data->crl, ca->ca_cert, &ca->single_crl_lock, conf )) < 1 ) {
		PKI_log_err( "CRL/CA check error [ %s:%d ]",
						ca->ca_id, ret );
		return PKI_ERR;
	}

	/* Now we copy the lastUpdate and nextUpdate fields */
	if( ca->crl_data->crl ) {
		ca->crl_data->lastUpdate = PKI_TIME_dup(
			PKI_X509_CRL_get_data (ca->crl_data->crl, 
				PKI_X509_DATA_LASTUPDATE));

		ca->crl_data->nextUpdate = PKI_TIME_dup (
			PKI_X509_CRL_get_data (ca->crl_data->crl,
				PKI_X509_DATA_NEXTUPDATE ));
	}

	if((ca->crl_data->crl_status = check_crl_validity(ca->crl_data, &ca->single_crl_lock, conf, ca->ca_id )) == CRL_OK ) {
		if(conf->verbose) PKI_log( PKI_LOG_INFO, "CRL for %s is Valid", 
				ca->ca_id );
	} else {
		PKI_log_err ( "CRL for %s has ERRORS (%d)", ca->ca_id, 
						ca->crl_data->crl_status );
	}

	/* Let's get the CRLs entries, if any */
	if( (ca->crl_data->crl_list = ocspd_build_crl_entries_list ( ca->crl_data->crl, ca->ca_id ) ) == NULL ) { 
		PKI_log(PKI_LOG_ALWAYS, "No CRL Entries for %s", ca->ca_id );
	};

	if(conf->verbose) PKI_log( PKI_LOG_ALWAYS, "CRL loaded for %s", ca->ca_id );

	return PKI_OK;
}

int ocspd_reload_all_ca ( OCSPD_CONFIG *conf ) {

	int i=0;
	CA_LIST_ENTRY *ca = NULL;

	for( i = 0; i < PKI_STACK_elements( conf->ca_list); i++) {

		ca = PKI_STACK_get_num( conf->ca_list, i );

		/* Let's free the CA certs list, if present */
		/*
		if( ca->cert ) {
			sk_X509_pop_free(ca->cert, X509_free );
		}
		*/

		if (ca->ca_url ) {
			if ( ca->ca_cert) PKI_X509_CERT_free ( ca->ca_cert );

			/* Get the CA certificate */
			ca->ca_cert = PKI_X509_CERT_get_url ( ca->ca_url,
							NULL, NULL );
		}

		/*
		if(!ca->cert || !sk_X509_num(ca->cert)) {
			syslog(LOG_ERR, "Error loading CA URL data.");
			continue;
		} else {
			if(conf->verbose)
				syslog( LOG_INFO,
					"CA CERT for %s loaded successfully.",
					ca->ca_id );
		}
		*/
		if( !ca->ca_cert ) {
			if( ca->ca_url && ca->ca_url->url_s ) {
			   PKI_log_err ( "Can not load CA cert from %s",
				ca->ca_url->url_s);
			} else {
				PKI_log_err ( "Can not load CA cert!");
				continue;
			}
		} else {
			PKI_log( PKI_LOG_INFO, " CA cert for %s loaded ok",
					ca->ca_id );
		}

		ca->sk_cid = CA_ENTRY_CERTID_new_sk ( ca->ca_cert, conf->issuerHashDigest );
		if(ca->sk_cid == NULL ) {
			PKI_log_err( "CA List structure init error (CERTID).");
			continue;
		}
	}

	return 1;
}

STACK_OF(X509_REVOKED) *ocspd_build_crl_entries_list ( PKI_X509_CRL *crl, char *ca_id )
{
	long rev_num = 0;

	STACK_OF(X509_REVOKED) *ret = NULL;
	PKI_X509_CRL_VALUE *crl_val = NULL;

	if ( !crl || !crl->value || !ca_id ) 
	{
		return NULL;
	}

	crl_val = crl->value;

	ret = X509_CRL_get_REVOKED(crl_val);
	rev_num = sk_X509_REVOKED_num(ret);

	// if( ocspd_conf->verbose )
	PKI_log( PKI_LOG_INFO, "INFO::CRL::%ld Entries [ %s ]", rev_num, ca_id );

	if ((rev_num > -1 ) && 
		(ret == NULL))
	{
		PKI_ERROR( PKI_ERR_MEMORY_ALLOC, NULL );
		return NULL;
	}

	sk_X509_REVOKED_sort(ret);

	return (ret);
}

/* --------------------------- CA_LIST_ENTRY ------------------------- */

CA_LIST_ENTRY * CA_LIST_ENTRY_new ( void ) {
	CA_LIST_ENTRY * ca = NULL;

	if((ca = (CA_LIST_ENTRY *) 
			PKI_Malloc ( sizeof (CA_LIST_ENTRY))) == NULL) {
		PKI_ERROR( PKI_ERR_MEMORY_ALLOC, NULL );

		return ( NULL );
	}

	return ( ca );
}

void CRL_DATA_free ( CRL_DATA *crl_data ) {

	if ( crl_data->crl_list )
	{
		X509_REVOKED *r = NULL;

		while ((r = sk_X509_REVOKED_pop ( crl_data->crl_list )) != NULL) 
		{
			X509_REVOKED_free ( r );
		}
	}

	if ( crl_data->crl ) PKI_X509_CRL_free ( crl_data->crl );
	if ( crl_data->nextUpdate ) PKI_TIME_free ( crl_data->nextUpdate );
	if ( crl_data->lastUpdate ) PKI_TIME_free ( crl_data->lastUpdate );
}

void CRL_DATA_free_all ( CRL_DATA *crl_data ) {

	CRL_DATA_free(crl_data);
	PKI_Free(crl_data);
}

void CA_LIST_ENTRY_free ( CA_LIST_ENTRY *ca ) {

	if ( !ca ) return;

	if ( ca->ca_id )
	{
		PKI_log_debug("MEM::Freeing %s CA config", ca->ca_id );
		PKI_Free ( ca->ca_id );
	}

	if ( ca->ca_cert ) PKI_X509_CERT_free ( ca->ca_cert );
	if ( ca->sk_cid )
	{
		CA_ENTRY_CERTID *cid;

		while ((cid = sk_CA_ENTRY_CERTID_pop ( ca->sk_cid )) != NULL) 
		{
			CA_ENTRY_CERTID_free ( cid );
		}
		sk_CA_ENTRY_CERTID_free ( ca->sk_cid );
	}
	if ( ca->ca_url ) URL_free ( ca->ca_url );
	if ( ca->crl_url ) URL_free ( ca->crl_url );

	CRL_DATA_free_all(ca->crl_data);

	if ( ca->token_name ) PKI_Free ( ca->token_name );
	if ( ca->token ) PKI_TOKEN_free ( ca->token );

	if ( ca->db_url ) URL_free ( ca->db_url );
	if ( ca->ca_cert_digest )             PKI_DIGEST_free ( ca->ca_cert_digest );
	if ( ca->db_column_ca_fingerprint )   PKI_Free ( ca->db_column_ca_fingerprint );
	if ( ca->db_column_issuer_name_hash ) PKI_Free ( ca->db_column_issuer_name_hash );
	if ( ca->db_column_serial_number )    PKI_Free ( ca->db_column_serial_number );
	if ( ca->db_column_issuer_dn )        PKI_Free ( ca->db_column_issuer_dn );

	PKI_Free ( ca );

	return;
}

CA_LIST_ENTRY * OCSPD_ca_entry_new ( OCSPD_CONFIG *handler,
				PKI_X509_CERT *x, PKI_CONFIG *cnf ) {

	CA_LIST_ENTRY *ret = NULL;

	if (!handler || !x || !cnf) return NULL;

	if (( ret = PKI_Malloc ( sizeof( CA_LIST_ENTRY ) )) == NULL ) return NULL;

	/* Let's get the CA_ENTRY_CERTID */
	ret->sk_cid = CA_ENTRY_CERTID_new_sk ( x, handler->issuerHashDigest );
	if(ret->sk_cid == NULL ) {
		CA_LIST_ENTRY_free ( ret );
		return ( NULL );
 	}

	return ret;

}

/* ---------------------------- CA_ENTRY_CERTID ------------------------- */

STACK_OF(CA_ENTRY_CERTID) * CA_ENTRY_CERTID_new_sk ( PKI_X509_CERT *cert, 
					STACK_OF(EVP_MD) *mds ) {

	int i;
	STACK_OF(CA_ENTRY_CERTID) *sk_cid = NULL;
	CA_ENTRY_CERTID *cid = NULL;

	PKI_STRING *keyString = NULL;
	PKI_DIGEST *keyDigest = NULL;

	PKI_X509_NAME *iName = NULL;
	PKI_DIGEST *nameDigest = NULL;
	STACK_OF(EVP_MD) *sk_md = NULL;


	PKI_log_debug("Building CA_ENTRY_CERTID stack");

	/* Check for needed info */
	if ( !cert || !cert->value ) return NULL;

	/* fallback */
	if ( !mds )
	{
		if(!OCSPD_EVP_MD_STACK_add_md(&(sk_md), PKI_DIGEST_ALG_SHA1))
		{
			PKI_log_err("Can not add digest algorithm");
			return (NULL);
		}

		mds = sk_md; // use input parameter as temporary variable
	}

	/* Retrieves the subject name from the certificate */
	if ((iName = PKI_X509_CERT_get_data(cert, PKI_X509_DATA_SUBJECT)) == NULL)
	{
		PKI_log_err("Can not get certificate's subject");
		goto err;
	};

	// Let's get the key bitstring from the certificate
	if (( keyString = PKI_X509_CERT_get_data( cert, 
				PKI_X509_DATA_PUBKEY_BITSTRING)) == NULL ) {
		PKI_log_err("Can not get certificate's pubkey bitstring");
		goto err;
	}

	// generate a digest for each given hash algorithm
	for (i = 0; i < sk_EVP_MD_num(mds); ++i) {

		EVP_MD *md = NULL;

		// Allocate Memory for the CA_ENTRY_CERTID stack
		if (!sk_cid && (sk_cid = sk_CA_ENTRY_CERTID_new_null()) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			goto err;
		}

		md = sk_EVP_MD_value(mds, i);
		if(!md)
			continue;

		PKI_log_debug("===Selected issuerHashDigestAlgorithm: %s", EVP_MD_name(md));

		// Allocate Memory for each CA_ENTRY_CERTID
		if((cid = PKI_Malloc(sizeof(CA_ENTRY_CERTID))) == NULL) {
			PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
			goto err;
		}

		// Let's build the HASH of the Name
		if((nameDigest = PKI_X509_NAME_get_digest(iName, md)) == NULL) {
			PKI_log_err("Can not get digest string from certificate's subject");
			goto err;
		}

		// Assign the new OCTET string to the nameHash field
		// remove comment: shouldn't PKI_STRING_new() use size_t ???
		if (( cid->nameHash = PKI_STRING_new ( PKI_STRING_OCTET,
				(char *)nameDigest->digest, (ssize_t) nameDigest->size )) == NULL ) {
			PKI_log_err("Can not assign nameHash to CERTID");
			goto err;
		};

		// We build the keyDigest from the keyString
		if((keyDigest = PKI_STRING_get_digest (keyString, md)) == NULL ) {
			PKI_log_err("Can not create new keyDigest from keyString");
			goto err;
		};

		// remove comment: shouldn't PKI_STRING_new() use size_t ???
		if((cid->keyHash = PKI_STRING_new ( PKI_STRING_OCTET,
						(char *)keyDigest->digest, (ssize_t) keyDigest->size )) == NULL ) {
			PKI_log_err("Can not assign keyHash to CERTID");
			goto err;
		}

		/* Set the Digest Algorithm used */
		if((cid->hashAlgorithm = PKI_ALGORITHM_new_digest( md )) == NULL ) {
			PKI_log_err("ERROR, can not create a new hashAlgorithm!");
			goto err;
		}

		// add entry to our stack
		if(!sk_CA_ENTRY_CERTID_push(sk_cid, cid)) {
			PKI_log_err("ERROR, can not create a new hashAlgorithm!");
			goto err;
		}
		cid = NULL;

		if ( nameDigest ) {
			PKI_DIGEST_free ( nameDigest );
			nameDigest = NULL;
		}
		if ( keyDigest  ) {
			PKI_DIGEST_free ( keyDigest );
			keyDigest = NULL;
		}
	}       

	if ( sk_md ) sk_EVP_MD_free(sk_md);

	return sk_cid;
 
err:
	if ( nameDigest ) PKI_DIGEST_free ( nameDigest );
	if ( keyDigest  ) PKI_DIGEST_free ( keyDigest );
	if ( sk_cid )     sk_CA_ENTRY_CERTID_free(sk_cid);
	if ( cid )        CA_ENTRY_CERTID_free ( cid );
	if ( sk_md )      sk_EVP_MD_free(sk_md);

	return ( NULL );
}


void CA_ENTRY_CERTID_free ( CA_ENTRY_CERTID *cid ) {

	if ( !cid ) return;

	if ( cid->keyHash ) {
		PKI_STRING_free ( cid->keyHash );
	}

	if ( cid->nameHash ) {
		PKI_STRING_free ( cid->nameHash );
	}

	if ( cid->hashAlgorithm ) {
		X509_ALGOR_free(cid->hashAlgorithm);
	}

	PKI_Free ( cid );

	return;
}

