/* file: src/ocspd/ocsp_request.c
 *
 * OpenCA OCSPD - Massimiliano Pala <madwolf@openca.org>
 * Copyright (c) 2001-2009 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 */

#include "general.h"

#define  OCSPD_DEF_MAX_SIZE 	65535
#define  OCSPD_DEF_MAX_READ	1024

#define  METHOD_UNKNOWN		0
#define  METHOD_GET		1
#define  METHOD_POST		2

#define  MAX_USEC		1000
#define  WAIT_USEC		50

#define MAX_LOG_TRACE_SIZE	256

extern OCSPD_CONFIG *ocspd_conf;

PKI_X509_OCSP_REQ * ocspd_req_get_socket ( int connfd, OCSPD_CONFIG *ocspd_conf) 
{
	PKI_X509_OCSP_REQ 	*req = NULL;
	PKI_X509_OCSP_REQ_VALUE *req_val = NULL;

	PKI_IO			*mem = NULL;
	PKI_MEM			*pathmem = NULL;

	PKI_SOCKET		sock;

	size_t maxsize  = 0;
	maxsize = (size_t) ocspd_conf->max_req_size;

	PKI_HTTP *http_msg = NULL;
	char *p_data = NULL;
	int  len = 0;


	if ( connfd <= 0 ) return NULL;

	// Initialize the sock structure
	memset(&sock, 0, sizeof(sock));
	PKI_SOCKET_set_fd ( &sock, connfd );

	http_msg = PKI_HTTP_get_message(&sock, (int) ocspd_conf->max_timeout_secs, maxsize);
	if (http_msg == NULL)
	{
		PKI_log_debug ("Network Error while reading Request!");
		return NULL;
	}

	/* If method is METHOD_GET we shall de-urlify the buffer and get the
	   right begin (keep in mind there might be a path set in the config */

	if( http_msg->method == PKI_HTTP_METHOD_GET )
	{
		char *req_pnt = NULL;

		if (http_msg->path == NULL)
		{
			PKI_log_err("Malformed GET request");
			goto err;
		}
		
		req_pnt = http_msg->path;
		if(strncmp_nocase(req_pnt, "http://", 7) == 0)
			req_pnt += 7;
		else if(strncmp_nocase(req_pnt, "https://", 8) == 0)
			req_pnt += 8;

		/* Skip leading '/' for the path */
		while( *req_pnt == '/' )
			req_pnt++;

		if(strlen(req_pnt) == 0)
		{
			PKI_log_err ( "HTTP GET URL does not contain a valid OCSP request");
			if( ocspd_conf->debug )
			{
				if(strlen(req_pnt) > MAX_LOG_TRACE_SIZE)
					PKI_log_hexdump(PKI_LOG_INFO, "HTTP GET URL (truncated)", MAX_LOG_TRACE_SIZE, http_msg->path);
				else
					PKI_log_hexdump(PKI_LOG_INFO, "HTTP GET URL", (int) strlen(http_msg->path), http_msg->path);
			}
			goto err;
		}

		pathmem = PKI_MEM_new_data(strlen(req_pnt), (unsigned char *) req_pnt);
		if (pathmem == NULL)
		{
			PKI_log_err("Memory allocation failed for %d bytes!", strlen(req_pnt));
			if(strlen(req_pnt) > MAX_LOG_TRACE_SIZE)
				PKI_log_hexdump(PKI_LOG_INFO, "PKI_MEM_new_data() (truncated)", MAX_LOG_TRACE_SIZE, req_pnt);
			else
				PKI_log_hexdump(PKI_LOG_INFO, "PKI_MEM_new_data()", (int) strlen(req_pnt), req_pnt);
			goto err;
		}

		if (PKI_MEM_decode(pathmem, PKI_DATA_FORMAT_URL, 0) != PKI_OK)
		{
			PKI_log_err("URL decode failed!");
			PKI_MEM_free(pathmem);
			goto err;
		}

		if (PKI_MEM_decode(pathmem, PKI_DATA_FORMAT_B64, 0) != PKI_OK)
		{
			PKI_log_err ("Error decoding B64 Mem");

			if(pathmem->size > MAX_LOG_TRACE_SIZE)
				PKI_log_hexdump(PKI_LOG_INFO, "PKI_MEM_B64_decode1() (truncated)", MAX_LOG_TRACE_SIZE, pathmem->data);
			else
				PKI_log_hexdump(PKI_LOG_INFO, "PKI_MEM_B64_decode1()", (int) pathmem->size, pathmem->data);

			PKI_MEM_free (pathmem);
			goto err;
		}

		if(pathmem->size == 0)
		{
			PKI_log_err("No data decoded from GET request");

			if( ocspd_conf->debug )
			{
				if(strlen(req_pnt) > MAX_LOG_TRACE_SIZE)
					PKI_log_hexdump(PKI_LOG_INFO, "Encoded URL (truncated)", MAX_LOG_TRACE_SIZE, req_pnt);
				else
					PKI_log_hexdump(PKI_LOG_INFO, "Encoded URL", (int) strlen(req_pnt), req_pnt);
			}

			PKI_MEM_free(pathmem);
			goto err;
		}

		// Generates a new mem bio from the pathmem
		if((mem = BIO_new_mem_buf(pathmem->data, (int) pathmem->size)) == NULL)
		{
			PKI_log_err("Memory allocation failed for decoded URL path (%d bytes)", pathmem->size);

			if(strlen(req_pnt) > MAX_LOG_TRACE_SIZE)
				PKI_log_hexdump(PKI_LOG_INFO, "Encoded URL (truncated)", MAX_LOG_TRACE_SIZE, req_pnt);
			else
				PKI_log_hexdump(PKI_LOG_INFO, "Encoded URL", (int) strlen(req_pnt), req_pnt);

			PKI_MEM_free(pathmem);
			goto err;
		}

		// Transfer data ownership and release the pathmem
		// BIO_new_mem_buf() creates a new memory buffer - therefore this is not needed
		//pathmem->data = NULL;
		//pathmem->size = 0;

		if( (len = (int)BIO_get_mem_data(mem, &p_data) ) <= 0)
			PKI_log_debug ( "BIO_get_mem_data(GET) failed");

		// Tries to decode the binary (der) encoded request
		if ((req_val = d2i_OCSP_REQ_bio(mem, NULL)) == NULL)
		{
			PKI_log_err("Can not parse REQ");

			if(len > MAX_LOG_TRACE_SIZE)
				PKI_log_hexdump(PKI_LOG_INFO, "d2i_OCSP_REQ_bio(GET) (truncated)", MAX_LOG_TRACE_SIZE, p_data);
			else
				PKI_log_hexdump(PKI_LOG_INFO, "d2i_OCSP_REQ_bio(GET)", len, p_data);

			BIO_free(mem);
			PKI_MEM_free(pathmem);
			goto err;
		}

		// Let's free the mem
		BIO_free(mem);

		PKI_MEM_free(pathmem);
	} 
	else if (http_msg->method == PKI_HTTP_METHOD_POST)
	{
		if(http_msg->body->size <= 0)
		{
			PKI_log_debug ( "HTTP POST message: Body does not contain any data.");
			goto err;
		}

		mem = BIO_new_mem_buf(http_msg->body->data, (int) http_msg->body->size);
		if (mem == NULL)
		{
			PKI_log_err( "Memory allocation failed for HTTP POST message (allocating %d bytes).", http_msg->body->size);
			goto err;
		}
		else
		{
			if( (len = (int)BIO_get_mem_data(mem, &p_data) ) <= 0)
				PKI_log_debug ( "BIO_get_mem_data(POST) failed");

			if ((req_val = d2i_OCSP_REQ_bio(mem, NULL)) == NULL)
			{
				PKI_log_err("Can not parse REQ");

				if(len > MAX_LOG_TRACE_SIZE)
					PKI_log_hexdump(PKI_LOG_INFO, "d2i_OCSP_REQ_bio(POST) (truncated)", MAX_LOG_TRACE_SIZE, p_data);
				else
					PKI_log_hexdump(PKI_LOG_INFO, "d2i_OCSP_REQ_bio(POST)", len, p_data);
			}
			BIO_free (mem);
		}
	} 
	else
	{
		PKI_log_err ( "HTTP Method not supported");
		goto err;
	}

	if ( !req_val ) goto err;

	req = PKI_X509_new_value(PKI_DATATYPE_X509_OCSP_REQ, req_val, NULL);
	if (req == NULL)
	{
		PKI_log_err ("Can not generate a new X509_OCSP_REQ");
		goto err;
	}

	if ( http_msg ) PKI_HTTP_free ( http_msg );

	return (req);

err:
	if (req) PKI_X509_OCSP_REQ_free(req);

	if (http_msg) PKI_HTTP_free(http_msg);

	return NULL;
}

