#include <sys/time.h>
#include "general.h"


extern OCSPD_CONFIG *ocspd_conf;
extern const char *x509statusInfo[];

/* Thread Function Prototype */
void * thread_main ( void *arg );


static int log_stats_data(OCSPD_SESSION_INFO *sinfo)
{
	int ret = 1;
	BIO *membio = NULL;
	PKI_MEM *pki_mem = NULL;
	long len = 0;
	char *p_data = NULL;
	const LOG_STATS_ITEM_TBL *tbl;
	int first = 1;
	struct tm tm;
	char stime[25];


	if( (membio = BIO_new(BIO_s_mem())) == NULL)
	{
		PKI_log_err("Memory allocation error!");
		return(PKI_ERR);
	}

	for(tbl = ocsp_stats_item_tbl; tbl->name; tbl++)
	{
		int err = 0;

		// For the first item a >'< will be prepended by URL_put_data_url()
		// After the last item a >'< will be appended by URL_put_data_url()
		switch(ocspd_conf->log_stats_flags & tbl->flag)
		{
			case OCSPD_STATS_INFO_STARTTIME:
				err = BIO_printf(membio, "%s%lld", first ? "" : "','", (long long)(((long long)sinfo->start.tv_sec * 1000) + (long long)sinfo->start.tv_usec / 1000));
				break;
			case OCSPD_STATS_INFO_ENDTIME:
				err = BIO_printf(membio, "%s%lld", first ? "" : "','", (long long)(((long long)sinfo->stop.tv_sec * 1000) + (long long)sinfo->stop.tv_usec / 1000));
				break;
			case OCSPD_STATS_ARRIVAL_TIME:
				// This is for logging an SQL TIMESTAMP with fractional part (support by MySQL 5.6 and above)
				// http://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-4.html
				// http://dev.mysql.com/doc/refman/5.6/en/datetime.html
				if(gmtime_r(&sinfo->start.tv_sec, &tm) != NULL)
				{
					if(strftime(stime, sizeof(stime), "%Y-%m-%d %H:%M:%S", &tm) > 0)
						err = BIO_printf(membio, "%s%s%ld", first ? "" : "','", stime, sinfo->start.tv_usec/1000);
					else
						PKI_log_err("strftime() returnd 0 - unable to calculate arrival time.");
				}
				else
					PKI_log_err("gmtime_r() failed - unable to calculate arrival time.");
				break;
			case OCSPD_STATS_DEPARTURE_TIME:
				if(gmtime_r(&sinfo->stop.tv_sec, &tm) != NULL)
				{
					if(strftime(stime, sizeof(stime), "%Y-%m-%d %H:%M:%S", &tm) > 0)
						err = BIO_printf(membio, "%s%s%ld", first ? "" : "','", stime, sinfo->stop.tv_usec/1000);
					else
						PKI_log_err("strftime() returnd 0 - unable to calculate departure time.");
				}
				else
					PKI_log_err("gmtime_r() failed - unable to calculate departure time.");
				break;
			case OCSPD_STATS_INFO_RESPONSE_STATUS:
				err = BIO_printf(membio, "%s%d", first ? "" : "','", sinfo->resp_status);
				break;
			case OCSPD_STATS_INFO_CERT_STATUS:
				err = BIO_printf(membio, "%s%d", first ? "" : "','", sinfo->cert_status);
				break;
			case OCSPD_STATS_INFO_SERIAL:
				if(sinfo->serial != NULL)
					err = BIO_printf(membio, "%s%s", first ? "" : "','", sinfo->serial);
				else
					err = BIO_printf(membio, "%sn/a", first ? "" : "','");
				break;
			case OCSPD_STATS_INFO_ISSUER:
				if(sinfo->issuer != NULL)
					err = BIO_printf(membio, "%s%s", first ? "" : "','", sinfo->issuer);
				else
					err = BIO_printf(membio, "%sn/a", first ? "" : "','");
				break;
			case OCSPD_STATS_INFO_CANAME:
				if(sinfo->ca_id != NULL)
					err = BIO_printf(membio, "%s%s", first ? "" : "','", sinfo->ca_id);
				else
					err = BIO_printf(membio, "%sn/a", first ? "" : "','");
				break;
			case OCSPD_STATS_INFO_IP:
				err = BIO_printf(membio, "%s%s", first ? "" : "','", inet_ntoa(sinfo->cliaddr.sin_addr));
				break;
			case OCSPD_STATS_INFO_DURATION:
				err = BIO_printf(membio, "%s%u", first ? "" : "','", sinfo->duration);
				break;
			case OCSPD_STATS_RESPONDER_NAME:
				if(ocspd_conf->responder_name != NULL)
					err = BIO_printf(membio, "%s%s", first ? "" : "','", ocspd_conf->responder_name);
				else
					err = BIO_printf(membio, "%sn/a", first ? "" : "','");
				break;
			default: // no match
				continue;
				break;
		}

		if(err <= 0)
		{
			PKI_log_err ("BIO_printf() failed by flag %X!\n", tbl->flag);
			goto end;
		}
		first = 0;
	}

	if( (len = BIO_get_mem_data(membio, &p_data) ) <= 0)
	{
		PKI_log_err ( "BIO_get_mem_data() failed");
		goto end;
	}

	if ((pki_mem = PKI_MEM_new_data((size_t)len, (unsigned char *)p_data)) == NULL)
	{
		PKI_ERROR(PKI_ERR_MEMORY_ALLOC, NULL);
		goto end;
	}

	if(URL_put_data_url(ocspd_conf->log_stats_url, pki_mem, NULL, NULL, 0, 0, NULL) != PKI_OK)
		PKI_log_err ( "URL_put_data_url() failed");
	else
		ret = 0;

end:
	if(membio)  BIO_free(membio);
	if(pki_mem) PKI_MEM_free (pki_mem);

	return(ret);
}

static void cleanup_handler(void *arg)
{
	PKI_log_debug ( "Mutex cleanup handler called...");

	PKI_MUTEX_release((PKI_MUTEX *)arg);
}


int thread_make ( int i )
{
	PKI_THREAD *th_id = NULL;
	int * id = NULL;

	// Basic Memory Check
	if (!ocspd_conf || !ocspd_conf->threads_list) return -1;

	if ((id = (int *) PKI_Malloc(sizeof(int))) == NULL)
	{
		PKI_log_err("Memory allocation error!");
		return -1;
	}

	// Assign the thread id
	*id = i;

	// Let's generate the new thread
	if ((th_id = PKI_THREAD_new(thread_main, (void *) id)) == NULL)
	{
		PKI_log_err("ERROR::OPENCA_SRV_ERR_THREAD_CREATE");
		return(-1);
	}

	// Copy the value of the thread structure
	memcpy(&ocspd_conf->threads_list[i].thread_tid, th_id, sizeof(PKI_THREAD));

	// Frees the memory associated with the original structure
	PKI_Free(th_id);

	// Returns ok
	return OCSPD_SRV_OK;
}

void * thread_main ( void *arg )
{
	int connfd    = -1;
	int thread_nr = -1;
	int *arg_int  = NULL;
	int ret = PKI_OK;
	char err_str[128];
	sigset_t signal_set;

	socklen_t cliaddrlen = sizeof( struct sockaddr_in );

	PKI_X509_OCSP_REQ  *req = NULL;
	PKI_X509_OCSP_RESP *resp = NULL;
	OCSPD_SESSION_INFO sinfo;


	if (arg)
	{
		arg_int = (int *) arg;
		thread_nr = *arg_int;

		PKI_Free(arg);
	}
	else
	{
		thread_nr = -1;
	}

	if ( ocspd_conf->verbose )
		PKI_log(PKI_LOG_INFO, "New Thread Started [%d]", thread_nr);

	if(sigemptyset(&signal_set) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigemptyset() failed: [%d] %s\n", errno, err_str);
		goto exit_thread;
	}

	if(sigaddset(&signal_set, SIGUSR1) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaddset() failed: [%d] %s\n", errno, err_str);
		goto exit_thread;
	}

	if(pthread_sigmask( SIG_UNBLOCK, &signal_set, NULL ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("pthread_sigmask() failed: [%d] %s\n", errno, err_str);
		goto exit_thread;
	}


	for ( ; ; )
	{
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.cert_status = V_OCSP_CERTSTATUS_UNKNOWN;

		pthread_cleanup_push(cleanup_handler, &ocspd_conf->mutexes[CLIFD_MUTEX]);

		/* Before calling the cond_wait we need to own the mutex */
		PKI_log_debug ( "acquire mutex..");
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		PKI_log_debug ( "got mutex..");

		while(ocspd_conf->connfd <= 2)
		{
			PKI_log_debug ( "cond wait..");
			PKI_COND_wait ( &ocspd_conf->condVars[CLIFD_COND],
				&ocspd_conf->mutexes[CLIFD_MUTEX] );
		}

		PKI_log_debug ( "got new connection");

		// Let's copy the socket descriptor
		connfd = ocspd_conf->connfd;

		// Reset the global value
		ocspd_conf->connfd = -1;

		// Let's now release the mutex to allow for the server to listen
		// for the next connection
		PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );

		pthread_cleanup_pop(0);

		// Communicate to the main thread to listen for the next connection
		pthread_cleanup_push(cleanup_handler, &ocspd_conf->mutexes[SRVFD_MUTEX]);
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		PKI_COND_signal ( &ocspd_conf->condVars[SRVFD_COND] );
		PKI_MUTEX_release ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		pthread_cleanup_pop(0);

		// Set start timer
		if(gettimeofday(&sinfo.start, NULL) != 0)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("Setting start timer with gettimeofday() failed [%d::%s]", errno, err_str);
		}

		// Some debugging information
		if (ocspd_conf->debug)
		{
			if (getpeername(connfd, (struct sockaddr*)&sinfo.cliaddr, &cliaddrlen) == -1)
			{
				PKI_strerror ( errno, err_str, sizeof(err_str));
				PKI_log_err("Network Error [%d::%s] in getpeername", errno, err_str);
			}

				PKI_log(PKI_LOG_INFO, "Connection from [%s]",
				inet_ntoa(sinfo.cliaddr.sin_addr));
		}

		// Retrieves the request from the socket
		req = ocspd_req_get_socket(connfd, ocspd_conf);

		// If there is an error and we want to debug, let's print some useful info
		if (req == NULL && ocspd_conf->debug) PKI_log_debug("Can not parse REQ");

		// Now let's build the response
		resp = make_ocsp_response(req, ocspd_conf, &sinfo);

		// If we do not have a response, we were not able to generate one
		// from the received request, let's send a generic error.
		if (resp == NULL)
		{
			// Error info
			PKI_log_err("Can not generate the OCSP response (internal error)");

			// Generate the error response
			resp = PKI_X509_OCSP_RESP_new();
			if (resp != NULL)
			{
				PKI_X509_OCSP_RESP_set_status(resp,
					PKI_X509_OCSP_RESP_STATUS_MALFORMEDREQUEST );
			}
		}

		// If we have a response, let's send it over the wire and free
		// the associated memory
		if (resp != NULL)
		{
			PKI_OCSP_RESP * r = resp->value;

			// Send the response over the wire
			ocspd_resp_send_socket( connfd, resp, ocspd_conf );

			sinfo.resp_status = (int)ASN1_ENUMERATED_get(r->resp->responseStatus);

			// Frees the response memory
			PKI_X509_OCSP_RESP_free (resp);
		}

		// Set end timer
		if(gettimeofday(&sinfo.stop, NULL) != 0)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("Setting end timer with gettimeofday() failed [%d::%s]", errno, err_str);
		}
		else
		{
			// we calculate directly milliseconds for further usage
			sinfo.duration = (unsigned int)((sinfo.stop.tv_sec - sinfo.start.tv_sec) * 1000 + (sinfo.stop.tv_usec - sinfo.start.tv_usec) / 1000);

			if(ocspd_conf->log_stats_url)
				(void)log_stats_data(&sinfo);
		}

		if(sinfo.serial)
			OPENSSL_free(sinfo.serial);

		if(sinfo.issuer)
			OPENSSL_free(sinfo.issuer);

		if(sinfo.ca_id)
			OPENSSL_free(sinfo.ca_id);

		// Free the memory associated with the request
		if (req != NULL) PKI_X509_OCSP_REQ_free (req);

		// Finally close the current socket
		PKI_NET_close(connfd);

exit_thread:
		if(ocspd_conf->valgrind) {
			PKI_final_thread();
			pthread_exit((void*)&ret); // valgrind
		}
	}
  return(NULL);
}
