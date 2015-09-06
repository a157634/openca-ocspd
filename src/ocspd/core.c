/* ===========================================================
 * OpenCA OCSPD Server - src/core.c
 * (c) 2001-2014 by Massimiliano Pala and OpenCA Labs
 * All Rights Reserved
 * ===========================================================
 * OpenCA Licensed Software
 * ===========================================================
 */

#include "general.h"
#include "threads.h"
#include "crl.h"
 #include <sys/resource.h>
#include <openssl/err.h>

extern void auto_crl_check( int );
extern OCSPD_CONFIG *ocspd_conf;

/* mutex internally used for the signal handling thread */
static pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;
static PKI_THREAD_ID th_id_main;
static PKI_THREAD_ID th_id_crl_hdl;
static PKI_THREAD_ID th_id_con_hdl;
static PKI_THREAD *th_sig_hdl = NULL;
static PKI_THREAD *th_con_hdl = NULL;

/* Function Bodies */

static void handle_sigusr1 ( int sig )
{
	int ret = PKI_OK;
	int i;
	int rv = 0;
	char err_str[128];
	int valgrind = ocspd_conf->valgrind;
  

	if(pthread_equal(PKI_THREAD_self(), th_id_main) != 0) // <> 0 means the IDs are equal
	{
		PKI_log_debug("Handle SIGUSR1 for main thread");

		// retrieve status from signal handling thread
		if( (rv = pthread_join(*th_sig_hdl, NULL) ) != 0)
		{
			PKI_strerror ( rv, err_str, sizeof(err_str));
			PKI_log_err("pthread_join() for signal handling thread failed: [%d::%s]", rv, err_str);
		}
		else
			PKI_log_debug("Signal handling thread returned");

		PKI_Free(th_sig_hdl);

		// retrieve status from connection handling thread
		if( (rv = pthread_join(*th_con_hdl, NULL) ) != 0)
		{
			PKI_strerror ( rv, err_str, sizeof(err_str));
			PKI_log_err("pthread_join() for connection handling thread failed: [%d::%s]", rv, err_str);
		}
		else
			PKI_log_debug("Connection handling thread returned");

		PKI_Free(th_con_hdl);

		for (i = 0; i < ocspd_conf->nthreads; i++)
		{
			PKI_log_debug("Retrieve status from worker threads");
			// retrieve status from worker threads
			if( (rv = pthread_join(ocspd_conf->threads_list[i].thread_tid, NULL) ) != 0)
			{
				PKI_strerror ( rv, err_str, sizeof(err_str));
				PKI_log_err("pthread_join() for worker thread failed: [%d::%s]", rv, err_str);
			}
			else
				PKI_log(PKI_LOG_INFO, "Worker thread %d returned", i);
		}

		if(ocspd_conf) OCSPD_free_config(ocspd_conf);
		if(ocspd_conf) PKI_Free(ocspd_conf);
		PKI_final_all();
		PKI_final_thread();  // also needed for the main thread

		PKI_log_debug("Exiting main thread");
		if(valgrind)
			pthread_exit((void*)&ret);
		else
			exit(0);
	}
  else if(pthread_equal(PKI_THREAD_self(), th_id_con_hdl) != 0) // <> 0 means the IDs are equal
	{
		PKI_log_debug("Handle SIGUSR1 for connection handling thread");
		PKI_final_thread();

		pthread_exit((void*)&ret);
	}
  else if(pthread_equal(PKI_THREAD_self(), th_id_crl_hdl) != 0) // <> 0 means the IDs are equal
	{
		PKI_log_debug("Handle SIGUSR1 for CRL handling thread");
		PKI_final_thread();

		pthread_exit((void*)&ret);
	}
	else
	{
		PKI_log_debug("Handle SIGUSR1 for worker thread");
		PKI_final_thread();

		pthread_exit((void*)&ret);
	}

	return;
}

static void handle_crl_reload ( int sig )
{
	switch( sig )
	{
		case SIGALRM:
			PKI_log_debug("Handle SIGALRM for crl thread");
			if( ocspd_conf->crl_auto_reload ||
					ocspd_conf->crl_check_validity ) {
				(void)auto_crl_check(sig);
			}
			break;

		case SIGHUP:
			PKI_log_debug("Handle SIGHUP for crl thread");
			ocspd_reload_crls( ocspd_conf );
			break;

		/* whatever you need to do for other signals */
		default:
			PKI_log (PKI_LOG_INFO, "handle_crl_reload(): Caught signal [%d] %s (unhandled)", sig, strsignal(sig));
			break;
	}

	return;
}

static void * thread_sig_handler ( void *arg )
{
	sigset_t signal_set;
	int sig;
	char err_str[512];

	PKI_log_debug ( "thread_sig_handler() started");

	// Register the alarm handler
	if(set_alrm_handler() != 0)
		return(NULL);

	for(;;)
	{
		/* wait for any and all signals */
		if(sigfillset(&signal_set) == -1)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("sigfillset() failed: [%d] %s", errno, err_str);
			return(NULL);
		}

    /* ignore the followin signals */
		if(sigdelset( &signal_set, SIGUSR1 ) == -1)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("sigdelset(SIGUSR1) failed: [%d] %s", errno, err_str);
			return(NULL);
		}
		if(sigdelset( &signal_set, SIGALRM ) == -1)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("sigdelset(SIGALRM) failed: [%d] %s", errno, err_str);
			return(NULL);
		}
		if(sigdelset( &signal_set, SIGHUP ) == -1)
		{
			PKI_strerror ( errno, err_str, sizeof(err_str));
			PKI_log_err("sigdelset(SIGHUP) failed: [%d] %s", errno, err_str);
			return(NULL);
		}

		sigwait( &signal_set, &sig );

		/* when we get here, we've caught a signal */

		switch( sig )
		{
			case SIGQUIT:
			case SIGTERM:
			case SIGINT:
			{
				int i;
				int err;

				pthread_mutex_lock(&sig_mutex);
				for (i = 0; i < ocspd_conf->nthreads; i++)
				{
					PKI_log_debug("Kill worker thread %d \n", i);

					if( (err = pthread_kill(ocspd_conf->threads_list[i].thread_tid, SIGUSR1) ) != 0)
					{
						PKI_strerror ( err, err_str, sizeof(err_str));
						PKI_log_err("pthread_kill() failed: [%d] %s", err, err_str);
					}
				}

				PKI_log_debug("Kill connection handling thread\n");

				if( (err = pthread_kill(th_id_con_hdl, SIGUSR1) ) != 0)
				{
					PKI_strerror ( err, err_str, sizeof(err_str));
					PKI_log_err("pthread_kill() failed: [%d] %s", err, err_str);
				}

				PKI_log_debug("Kill main thread\n");

				if( (err = pthread_kill(th_id_main, SIGUSR1) ) != 0)
				{
					PKI_strerror ( err, err_str, sizeof(err_str));
					PKI_log_err("pthread_kill() failed: [%d] %s", err, err_str);
				}
				pthread_mutex_unlock(&sig_mutex);
				err = 0;
				PKI_final_thread();
				pthread_exit((void*)&err);
				break;
			}
			case SIGALRM:
				pthread_mutex_lock(&sig_mutex);
				pthread_mutex_unlock(&sig_mutex);
				if( ocspd_conf->crl_auto_reload ||
						ocspd_conf->crl_check_validity ) {
					(void)auto_crl_check(sig);
				}
				break;

			case SIGHUP:
				pthread_mutex_lock(&sig_mutex);
				ocspd_reload_crls( ocspd_conf );
				pthread_mutex_unlock(&sig_mutex);
				break;

			case SIGUSR2:
				pthread_mutex_lock(&sig_mutex);
				pthread_mutex_unlock(&sig_mutex);
				break;

			/* whatever you need to do for
			 * other signals */
			default:
				pthread_mutex_lock(&sig_mutex);
				PKI_log (PKI_LOG_INFO, "Caught signal [%d] %s (unhandled)", sig, strsignal(sig));
				pthread_mutex_unlock(&sig_mutex);
				break;
		}
	}

	return(NULL);
}

static void cleanup_handler(void *arg)
{
	PKI_log_debug ( "Mutex cleanup handler called...");

	PKI_MUTEX_release((PKI_MUTEX *)arg);
}

static void * thread_con_handler ( void *arg )
{
	char err_str[512];
	sigset_t signal_set;
	int ret = PKI_OK;


	th_id_con_hdl = PKI_THREAD_self();

	PKI_log_debug ( "thread_con_handler() started");

	if(sigemptyset(&signal_set) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigemptyset() failed: [%d] %s", errno, err_str);
		goto exit_thread;
	}

	if(sigaddset(&signal_set, SIGUSR1) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaddset(SIGUSR1) failed: [%d] %s", errno, err_str);
		goto exit_thread;
	}

	if(pthread_sigmask( SIG_UNBLOCK, &signal_set, NULL ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("pthread_sigmask() failed: [%d] %s", errno, err_str);
		goto exit_thread;
	}


	for ( ; ; ) 
	{
		int err = 0;

		// Acquires the Mutex for handling the ocspd_conf->connfd
		pthread_cleanup_push(cleanup_handler, &ocspd_conf->mutexes[CLIFD_MUTEX]);
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		PKI_log_debug ( "Con thread: Wait for a new connection..");

		if( (ocspd_conf->connfd = PKI_NET_accept(ocspd_conf->listenfd, 0) ) == -1)
		{
			// Provides some information about the error
			if (ocspd_conf->verbose || ocspd_conf->debug)
			{
				char err_str[512];
				PKI_strerror ( err, err_str, sizeof(err_str));
				PKI_log_err("Network Error [%d::%s]", err, err_str);
			}

			err = 1;
		}
		else
		{
			// Communicate that there is a good socket waiting for a thread to pickup
			PKI_COND_broadcast ( &ocspd_conf->condVars[CLIFD_COND] );
		}

		// Release the connfd MUTEX
		PKI_MUTEX_release ( &ocspd_conf->mutexes[CLIFD_MUTEX] );
		pthread_cleanup_pop(0);

		if(err)
		{
			// Restart from the top of the cycle
			continue;
		}

		PKI_log_debug ( "Con thread: got new connection..");

		// Waits for a thread to successfully pickup the socket
		PKI_log_debug ( "Con thread: acquire next mutex..");
		pthread_cleanup_push(cleanup_handler, &ocspd_conf->mutexes[SRVFD_MUTEX]);
		PKI_MUTEX_acquire ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		while (ocspd_conf->connfd > 2)
		{
			PKI_log_debug ( "Con thread: cond wait..");
			PKI_COND_wait ( &ocspd_conf->condVars[SRVFD_COND],
				&ocspd_conf->mutexes[SRVFD_MUTEX] );
		}
		PKI_MUTEX_release ( &ocspd_conf->mutexes[SRVFD_MUTEX] );
		PKI_log_debug ( "Con thread: connection handled by a thread");
		pthread_cleanup_pop(0);
	}


exit_thread:
	PKI_final_thread();
	pthread_exit((void*)&ret);

	return(NULL);
}

int start_threaded_server ( OCSPD_CONFIG * ocspd_conf )
{
	int i = 0;
	int rv = 0;
	sigset_t signal_set;
	struct sigaction sa;
	char err_str[512];

	th_id_main = PKI_THREAD_self();

	// Just print a nice log message when exits
	atexit(close_server);

	if( ocspd_conf->token ) {

		if( PKI_TOKEN_init(ocspd_conf->token, 
				ocspd_conf->token_config_dir, ocspd_conf->token_name)
								== PKI_ERR)
		{
			PKI_log_err( "Can not load default token (%s:%s)",
				ocspd_conf->cnf_filename, ocspd_conf->token_name );
			return(1);
		}


		PKI_TOKEN_cred_set_cb ( ocspd_conf->token, NULL, NULL);

		if (PKI_TOKEN_login ( ocspd_conf->token ) != PKI_OK)
		{
			PKI_log_debug("Can not login into token!");
			return(1);
		}

		rv = PKI_TOKEN_check(ocspd_conf->token);
		if (rv & (PKI_TOKEN_STATUS_KEYPAIR_ERR |
							PKI_TOKEN_STATUS_CERT_ERR |
							PKI_TOKEN_STATUS_CACERT_ERR))
		{
			if (rv & PKI_TOKEN_STATUS_KEYPAIR_ERR) PKI_ERROR(PKI_ERR_TOKEN_KEYPAIR_LOAD, NULL);
			if (rv & PKI_TOKEN_STATUS_CERT_ERR) PKI_ERROR(PKI_ERR_TOKEN_CERT_LOAD, NULL);
			if (rv & PKI_TOKEN_STATUS_CACERT_ERR) PKI_ERROR(PKI_ERR_TOKEN_CACERT_LOAD, NULL);

			PKI_log_err("Token Configuration Fatal Error (%d)", rv);
			return(rv);
		}
	}

	/* Initialize all the tokens configured for the single CA entries */
	for (i = 0; i < PKI_STACK_elements(ocspd_conf->ca_list); i++)
	{
		CA_LIST_ENTRY *ca = NULL;

		if ((ca = PKI_STACK_get_num( ocspd_conf->ca_list, i )) == NULL)
			continue;

		if (ca->token_name == NULL)
			continue;

		rv = PKI_TOKEN_init(ca->token, ca->token_config_dir, ca->token_name);
		if (rv != PKI_OK)
		{
			PKI_ERROR(rv, NULL);
			PKI_log_err ( "Can not load token %s for CA %s (%s)",
				ca->token_name, ca->ca_id, ca->token_config_dir );
			return (rv);
		}

		PKI_TOKEN_cred_set_cb ( ocspd_conf->token, NULL, NULL);

		rv = PKI_TOKEN_login(ca->token);
		if (rv != PKI_OK)
		{
			PKI_log_err("Can not login into token (%s)!", ca->ca_id);
			return(rv);
		}

		rv = PKI_TOKEN_check(ca->token);
		if ( rv & (PKI_TOKEN_STATUS_KEYPAIR_ERR |
							 PKI_TOKEN_STATUS_CERT_ERR |
							 PKI_TOKEN_STATUS_CACERT_ERR))
		{
			if (rv & PKI_TOKEN_STATUS_KEYPAIR_ERR) PKI_ERROR(PKI_TOKEN_STATUS_KEYPAIR_ERR, NULL);
			if (rv & PKI_TOKEN_STATUS_CERT_ERR) PKI_ERROR(PKI_TOKEN_STATUS_CERT_ERR, NULL);
			if (rv & PKI_TOKEN_STATUS_CACERT_ERR) PKI_ERROR(PKI_TOKEN_STATUS_CACERT_ERR, NULL);

			PKI_log_err ( "Token Configuration Fatal Error (%d) for ca %s", rv, ca->ca_id);
			return(rv);
		}
	}

	if((ocspd_conf->listenfd = PKI_NET_listen (ocspd_conf->bindUrl->addr,
					ocspd_conf->bindUrl->port, PKI_NET_SOCK_STREAM )) == PKI_ERR ) {
		PKI_log_err ("Can not bind to [%s],[%d]",
			ocspd_conf->bindUrl->addr, ocspd_conf->bindUrl->port);
		return(101);
	}

	// Now Chroot the application
	if ((ocspd_conf->chroot_dir) && (set_chroot( ocspd_conf ) < 1))
	{
		PKI_log_err ("Can not chroot, exiting!");
		return(204);
	}

	// Set privileges
	if (set_privileges(ocspd_conf) < 1)
	{
		if (ocspd_conf->chroot_dir != NULL)
		{
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Can not drop privileges! [203]");
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Continuing because chrooted");
		}
		else
		{
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Can not drop privileges! [204]");
			PKI_log(PKI_LOG_ALWAYS, "SECURITY:: Check User/Group in config file!");
			return(204);
		}
	}

	/* We set our needed signal handlers in the main program (aka main thread).
	 * Later we will create some sub-threads as worker threads, connection handler
	 * and signal handler. Depending on the thread some signals will then be
	 * blocked using pthread_sigmask() */

	/* Using SIGUSR1 for a clean termination of the threads */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handle_sigusr1;
	sigemptyset(&sa.sa_mask);
	
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaction(SIGUSR1) failed [%d::%s]", errno, err_str);
		return(1);
	}

	/* A CRL reload is performed on SIGALRM and SIGHUP */
	sa.sa_handler = handle_crl_reload;

	if (sigaction(SIGALRM, &sa, NULL) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaction(SIGALRM) failed [%d::%s]", errno, err_str);
		return(1);
	}

	if (sigaction(SIGHUP, &sa, NULL) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaction(SIGHUP) failed [%d::%s]", errno, err_str);
		return(1);
	}

	/* block all signals in the main thread */
	if(sigfillset( &signal_set ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigfillset() failed: [%d] %s", errno, err_str);
		return(1);
	}

	/* but use SIGUSR1 for thread termination */
	if(sigdelset( &signal_set, SIGUSR1 ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigdellset() failed: [%d] %s", errno, err_str);
		return(1);
	}

	if( (rv = pthread_sigmask( SIG_BLOCK, &signal_set, NULL )) == -1)
	{
		PKI_strerror ( rv, err_str, sizeof(err_str));
		PKI_log_err("pthread_sigmask() failed: [%d] %s", rv, err_str);
		return(1);
	}

	/* create the signal handling thread (only ignores SIGALRM, SIGHUP and SIGUSR1) */
	if ((th_sig_hdl = PKI_THREAD_new(thread_sig_handler, NULL)) == NULL)
	{
		PKI_log_err("ERROR::OPENCA_SRV_ERR_THREAD_CREATE");
		return(-1);
	}

	if((ocspd_conf->threads_list = calloc ( (size_t) ocspd_conf->nthreads, 
					sizeof(Thread))) == NULL )
	{
		PKI_log_err ("Memory allocation failed");
		return(79);
	}

	/* Create the worker threads */
	for (i = 0; i < ocspd_conf->nthreads; i++)
	{
		if (thread_make(i) != 0)
		{
			PKI_log_err ("Can not create thread (%d)\n", i );
			return(80);
		}
	}

	/* create the connection handling thread */
	if ((th_con_hdl = PKI_THREAD_new(thread_con_handler, NULL)) == NULL)
	{
		PKI_log_err("ERROR::OPENCA_SRV_ERR_THREAD_CREATE");
		return(-1);
	}

	if(sigemptyset(&signal_set) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigemptyset() failed: [%d] %s", errno, err_str);
		return(-1);
	}

	if(sigaddset(&signal_set, SIGUSR1) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaddset(SIGUSR1) failed: [%d] %s", errno, err_str);
		return(-1);
	}

	if(sigaddset(&signal_set, SIGHUP) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaddset(SIGHUP) failed: [%d] %s", errno, err_str);
		return(-1);
	}

	if(sigaddset(&signal_set, SIGALRM) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("sigaddset(SIGALRM) failed: [%d] %s", errno, err_str);
		return(-1);
	}

	if(pthread_sigmask( SIG_UNBLOCK, &signal_set, NULL ) == -1)
	{
		PKI_strerror ( errno, err_str, sizeof(err_str));
		PKI_log_err("pthread_sigmask() failed: [%d] %s", errno, err_str);
		return(-1);
	}

	while(1)
	{
		pause();
	}


	return(0);
}

int set_alrm_handler( void ) {

	/* Now on the parent process we setup the auto_checking
	   functions */

	if( ocspd_conf->crl_auto_reload ||
			ocspd_conf->crl_check_validity ) {

		int auto_rel, val_check;

		/* Help variable, for readability reasons */
		auto_rel = ocspd_conf->crl_auto_reload;
		val_check = ocspd_conf->crl_check_validity;

		/* This returns the min of the two values if it
		   is not 0, otherwise return the other */
		ocspd_conf->alarm_decrement = 
			(( auto_rel > val_check ) ? 
				(val_check ? val_check : auto_rel) : 
					(auto_rel ? auto_rel : val_check ));

		alarm ( (unsigned int) ocspd_conf->alarm_decrement );
	}

	return 0;
}

void close_server ( void ) {
	PKI_log (PKI_LOG_NOTICE, "Exiting, Glad to serve you, Master!");
	return;
}

int set_privileges( OCSPD_CONFIG *conf ) {

	struct passwd *pw = NULL;
	struct group *gr = NULL;

	if( !conf->group || !conf->user)
		return 0;

	if( (gr = getgrnam( conf->group ) ) == NULL ) {
		PKI_log_err("Cannot find group %s", conf->group);
		return 0;
	}
	
	if( (pw = getpwnam( conf->user ) ) == NULL ) {
		PKI_log_err ("Cannot find user %s", conf->user);
		return 0;
	}

	/* When dropping privileges from root, the setgroups() call will
	 * remove any extraneous groups.
	 */

	if(setgroups(0, NULL) == -1) {
		PKI_log_err ("Dropping privileges failed [%s]", strerror(errno));
		return 0;
	}

	if (setgid (gr->gr_gid) == -1) {
		PKI_log_err ("Error setting group %d (%s): %s", 
			gr->gr_gid, conf->group, strerror(errno));
		return 0;
	}

	if (setuid (pw->pw_uid) == -1) {
		PKI_log_err("Error setting user %d (%s): %s", 
						pw->pw_uid, conf->user, strerror(errno));
		return 0;
	}

	return 1;
}

int set_chroot( OCSPD_CONFIG *conf ) {

	if( (!conf) || (!conf->chroot_dir))
		return(1);

	/* Now chroot the running process before starting the server */
	if( chdir ( conf->chroot_dir ) != 0 ) {
		/* Error in changing to working directory */
		PKI_log_err ("SECURITY::CHROOT::ERROR [%s]", strerror(errno));
		perror(NULL);
		return(0);
	}

	if( chroot( conf->chroot_dir ) != 0 ) {
		/* Error chrooting the process */
		PKI_log_err ("SECURITY::CHROOT::ERROR [%s]", strerror(errno));
		perror(NULL);
		return(0);
	}

	PKI_log(PKI_LOG_INFO,"SECURITY::CHROOT::Completed [%s]",
		conf->chroot_dir );

	/* Ok, chdir and chroot! */
	return(1);
}

