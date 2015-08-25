#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/e_os2.h>
#include <openssl/lhash.h>
#include <openssl/bn.h>
#define USE_SOCKETS
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RSA_SERVER_CERT "server3.crt"
#define RSA_SERVER_KEY	"server3.key"
#define RSA_CA_CERT		"ca.crt"
#define SERVER_PORT		443
#define OK 0
#define ERROR -1
#define SSL_TRACE

void track_handshake_state_cb(SSL *ssl, int where, int ret_code)
{
	char *str;
	int w;

	w=where& ~SSL_ST_MASK;

	if (ssl->state == SSL3_ST_CW_CHANGE_A || 
		ssl->state == SSL3_ST_CW_CHANGE_A ) {
		/* Save the key_block for extracting session keys */
	}

	if (w & SSL_ST_CONNECT)
		str="SSL_connect";
	else if (w & SSL_ST_ACCEPT)
		str="SSL_accept";
	else
		str="undefined";

	if (where & SSL_CB_LOOP) {
		printf("%s:%s\n", str, SSL_state_string_long(ssl));
	}
	else if (where & SSL_CB_ALERT) {
		str=(where & SSL_CB_READ)?"read":"write";
		printf("SSL3 alert %s:%s:%s\n", str,
				   SSL_alert_type_string_long(ret_code),
				   SSL_alert_desc_string_long(ret_code));
	}
	else if (where & SSL_CB_EXIT) {
		if (ret_code == 0) {
			printf("%s:failed in %s\n", str, SSL_state_string_long(ssl));
		}
		else if (ret_code < 0) {
			printf("%s:error in %s\n", str, SSL_state_string_long(ssl));
		}
	}
}

int validateCertificateDates(X509_STORE_CTX *x509_ctx,X509 *err_cert,int *preverify_ok) {
	int cmpTimeResult = -1;
	int retVal = 0,nm_i;
	time_t currentTime;
	struct timespec time_value;
	ASN1_TIME *nbf = X509_get_notBefore(err_cert);
	ASN1_TIME *naf = X509_get_notAfter(err_cert);
	clock_gettime(CLOCK_REALTIME,&time_value);
	currentTime=time_value.tv_sec;
	//get the timeinfo.
	#ifdef NM_DEBUG
	printf("Entring [%s][%s][%d] currenttime=%x\n",__FILE__,__FUNCTION__,__LINE__,currentTime);
	printf("x509_ctx->error=%d\n",x509_ctx->error);
	printf("Time stamp for nbf is \n");
	for(nm_i=0;nm_i<nbf->length;nm_i++)
	printf("%c",nbf->data[nm_i]);
	printf("\n");
	printf("Time stamp for naf is \n");
	for(nm_i=0;nm_i<naf->length;nm_i++)
	printf("%c",naf->data[nm_i]);
	printf("\n");
	printf("Tot length is nbf=%d naf=%d\n",nbf->length,naf->length);
	#endif
	X509_cmp_time(nbf, &currentTime);
	
	switch (x509_ctx->error) {
		case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
			if (currentTime > 0) {
				//printf("[%s][%s][%d] \n",__FILE__,__FUNCTION__,__LINE__);
				cmpTimeResult = X509_cmp_time(X509_get_notBefore(err_cert), &currentTime);
				if (cmpTimeResult == 0) {
				    retVal = X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
				} else if (cmpTimeResult > 0) {
				      retVal = X509_V_ERR_CERT_NOT_YET_VALID;
				}
			}
			if (retVal == 0) {
				if (time > 0) {
					//printf("[%s][%s][%d] \n",__FILE__,__FUNCTION__,__LINE__);
					cmpTimeResult = X509_cmp_time(X509_get_notAfter(err_cert), &currentTime);
					if (cmpTimeResult == 0) {
						retVal = X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
					} else if (cmpTimeResult < 0) {
						retVal = X509_V_ERR_CERT_HAS_EXPIRED;
					}
				}
			}
			if (retVal == 0) {
				x509_ctx->error = 0;
				*preverify_ok = 1;
				//printf("[%s][%s][%d] \n",__FILE__,__FUNCTION__,__LINE__);
			}
		break;
	}
	//printf("Exitintg [%s][%s][%d] \n",__FILE__,__FUNCTION__,__LINE__);
	return retVal;
}

int verifyClientCertificate(int preverify_ok, X509_STORE_CTX *x509_ctx)	{
	X509 *err_cert;
	int err;
	int depth;
	X509_NAME* x509Name;
	char buf[256];
	int retVal;

	err_cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	err = X509_STORE_CTX_get_error(x509_ctx);
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);

	if (!preverify_ok || depth != 0) {
#ifdef SSL_TRACE	
		printf("verifyClientCertificate()::error = %d depth = %d:%s\n", err, depth, X509_verify_cert_error_string(err));
		X509_NAME_oneline(X509_get_subject_name(err_cert),buf,sizeof(buf));
		printf("Cert subject = %s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, sizeof(buf));
		printf("Cert issuer = %s\n", buf);
#endif		
      	err = validateCertificateDates(x509_ctx,err_cert,&preverify_ok);	  
   }
   else {
      preverify_ok = 1;
   }   
   return (preverify_ok);
}

void initSSLLibrary() {
	SSL_library_init();
	SSL_load_error_strings();
#if OPENSSL_VERSION_NUMBER < 0x009080ffL	
	OpenSSL_add_all_algorithms();
#endif	
}

SSL_CTX *initSSLServerContext() {
	int status = OK;
	SSL_CTX *ssl_ctx = NULL;
	
	/* Create a server context*/
	ssl_ctx = SSL_CTX_new(SSLv23_server_method());
	if (ssl_ctx == NULL) {
#ifdef SSL_TRACE
      printf("SSL_CTX_new() failed : %s.\n", ERR_error_string(ERR_get_error(), NULL));
#endif
	  return NULL;
	}	

	/* Set the options in the SSL server context */
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
	
	/* Client certificate validation routine*/
	SSL_CTX_set_verify(ssl_ctx,SSL_VERIFY_PEER,verifyClientCertificate);
	
	/* Set the verification depth to 1 */
	SSL_CTX_set_verify_depth(ssl_ctx,1);
	
#ifdef SSL_TRACE
	SSL_CTX_set_info_callback(ssl_ctx, (void*)track_handshake_state_cb);
#endif
	
	/* Session caching */
	SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);	
	
	/* Load the server certificate into the SSL context structure */
    if (SSL_CTX_use_certificate_file(ssl_ctx, RSA_SERVER_CERT, SSL_FILETYPE_PEM) <= 0) {
#ifdef SSL_TRACE
		printf("SSL_CTX_use_certificate_file() failed : %s.\n", ERR_error_string(ERR_get_error(), NULL));
#endif
		SSL_CTX_free(ssl_ctx);
		return NULL;
    }
 
     /* Load the private-key corresponding to the server certificate */
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, RSA_SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
#ifdef SSL_TRACE
		printf("SSL_CTX_use_PrivateKey_file() failed : %s.\n", ERR_error_string(ERR_get_error(), NULL));
#endif
		SSL_CTX_free(ssl_ctx);
		return NULL;
    }
 
      /* Check if the server certificate and private-key matches */
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
		printf("Inside the if condition of ssl_ctx_check_private_key condiditon [%d]\n",__LINE__);
#ifdef SSL_TRACE
		printf("SSL_CTX_check_private_key() failed : %s.\n", ERR_error_string(ERR_get_error(), NULL));
#endif
		SSL_CTX_free(ssl_ctx);
		return NULL;	          
    }
	
	/* Load the RSA CA certificate into the SSL contextstructure */
	if (!SSL_CTX_load_verify_locations(ssl_ctx, RSA_CA_CERT, NULL)) {
#ifdef SSL_TRACE
		printf("SSL_CTX_load_verify_locations() failed : %s.\n", ERR_error_string(ERR_get_error(), NULL));		
#endif
		SSL_CTX_free(ssl_ctx);
		return NULL;
	}
	//printf("returning ssl_ctx %x\n",ssl_ctx);
	return ssl_ctx;
} 

int initServerSocket() {
	int server_sock;
	struct sockaddr_in sa_server;
	
	server_sock	= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);   
	if (server_sock == -1) {
#ifdef SSL_TRACE
		printf("socket() failed :\n");		
#endif
		return ERROR;
	}
	
	memset (&sa_server, '0', sizeof(sa_server));
	sa_server.sin_family      = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (SERVER_PORT);
	
	if (bind(server_sock, (struct sockaddr*)&sa_server,sizeof(sa_server)) < 0) {
#ifdef SSL_TRACE
		printf("bind() failed :\n");		
#endif
		close(server_sock);
		return ERROR;
	}
   
    listen(server_sock, 5);   
	
	return server_sock;
}	
 


	
void cve1789_server() {
	
	SSL_CTX *ssl_ctx = NULL;		
	SSL *ssl = NULL;
	int status = ERROR;
	int server_socket = ERROR;
	int client_socket = ERROR;
	struct sockaddr_in sa_client;
    size_t client_len = sizeof(sa_client);
    int number;
    
	/* Initalize OpenSSL library */
	initSSLLibrary();
	
	/* Initalize server context */
	ssl_ctx = initSSLServerContext();	
	if (ssl_ctx) {
		/* Setup TCP server socket*/
		server_socket = initServerSocket();
	}
	
	if (server_socket) {
		printf("ACCEPT..\n");
		client_socket = accept(server_socket, (struct sockaddr*)&sa_client, &client_len);
		if (client_socket == -1) {
#ifdef SSL_TRACE	
			printf("could not accept the client connection \n");
#endif
		}
		else {
			/* A SSL structure is created */
			ssl = SSL_new(ssl_ctx);
			if (ssl) {
				#if 0  // BIO option
					BIO   *ssl_bio;
					ssl_bio = BIO_new_socket(client_socket, BIO_NOCLOSE);
					BIO_set_nbio(ssl_bio, 1); /* 1 = non-blocking */
					SSL_set_bio(pSsl, ssl_bio, ssl_bio);
				#endif
 
				/* Assign the socket into the SSL structure (SSL and socket without BIO) */
				SSL_set_fd(ssl, client_socket);
 
				status = SSL_accept(ssl);
				if (status == 1) {
				printf("Connection is established\n");
				scanf("%d\n",&number);
					/* Receive data from the SSL client */
					/* Send data to the SSL client */					 
				} else {
					printf("SSL_accept returned error, %s\n", ERR_error_string(ERR_get_error(), NULL));
				}
				printf("Connection terminating..\n");
				SSL_shutdown(ssl);
			}
		}
	}
	
	if (server_socket) 
		close (server_socket);
	if (client_socket)
		close (client_socket);
	if (ssl)
		SSL_free(ssl);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
}

