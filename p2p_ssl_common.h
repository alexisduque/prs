/* 
 * File:   p2p_common_ssl.h
 * Author: alex
 *
 * Created on 19 mai 2013, 09:00
 */

#ifndef P2P_COMMON_SSL_H
#define	P2P_COMMON_SSL_H


#define CAFILE "rootcert.pem" 
#define CADIR "./"
#define CLIENT_CERTFILE "client.pem"
#define SERVER_CERTFILE "server.pem"

#define SSL_SERVER_RSA_CERT	"ssl_server.crt"
#define SSL_SERVER_RSA_KEY	"ssl_server.key"
#define SSL_SERVER_RSA_CA_CERT	"ca.crt"
#define SSL_SERVER_RSA_CA_PATH	"./"
#define KEY_PASSWD "alex"

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h>

#include "p2p_common.h"
#include "p2p_options.h"
#include "p2p_msg.h"

#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 


int p2p_ssl_init_server(server_params* sp);
int p2p_ssl_init_client(server_params* sp);
int p2p_ssl_tcp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* ssl);
int p2p_ssl_tcp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl) ;
int p2p_ssl_tcp_msg_send(server_params* sp, const p2p_msg msg);
void p2p_ssl_tcp_close(server_params* sp, SSL* ssl);
int p2p_ssl_tcp_server_init_sock(server_params* sp, SSL* ssl, int fd);
int p2p_ssl_tcp_client_init_sock(server_params* sp, SSL* clientssl, int fd);
void p2p_ssl_showCerts(server_params* sp, SSL* ssl);
#endif	/* P2P_COMMON_SSL_H */