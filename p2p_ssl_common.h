/* 
 * File:   p2p_common_ssl.h
 * Author: alex
 *
 * Created on 19 mai 2013, 09:00
 */

#ifndef P2P_COMMON_SSL_H
#define	P2P_COMMON_SSL_H

#define CAFILE "./keys/rootcert.pem" 
#define CAKEY "./keys/rootkey.pem"
#define CADIR "./keys/"
#define CLIENT_CERTFILE "./keys/client1.pem"
#define SERVER_CERTFILE "./keys/server.pem"
#define KEY_PASSWD "alex"

#define DAYS_TILL_EXPIRE 365
#define EXPIRE_SECS (60*60*24*DAYS_TILL_EXPIRE)
#define EXT_COUNT 5
#define ENTRY_COUNT 6

#define SSL23_METH 1
#define DTLS_METH 2

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



int p2p_ssl_pass_cb(char *buf, int size, int rwflag, char *u);
X509* p2p_ssl_load_cert(server_params* sp, char* file);
int p2p_ssl_gen_cert(server_params* sp);
void p2p_ssl_showCerts(server_params* sp, SSL* ssl);

int p2p_ssl_init_server(server_params* sp, int meth);
int p2p_ssl_init(server_params* sp, int meth);
void p2p_ssl_showCerts(server_params* sp, SSL* ssl);

int p2p_ssl_tcp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* ssl);
int p2p_ssl_tcp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl);
int p2p_ssl_tcp_msg_send(server_params* sp, const p2p_msg msg);
void p2p_ssl_tcp_close(server_params* sp, SSL* ssl);
int p2p_ssl_tcp_server_init_sock(server_params* sp, SSL* ssl, int fd);
int p2p_ssl_tcp_client_init_sock(server_params* sp, SSL* clientssl, int fd);

/* 
 * 
 * DTLS function are not use
 * 
 * 
int p2p_ssl_udp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* ssl);
int p2p_ssl_udp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl) ;
int p2p_ssl_udp_msg_send(server_params* sp, const p2p_msg msg);
int p2p_ssl_udp_msg_rebroadcast(server_params* sp, p2p_msg msg);
int p2p_ssl_udp_server_init_sock(server_params* sp, SSL* ssl, int fd);
int p2p_ssl_udp_client_init_sock(server_params* sp, SSL* clientssl, int fd, p2p_addr dest);
 * 
 * 
 * 
 */
#endif	/* P2P_COMMON_SSL_H */