/* 
 * File:   p2p_common_ssl.h
 * Author: alex
 *
 * Created on 19 mai 2013, 09:00
 */

#ifndef P2P_COMMON_SSL_H
#define	P2P_COMMON_SSL_H

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

typedef struct {
    int socket;
    SSL *cssl;
    SSL_CTX *sslctx;
} SSLconnection;

void InitializeSSL();

void DestroySSL();

int sslDisconnect();

int init_ssl(int port);

SSLconnection *accept_ssl(int socketfd, struct sockaddr_in cli_addr, unsigned int clilen) ;

SSLconnection *p2p_tcp_socket_ssl_create(server_params* sp, p2p_addr dst);

int p2p_tcp_ssl_socket_close(server_params* sp, SSLconnection *c) ;
int p2p_tcp_ssl_msg_sendfd(server_params* sp, p2p_msg msg, int fd);
int p2p_tcp_ssl_msg_recvfd(server_params* sp, p2p_msg msg, int fd) ;
int p2p_tcp_ssl_msg_send(server_params* sp, const p2p_msg msg);

#endif	/* P2P_COMMON_SSL_H */