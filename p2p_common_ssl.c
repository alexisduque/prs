/* 
 * File:   p2p_common_ssl.h
 * Author: alexis
 *
 * Created on 19 mai 2013, 14:45
 * 
 * Function for SSL support
 *  */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netdb.h> 
#include <assert.h>
#include <arpa/inet.h>

#include "p2p_msg.h"
#include "p2p_common.h"
#include "p2p_options.h"
#include "p2p_common_ssl.h"
#include "p2p_addr.h"

#include <openssl/rand.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 


void InitializeSSL() {
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void DestroySSL() {
    ERR_free_strings();
    EVP_cleanup();
}


int init_ssl(int port) {

    int sockfd;
    int valid;
    struct sockaddr_in adresse;
    int longueur = sizeof (struct sockaddr_in);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        //Log and Error
        perror("Error creating SSL Socket");
    }

    /* Preparation de l'adresse d'attachement */
    adresse.sin_family = AF_INET;
    /* Conversion (representation interne) -> (reseau) avec htonl et htons */
    adresse.sin_addr.s_addr = htonl(INADDR_ANY);
    adresse.sin_port = htons(port);

    valid = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &valid, sizeof (valid)) < 0) {
        perror("Could'nt setsockopt");
        close(sockfd);
        return -1;
    }

    if (bind(sockfd, (struct sockaddr*) &adresse, longueur) == -1) {
        perror(" Socket attachement failed");
        close(sockfd);
        return -1;
    }

    return sockfd;

}

SSLconnection *accept_ssl(int socketfd, struct sockaddr_in cli_addr, unsigned int clilen) {
    
    InitializeSSL();
    SSLconnection *c;
    
    c = malloc (sizeof (SSLconnection));
    c->cssl = NULL;
    c->sslctx = NULL;
    c->socket = accept(socketfd, (struct sockaddr *) &cli_addr, &clilen);
    c->sslctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(c->sslctx, SSL_OP_SINGLE_DH_USE);
    int use_cert = SSL_CTX_use_certificate_file(c->sslctx, "serverCertificate.pem", SSL_FILETYPE_PEM);

    int use_prv = SSL_CTX_use_PrivateKey_file(c->sslctx, "serverCertificate.pem", SSL_FILETYPE_PEM);

    c->cssl = SSL_new(c->sslctx);
    if ( !SSL_set_fd(c->cssl, c->socket) ){
        //log and close down ssl
        sslDisconnect(c);
        perror("Error SetFD SSL\n");
    }
    
      if (SSL_connect (c->cssl) != 1){
        //log and close down ssl
        sslDisconnect(c);
        perror("Error accepting SSL\n");
    }
    
    return c;
}


// Disconnect & free connection struct

int sslDisconnect(SSLconnection* c) {
    if (c->socket)
        close(c->socket);
    
    if (c->cssl) {
        SSL_shutdown(c->cssl);
        SSL_free(c->cssl);
    }
    if (c->sslctx)
        SSL_CTX_free(c->sslctx);

    free(c);
    
    return P2P_OK;
}


SSLconnection *p2p_tcp_socket_ssl_create(server_params* sp, p2p_addr dst) {

    // Definition des variables locales
    struct sockaddr_in adresse;
    int port, desc;
    int lg = sizeof (adresse);
    struct hostent *hp;
    char * ip;
    SSLconnection *c;
    
    // Creation et attachement de la socket sur un port quelconque 
    port = 0;
    if ((desc = creer_socket(SOCK_STREAM, port)) == P2P_ERROR) {
        perror("tcp_socket_create : Error creating the socket\n");
    }

    // Recherche de l'adresse internet du serveur 
    ip = p2p_addr_get_ip_str(dst);
    if ((hp = gethostbyname(ip)) == NULL) {
        printf("tcp_socket_create : Computer %s unknown\n", ip);
    }

    // Preparation de l'adresse destinatrice 
    port = p2p_addr_get_tcp_port(dst);
    adresse.sin_family = AF_INET;
    adresse.sin_port = htons(port);
    memcpy(&(adresse.sin_addr.s_addr), hp->h_addr, hp->h_length);

    // Demande de connexion au serveur 
    c = accept_ssl(desc, adresse, lg);
    if (c->socket == -1) {
        perror("tcp_socket_create : Error connecting to server\n");
    }
    
    VERBOSE(sp, VPROTO, "SOCKET CREATED\n");
    // On renvoie le descripteur de socket
    return c;

}


//Fermeture de la socket donnée par le descripteur fd

int p2p_tcp_ssl_socket_close(server_params* sp, SSLconnection* c) {
    if (sslDisconnect(c) == -1) {
        perror("tcp_ssl_socket_close : Error closing TCP socket\n");
        VERBOSE(sp, CLIENT, "tcp_socket_close : Error closing TCP socket\n");
        VERBOSE(sp, CLIENT, "END_OF_TRANSMISSION\n");
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VSYSCL, "TCP SSL socket disconnected %d\n", c->socket);
        return P2P_OK;
    }

}

//Envoi du message msg via la socket tcp fd

int p2p_tcp_ssl_msg_sendfd(server_params* sp, p2p_msg msg, int fd) {
    VERBOSE(sp, VPROTO, "TRY TO SEND TCP msg ...\n");
    //SSL Init
    int ret;
    SSL *clientssl;
    clientssl = SSL_new(sp->ssl_client_ctx);
    if(!clientssl)
    {
            printf("Error SSL_new\n");
            return -1;
    }

    if((ret = SSL_set_fd(clientssl, fd)) != 1)
    {
            printf("SetFD Error %d\n", SSL_get_error(clientssl, ret));
            return -1;
    }

    if((SSL_connect(clientssl)) != 1)
    {
            printf("Handshake Error %d\n", SSL_get_error(clientssl, ret));
            return -1;
    }

    if(sp->verify_peer)
    {
            X509 *ssl_client_cert = NULL;

            ssl_client_cert = SSL_get_peer_certificate(clientssl);

            if(ssl_client_cert)
            {
                    long verifyresult;

                    verifyresult = SSL_get_verify_result(clientssl);
                    if(verifyresult == X509_V_OK)
                            printf("Certificate Verify Success\n"); 
                    else
                            printf("Certificate Verify Failed\n"); 
                    X509_free(ssl_client_cert);				
            }
            else
                    printf("There is no client certificate\n");
    }
    
    //On verifie que l'on essaie pas d'envoyer un message à nous même
    if (p2p_addr_is_equal(sp->p2pMyId, p2p_msg_get_dst(msg)) != 0) {
        VERBOSE(sp, VPROTO, "ERROR : SENDING TCP msg YOURSELF\n");
        return P2P_ERROR;
    }

    //On remplit le buffer toWrite, avec les infos contenues dans le msg en paramètre, selon le format du CDC

    //allocation de la mémoire pour le buffer
    int message_size = ntohs(p2p_msg_get_length(msg));
    unsigned char* toWrite = (unsigned char*) malloc(P2P_HDR_SIZE + message_size);

    // ajout du champs "version" au buffer
    memcpy(toWrite, &(msg->hdr.version_type), P2P_HDR_BITFIELD_SIZE);
    // ajout du champs "Adresse Source"
    memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE], p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    //ajout du champs "Adresse Dest"
    memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE + P2P_ADDR_SIZE], p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    // Si contenu du message non vide, ajout du champs "Message"
    if (message_size > 0) {
        memcpy(&toWrite[P2P_HDR_SIZE], p2p_get_payload(msg), message_size);
    }


    // On envoie via le socket tcp fd, le message contenu dans le buffer, sinon message d'erreur
    if (SSL_write (clientssl, toWrite, P2P_HDR_SIZE + message_size) != (P2P_HDR_SIZE + message_size)) {
        VERBOSE(sp, VPROTO, "Unable to send msg to the socket\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VPROTO, "TCP MSG SUCCESFULL SEND\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        SSL_shutdown(clientssl);
    	SSL_free(clientssl);
        clientssl = NULL;
	SSL_CTX_free(sp->ssl_client_ctx);
        return P2P_OK;
    }


}

// Recoie dans msg un message depuis la socket fd

int p2p_tcp_ssl_msg_recvfd(server_params* sp, p2p_msg msg, int fd) {
    int length;
     //SSL check
    SSL *serverssl;
    int ret;
    serverssl = SSL_new(sp->ssl_server_ctx);
    if(!serverssl)
    {
            printf("Error SSL_new\n");
            return -1;
    }
printf("SSL_new\n");
    if((ret = SSL_set_fd(serverssl, fd)) != 1)
    {
            printf("SetFD Error %d\n", SSL_get_error(serverssl, ret));
            return -1;
    }
printf("SSL_fd\n");
    if((SSL_accept(serverssl))!= 1)
    {
            printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
            return -1;
    }
printf("SSL_accept\n");
    if(sp->verify_peer)
    {
            X509 *ssl_client_cert = NULL;

            ssl_client_cert = SSL_get_peer_certificate(serverssl);

            if(ssl_client_cert)
            {
                    long verifyresult;

                    verifyresult = SSL_get_verify_result(serverssl);
                    if(verifyresult == X509_V_OK)
                            printf("Certificate Verify Success\n"); 
                    else
                            printf("Certificate Verify Failed\n"); 
                    X509_free(ssl_client_cert);				
            }
            else
                    printf("There is no client certificate\n");
    }
   
    SSL_read (serverssl, msg, P2P_HDR_BITFIELD_SIZE);
    SSL_read (serverssl, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    SSL_read (serverssl, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    length = p2p_msg_get_length(msg);
    unsigned char data_payload[length];
    SSL_read (serverssl, data_payload, length);
    p2p_msg_init_payload(msg, length, data_payload);
    p2p_msg_display(msg);
    VERBOSE(sp, VMCTNT, "RECV MSG OK\n");
    
    SSL_shutdown(serverssl);
    SSL_free(serverssl);
    serverssl = NULL;
    return P2P_OK;
}

// Envoi du message msg via tcp au noeud destination indiquée dans le champ dst de msg

int p2p_tcp_ssl_msg_send(server_params* sp, const p2p_msg msg) {

    int socketTMP = p2p_tcp_socket_create(sp, p2p_msg_get_dst(msg));
    
    if (socketTMP == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "TCP SSL socket creation impossible \n");
        //printf("Impossible de créer la socket TCP \n");
        return (P2P_ERROR);
    }
    
    if (p2p_tcp_ssl_msg_sendfd(sp, msg, socketTMP) != P2P_OK) {
        return (P2P_ERROR);
    }
    
    p2p_tcp_socket_close(sp, socketTMP);
    VERBOSE(sp, VPROTO, "SEND msg DONE\n");
    return P2P_OK;
}