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
#include "p2p_ssl_common.h"
#include "p2p_addr.h"

#include <openssl/rand.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/err.h> 
#include <errno.h>


// Initialise le contexte SSL pour le serveur

int p2p_ssl_init_server(server_params* sp) {

    //Chargement des librairies
    VERBOSE(sp, VSYSCL, "SSL INIT server context\n");
    SSL_library_init();
    SSL_load_error_strings();
    sp->node_meth = SSLv23_server_method();
    sp->ssl_node_ctx = SSL_CTX_new(sp->node_meth);


    if (!sp->ssl_node_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }        
    
    VERBOSE(sp, VSYSCL, "SSL : Loading Certificat\n");
    //Ajout des certificats serveur 
    if (SSL_CTX_load_verify_locations(sp->ssl_node_ctx, CAFILE, CADIR) != 1)
        perror("Error loading CA file and/or directory");

    //Ajout des certificats serveur 
    SSL_CTX_set_default_passwd_cb_userdata(sp->ssl_node_ctx, KEY_PASSWD);

    if (SSL_CTX_set_default_verify_paths(sp->ssl_node_ctx) != 1)
        perror("Error loading default CA file and/or directory");

    if (SSL_CTX_use_certificate_chain_file(sp->ssl_node_ctx, SERVER_CERTFILE) != 1)
        perror("Error loading certificate from file");

    if (SSL_CTX_use_PrivateKey_file(sp->ssl_node_ctx, SERVER_CERTFILE, SSL_FILETYPE_PEM) != 1)
        perror("Error loading private key from file");

    //Demande la verification des crificats du clients si verify_peer est ON
    if (sp->verify_peer) {
        SSL_CTX_set_verify(sp->ssl_node_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(sp->ssl_node_ctx, 4);
    }
    VERBOSE(sp, VSYSCL, "SSL : Certificat Loaded\n\n");
    return P2P_OK;

}

//Initialisation du contexte SSL client

int p2p_ssl_init_client(server_params* sp) {

    //Charement des librairies
    VERBOSE(sp, VSYSCL, "SSL INIT client context\n");
    SSL_library_init();
    SSL_load_error_strings();
    sp->node_meth = SSLv23_client_method();
    sp->ssl_node_ctx = SSL_CTX_new(sp->node_meth);

    if (!sp->ssl_node_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //Si la verification des crtificats est activée, on ajoute les certificats au contexte
    if (sp->verify_peer) {
        VERBOSE(sp, VSYSCL, "SSL : Loading Certificat\n");
        SSL_CTX_set_default_passwd_cb_userdata(sp->ssl_node_ctx, KEY_PASSWD);

        if (SSL_CTX_load_verify_locations(sp->ssl_node_ctx, CAFILE, CADIR) != 1)
            perror("Error loading CA file and/or directory");
        
        if (SSL_CTX_set_default_verify_paths(sp->ssl_node_ctx) != 1)
            perror("Error loading default CA file and/or directory");

        if (SSL_CTX_use_certificate_chain_file(sp->ssl_node_ctx, CLIENT_CERTFILE) != 1)
            perror("Error loading certificate from file");

        if (SSL_CTX_use_PrivateKey_file(sp->ssl_node_ctx, CLIENT_CERTFILE, SSL_FILETYPE_PEM) != 1)
            perror("Error loading private key from file");
        
        SSL_CTX_set_verify(sp->ssl_node_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(sp->ssl_node_ctx, 4);
        VERBOSE(sp, VSYSCL, "SSL : Certificat Loaded\n\n");
    }

    return P2P_OK;
}

//Envoi du message msg via la stracture SSL clientssl

int p2p_ssl_tcp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* clientssl) {

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
    if (SSL_write(clientssl, toWrite, P2P_HDR_SIZE + message_size) != (P2P_HDR_SIZE + message_size)) {
        VERBOSE(sp, VPROTO, "Unable to send msg to the socket\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VPROTO, "TCP MSG SUCCESFULL SEND\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        //Fermeture de la connexion SSL
        SSL_shutdown(clientssl);
        return P2P_OK;
    }


}

// Initialise la connexion SSL coté client avec la socket fd

int p2p_ssl_tcp_client_init_sock(server_params* sp, SSL* clientssl, int fd) {

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE ... \n");
    int ret;
    if ((ret = SSL_set_fd(clientssl, fd)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL: SetFD ERROR %d\n", SSL_get_error(clientssl, ret));
        return P2P_ERROR;
    }

    if ((ret = SSL_connect(clientssl)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(clientssl, ret));
        return P2P_ERROR;
    }

    if (sp->verify_peer) {

        X509 *ssl_client_cert = NULL;

        ssl_client_cert = SSL_get_peer_certificate(clientssl);

        if (ssl_client_cert) {
            long verifyresult;
            p2p_ssl_showCerts(sp, clientssl);
            verifyresult = SSL_get_verify_result(clientssl);
            if (verifyresult == X509_V_OK) {
                VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
            } else {
                VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                X509_free(ssl_client_cert);
                return (P2P_ERROR);
            }
        } else {
            VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
            return (P2P_ERROR);
        }
    }

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;
}

// Initialise la connexion SSL coté server avec la socket fd

int p2p_ssl_tcp_server_init_sock(server_params* sp, SSL* ssl, int fd) {
    
    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE... \n");
    int ret;
    if ((ret = SSL_set_fd(ssl, fd)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL: SetFD ERROR %d\n", SSL_get_error(ssl, ret));
        return (P2P_ERROR);
    }
    
    
    if ((ret = SSL_accept(ssl)) != 1) {
       VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(ssl, ret));
        return (P2P_ERROR);
    }


    if (sp->verify_peer) {

        X509 *ssl_client_cert = NULL;
        ssl_client_cert = SSL_get_peer_certificate(ssl);

        if (ssl_client_cert) {
            
            long verifyresult;
            p2p_ssl_showCerts(sp, ssl);
            verifyresult = SSL_get_verify_result(ssl);
            
            if (verifyresult == X509_V_OK) {
                VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
            } else {
                VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                SSL_shutdown(ssl);
                X509_free(ssl_client_cert);
                return (P2P_ERROR);
            }
        
        } else {
            VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
            SSL_shutdown(ssl);
            return (P2P_ERROR);
        } 
    }    
    
    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;
    
}

//Ferme la connection SSL
void p2p_ssl_tcp_close(server_params* sp, SSL* ssl) {
    //SSL_shutdown(ssl);
    SSL_free(ssl);
    ssl = NULL;
    VERBOSE(sp, VSYSCL, "SSL : Connection successful closed\n");
}

// Recois dans msg un message depuis la connection ssl serverssl
int p2p_ssl_tcp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl) {

    int length;
    if (SSL_read(serverssl, msg, P2P_HDR_BITFIELD_SIZE)== 0 ) return P2P_ERROR;
    SSL_read(serverssl, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    SSL_read(serverssl, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    length = p2p_msg_get_length(msg);
    unsigned char data_payload[length];
    SSL_read(serverssl, data_payload, length);
    p2p_msg_init_payload(msg, length, data_payload);
    p2p_msg_display(msg);
    VERBOSE(sp, VMCTNT, "RECV MSG OK\n");
    //SSL_shutdown(serverssl);
    return P2P_OK;

}


// Envoi du message msg via tcp au noeud destination indiquée dans le champ dst de msg
int p2p_ssl_tcp_msg_send(server_params* sp, const p2p_msg msg) {

    SSL *clientssl = SSL_new(sp->ssl_node_ctx);
    
    VERBOSE(sp, VPROTO, "DEST : %s\n", p2p_addr_get_str(p2p_msg_get_dst(msg)));
    int socketTMP = p2p_tcp_socket_create(sp, p2p_msg_get_dst(msg));

    if (socketTMP == P2P_ERROR) {
        VERBOSE(sp, VSYSCL, "SSL : TCP socket creation impossible \n");
        //printf("Impossible de créer la socket TCP \n");
        return (P2P_ERROR);
    }
    if (p2p_ssl_tcp_client_init_sock(sp, clientssl, socketTMP) != P2P_OK) {
        VERBOSE(sp, VSYSCL, "SSL : INIT Impossible \n");
        return (P2P_ERROR);
    }
    if (p2p_ssl_tcp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
        return (P2P_ERROR);
    }

    p2p_ssl_tcp_close(sp, clientssl);
    p2p_tcp_socket_close(sp, socketTMP);
    VERBOSE(sp, VPROTO, "SEND msg DONE\n\n");
    return P2P_OK;
}

//Affiche le certificat du peer
void p2p_ssl_showCerts(server_params* sp, SSL* ssl) {
    
    X509 *cert;
    char *line;
    //obtient le certiication du paire connecté
    cert = SSL_get_peer_certificate(ssl);
    
    if (cert != NULL) {
        VERBOSE(sp, VMCTNT, "------------------Peer certificates ----------------------\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        VERBOSE(sp, VMCTNT, "Subject: %s\n", line);
        //libère la mémoire allouée 
        free(line); 
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        VERBOSE(sp, VMCTNT, "Issuer: %s\n", line);
        VERBOSE(sp, VMCTNT, "-----------------------------------------------------------\n");
        //libère la mémoire allouée
        free(line);
        X509_free(cert);
    } else
        VERBOSE(sp, VMCTNT, "No certificates.\n");
}

