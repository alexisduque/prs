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

int p2p_ssl_init_server(server_params* sp, int meth) {

    //Chargement des librairies
    VERBOSE(sp, VSYSCL, "SSL INIT server context\n");
    SSL_library_init();
    SSL_load_error_strings();
    switch (meth) {
        case SSL23_METH : sp->node_meth = SSLv23_server_method();
        break;
        case DTLS_METH: sp->node_meth = DTLSv1_server_method();
        break;
    }
    

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

int p2p_ssl_init_client(server_params* sp, int meth) {

    //Charement des librairies
    VERBOSE(sp, VSYSCL, "SSL INIT client context\n");
    SSL_library_init();
    SSL_load_error_strings();
    switch (meth) {
        case SSL23_METH : sp->node_meth = SSLv23_client_method();
        break;
        case DTLS_METH: sp->node_meth = DTLSv1_client_method();
        break;
    }
        
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
    unsigned short int message_size = ntohs(p2p_msg_get_length(msg));
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
void p2p_ssl_close(server_params* sp, SSL* ssl) {
    SSL_shutdown(ssl);
   // SSL_free(ssl);
    SSL_clear(ssl);
    VERBOSE(sp, VSYSCL, "SSL : Connection successful closed\n");
}

// Recois dans msg un message depuis la connection ssl serverssl
int p2p_ssl_tcp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl) {
    
    int tot = 0;
    int i = 0;
    unsigned short int length = 0;
    unsigned char* data_payload = NULL;
    if (SSL_read(serverssl, msg, P2P_HDR_BITFIELD_SIZE) == 0 ) return P2P_ERROR;
    SSL_read(serverssl, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    SSL_read(serverssl, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    length = p2p_msg_get_length(msg);
    length = ntohs(length);
    data_payload = (unsigned char *) malloc (sizeof(unsigned char) * P2P_MSG_MAX_SIZE);
    memset (data_payload, 0, P2P_MSG_MAX_SIZE * sizeof (char));
    if (length > 0) {
        while (tot < length)
        {
            i = SSL_read(serverssl, data_payload + tot, length - tot);
            tot += i;
        }
    p2p_msg_init_payload(msg, length, data_payload);
    }

    p2p_msg_display(msg);
    free(data_payload);
    VERBOSE(sp, VMCTNT, "RECV MSG OK\n");
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

    p2p_ssl_close(sp, clientssl);
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

/* 
 
 ****************  UDP Functions  ***************************
 
 */


int p2p_ssl_udp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* clientssl) {
    
    VERBOSE(sp, VPROTO, "TRY TO SEND UDP MSG ...\n");
    int message_size = p2p_msg_get_length(msg);
    message_size = ntohs(message_size);
    char toWrite [P2P_HDR_SIZE + sizeof (char)*message_size];

    memcpy(toWrite, msg, P2P_HDR_BITFIELD_SIZE);
    memcpy(&toWrite[4], p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[12], p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[20], p2p_get_payload(msg), message_size);

    if (SSL_write(clientssl, toWrite, P2P_HDR_SIZE + message_size) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to send msg\n");
     //   free(toWrite);
        return P2P_ERROR;
    }
    p2p_msg_display(msg);
    //free(toWrite);
    VERBOSE(sp, VPROTO, "UDP MSG SEND\n\n");
    return P2P_OK;

}

//recoie dans msg un message depuis la socket UDP fd

int p2p_ssl_udp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* clientssl) {
    VERBOSE(sp, VMCTNT, "TRY TO RECEIVE MSG ...\n");

    //Declaration du buffer
    char data[200];
    //free(msg->payload);
    // Allocation de la mémoire pour le payload
    msg->payload = (unsigned char*) malloc(sizeof (unsigned char)*200);

    //Lecture de la soccket et remplissage du buffer
    SSL_read(clientssl, &data, sizeof (data));

    //Remplissage des champs du message à partir du buffert
    memcpy(&(msg->hdr), data, P2P_HDR_BITFIELD_SIZE);
    memcpy(msg->hdr.src, &data[4], P2P_ADDR_SIZE);
    memcpy(msg->hdr.dst, &data[12], P2P_ADDR_SIZE);
    memcpy(msg->payload, &data[20], sizeof (data) - 20);
    p2p_msg_display(msg);
    VERBOSE(sp, VMCTNT, "RECVD MSG OK\n");

    return P2P_OK;

}

//envoie le message msg via udp au noeud destination indique dans le
//champ dst de msg

int p2p_ssl_udp_msg_send(server_params* sp, p2p_msg msg) {
   
    int sock = -1;
    SSL *clientssl = SSL_new(sp->ssl_node_ctx);
    
    if ((sock = p2p_udp_socket_create(sp, msg->hdr.dst)) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to send UDP_MSG\n");
        return P2P_ERROR;
    }
    if (p2p_ssl_udp_client_init_sock(sp, clientssl, sock, p2p_addr_get_udp_port((p2p_msg_get_dst(msg)))) != P2P_OK) {
        VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
        return (P2P_ERROR);
    }

    p2p_ssl_udp_msg_sendfd(sp, msg, clientssl);
    p2p_ssl_close(sp, clientssl);
    p2p_udp_socket_close(sp, sock);
    
    VERBOSE(sp, VSYSCL, "Send MSG done \n");
    return P2P_OK;
}

//rebroadcast le message msg

int p2p_ssl_udp_msg_rebroadcast(server_params* sp, p2p_msg msg) {

    printf("----------------------Rebroadcast-----------------------------\n");

    int fd;
    SSL *clientssl = SSL_new(sp->ssl_node_ctx);
    p2p_ssl_init_client(sp, DTLS_METH);
    
    p2p_addr src = p2p_msg_get_src(msg);
    printf("Message Source : %s\n", p2p_addr_get_str(src));
    printf("Right ngb : %s\n", p2p_addr_get_str(sp->p2p_neighbors.right_neighbor));
    printf("Left ngb : %s\n", p2p_addr_get_str(sp->p2p_neighbors.left_neighbor));

    p2p_addr initiator = p2p_addr_create();
    memcpy(initiator, p2p_get_payload(msg), P2P_ADDR_SIZE);


    printf("initiator = %s\n\n", p2p_addr_get_str(initiator));
    printf("equal(me, right)  = %d\n", p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.right_neighbor));
    printf("equal(src, right)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor));
    printf("equal(init, right)  = %d\n", p2p_addr_is_equal(initiator, sp->p2p_neighbors.right_neighbor));
    printf("equal(me, left)  = %d\n", p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.left_neighbor));
    printf("equal(src, left)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor));
    printf("equal(init, left)  = %d\n\n", p2p_addr_is_equal(initiator, sp->p2p_neighbors.left_neighbor));

    if ((p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.right_neighbor) || p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor) || p2p_addr_is_equal(initiator, sp->p2p_neighbors.right_neighbor)) != 1) {

        p2p_msg_set_src(msg, sp->p2pMyId);
        fd = p2p_udp_socket_create(sp, sp->p2p_neighbors.right_neighbor);
        if (p2p_ssl_udp_client_init_sock(sp, clientssl, fd, p2p_addr_get_udp_port(p2p_msg_get_dst(msg))) != P2P_OK) {
                VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
                return (P2P_ERROR);
        }
        printf("Send to right\n");
        printf("Equal(src, right)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor));

        if (p2p_ssl_udp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
            printf("UDP_rebroadcast : sending FAILED\n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.right_neighbor));
        }
        
        p2p_ssl_close(sp, clientssl);
        p2p_udp_socket_close(sp, fd);

    }

    if ((p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(initiator, sp->p2p_neighbors.left_neighbor)) != 1) {

        p2p_msg_set_src(msg, sp->p2pMyId);
        printf("Send to left\n");
        printf("Equal(src, left)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor));
        fd = p2p_udp_socket_create(sp, sp->p2p_neighbors.left_neighbor);
        if (p2p_ssl_udp_client_init_sock(sp, clientssl, fd, p2p_addr_get_udp_port(p2p_msg_get_dst(msg))) != P2P_OK) {
            VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
            return (P2P_ERROR);
        }
        if (p2p_ssl_udp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
            printf("UDP rebroadcast : Sending FAILED \n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.left_neighbor));
        }
       
        p2p_ssl_close(sp, clientssl);
        p2p_udp_socket_close(sp, fd);

    }
    p2p_addr_delete(initiator);
    //p2p_addr_delete(src);
   
    return P2P_OK;

}

int p2p_ssl_udp_client_init_sock(server_params* sp, SSL* clientssl, int fd, int port) {
    
    BIO* conn = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (conn == NULL) {
        fprintf ( stderr , "error creating bio\n");
        return P2P_ERROR;
    }
    printf("PORT UDP: %d\n", port);
    struct sockaddr_in dst;
    struct sockaddr* d = (struct sockaddr*) &dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int err = BIO_dgram_set_peer(conn, d);
    fprintf ( stderr , "BIO dgram set peer: %d\n", err);
    SSL_set_bio(clientssl, conn, conn);
    SSL_set_connect_state(clientssl);
    
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

int p2p_ssl_udp_server_init_sock(server_params* sp, SSL* ssl, int fd) {
    
    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE... \n");
     
    BIO* conn = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (conn == NULL) {
        fprintf ( stderr , "error creating bio\n");
        return P2P_ERROR;
    }

    SSL_set_bio(ssl, conn, conn);
    SSL_set_accept_state(ssl);
    
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