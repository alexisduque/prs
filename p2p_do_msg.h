/* 
 * File:   p2p_do_msg.h
 * Author: alexis
 *
 * Created on 27 mars 2013, 08:48
 */

#ifndef P2P_DO_MSG_H
#define	P2P_DO_MSG_H
#define MAX_DATA_SIZE 65527

#include <stdio.h>
#include "p2p_msg.h"
#include "p2p_addr.h"
#include "p2p_file.h"
#include "p2p_search.h"
 
/* Fonctions de traitement des differents type de messages */

//Traitement du JOIN ACK
int p2p_do_join_ack (server_params *sp, p2p_msg ack_msg);

//Envoi du JOIN REQ
int p2p_send_join_req (server_params *sp, p2p_addr destinataire);

//Traitement du JOIN REQ                                                                                                                                                                                                
int p2p_do_join_req(server_params *sp, p2p_msg join_req, int socket);

//Traitement du GET
int p2p_do_get(server_params *sp, p2p_msg get_msg, int socket) ;

//Traitement du LINK UPDATE
int p2p_do_link_update(server_params *sp, p2p_msg link_update_msg) ;

//Traitement du SEARCH
int p2p_do_search(server_params *sp, p2p_msg search_msg) ;

//Traitement du REPLY  
int p2p_do_reply(server_params *sp, p2p_msg reply_msg) ;

//TRAITEMENT DU NEIGHBORS_REQ
int p2p_do_neighbors_req(server_params *sp, p2p_msg neighbors_req_msg) ;

//TRAITEMENT DU NEIGHBORS_LIST
int p2p_do_neighbors_list(server_params *sp, p2p_msg neighbors_list_msg) ;

// Te
int p2p_treat_get(server_params *sp, p2p_msg get, int fd);


int p2p_send_get(server_params *sp, p2p_addr dst, char* filename, int beginOffset, int endOffset, int fd);

int p2p_get_file(server_params *sp, int searchID, int replyID);

int p2p_do_data(server_params *sp, p2p_msg data, char* filename, int beginOffset, int endOffset);

#endif /* __P2P_DO_MSG */
