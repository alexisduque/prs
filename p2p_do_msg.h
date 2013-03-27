/* 
 * File:   p2p_do_msg.h
 * Author: alexis
 *
 * Created on 27 mars 2013, 08:48
 */

#ifndef P2P_DO_MSG_H
#define	P2P_DO_MSG_H

#include <stdio.h>
#include "p2p_msg.h"
#include "p2p_addr.h"
/* Fonctions de traitement des differents type de messages */

//Traitement du JOIN
int p2p_do_join_req(server_params *sp, p2p_msg join_req, int socket);

//Traitement du GET
void p2p_do_get() ;

//Traitement du LINK UPDATE
void p2p_do_link_update() ;

#endif /* __P2P_DO_MSG */