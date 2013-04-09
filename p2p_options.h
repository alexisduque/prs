/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_options.h
   PURPOSE
     definition de la structure de donn�e permettant de stocker l'�tat
     global du syst�me.
   NOTES
     
   HISTORY
   Revision 1.2  2005/03/06 12:31:42  efleury
   Qqc comments dans les .h

   Revision 1.1  2005/02/21 18:34:33  afraboul
   ajout des sources qui seront distribu�es aux �tudiants

   Revision 1.3  2005/02/08 16:09:49  afraboul
***/

#ifndef __P2P_OPTIONS
#define __P2P_OPTIONS

/****************************************************/
/****************************************************/

#include <stdio.h>       /* pour FILE*       */
#include <sys/types.h>   /* pour freebsd4.10 */
#include <sys/time.h>    /* pour freebsd4.10 */
#include <sys/select.h>  /* pour fd_set      */
#include <netinet/in.h>  /* pour sockaddr_in */

/****************************************************/
/****************************************************/

#define P2P_OK 0
#define P2P_ERROR -1

/****************************************************/
/****************************************************/

#define P2P_SHORT_SIZE 2
#define P2P_INT_SIZE   4

/****************************************************/
/****************************************************/

#define P2P_DATA_ERROR                   0
#define P2P_DATA_OK                    200
#define P2P_DATA_BAD_REQUEST           400
#define P2P_DATA_UNAUTHORIZED          401
#define P2P_DATA_FORBIDDEN             402
#define P2P_DATA_NOT_FOUND             403
#define P2P_BAD_REQUEST                410
#define P2P_REQUEST_URI_TOO_LARGE      414
#define P2P_INTERNAL_SERVER_ERROR      500
#define P2P_NOT_IMPLEMENTED            501
#define P2P_SERVICE_UNAVAILABLE        502

/****************************************************/
/****************************************************/

#include "p2p_addr.h"
//#include "p2p_search.h"
//#include "p2p_do_msg.h"


//Structure contenant tous les parametres d'un noeud P2P. Permet
//d'avoir toutes les varaibles globales d�finissant l'environnement
//dans une seule structure que l'on peut ainsi passer � toutes les
//fonctions. 
/* server parameters */
struct server_params_t {
  char *server_name;		/* son nom */
  char *dir_name;		/* le directory ou l'on copie les fichiers */
  int verbosity;		/* le niveau de verbosite */

  int port_ui;			/* le numero de port pour l'interface
				   utilisateur */
  int port_p2p_tcp;		/* le numero de port TCP du noeud */
  int port_p2p_udp;		/* le numero de port UDP du noeud */

  int client_ui;                /* socket connect�e par telnet */

  /*********************************/
  /*********************************/
  /*                               */
  /* A COMPLETER                   */
  /*                               */
  /*********************************/
  /*********************************/

  /* Topology */
  p2p_addr p2pMyId;	        /* son adresse P2P */
  
  //  p2p_topology p2p_neighbors;	/* Ses voisins */
  
  p2p_addr right_neighbor;
  p2p_addr left_neighbor;
  
  /* Search */
  //p2p_search p2pSearchList;	/* la liste des requetes envoy�es */

};
typedef struct server_params_t server_params;

#endif
/****************************************************/
/****************************************************/
