/* Copyright (c) 2004 by ARES Inria.  All Rights Reserved */

/***
   NAME
     p2p_common
   PURPOSE
     Global settings
   NOTES
     
   HISTORY
     efleury - May 02, 2004: Created.
     Revision 1.7  2004/07/26 08:24:34  afraboul
     	* [all]: premi�re version compl�te du noeud de r�f�rence

     Revision 1.6  2004/06/16 23:07:04  afraboul
        ajout du type de messages pour la decouverte de topology et d�but
        de la gestion du broadcast en UDP

     Revision 1.5  2004/06/15 21:45:21  afraboul
       join+ack+update link fonctionne. Le select de la boucle principale est
       a refaire

     Revision 1.4  2004/06/14 16:18:47  afraboul
       mise en place des canaux de comm. pour envoyer et recevoir des paquets
       udp et tcp. Le join_req et join_ack fonctionnent. Il faut compl�ter avec
       les autres types de paquet.

     Revision 1.3  2004/06/10 23:21:05  afraboul
      - ajout de p2p_addr.[h|c] : l'ancienne gestion des adresses pouvait poser
        des problemes d'endianess.
      - correction des autres fichiers pour traiter les nouvelles adresses, il
        manque encore une solution pour la lecture et l'ecriture des paquets qui
        se font par des memcpy
      - la gestion de la topologie est a revoir pour supprimer les variables
        globales.

     Revision 1.2  2004/05/24 09:05:59  afraboul
     p2p_ui et interface utilisateur par telnet

     Revision 1.1  2004/05/02 19:48:48  efleury
     code-equals-spec-equals-doc

***/
#ifndef __P2P_COMMON
#define __P2P_COMMON

/****************************************************/
/****************************************************/

#define P2P_OK 0
#define P2P_ERROR -1

/****************************************************/
/****************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#define P2P_SHORT_SIZE SIZEOF_SHORT
#define P2P_INT_SIZE   SIZEOF_INT
#else
#define P2P_SHORT_SIZE 2
#define P2P_INT_SIZE   4
#endif

/****************************************************/
/****************************************************/

#define P2P_DATA_OK                    200
#define P2P_DATA_ERROR                   0

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

#include "p2p_options.h"

/****************************************************/
/****************************************************/

/*************************************
  get_tokens : d�coupage d'une cha�ne en �l�ments
*************************************/

#define MAX_TOK 3
#define MAX_TOKLEN 30
int get_tokens(const char *str, char tok[MAX_TOK][MAX_TOKLEN], int (*test_delim)(char));

/************************************
 VERBOSE : affichage des messages 
       0 - print nothing\n\
       1 - print protocol errors\n\
       2 - trace received msg\n\
       3 - trace msg actions and content\n\
       4 - trace server syscalls\n\
*************************************/

#define VSINFO  0
#define VPROTO  1
#define VMRECV  2
#define VMCTNT  3
#define VSYSCL  4
#define CLIENT 10

void VERBOSE(server_params* sp, int level, char* fmt, ...); 
void raw_print(char *buf,int size);

int create_socket(int type, int port);
/****************************************************/
/****************************************************/

#endif /* __P2P_COMMON */
