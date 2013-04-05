/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     message
   PURPOSE
     Structure des messages P2P
   NOTES
     
   HISTORY
     efleury - Apr 30, 2004: Created.
     Revision 1.2  2005/03/06 12:31:42  efleury
     Qqc comments dans les .h

     Revision 1.1  2005/02/21 18:34:33  afraboul
     ajout des sources qui seront distribu�es aux �tudiants

     Revision 1.12  2004/12/26 16:15:15  afraboul
***/

#ifndef __P2P_MSG
#define __P2P_MSG

#include <stdio.h>
#include "p2p_addr.h"

//definition des constantes donn�e dans le RFC P2P_3TC
#define P2P_VERSION              1

#define P2P_MSG_UNDEFINED        0
#define P2P_MSG_JOIN_REQ         4
#define P2P_MSG_JOIN_ACK         5
#define P2P_MSG_LINK_UPDATE      6
#define P2P_MSG_SEARCH           8
#define P2P_MSG_REPLY            9
#define P2P_MSG_NEIGHBORS_REQ   10
#define P2P_MSG_NEIGHBORS_LIST  11 
#define P2P_MSG_GET             12
#define P2P_MSG_DATA            13

#define P2P_MSG_TTL_NULL         0
#define P2P_MSG_TTL_ONE_HOP      1
#define P2P_MSG_TTL_MAX          16

#define P2P_BAD_MSG_TYPE   0xFF000000

#define P2P_HDR_BITFIELD_SIZE   4 /* bytes */
#define P2P_HDR_SIZE            (P2P_HDR_BITFIELD_SIZE + 2 * P2P_ADDR_SIZE)


typedef struct p2p_msg_struct *p2p_msg;

/*** create / destroy msg ***/

//Cr�e (alloue) un message P2P dont le payload peut contenir une
//payload_size octets.
p2p_msg  p2p_msg_create      (void);

//D�truit le message msg, i.e., l'ensemble des structures allou�es
//(les addresses, l epaylod et le msg lui m�me)
void     p2p_msg_delete      (p2p_msg msg);

//Duplique le message dans un nouveau message
p2p_msg  p2p_msg_duplicate   (const p2p_msg msg);

//initialise un message avec type, TTL, src et dest
int      p2p_msg_init        (p2p_msg msg, unsigned int type, unsigned int ttl, const p2p_addr src, const p2p_addr dst);

//initialise le paylod de msg avec payload de taille length
int      p2p_msg_init_payload(p2p_msg msg, unsigned short int length, unsigned char* payload);

// R�cup�ration du payload
unsigned char* p2p_get_payload(p2p_msg msg);
/*** header ***/
//renvoie la version de msg
unsigned char  p2p_msg_get_version (const p2p_msg msg);

//initialise la version de msg � version
void           p2p_msg_set_version (p2p_msg msg, unsigned char version);

//renvoie le type de msg
unsigned char  p2p_msg_get_type    (const p2p_msg msg);

//initialise le type de msg � type
void           p2p_msg_set_type    (p2p_msg msg, unsigned char type);

//renvoie le TTL de msg
unsigned char  p2p_msg_get_ttl     (const p2p_msg msg);

//initialise le TTL de msg � ttl
void           p2p_msg_set_ttl     (p2p_msg msg, unsigned char ttl);

//renvoie la longueur de l'entete de msg
unsigned short p2p_msg_get_length  (const p2p_msg msg);

//initialise la longueur de l'entete de msg � length
void           p2p_msg_set_length  (p2p_msg msg, unsigned short length);

//renvoie l'adresse source de msg
p2p_addr       p2p_msg_get_src     (const p2p_msg msg);

//initialise l'adresse source de msg � src
void           p2p_msg_set_src     (p2p_msg msg, p2p_addr src);

//renvoie l'adresse destination de msg
p2p_addr       p2p_msg_get_dst     (const p2p_msg msg);

//initialise l'adrersse destination de msg � dst
void           p2p_msg_set_dst     (p2p_msg msg, p2p_addr dst);

/*** debug ***/
//ecrit le message msg dans le fichier fd. Si print_payload != 0 �crit
//aussi le payload du message sinon on n'�crit que l'entete.
int p2p_msg_dumpfile       (const p2p_msg msg, const FILE* fd, int print_payload);

//�crit l'entete du message msg en hexa. 
int p2p_msg_hexdumpheader  (unsigned char* msg, const FILE* fs);

// Fonction d'affichage des caract. du message
int p2p_msg_display(p2p_msg message);

/*** tcp ***/
//Cr�e une socket TCP vers le noeud P2P dst.
int p2p_tcp_socket_create  (server_params* sp, p2p_addr dst);

//Ferme la socket donn�e par le descripteur fd
int p2p_tcp_socket_close   (server_params* sp, int fd);

//Envoie le message msg via la socket tcp fd
int p2p_tcp_msg_sendfd     (server_params* sp, p2p_msg msg, int fd);

//re�oie dans msg un message depuis la socket fd
int p2p_tcp_msg_recvfd     (server_params* sp, p2p_msg msg, int fd);

//envoie le message msg via tcp au noeud destination indiqu� dans le
//champ dst de msg
int p2p_tcp_msg_send       (server_params* sp, const p2p_msg msg);

/*** udp ***/
//Cr�e une socket UDP vers le noeud P2P dst.
int p2p_udp_socket_create  (server_params* sp, p2p_addr dst);

//Ferme la socket donn�e par le descripteur fd
int p2p_udp_socket_close   (server_params* sp, int fd);

//Envoie le message msg via la socket UDP fd
int p2p_udp_msg_sendfd     (server_params* sp, p2p_msg msg, int fd);

//re�oie dans msg un message depuis la socket UDP fd
int p2p_udp_msg_recvfd     (server_params* sp, p2p_msg msg, int fd);

//envoie le message msg via udp au noeud destination indiqu� dans le
//champ dst de msg
int p2p_udp_msg_send       (server_params* sp, p2p_msg msg);

//rebroadcast le message msg
int p2p_udp_msg_rebroadcast(server_params* sp, p2p_msg msg);

#endif /* __P2P_MSG */
