/* Copyright (c) 2004 by ARES Inria.  All Rights Reserved */

/***
   NAME
    p2p_addr
   PURPOSE
     Structure des adresses P2P
   NOTES
     
   HISTORY
   Revision 1.2  2005/03/06 12:31:42  efleury
   Qqc comments dans les .h

   Revision 1.1  2005/03/01 21:50:12  afraboul
   ajour des adresses pour les étudiants

   Revision 1.6  2005/02/21 18:34:32  afraboul
   ajout des sources qui seront distribuées aux étudiants

   Revision 1.5  2005/02/08 16:09:49  afraboul
   quelques modification
    - ajout d'un champs listening_ipn dans l'état du server
      adresse IP locale de bind
    - bind sur adresse locale dans le server
    - ajout d'un timer pour tuer le server au bout de 2 heures
    - correction d'erreurs de typo

   Revision 1.4  2004/07/26 08:24:34  afraboul
   	* [all]: première version complète du noeud de référence

   Revision 1.3  2004/06/15 21:45:21  afraboul
     join+ack+update link fonctionne. Le select de la boucle principale est
     a refaire

   Revision 1.2  2004/06/14 16:18:47  afraboul
     mise en place des canaux de comm. pour envoyer et recevoir des paquets
     udp et tcp. Le join_req et join_ack fonctionnent. Il faut compléter avec
     les autres types de paquet.

   Revision 1.1  2004/06/10 23:21:05  afraboul
    - ajout de p2p_addr.[h|c] : l'ancienne gestion des adresses pouvait poser
      des problemes d'endianess.
    - correction des autres fichiers pour traiter les nouvelles adresses, il
      manque encore une solution pour la lecture et l'ecriture des paquets qui
      se font par des memcpy
    - la gestion de la topologie est a revoir pour supprimer les variables
      globales.


***/
#ifndef __P2P_ADDR
#define __P2P_ADDR

#include <stdio.h>

//Taille d'une adresse P2P en octets.
#define P2P_ADDR_SIZE (P2P_INT_SIZE + 2 * P2P_SHORT_SIZE)

//On n'exporte qu'un pointeur sur la structure p2p_addr qui elle reste
//cachée au sien du module p2p_addr.c
typedef struct p2p_addr_struct *p2p_addr;

//Créer et donc alloue une structure p2p_addr. retourne une p2p_addr,
//donc un pointeur sur la structure crée
p2p_addr p2p_addr_create();

//Supprime une adresse p2p_addr. (i.e., supprime la structure pointé
//par addr
void     p2p_addr_delete(p2p_addr addr);

//Copie l'adresse source src dans l'adress destination dst. La
//structure dst doit être allouée avant.
void     p2p_addr_copy(p2p_addr dst, p2p_addr src);

//Duplique l'adresse p2p addr et retourne une nouvelle structure
//contenant une copie de addr. Cette fonction alloue donc une nouvelle
//structure. 
p2p_addr p2p_addr_duplicate(p2p_addr addr);

//Compare les 2 adresses P2P. Renvoie 0 si elle sont différentes,
//i.e., si la partie IP n'est pas la même ou si les ports employés
//sont différents.
int p2p_addr_is_equal(const p2p_addr addr1, const p2p_addr addr2);

//Renvoie 0 si l'adresse addr n'est pas uen adresse de broadcast P2P
int p2p_addr_is_broadcast(const p2p_addr addr);

//Renvoie 0 si l'adresse addr n'est pas l'adresse non définie P2P
int p2p_addr_is_undefined(const p2p_addr addr);

//renvoie un pointeur sur l'adresse P2P de broadcast
p2p_addr p2p_addr_broadcast();

//renvoie un pointeur sur l'adresse P2P non définie
p2p_addr p2p_addr_undefined();

//assigne l'adresse P2P dst. Les paramètres sont l'adresse IP ip_str sous
//forme de chaine, l eportt tcp et udp sous la forme d entier short
//non signé. 
int   p2p_addr_set(p2p_addr dst, const char* ip_str, unsigned short tcp, unsigned short udp);

//assigne l'adresse dst à partir d'une adresse sous forme de string,
//i.e., IP:TCP_PORT:UDP_PORT
int   p2p_addr_setstr(p2p_addr dst, const char* p2p_str);

//assigne l'adresse addr à P2P broadcast : 255.255.255.255:0:0
void  p2p_addr_set_broadcast(p2p_addr addr);

//assigne l'adresse addr à P2P undifinied : 0.0.0.0:0:0
void  p2p_addr_set_undefined(p2p_addr addr);

//renvoie addr sous forme de chaine
char*          p2p_addr_get_str     (p2p_addr addr);

//renvoie la partie IP de addr sous forme de chaine
char*          p2p_addr_get_ip_str  (p2p_addr addr);

//renvoie le port TCP de addr
unsigned short p2p_addr_get_tcp_port(p2p_addr addr);

//renvoie le port UDP de addr
unsigned short p2p_addr_get_udp_port(p2p_addr addr);

//ecrit l'adresse addr dans le fichier fd (file descriptor)
void p2p_addr_dump(const p2p_addr addr, int fd);

//ecrit l'adresse formatée addr dans le fichier fd 
void p2p_addr_dumpfile(const p2p_addr addr, const FILE *fd);

#endif /* __P2P_ADDR */
