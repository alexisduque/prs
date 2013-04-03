/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_msg
   PURPOSE
     
   NOTES
     
   HISTORY
     Revision 1.1  2005/02/21 18:34:32  afraboul
     ajout des sources qui seront distribu�es aux �tudiants

     Revision 1.11  2004/12/26 16:15:15  afraboul
***/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <netdb.h> 
#include <assert.h>
#include <arpa/inet.h>

#include "p2p_common.h"
#include "p2p_addr.h"
#include "p2p_msg.h"
#include "p2p_options.h"


#define MIN(a,b)    (((a)<(b))?(a):(b))

//Definition de la structure de l'entete d'un message P2P
struct p2p_msg_hdr_struct {
  unsigned char  version_type;	/* Les champs Version et CmdType sont
				   cod�s tous les deux sur 1 octet */ 
  unsigned char  ttl;		/* Le champ  TTTL*/
  unsigned short length;	/* Le champ longueur */
  p2p_addr src;			/* Le champ adresse source */
  p2p_addr dst;			/* Le champ adresse destination */
};

//Definition du type p2p_msg_hdr qui est un pointeur sur la structure
//p2p_msg_hdr_struct 
typedef struct p2p_msg_hdr_struct p2p_msg_hdr;

//Definition de la structure d'un message P2P
struct p2p_msg_struct {
  p2p_msg_hdr hdr;		/* Un entete */
  unsigned char *payload;	/* Un payload qui un pointeur sur une
				   zone m�moire de unsigned char */
};
unsigned char* p2p_get_payload(p2p_msg msg) {
  return msg->payload;
}


p2p_msg
p2p_msg_create()
{
  p2p_msg msg;
    
  if ((msg = (p2p_msg) malloc(sizeof(struct p2p_msg_struct))) == NULL)
    return NULL;
  
  p2p_msg_set_version (msg,P2P_VERSION);
  p2p_msg_set_type    (msg,P2P_MSG_UNDEFINED);
  /*  p2p_msg_set_ttl     (msg,P2P_MSG_TTL_NULL);*/
  /*  p2p_msg_set_length  (msg,payload_size);    */
  assert(msg->hdr.src = p2p_addr_create());
  assert(msg->hdr.dst = p2p_addr_create());
  msg->payload        = NULL;

  return msg;
} /* p2p_msg_create */


void 
p2p_msg_delete(p2p_msg msg)
{
  p2p_addr_delete(msg->hdr.src);
  p2p_addr_delete(msg->hdr.dst);
  if (msg->payload != NULL)
    free(msg->payload);
  free(msg);
} /* p2p_msg_free */


p2p_msg 
p2p_msg_duplicate(const p2p_msg msg)
{
  p2p_msg msgDuplicata;
  
  if ((msgDuplicata = p2p_msg_create()) == NULL)
    return NULL;

  p2p_msg_set_version(msgDuplicata,p2p_msg_get_version(msg));
  p2p_msg_set_type   (msgDuplicata,p2p_msg_get_type   (msg));
  /* p2p_msg_set_ttl    (msgDuplicata,p2p_msg_get_ttl    (msg)); */

  msgDuplicata->hdr.src  = p2p_addr_duplicate(msg->hdr.src);
  msgDuplicata->hdr.dst  = p2p_addr_duplicate(msg->hdr.dst);

  /* assert(msgDuplicata->payload = (char*)malloc(sizeof(char)*p2p_msg_get_length(msg))); */
  /* memcpy(msgDuplicata->payload, msg->payload, p2p_msg_get_length(msg)); */
  return msgDuplicata;
} /* p2p_msg_duplicate */


int 
p2p_msg_init(p2p_msg msg, 
	     unsigned int type, unsigned int ttl,
	     const p2p_addr src, const p2p_addr dst)
{
  p2p_msg_set_version(msg,P2P_VERSION);
  p2p_msg_set_type   (msg,type);
  /* p2p_msg_set_ttl    (msg,ttl); */
  p2p_addr_copy      (msg->hdr.src,src);
  p2p_addr_copy      (msg->hdr.dst,dst);

  return P2P_OK;
} /* p2p_msg_init */


int 
p2p_msg_init_payload(p2p_msg msg,
		     const unsigned short int length,
		     char* payload)
{
  p2p_msg_set_length(msg,length);
  free(msg->payload);
  assert(msg->payload = (unsigned char*)malloc(sizeof(unsigned char)*length));
  memcpy(msg->payload,payload,length);
  return P2P_OK;
} /* p2p_msg_init_payload */

/*********************************************************/
/*               Fonctions sur les headers               */
/*********************************************************/

/********************/
/* VERSION | TYPE   */
/********************/
unsigned char 
p2p_msg_get_version(const p2p_msg msg) 
{
  return (msg->hdr.version_type & 0xF0) >> 4;
}

void 
p2p_msg_set_version(p2p_msg msg, unsigned char version) 
{
  msg->hdr.version_type = ((version & 0x0F) << 4) | p2p_msg_get_type(msg);
}

unsigned char 
p2p_msg_get_type(const p2p_msg msg) 
{
  return msg->hdr.version_type & 0x0F;
}

void 
p2p_msg_set_type(p2p_msg msg, unsigned char type) 
{
  msg->hdr.version_type = (p2p_msg_get_version(msg) << 4) | (type & 0x0F);
}

//renvoie le TTL de msg
unsigned char  p2p_msg_get_ttl(const p2p_msg msg)
{
    return msg->hdr.ttl;
}

//initialise le TTL de msg � ttl
void p2p_msg_set_ttl(p2p_msg msg, unsigned char ttl)
{
    msg->hdr.ttl = ttl;
}

//renvoie la longueur de l'entete de msg
unsigned short p2p_msg_get_length  (const p2p_msg msg)
{
    return (msg->hdr.length);
}

//initialise la longueur de l'entete de msg � length
void p2p_msg_set_length  (p2p_msg msg, unsigned short length)
{
    msg->hdr.length =htons(length); 
}

//renvoie l'adresse source de msg
p2p_addr p2p_msg_get_src (const p2p_msg msg)
{
  return msg->hdr.src;
}

//initialise l'adresse source de msg � src
void p2p_msg_set_src(p2p_msg msg, p2p_addr src)
{
  p2p_addr_copy(msg->hdr.src,src);
}

//renvoie l'adresse destination de msg
p2p_addr p2p_msg_get_dst(const p2p_msg msg)
{
  return msg->hdr.dst;
   
}

//initialise l'adrersse destination de msg � dst
void p2p_msg_set_dst(p2p_msg msg, p2p_addr dst)
{
   p2p_addr_copy(msg->hdr.dst,dst);
}

int p2p_msg_display(p2p_msg message){
  printf("Contenu du message : \n");
  printf("Version :%d ", p2p_msg_get_version(message));
  printf("Type : %d \n",p2p_msg_get_type(message));
  printf("TTL :%d ", p2p_msg_get_ttl(message));
  printf("Length : %d \n", p2p_msg_get_length(message));
  printf("Source adress : %s \n", p2p_addr_get_str(p2p_msg_get_src(message)));
  printf("Destination adress : %s \n", p2p_addr_get_str(p2p_msg_get_dst(message)));
  printf("Payload : %s", p2p_get_payload(message));
  return P2P_OK;
}


/*********************************************************/
/*               Fonctions sur les debugs                */
/*********************************************************/

//ecrit le message msg dans le fichier fd. Si print_payload != 0 �crit
//aussi le payload du message sinon on n'�crit que l'entete.
int p2p_msg_dumpfile(const p2p_msg msg, const FILE* fd, int print_payload)
{
  return P2P_OK; 
}

//�crit l'entete du message msg en hexa. 
int p2p_msg_hexdumpheader(unsigned char* msg, const FILE* fs)
{
    return P2P_OK; 
}

/*** Méthode socket pour TCP ***/
//Crée une socket TCP vers le noeud P2P dst.
int p2p_tcp_socket_create(server_params* sp, p2p_addr dst)
{
  struct sockaddr_in adresse;
  int fd, lg = sizeof(adresse);
  fd = creer_socket(SOCK_STREAM, 0);
  
  adresse.sin_family = AF_INET;
  adresse.sin_port = htons(p2p_addr_get_tcp_port(dst));
  adresse.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if (connect(fd, (struct sockaddr*)&adresse,lg)==P2P_ERROR){
    p2p_tcp_socket_close(sp,fd);
    return(P2P_ERROR);
  }
  VERBOSE(sp,VSYSCL,"SOCKET TCP created \n");
  return P2P_OK;
}

//Fermeture de la socket donnée par le descripteur fd
int p2p_tcp_socket_close(server_params* sp, int fd)
{
    close(fd);
    VERBOSE(sp,VSYSCL,"TCP socket disconnected %d\n",fd);
    return P2P_OK;
}

//Envoi du message msg via la socket tcp fd
int p2p_tcp_msg_sendfd(server_params* sp, p2p_msg msg, int fd)
{
  VERBOSE(sp,VPROTO,"TRY TO SEND msg ...\n");
  //On verifie que l'on essaie pas d'envoyer un message à nous même
  if (p2p_addr_is_equal(sp->p2pMyId,p2p_msg_get_dst(msg))!=0 ) 
    return P2P_ERROR;
  
  //On remplit le buffer toWrite, avec les infos contenues dans le msg en paramètre, selon le format du CDC
  char* toWrite = "";
  //allocation de la mémoire pour le buffer
  toWrite = (char*)malloc(P2P_HDR_SIZE + p2p_msg_get_length(msg));
  // ajout du champs "version" au buffer
  memcpy(toWrite, &(msg->hdr.version_type), P2P_HDR_BITFIELD_SIZE); 
  // ajout du champs "Adresse Source"
  memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE], p2p_msg_get_src(msg), P2P_ADDR_SIZE); 
  //ajout du champs "Adresse Dest"
  memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE + P2P_ADDR_SIZE], p2p_msg_get_dst(msg), P2P_ADDR_SIZE); 
  // Si contenu du message non vide, ajout du champs "Message"
  if (p2p_msg_get_length(msg) != 0){
    memcpy(&toWrite[P2P_HDR_SIZE], p2p_get_payload(msg), p2p_msg_get_length(msg));
  }
  
  // On envoie via le socket tcp fd, le message contenu dans le buffer, sinon message d'erreur
  if (write(fd, toWrite, P2P_HDR_SIZE + msg->hdr.length) != (P2P_HDR_SIZE + msg->hdr.length)){
    //printf("Echec de l'envoi du message dans la socket\n");
    VERBOSE(sp,VPROTO,"Unable to send msg to the socket\n");
    return P2P_ERROR;
  } else {
    return P2P_OK;
  }
 
}

// Renvoie dans msg un message depuis la socket fd
int p2p_tcp_msg_recvfd(server_params* sp, p2p_msg msg, int fd)
{
  int length;
  read(fd,msg,P2P_HDR_BITFIELD_SIZE);
  read(fd, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
  read(fd, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
  length = p2p_msg_get_length(msg);
  char data_payload[p2p_msg_get_length(msg)];
  read(fd,data_payload,length);
  p2p_msg_init_payload(msg,length,data_payload);
  p2p_msg_display(msg);
  VERBOSE(sp,VMCTNT,"RECV MSG OK\n");
  return P2P_OK;
} 

// Envoi du message msg via tcp au noeud destination indiquée dans le champ dst de msg
int p2p_tcp_msg_send(server_params* sp, const p2p_msg msg)
{
   
  int socketTMP = p2p_tcp_socket_create(sp,p2p_msg_get_dst(msg));
  if(socketTMP==P2P_ERROR)
  {
    VERBOSE(sp,VPROTO,"TCP socket creation impossible \n");
    //printf("Impossible de créer la socket TCP \n");
    return (P2P_ERROR);
  }

  if(p2p_tcp_msg_sendfd(sp,msg,socketTMP)!=P2P_OK)
  {
    return (P2P_ERROR);
  }
  p2p_tcp_socket_close(sp,socketTMP);
  VERBOSE(sp,VPROTO,"SEND msg DONE\n");
  return P2P_OK;
}


/*** Communication via UDP ***/
//Cr�e une socket UDP vers le noeud P2P dst.
int p2p_udp_socket_create(server_params* sp, p2p_addr dst)
{
  int sock_udp;
  struct sockaddr_in adresse;
  socklen_t longueur = sizeof(struct sockaddr_in);
  int port = 0;

  if ((sock_udp = creer_socket(SOCK_DGRAM, port))== P2P_ERROR){
    VERBOSE(sp,VPROTO,"UDP socket creation impossible \n");
    return P2P_ERROR;
  }

  adresse.sin_family  =AF_INET;
  inet_aton(p2p_addr_get_ip_str(dst),&adresse.sin_addr);
  adresse.sin_port=htons(p2p_addr_get_udp_port(dst));

  if (connect(sock_udp,(struct sockaddr*)&adresse,longueur) == P2P_ERROR)
  {
    VERBOSE(sp,VPROTO,"Unable to connect the socket \n");
    close(sock_udp);
    return P2P_ERROR;
  }
  VERBOSE(sp,VSYSCL,"SOCKET UDP created \n");
  return sock_udp;
}

//Ferme la socket donnée par le descripteur fd
int p2p_udp_socket_close(server_params* sp, int fd)
{
  close(fd);
  VERBOSE(sp,VSYSCL,"UDP socket disconnected %d\n",fd);
  return P2P_OK;
}

//Envoie le message msg via la socket UDP fd
int p2p_udp_msg_sendfd(server_params* sp, p2p_msg msg, int fd)
{
  
  return P2P_OK;
}

//re�oie dans msg un message depuis la socket UDP fd
/*int p2p_udp_msg_recvfd(server_params* sp, p2p_msg msg, int fd)
{
    return P2P_OK;
}*/

//envoie le message msg via udp au noeud destination indique dans le
//champ dst de msg
int p2p_udp_msg_send(server_params* sp, p2p_msg msg)
{
  int sock;
  if ((sock=p2p_udp_socket_create(sp,msg->hdr.dst))==P2P_ERROR){
    VERBOSE(sp,VPROTO,"Unable to send UDP_MSG\n");
    return P2P_ERROR;
  };
  p2p_udp_msg_sendfd(sp,msg,sock);
  p2p_udp_socket_close(sp,sock);
  VERBOSE(sp,VSYSCL,"Send MSG done \n");
  return P2P_OK;
}

//rebroadcast le message msg
int p2p_udp_msg_rebroadcast(server_params* sp, p2p_msg msg)
{
  return P2P_OK;
}
