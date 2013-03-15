/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_msg
   PURPOSE
     
   NOTES
     
   HISTORY
     Revision 1.1  2005/02/21 18:34:32  afraboul
     ajout des sources qui seront distribuées aux étudiants

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

#include "p2p_common.h"
#include "p2p_addr.h"
#include "p2p_msg.h"

#define MIN(a,b)    (((a)<(b))?(a):(b))

//Definition de la structure de l'entete d'un message P2P
struct p2p_msg_hdr_struct {
  unsigned char  version_type;	/* Les champs Version et CmdType sont
				   codés tous les deux sur 1 octet */ 
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
				   zone mémoire de unsigned char */
};



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
  /* p2p_msg_set_length(msg,length); */
  assert(msg->payload = (unsigned char*)malloc(sizeof(unsigned char)*length));
  memcpy(msg->payload,payload,length);
  return P2P_OK;
} /* p2p_msg_init_payload */

/*********************************************************/
/* Header                                                */
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



/********************/
/* A COMPLETER      */
/********************/
