/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_client.c
   PURPOSE
     UI command line parsing

   NOTES

   HISTORY
   Revision 1.1  2005/02/21 18:34:33  afraboul
   ajout des sources qui seront distribu�es aux �tudiants

   Revision 1.11  2004/12/26 16:15:15  afraboul
***/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "p2p_common.h"
#include "p2p_addr.h"
#include "p2p_msg.h"
#include "p2p_ui.h"
#include "p2p_do_msg.h"
#include "p2p_msg.h"

#define MAX_PATH 1024
#define MAX_REQ 1000
#define MAX_OPT 4

/****************************************************/
/****************************************************/

struct params_t {
  server_params *sp;
  char *options[MAX_OPT];
};
typedef struct params_t params;

int help           (params*);
int quit           (params*);
int status         (params*);
int file_list      (params*);
int p2pjoin        (params*);
int p2pleave       (params*);
int p2phalt        (params*);
int p2pdiscover    (params*); 
int p2psearch      (params*);
int p2plist_search (params*);
int p2plist_result (params*);
int p2pget         (params*);


/****************************************************/
/****************************************************/

struct cmd_t {
  char* name;
  int options;
  char* text;
  int (*fun)(params*);
};

static struct cmd_t commands[] = {
  { "help"    , 0, "print this message"               , help },
  { "state"   , 0, "print server state"               , status },
  { "list"    , 0, "list available files"             , file_list},
  { ""        , 0, ""                                 , NULL},
  { "join"    , 1, "connect to node [p2p_Id]"         , p2pjoin },
  { "leave"   , 0, "leave the p2p network"            , p2pleave },
  { "quit"    , 0, "detach ui from the server"        , quit },
  { "halt"    , 0, "leave the p2p and stop the server", p2phalt},
  { "discover", 0, "discover topology "               , p2pdiscover},
  { "search"  , 1, "search the [file]"                , p2psearch },
  { "list_search", 0, "list searches"                 , p2plist_search },
  { "list_result", 1, "list the results of search [n]", p2plist_result },
  { "get"     , 2, "get [result] from [search]"       , p2pget },
  { NULL, 0, NULL, NULL}
};

/****************************************************/
/****************************************************/

int help(params *p)
{
  int i;
  VERBOSE(p->sp,CLIENT,"\n");
  for(i=0; commands[i].name; i++)
    {
      VERBOSE(p->sp,CLIENT,"%11s : %s\n",commands[i].name, commands[i].text);
    }
  VERBOSE(p->sp,CLIENT,"\n");
  return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int quit(params *p)
{
  return P2P_UI_QUIT;
}

/****************************************************/
/****************************************************/

int status(params *p)
{
  VERBOSE(p->sp,CLIENT,"\n");
  VERBOSE(p->sp,CLIENT,"  server_name = \"%s\"\n",p->sp->server_name);
  VERBOSE(p->sp,CLIENT,"  dir_name    = \"%s\"\n",p->sp->dir_name);
  VERBOSE(p->sp,CLIENT,"  ui tcp      = %d\n"    ,p->sp->port_ui);
  VERBOSE(p->sp,CLIENT,"  p2p tcp     = %d\n"    ,p->sp->port_p2p_tcp);
  VERBOSE(p->sp,CLIENT,"  p2p udp     = %d\n"    ,p->sp->port_p2p_udp);
  VERBOSE(p->sp,CLIENT,"  verbose     = %d\n"    ,p->sp->verbosity);
  VERBOSE(p->sp,CLIENT,"  neighbors   = [ip:tcp:udp]\n");
  VERBOSE(p->sp,CLIENT,"\n");
  return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int file_list(params *p)
{
  DIR *dir;
  struct dirent* file;
  struct stat state;
  char dirname[MAX_PATH];
  char filename[MAX_PATH];

  strncpy(dirname,p->sp->dir_name,MAX_PATH);
  if (strlen(dirname) == 0)
    strncat(dirname,".",MAX_PATH);
  if (dirname[strlen(dirname) - 1] != '/')
    strncat(dirname,"/",MAX_PATH - strlen(dirname));

  if ((dir = opendir(dirname)) == NULL)
    {
      VERBOSE(p->sp,VSYSCL,"\nCannot open the shared directory \"%s\"\n",dirname);
      VERBOSE(p->sp,CLIENT,"\n\n  ** cannot open the shared directory on server ** \n\n");
      return P2P_UI_OK;
    }
  VERBOSE(p->sp,VSYSCL,"UI: getting list file for %s\n",dirname);
  VERBOSE(p->sp,CLIENT,"\nFile list\n");
  while ((file = readdir(dir)) != NULL) 
    {
      strncpy(filename,dirname,MAX_PATH);
      strncat(filename,file->d_name, MAX_PATH - strlen(filename));
      if (stat(filename,&state) == 0)
	{
	  if (S_ISREG(state.st_mode))
	    {
	      VERBOSE(p->sp,CLIENT,"  %20s  (%d bytes)\n",file->d_name,state.st_size);
	    }
	  else if (S_ISDIR(state.st_mode))
	    {
	      VERBOSE(p->sp,CLIENT,"  [dir] %14s\n",file->d_name);
	    }
	}
    }
  VERBOSE(p->sp,CLIENT,"\n");
  closedir(dir);
  return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int 
p2pjoin(params *p)
{
  p2p_addr dst = p2p_addr_create();
  
  if (p2p_addr_setstr(dst,p->options[0]) != P2P_OK)
    {
      VERBOSE(p->sp,CLIENT,">> Could not parse p2p address\n");
      return P2P_UI_ERROR;
    }

  VERBOSE(p->sp,CLIENT,">> Sending p2p join msg to %s\n",p2p_addr_get_str(dst));

   //Verifie que l'on ne se connecte pas avec nous meme
  if(p2p_addr_is_equal(dst, p->sp->p2pMyId)!=0){
	printf(">> Try to connet yourself ;-)\n");
	return(P2P_OK);
  }
	
  if(p2p_send_join_req(p->sp, dst) != P2P_OK ){
	printf(">> Could not send the JOIN REQ\n");
        return(P2P_UI_ERROR);
  }

  p2p_addr_delete(dst);
  return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int
p2pleave(params *p)
{
    
    int neighbor_type, i;
    p2p_addr neighbor_addresse, new_neighbor;
    p2p_msg link_update_msg;
    char * buffer;

    // Envoi de 2 link update pour enlever le noeud de l'anneau

    link_update_msg = p2p_msg_create();
    buffer = (char*)malloc(P2P_ADDR_SIZE + P2P_INT_SIZE);

    for(i=0; i<2; i++){
        
            // Premier envoi : le voisin de gauche a un nouveau voisin de droite
            if(i == 0){
                    printf("UI: Sending LINK_UPDATE to left neighbor\n");
                    neighbor_type = htonl(0x0000FFFF);
                    neighbor_addresse = p->sp->p2p_neighbors.left_neighbor;
                    new_neighbor = p->sp->p2p_neighbors.right_neighbor;
            }
            
            // Deuxieme envoi : l'inverse
            else {
                    printf("UI: Sending LINK_UPDATE to right neighbor\n");
                    neighbor_type = htonl(0xFFFF0000);
                    neighbor_addresse = p->sp->p2p_neighbors.right_neighbor;
                    new_neighbor = p->sp->p2p_neighbors.left_neighbor;
            }

            // Creation du header
            if (p2p_msg_init (link_update_msg, P2P_MSG_LINK_UPDATE, P2P_MSG_TTL_ONE_HOP, p->sp->p2pMyId, neighbor_addresse)!= P2P_OK){
                    perror("Erreur a l'initialisation de link update gauche\n");
                    return P2P_ERROR;
            }

            // Creation du payload
            memcpy(buffer, new_neighbor, P2P_ADDR_SIZE);
            memcpy(buffer + P2P_ADDR_SIZE, &neighbor_type, P2P_INT_SIZE);
            p2p_msg_init_payload( link_update_msg, P2P_ADDR_SIZE + P2P_INT_SIZE,(unsigned char*) buffer); 

            // Envoi du message
            if(p2p_tcp_msg_send(p->sp,link_update_msg) == P2P_ERROR){
                    perror("Erreur envoi link update\n");
                    return P2P_ERROR;
            }

    }       
    
    // Réinitialisation des voisins du noeud quitté
    p->sp->p2p_neighbors.left_neighbor = p2p_addr_duplicate(p->sp->p2pMyId);
    p->sp->p2p_neighbors.right_neighbor = p2p_addr_duplicate(p->sp->p2pMyId); 

    // Nettoyage des variables
    p2p_msg_delete(link_update_msg);
    free(buffer);
                
  return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int p2phalt(params *p)
{
  p2pleave(p);
  return P2P_UI_KILL;
}

/****************************************************/
/****************************************************/

int
p2psearch(params* p)
{
    
        // Initialisation
        unsigned char * buffer;
        p2p_msg search_message = p2p_msg_create();
        int search_id;
        p2p_addr src_adresse,dst_adresse;
        
        //Récuperation des adresses source et destionation
        src_adresse = p2p_addr_create();
        p2p_addr_copy(src_adresse,p->sp->p2pMyId);
        dst_adresse = p2p_addr_create();
        p2p_addr_copy(dst_adresse,p2p_addr_broadcast());
        
        // Creation de l'en-tete du message
        p2p_msg_init(search_message,P2P_MSG_SEARCH,P2P_MSG_TTL_MAX,src_adresse,dst_adresse);

        // Creation du buffer
        printf("\nUI: Recherche du fichier : %s\n", p->options[0]);
        buffer = malloc(P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE + sizeof(char)*strlen(p->options[0]));
        memcpy(buffer, p->sp->p2pMyId, P2P_ADDR_SIZE);
        search_id = htonl(p->sp->search_id);
        memcpy(buffer + P2P_ADDR_SIZE, &search_id, P2P_HDR_BITFIELD_SIZE);
        memcpy(buffer + P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE, p->options[0], sizeof(char)*strlen(p->options[0]));
        
        // Creation du payload depuis le buffer
        p2p_msg_init_payload(search_message, P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE+sizeof(char)*strlen(p->options[0]),(unsigned char*) buffer);

        //printf("DEBUG p2p_ui search envoi du msg search taille fichier %d len %d\n",sizeof(p->options[0]),sizeof(char)*strlen(p->options[0]));
        
        // Envoi du message UDP aux voisins
        p2p_udp_msg_rebroadcast (p->sp, search_message);

        // Ajout de la recherche dans la liste des recherches effectuees
        p2p_add_search(&(p->sp->p2pSearchList),p->sp->search_id,p->options[0]);
        
        //Incrementation de l'ID de recherche
        p->sp->search_id++;
        
        // Nettoyage des variables
        
        p2p_msg_delete(search_message);
        free(buffer);

        return P2P_UI_OK;
 
}

/****************************************************/
/****************************************************/

int 
p2plist_search (params* p)
{
    printf("\nUI: Liste des recherches\n\n");
    p2p_list_search(p->sp);
    return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int 
p2plist_result (params* p)
{
    
        printf("\nUI: Liste des resultats de la recherche %s\n\n",p->options[0]);
        p2p_list_results(p->sp,atoi(p->options[0]));

        return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int
p2pget(params* p)
{       
        int search, result;
        int socket_tcp;
        char * file_name;
        char * buffer;
        unsigned char * data;
        int begin_offset;
        int file_size;
        unsigned char status;
        p2p_msg get_msg,data_msg;
        p2p_addr dst ;

        // Recuperation des ID de recherche et de resultat
        result = atoi(p->options[0]);
        search = atoi(p->options[1]);
        VERBOSE(p->sp,VSYSCL,"UI: starting get result [%d] from search [%d]\n",result, search); 
            printf("\nUI: Demande de recuperation de fichier :\n");
        printf("Reponse [%d] a la recherche [%d]\n\n",result, search); 
        
        // Recuperation des infos sur le fichier voulu
        file_size = p2p_get_owner_file(p->sp->p2pSearchList, search, result, &file_name, &dst);
        if (file_size == P2P_ERROR){
                perror("Error : File not FOUND \n\n");
                return P2P_ERROR;
        }       
                
/*
        printf("   Nom du fichier : %s\n", file_name);
        printf("   Taille : %d\n", file_size);
        printf("   Proprietaire : %s\n", p2p_addr_get_str(dst));
*/
        
        // Creation du GET
        get_msg = p2p_msg_create();
        p2p_msg_init (get_msg, P2P_MSG_GET, P2P_MSG_TTL_ONE_HOP, p->sp->p2pMyId, dst);
                
        begin_offset = 0;
        file_size = htonl(file_size - 1);
        buffer = malloc(2*P2P_INT_SIZE + strlen(file_name));
        memcpy(buffer, &begin_offset, P2P_INT_SIZE);
        memcpy(buffer + P2P_INT_SIZE, &file_size, P2P_INT_SIZE);
        memcpy(buffer + 2*P2P_INT_SIZE, file_name, strlen(file_name));
        
        p2p_msg_init_payload(get_msg, 2*P2P_INT_SIZE + strlen(file_name), (unsigned char*) buffer);
        
        // Création de la socket pour envoyer au noeud
        socket_tcp= p2p_tcp_socket_create(p->sp,dst);
        if (socket_tcp == P2P_ERROR) return socket_tcp;
        
        // Envoi du msg
        if(p2p_tcp_msg_sendfd(p->sp, get_msg, socket_tcp) == P2P_ERROR){
                perror("Error sending GET message\n\n");
                return P2P_ERROR;
        }
        
        // Nettoyage des variables
        p2p_msg_delete(get_msg);
        free(buffer);   
        
        // Reception du data
        
        data_msg = p2p_msg_create();
        printf("\n>> Waiting for data...\n"); 
        if ( p2p_tcp_msg_recvfd (p->sp, data_msg, socket_tcp) == P2P_ERROR ){
                perror("Error receiving DATA messsage\n\n");
                return P2P_ERROR;
        }
        
        printf("****  Data received  **** !\n");
        p2p_msg_dumpfile(data_msg,stdout,1);
        VERBOSE(p->sp, VSYSCL,"MSG size : %d\n",p2p_msg_get_length(data_msg));
        
        // Recuperation du status
        memcpy(&status, p2p_get_payload(data_msg), 1);
        
        printf("   Status code : %d\n",status);
        if (status == P2P_DATA_OK){
                printf("   Recuperation des donnees\n");
                // Recuperation taille des donnees
                memcpy(&file_size, p2p_get_payload(data_msg) + P2P_HDR_BITFIELD_SIZE, P2P_INT_SIZE);
                file_size = ntohl(file_size);
                
                // Creation du fichier d'accueil
                p2p_file_create_file(p->sp, file_name, file_size);
                
                if(file_size > 0){
                // Ecriture des donnees
                printf("   Ecriture dans le fichier (taille : %d)\n", file_size);
                printf("***********************************************\n\n");
                data = malloc (file_size*sizeof(char));
                memcpy(data, p2p_get_payload(data_msg) + 2*P2P_HDR_BITFIELD_SIZE, file_size);
                p2p_file_set_chunck(p->sp, file_name, 0, file_size-1, data);
                }
                return P2P_OK;

        } else {
                return P2P_ERROR;
        }
        
        // Nettoyage des variables
        p2p_msg_delete(data_msg);
        free(data);  
        
        // Fermeture de la socket
        p2p_tcp_socket_close(p->sp,socket_tcp);
        
        //free(buffer);
        free(file_name);
        //p2p_msg_delete(get);
        return P2P_OK;

}

int p2pdiscover(params *p)
{
VERBOSE(p->sp,VSYSCL,"Decouverte de topology -- Mise a jour de la liste des voisins\n");
	
		// Writing Neighbors_REQ Message
		
		//Message INIT
		int length = P2P_ADDR_SIZE;
		p2p_addr broad;
		broad = p2p_addr_create();
		broad = p2p_addr_broadcast();
		p2p_msg neighbors_req_msg;

		
		neighbors_req_msg = p2p_msg_create();//p2p_msg_dumpfile(msg,stdout,1);
		p2p_msg_set_length(neighbors_req_msg,length);
		p2p_msg_set_length(neighbors_req_msg,ntohs(p2p_msg_get_length(neighbors_req_msg)));
		
		p2p_msg_init(neighbors_req_msg, P2P_MSG_NEIGHBORS_REQ,P2P_MSG_TTL_MAX, p->sp->p2pMyId, broad);
		p2p_msg_init_payload(neighbors_req_msg,P2P_ADDR_SIZE , (unsigned char *)p2p_addr_get_str(p->sp->p2pMyId));
             //   p2p_get_payload(neighbors_req_msg) = (unsigned char*)malloc(sizeof(unsigned char)*length);
		//memcpy(&(p2p_get_payload(neighbors_req_msg)[0]), p->sp->p2pMyId,P2P_ADDR_SIZE);
		
		p2p_get_payload(neighbors_req_msg)[length] = '\0';

	
	//Send to left
		//if (p2p_udp_msg_send(p->sp, neighbors_req_msg, p->sp->p2p_neighbors.right_neighbor) == -1) return P2P_UI_ERROR;
	
	//Send to right
		//if (p2p_udp_msg_send(p->sp,neighbors_req_msg,p->sp->p2p_neighbors.left_neighbor) == -1) return P2P_UI_ERROR;
	// Broadcast Send
                if (p2p_udp_msg_send(p->sp,neighbors_req_msg) == -1) return P2P_UI_ERROR;
                
	
	//Destroy msg
		printf("Fin envoi du message P2P_NEIGHBORS_REQ\n");
		p2p_msg_delete(neighbors_req_msg);
		
	return P2P_UI_OK;
}

/****************************************************/
/****************************************************/

int 
test_ui_delim(char c)
{
  return (c == ' ' || c == '\t' || c == 10 || c == 13);
}

static int
read_command(char* buf, int maxsize, int sock)
{
  int eol = 0;
  char c;
  int length = 0;
  
  /* telnet sends '1310' == '\r\n' for each newline          */
  /* eol == 2 at the end of a line after it receives '13'10' */
  while (eol < 2 && length < maxsize)
    {
      if (read(sock,&c,sizeof(char)) == -1)
	{
	  return P2P_UI_QUIT;
	}
      else
	{
	  if (c == '\n' || c == '\r')
	    {
	      eol ++;
	    }
	  else
	    {
	      buf[length] = c;
	      length++;
	    }
	}
    }
  buf[length] = '\0';

  return length;
}

/****************************************************/
/****************************************************/

int ui_command(server_params *sp)
{
  int i,o;
  int ntokens;
  char req[MAX_REQ];
  char tokens[MAX_TOK][MAX_TOKLEN];
  params p = { sp, { NULL, NULL, NULL, NULL } };

  if (read_command(req,sizeof(req),sp->client_ui) == -1)
    {
      return P2P_UI_QUIT;
    }
  
  VERBOSE(sp,VSYSCL,"ui: request=-%s-\n",req);

  if ((ntokens = get_tokens(req,tokens,test_ui_delim)) == 0)
    {
      return help(&p);
    }

  for(i=0; i < ntokens; i++)
    VERBOSE(sp,VSYSCL,"   token %d: -%s-\n",i,tokens[i]);

  for(i=0; commands[i].name != NULL; i++)
    {
      if (strcasecmp(commands[i].name,tokens[0]) == 0)
	{
	  if (commands[i].options != ntokens - 1)
	    {
	      VERBOSE(sp,VSYSCL,"ui: incorrect number of arguments %s\n",tokens[0]);
	      VERBOSE(p.sp,CLIENT," ** incorrect number of arguments for %s\n",tokens[0]);
	      return P2P_UI_OK;
	    }
	  for(o=0; o < ntokens; o++)
	    {
	      p.options[o] = tokens[o+1];
	    }
	  return commands[i].fun(&p);
	}
    }

  VERBOSE(p.sp,CLIENT,"\n %s command unknown\n\n",tokens[0]);

  return P2P_UI_OK;
}
