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
  { ""        , 0, ""                                 , NULL},
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
  VERBOSE(p->sp,VSYSCL,"ui: getting list file for %s\n",dirname);
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
      VERBOSE(p->sp,CLIENT,"ui: could not parse p2p address\n");
      return P2P_UI_ERROR;
    }

  VERBOSE(p->sp,VSYSCL,"ui:  sending p2p join msg to %s\n\n",p2p_addr_get_str(dst));

     printf(" p2pjoin : dest = %s \n", p2p_addr_get_str(dst));
  
  
   //Verifie que l'on ne se connecte pas avec nous meme
  if(p2p_addr_is_equal(dst, p->sp->p2pMyId)!=0){
	printf("tu essaies de te connecter avec toi meme\n");
	return(P2P_OK);
  }
	
  if(p2p_send_join_req(p->sp, dst) != P2P_OK ){
	printf("could not send the p2p join request\n");
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
  /**** A COMPLETER ****/
  return P2P_UI_ERROR;
}

/****************************************************/
/****************************************************/

int p2phalt(params *p)
{
  /**** A COMPLETER ****/
  return P2P_UI_ERROR;
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
        p2p_addr_copy(dst_adresse,p->sp->p2pMyId);
        
        // Creation de l'en-tete du message
        p2p_msg_init(search_message,P2P_MSG_SEARCH,P2P_MSG_TTL_MAX,src_adresse,dst_adresse);

        /* TODO */
        
        //p2p_msg_delete(msg_search);
        //free(buffer);

        return P2P_UI_ERROR;
 
}

/****************************************************/
/****************************************************/

int 
p2plist_search (params* p)
{
  /**** A COMPLETER ****/
  return P2P_UI_ERROR;
}

/****************************************************/
/****************************************************/

int 
p2plist_result (params* p)
{
  /**** A COMPLETER ****/
  return P2P_UI_ERROR;
}

/****************************************************/
/****************************************************/

int
p2pget(params* p)
{
  int search, result;
  result = atoi(p->options[0]);
  search = atoi(p->options[1]);
  VERBOSE(p->sp,VSYSCL,"ui: starting get result [%d] from search [%d]\n",result, search); 

  /**** A COMPLETER ****/
  return P2P_UI_ERROR;
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
