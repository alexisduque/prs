/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_client.c
   PURPOSE
     UI command line parsing

   NOTES

   HISTORY
   $Log: p2p_main.c,v $
   Revision 1.1  2006-02-10 13:21:41  afraboul
   add p2p_main.c

   Revision 1.1  2005/02/21 18:34:33  afraboul
   ajout des sources qui seront distribu�es aux �tudiants

   Revision 1.11  2004/12/26 16:15:15  afraboul
***/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>

// Pour la gestion des options sur la ligne de commande
#define _GNU_SOURCE
#include <getopt.h>

#include "p2p_common.h"
#include "p2p_options.h"
#include "p2p_do_msg.h"
#include "p2p_msg.h"

#define DEFAULT_SERVER_NAME "reference_node"
#define DEFAULT_DIR_NAME    "."

#define DEFAULT_IP          "127.0.0.1"
#define DEFAULT_IP_NUMBER   0x7f000001

#define DEFAULT_UI_TCP      3456
#define DEFAULT_P2P_TCP     4567
#define DEFAULT_P2P_UDP     4567
#define DEFAULT_VERBOSITY   2


static struct option long_options[] =
  {
    {"dir",           required_argument,0,'d'},
    {"server-name",   required_argument,0,'s'},
    {"listening-ip",  required_argument,0,'i'},
    {"ui-tcp-port",   required_argument,0,'U'},
    {"p2p-tcp-port",  required_argument,0,'t'},
    {"p2p-udp-port",  required_argument,0,'u'},
    {"connect",       required_argument,0,'c'},
    {"verbose",       optional_argument,0,'v'},
    {"help",          no_argument      ,0,'h'},
    {0, 0, 0, 0}
  };

static char str_options[] = "d:s:i:U:t:u:c:v::h";

/****************************************************/
/****************************************************/

void 
usage(char* progname)
{
  char msg[] = "\
%s: a p2p node                                                    \n\
  -c, --connect=[p2paddr]    : connect to node after init         \n\
  -d, --dir=[path]           : directory for download files       \n\
  -s, --server-name=[string] : server name                        \n\
  -i, --listening-ip=[ip]    : listening ip address               \n\
  -U, --ui-tcp-port=[port]   : listening port for user interface  \n\
  -t, --p2p-tcp-port=[port]  : listening port for tcp p2p traffic \n\
  -u, --p2p-udp-port=[port]  : listening port for udp p2p traffic \n\
  -v, --verbose=[int]        : debug verbosity level              \n\
                               0 - print nothing                  \n\
                               1 - print protocol errors          \n\
                               2 - trace received msg             \n\
                               3 - trace msg actions and content  \n\
                               4 - trace server syscalls          \n\
  -h, --help                 : this message                       \n";

  fprintf(stdout,msg,progname);
}

/****************************************************/
/****************************************************/


void
print_options(server_params *sp)
{
  if (sp->verbosity > 0)
    {
      fprintf(stderr,"\n");
      fprintf(stderr,"Starting p2p server node : \n");
      fprintf(stderr,"  pid          = %d\n"    ,getpid());
      fprintf(stderr,"  dir_name     = \"%s\"\n",sp->dir_name);
      fprintf(stderr,"  server_name  = \"%s\"\n",sp->server_name);
      fprintf(stderr,"  ui tcp       = %d\n"    ,(unsigned)sp->port_ui);
      fprintf(stderr,"  p2p tcp      = %d\n"    ,(unsigned)sp->port_p2p_tcp);
      fprintf(stderr,"  p2p udp      = %d\n"    ,(unsigned)sp->port_p2p_udp);
      fprintf(stderr,"  verbose      = %d\n"    ,sp->verbosity);
      fprintf(stderr,"\n");
    }
}


/****************************************************/
/****************************************************/

int main(int argc, char* argv[])
{
  server_params sp = {
    .server_name    = DEFAULT_SERVER_NAME,
    .dir_name       = DEFAULT_DIR_NAME,
    .verbosity      = DEFAULT_VERBOSITY,
    .port_ui        = DEFAULT_UI_TCP,
    .port_p2p_tcp   = DEFAULT_P2P_TCP,
    .port_p2p_udp   = DEFAULT_P2P_UDP,
    .client_ui      = -1,
    .p2pMyId	    = p2p_addr_create(),
    .right_neighbor = p2p_addr_create(),
    .left_neighbor  = p2p_addr_create(),
  };

  /* parsing command line args */
  while (1)
    {
      int c;
      int option_index = 0;
      
      if ((c = getopt_long(argc,argv, str_options, long_options, 
			   &option_index)) == -1)
	break;

      switch (c)
	{
	case 'c': /* connect: TODO */             break;
	case 'd': sp.dir_name     = optarg;       break;
	case 's': sp.server_name  = optarg;       break;
	case 'i': /* listening ip: TODO */  	  break;
	case 'U': sp.port_ui      = atoi(optarg); break;
	case 'u': sp.port_p2p_udp = atoi(optarg); break;
	case 't': sp.port_p2p_tcp = atoi(optarg); break;
	case 'v': 
	  if (optarg)
	    sp.verbosity = atoi(optarg);
	  else
	    sp.verbosity = DEFAULT_VERBOSITY;
	  break;
	case 'h': 
	default:
	  usage(argv[0]);
	  exit(0);
	  break;
	}
    }

  print_options(&sp);

  printf("Creation des socket\n");
  
  // Creation des variables
  int sock_ui, sock_ui_connected = -1, sock_tcp, sock_udp, sock_tcp_rcv;
  int return_select;
  fd_set fd;
  struct timeval timeout;
  struct sockaddr_in adresse;
  unsigned int lg=sizeof(adresse);
  p2p_msg message;
  
  // Init du timeout
  timeout.tv_sec=300;
  timeout.tv_usec=0;
  
   // Creation socket UI
  sock_ui = creer_socket(SOCK_STREAM, sp.port_ui);
  if (listen(sock_ui, 10) == -1){
    printf("Error creating UI socket\n");
    return -1;  
  } 
  
  //Creation socket TCP
  sock_tcp = creer_socket(SOCK_STREAM, sp.port_p2p_tcp);
  if (listen(sock_tcp, 10) == -1){
    printf("Error creating TCP socket\n");
    return -1;
  } 
	
  //Creation socket UDP
  sock_udp = creer_socket(SOCK_DGRAM, sp.port_p2p_udp);
  if (sock_udp == -1){
      printf("Error creating UDP socket\n");
      return -1;
  }
  
  printf("Entree dans la boucle principale\n");
  //Boucle principale
  while(1) {
      
      //Ajout des sockets au FD_SET
      FD_ZERO(&fd); 
      FD_SET(sock_ui, &fd);
      FD_SET(sock_tcp, &fd);
      FD_SET(sock_udp, &fd);
      
      //SELECT
      return_select = select(max(sock_ui, max(sock_tcp, sock_udp)) + 1, &fd, NULL, NULL, &timeout);
      
      // Si erreur dans le select
      if (return_select == -1) {
          printf("Erreur dans le select\n");
          exit(-1);
      } else
          
          //Si socket_tcp ready
          if (FD_ISSET(sock_tcp, &fd)){
              
              //on accepte la connexion
              sock_tcp_rcv = accept(sock_tcp, (struct sockaddr*) &adresse, &lg);
              //preparation du message
               message = p2p_msg_create();
               
               printf("Reception d'un message TCP\n");
               p2p_tcp_msg_recvfd(&sp, message, sock_tcp_rcv);
               
               //En fonction du message
               switch (p2p_msg_get_type(message)){	
                   
                        case P2P_MSG_JOIN_REQ  : //p2p_do_join_req(&sp, message, sock_tcp_rcv);
                                break;
							
                        case P2P_MSG_GET : //p2p_do_get(&sp, message, sock_tcp_rcv);
                                break;
						
                        case P2P_MSG_LINK_UPDATE : //p2p_do_link_update(&sp, message);
                                break;
               }	
              
               //Fermeture de la soscket de reception
               close(sock_tcp_rcv);
              
          } 
      
          //Si socket_udp ready
          else if (FD_ISSET(sock_udp, &fd)){
              
          }
      
                  
          //Si socket_ui ready
          else if (FD_ISSET(sock_ui, &fd)){
          
          }
      
          //Si socket_ui_connected ready
          else if (FD_ISSET(sock_ui_connected, &fd)){
              
          }
      
          else break; // Timeout
      
  }  
  
  close(sock_tcp);
  close(sock_udp);
  close(sock_ui);
  
  return 0;
  
}
