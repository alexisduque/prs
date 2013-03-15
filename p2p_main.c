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
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// Pour la gestion des options sur la ligne de commande
#define _GNU_SOURCE
#include <getopt.h>

#include "p2p_common.h"
#include "p2p_options.h"

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


  printf("Ce programme ne fait rien.\nVous devez modifier son code source pour le rendre compatible avec le noeud de reference.\n");
  return 0;
}