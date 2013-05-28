/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_client.c
   PURPOSE
     UI command line parsing

   NOTES

   HISTORY
   Revision 1.1  2005/02/21 18:34:33  afraboul
   ajout des sources qui seront distribuees aux etudiants

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

int help(params*);
int quit(params*);
int status(params*);
int file_list(params*);
int p2pjoin(params*);
int p2pleave(params*);
int p2phalt(params*);
int p2pdiscover(params*);
int p2psearch(params*);
int p2plist_search(params*);
int p2plist_result(params*);
int p2pget(params*);


/****************************************************/

/****************************************************/

struct cmd_t {
    char* name;
    int options;
    char* text;
    int (*fun)(params*);
};

static struct cmd_t commands[] = {
    { "help", 0, "print this message", help},
    { "state", 0, "print server state", status},
    { "list", 0, "list available files", file_list},
    { "", 0, "", NULL},
    { "join", 1, "connect to node [p2p_Id]", p2pjoin},
    { "leave", 0, "leave the p2p network", p2pleave},
    { "quit", 0, "detach ui from the server", quit},
    { "halt", 0, "leave the p2p and stop the server", p2phalt},
    { "discover", 0, "discover topology ", p2pdiscover},
    { "search", 1, "search the [file]", p2psearch},
    { "list_search", 0, "list searches", p2plist_search},
    { "list_result", 1, "list the results of search [n]", p2plist_result},
    { "get", 2, "get [result] from [search]", p2pget},
    { NULL, 0, NULL, NULL}
};

/****************************************************/

/****************************************************/

int help(params *p) {
    int i;
    VERBOSE(p->sp, CLIENT, "\n");
    for (i = 0; commands[i].name; i++) {
        VERBOSE(p->sp, CLIENT, "%11s : %s\n", commands[i].name, commands[i].text);
    }
    VERBOSE(p->sp, CLIENT, "\n");
    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int quit(params *p) {
    return P2P_UI_QUIT;
}

/****************************************************/

/****************************************************/

int status(params *p) {
    VERBOSE(p->sp, CLIENT, "\n");
    VERBOSE(p->sp, CLIENT, "  server_name = \"%s\"\n", p->sp->server_name);
    VERBOSE(p->sp, CLIENT, "  dir_name    = \"%s\"\n", p->sp->dir_name);
    VERBOSE(p->sp, CLIENT, "  ui tcp      = %d\n", p->sp->port_ui);
    VERBOSE(p->sp, CLIENT, "  p2p tcp     = %d\n", p->sp->port_p2p_tcp);
    VERBOSE(p->sp, CLIENT, "  p2p udp     = %d\n", p->sp->port_p2p_udp);
    VERBOSE(p->sp, CLIENT, "  verbose     = %d\n", p->sp->verbosity);
    VERBOSE(p->sp, CLIENT, "  neighbors   = [ip:tcp:udp]\n");
    VERBOSE(p->sp, CLIENT, "\n");
    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int file_list(params *p) {
    DIR *dir;
    struct dirent* file;
    struct stat state;
    char dirname[MAX_PATH];
    char filename[MAX_PATH];

    strncpy(dirname, p->sp->dir_name, MAX_PATH);
    if (strlen(dirname) == 0)
        strncat(dirname, ".", MAX_PATH);
    if (dirname[strlen(dirname) - 1] != '/')
        strncat(dirname, "/", MAX_PATH - strlen(dirname));

    if ((dir = opendir(dirname)) == NULL) {
        VERBOSE(p->sp, VSYSCL, "\nCannot open the shared directory \"%s\"\n", dirname);
        VERBOSE(p->sp, CLIENT, "\n\n  ** cannot open the shared directory on server ** \n\n");
        return P2P_UI_OK;
    }
    VERBOSE(p->sp, VSYSCL, "UI: getting list file for %s\n", dirname);
    VERBOSE(p->sp, CLIENT, "\nFile list\n");
    while ((file = readdir(dir)) != NULL) {
        strncpy(filename, dirname, MAX_PATH);
        strncat(filename, file->d_name, MAX_PATH - strlen(filename));
        if (stat(filename, &state) == 0) {
            if (S_ISREG(state.st_mode)) {
                VERBOSE(p->sp, CLIENT, "  %20s  (%d bytes)\n", file->d_name, state.st_size);
            } else if (S_ISDIR(state.st_mode)) {
                VERBOSE(p->sp, CLIENT, "  [dir] %14s\n", file->d_name);
            }
        }
    }
    VERBOSE(p->sp, CLIENT, "\n");
    closedir(dir);
    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int
p2pjoin(params *p) {
    p2p_addr dst = p2p_addr_create();

    if (p2p_addr_setstr(dst, p->options[0]) != P2P_OK) {
        VERBOSE(p->sp, CLIENT, ">> Could not parse p2p address\n");
        p2p_addr_delete(dst);
        return P2P_UI_ERROR;
    }

    VERBOSE(p->sp, CLIENT, ">> Sending p2p join msg to %s\n", p2p_addr_get_str(dst));

    //Verifie que l'on ne se connecte pas avec nous meme
    if (p2p_addr_is_equal(dst, p->sp->p2pMyId) != 0) {
        printf(">> Try to connet yourself ;-)\n");
        p2p_addr_delete(dst);
        return (P2P_OK);
    }

    if (p2p_send_join_req(p->sp, dst) != P2P_OK) {
        printf(">> Could not send the JOIN REQ\n");
        p2p_addr_delete(dst);
        return (P2P_UI_ERROR);
    }

    p2p_addr_delete(dst);
    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int
p2pleave(params *p) {

    int neighbor_type, i;
    p2p_addr neighbor_addresse = NULL;
    p2p_addr new_neighbor = NULL;
    p2p_msg link_update_msg = NULL;
    char * buffer;

    // Envoi de 2 link update pour enlever le noeud de l'anneau

    link_update_msg = p2p_msg_create();
    buffer = (char*) malloc(P2P_ADDR_SIZE + P2P_INT_SIZE);

    for (i = 0; i < 2; i++) {

        // Premier envoi : le voisin de gauche a un nouveau voisin de droite
        if (i == 0) {
            VERBOSE(p->sp, VMRECV, "UI: Sending LINK_UPDATE to left neighbor\n");
            neighbor_type = htonl(0x0000FFFF);
            neighbor_addresse = p->sp->p2p_neighbors.left_neighbor;
            new_neighbor = p->sp->p2p_neighbors.right_neighbor;
        }
            // Deuxieme envoi : l'inverse
        else {
            VERBOSE(p->sp, VMRECV, "UI: Sending LINK_UPDATE to right neighbor\n");
            neighbor_type = htonl(0xFFFF0000);
            neighbor_addresse = p->sp->p2p_neighbors.right_neighbor;
            new_neighbor = p->sp->p2p_neighbors.left_neighbor;
        }

        // Creation du header
        if (p2p_msg_init(link_update_msg, P2P_MSG_LINK_UPDATE, P2P_MSG_TTL_ONE_HOP, p->sp->p2pMyId, neighbor_addresse) != P2P_OK) {
            perror(" Error during the initialisation link update left\n");
            return P2P_ERROR;
        }

        // Creation du payload
        memcpy(buffer, new_neighbor, P2P_ADDR_SIZE);
        memcpy(buffer + P2P_ADDR_SIZE, &neighbor_type, P2P_INT_SIZE);
        p2p_msg_init_payload(link_update_msg, P2P_ADDR_SIZE + P2P_INT_SIZE, (unsigned char*) buffer);

        // Envoi du message
        if (p2p_tcp_msg_send(p->sp, link_update_msg) == P2P_ERROR) {
            perror(" Error send link update\n");
            return P2P_ERROR;
        }

    }

    // Réinitialisation des voisins du noeud quitté
    p2p_addr_copy (p->sp->p2p_neighbors.left_neighbor, p->sp->p2pMyId);
    p2p_addr_copy (p->sp->p2p_neighbors.right_neighbor, p->sp->p2pMyId);

    // Nettoyage des variables
    p2p_msg_delete(link_update_msg);
    free(buffer);

    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int p2phalt(params *p) {
    p2pleave(p);
    return P2P_UI_KILL;
}

/****************************************************/

/****************************************************/

int
p2psearch(params* p) {

    // Initialisation
    unsigned char * buffer;
    p2p_msg search_message = p2p_msg_create();
    int search_id;
    p2p_addr src_adresse, dst_adresse;

    //Récuperation des adresses source et destionation
    src_adresse = p2p_addr_create();
    p2p_addr_copy(src_adresse, p->sp->p2pMyId);
    dst_adresse = p2p_addr_create();
    p2p_addr_copy(dst_adresse, p2p_addr_broadcast());

    // Creation de l'en-tete du message
    p2p_msg_init(search_message, P2P_MSG_SEARCH, P2P_MSG_TTL_MAX, src_adresse, dst_adresse);

    // Creation du buffer
    printf("\nUI: Research file : %s\n", p->options[0]);
    buffer = malloc(P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE + sizeof (char)*strlen(p->options[0]));
    memcpy(buffer, p->sp->p2pMyId, P2P_ADDR_SIZE);
    search_id = htonl(p->sp->search_id);
    memcpy(buffer + P2P_ADDR_SIZE, &search_id, P2P_HDR_BITFIELD_SIZE);
    memcpy(buffer + P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE, p->options[0], sizeof (char)*strlen(p->options[0]));

    // Creation du payload depuis le buffer
    p2p_msg_init_payload(search_message, P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE + sizeof (char)*strlen(p->options[0]), (unsigned char*) buffer);

    //printf("DEBUG p2p_ui search envoi du msg search taille fichier %d len %d\n",sizeof(p->options[0]),sizeof(char)*strlen(p->options[0]));

    // Envoi du message UDP aux voisins
    p2p_udp_msg_rebroadcast(p->sp, search_message);

    // Ajout de la recherche dans la liste des recherches effectuees
    p2p_add_search(&(p->sp->p2pSearchList), p->sp->search_id, p->options[0]);

    //Incrementation de l'ID de recherche
    p->sp->search_id++;

    // Nettoyage des variables

    //p2p_msg_delete(search_message);
    free(buffer);
    p2p_msg_delete(search_message);
    p2p_addr_delete(src_adresse);
    p2p_addr_delete(dst_adresse);
    return P2P_UI_OK;

}

/****************************************************/

/****************************************************/

int
p2plist_search(params* p) {
    printf("\nUI: Researches List :\n\n");
    p2p_list_search(p->sp);
    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int
p2plist_result(params* p) {

    printf("\nUI: Results list of the research %s\n\n", p->options[0]);
    p2p_list_results(p->sp, atoi(p->options[0]));

    return P2P_UI_OK;
}

/****************************************************/

/****************************************************/

int
p2pget(params* p) {
    int searchID, resultID;
    resultID = atoi(p->options[0]);
    searchID = atoi(p->options[1]);
    VERBOSE(p->sp, VSYSCL, "SearchID = %d   / ReplyID = %d\n\n", searchID, resultID);
    VERBOSE(p->sp, VSYSCL, "UI: Starting get result [%d] from search [%d]\n", resultID, searchID);

    if (p2p_get_file(p->sp, searchID, resultID) != P2P_OK) {
        printf("*** GET ERROR****");
        return P2P_UI_ERROR;
    }

    return (P2P_OK);
    /*
        p2p_addr_delete(dst);
        free(file_name);
     */
}

int p2pdiscover(params *p) {
    	if (p2p_send_neighbor_req(p->sp) == P2P_OK){
		return(P2P_UI_OK);
	} else return P2P_UI_ERROR;
}

/****************************************************/

/****************************************************/

int
test_ui_delim(char c) {
    return (c == ' ' || c == '\t' || c == 10 || c == 13);
}

static int
read_command(char* buf, int maxsize, int sock) {
    int eol = 0;
    char c;
    int length = 0;

    /* telnet sends '1310' == '\r\n' for each newline          */
    /* eol == 2 at the end of a line after it receives '13'10' */
    while (eol < 2 && length < maxsize) {
        if (read(sock, &c, sizeof (char)) == -1) {
            return P2P_UI_QUIT;
        } else {
            if (c == '\n' || c == '\r') {
                eol++;
            } else {
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

int ui_command(server_params *sp) {
    int i, o;
    int ntokens;
    char req[MAX_REQ];
    char tokens[MAX_TOK][MAX_TOKLEN];
    params p = {sp,
        { NULL, NULL, NULL, NULL}};

    if (read_command(req, sizeof (req), sp->client_ui) == -1) {
        return P2P_UI_QUIT;
    }

    VERBOSE(sp, VSYSCL, "ui: request=-%s-\n", req);

    if ((ntokens = get_tokens(req, tokens, test_ui_delim)) == 0) {
        return help(&p);
    }

    for (i = 0; i < ntokens; i++)
        VERBOSE(sp, VSYSCL, "   token %d: -%s-\n", i, tokens[i]);

    for (i = 0; commands[i].name != NULL; i++) {
        if (strcasecmp(commands[i].name, tokens[0]) == 0) {
            if (commands[i].options != ntokens - 1) {
                VERBOSE(sp, VSYSCL, "ui: incorrect number of arguments %s\n", tokens[0]);
                VERBOSE(p.sp, CLIENT, " ** incorrect number of arguments for %s\n", tokens[0]);
                return P2P_UI_OK;
            }
            for (o = 0; o < ntokens; o++) {
                p.options[o] = tokens[o + 1];
            }
            return commands[i].fun(&p);
        }
    }

    VERBOSE(p.sp, CLIENT, "\n %s command unknown\n\n", tokens[0]);

    return P2P_UI_OK;
}
