/* 
 * File:   p2p_search.h
 * Author: alexis
 *
 * Created on 3 avril 2013, 14:45
 */


#ifndef P2P_SEARCH_H
#define	P2P_SEARCH_H

#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#include "common.h"
#include "options.h"
#include "p2p_msg.h"
#include "p2p_addr.h"
#include "p2p_file.h"
#include "p2p_do_msg.h"

#define MAX_TAILLE_FICHIER 50

typedef struct search_req {
	int id;
	int file_size;
	p2p_addr file_owner;
	struct search_req* next;
} search_req;

typedef struct search_result {
	int search_id;
	int nb_reply;
	char file_name[30];
	struct search_req* list_owners;
	struct search_result* next;

} search_result;
typedef search_result* p2pSearchList;


int p2p_search_insert_reply (search_req *pliste, int id, p2p_addr file_owner, int taille_fichier);


#endif	/* P2P_SEARCH_H */

