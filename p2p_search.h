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

#include "p2p_common.h"
#include "p2p_options.h"
#include "p2p_msg.h"
#include "p2p_addr.h"
#include "p2p_file.h"
#include "p2p_do_msg.h"


#define P2P_DATA_ERROR 0
#define P2P_DATA_OK 200
#define MAX_DATA_SIZE 65527

int p2p_add_search (search_list *pliste, int id, char file_name[30]);

void p2p_list_search(server_params *sp);

int p2p_get_owner_file(search_list liste, int search_id, int reply_id, char** file_name, p2p_addr * owner);

int p2p_insert_reply (search_list *pliste, int id, p2p_addr file_owner, int taille_fichier);

int p2p_list_results(server_params *sp, int id);



#endif	/* P2P_SEARCH_H */

