/* 
 * File:   p2p_search.h
 * Author: alexis
 *
 * Created on 3 avril 2013, 14:45
 */

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
#include <inttypes.h>


#include "p2p_common.h"
#include "p2p_addr.h"
#include "p2p_msg.h"
#include "p2p_options.h"
#include "p2p_do_msg.h"
#include "p2p_file.h"

int p2p_search_insert_reply (search_req *pliste, int id, p2p_addr file_owner, int taille_fichier)
{
	search_req *newelem;  
	p2pSearchList liste;
	liste=*pliste;

	search_result *visitor; 
	search_req *parcour;
	int HERE = 0;

	visitor=liste;

	// On cherche la recherche correspondante
	while((visitor!=NULL) && (visitor->search_id != id))
	{
		visitor=visitor->next;
	}

	// On regarde si la rÃ©ponse n'est pas dÃ©ja la
	parcour = visitor->list_owners;
	while(parcour!=NULL) {
		if(p2p_addr_is_equal(parcour->file_owner,file_owner)){
			HERE = 1;
			printf("Already here \n");
		}
		parcour=parcour->next;
	}

	// Si non, on l'ajoute
	if(HERE==0){
		newelem=(search_req *)malloc(sizeof(search_req));
		if (newelem==0) perror("p2p_search_insert_reply : plus de place mémoire");
		newelem->reply_id = ++visitor->nb_reply;
		newelem->file_size = taille_fichier;
		newelem->file_owner = p2p_addr_duplicate(file_owner);
		newelem->next=visitor->list_owners;
		visitor->list_owners=newelem;
		*pliste=liste;

	}
	return P2P_OK;

}


// Put usefull SEARCH function here