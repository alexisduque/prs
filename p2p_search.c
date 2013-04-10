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


p2p_search p2p_searchlist_create(){
	int i;
	p2p_search searchlist = (p2p_search)malloc(sizeof(struct search_list));
	searchlist->search_nb = 0;
	for (i=0; i<P2P_MAX_SEARCH_NB;i++)
	{
		searchlist->search_array[i]=NULL;
	}
	return searchlist;
}

search p2p_search_create(){
	int i;
	search s = (search)malloc(sizeof(struct search_t));
	s->reply_nb=0;
	s->file_name=NULL;
	for (i=0;i<P2P_MAX_RESULT_NB;i++)
	{
		s->reply_array[i]=NULL;
	}
	return s;
}

reply p2p_reply_create(){
	reply r =(reply)malloc(sizeof(struct reply_t));
	r->file_size=0;
	r->src=NULL;
	return r;
}