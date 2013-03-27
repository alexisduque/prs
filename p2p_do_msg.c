/* 
 * File:   p2p_do_msg.c
 * Author: alexis
 *
 * Created on 27 mars 2013, 08:48
 */


#include "p2p_do_msg.h"
#include "p2p_options.h"


//Traitement du JOIN

int p2p_do_join_req(server_params *sp, p2p_msg join_req, int socket){
    
	printf("\n!************************************************************!\n");
	printf("              FUNCTION DO JOIN REQ\n");
	printf("!**************************************************************!\n");
	p2p_msg join_ack = p2p_msg_create();

	//On remplit l'entête du message
	p2p_msg_init(join_ack, P2P_MSG_JOIN_ACK, P2P_MSG_TTL_ONE_HOP, sp->p2pMyId, p2p_msg_get_src(join_req));
	
	//On remplit + init du playload
        
	unsigned char payload[2*P2P_ADDR_SIZE];	
	
	memcpy(payload, sp->p2pMyId, P2P_ADDR_SIZE);
	if (p2p_addr_is_equal(sp->p2pMyId, sp->right_neighbor)){
		memcpy(&payload[P2P_ADDR_SIZE], sp->p2pMyId, P2P_ADDR_SIZE);		
	} 
	else {
		memcpy(&payload[P2P_ADDR_SIZE], sp->right_neighbor, P2P_ADDR_SIZE);
	}
	
	
	p2p_msg_init_payload(join_ack, 2*P2P_ADDR_SIZE, payload);
	printf("\nMessage JOIN_ACK rempli : \n");
	p2p_msg_display(join_ack);
	
	
	p2p_addr MyId = p2p_addr_create();
	p2p_addr right_neighbor = p2p_addr_create();
	
	memcpy(MyId, p2p_get_payload(join_ack), P2P_ADDR_SIZE);
	memcpy(right_neighbor, &(p2p_get_payload(join_ack))[P2P_ADDR_SIZE], P2P_ADDR_SIZE);
	
	
	printf("Voisin de gauche : %s \n", p2p_addr_get_str(MyId));
	printf("Voisin de droite %s \n", p2p_addr_get_str(right_neighbor));

	//Envoi du message
	if (p2p_tcp_msg_sendfd(sp, join_ack, socket) == P2P_OK){
		printf("\n\n Message JOIN_ACK envoyé ! \n\n");
	}
	
 	return P2P_OK;
}

//Traitement du GET
void p2p_do_get() { 
    
}


//Traitement dy LINK UPDATE
void p2p_do_link_update { 
    
}
