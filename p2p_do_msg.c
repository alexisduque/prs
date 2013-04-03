/* 
 * File:   p2p_do_msg.c
 * Author: alexis
 *
 * Created on 27 mars 2013, 08:48
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

//Envoi du JOIN REQ
int p2p_send_join_req (server_params *sp, p2p_addr destinataire) {
    
  printf("\n!**************************************************************!\n");
  printf("              FUNCTION SEND JOIN REQ\n");
  printf("!**************************************************************!\n");
	
 //création des messages à envoyer
  p2p_msg join_msg = p2p_msg_create();
  p2p_msg ack_msg = p2p_msg_create();
  
  //on remplit le message avec une longueur nulle
  if ( p2p_msg_init(join_msg, P2P_MSG_JOIN_REQ, P2P_MSG_TTL_ONE_HOP, sp->p2pMyId, destinataire) != P2P_OK ) 
    return(P2P_ERROR);
  p2p_msg_set_length(join_msg, 0);
  
  // on envoi le message
  int socket = p2p_tcp_socket_create(sp, destinataire);
  if ( p2p_tcp_msg_sendfd(sp, join_msg, socket) != P2P_OK )
    return (P2P_ERROR);
    
  //réception du message d'acquittement
  if (p2p_tcp_msg_recvfd(sp, ack_msg, socket) != P2P_OK) {
  	return (P2P_ERROR);
  }
  //on peut fermer la socket
  p2p_tcp_socket_close(sp, socket);
  
  //on traite le message d'acquittement
  if (p2p_do_join_ack(sp, ack_msg) != P2P_OK) {
  	return P2P_ERROR;
  }
  
  //on libère la mémoire
  p2p_msg_delete(join_msg);
  p2p_msg_delete(ack_msg);
  
  return(P2P_OK);
}

//Traitement du JOIN REQ = Envoi du JOIN_ACK

int p2p_do_join_req(server_params *sp, p2p_msg join_req, int socket){
    
	printf("\n!************************************************************!\n");
	printf("              FUNCTION DO JOIN REQ\n");
	printf("!************************************************************!\n");
	p2p_msg join_ack = p2p_msg_create();

	//On remplit l'entête du message
	p2p_msg_init(join_ack, P2P_MSG_JOIN_ACK, P2P_MSG_TTL_ONE_HOP, sp->p2pMyId, p2p_msg_get_src(join_req));
	
	//On remplit + init du playload
        
	char payload[2*P2P_ADDR_SIZE];	
	
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

	//Envoi du message JOIN ACK
	if (p2p_tcp_msg_sendfd(sp, join_ack, socket) == P2P_OK){
		printf("Message JOIN_ACK envoyé ! \n\n");
	}
	
 	return P2P_OK;
}

// Reception du JOIN ACK

int p2p_do_join_ack (server_params *sp, p2p_msg ack_msg) {
    
	printf("\n!************************************************************!\n");
        printf("              FUNCTION DO JOIN ACK\n");
        printf("!**************************************************************!\n");
        
	unsigned char *ack_payload=p2p_get_payload(ack_msg);
	
	// on récupère les adresses stockées dans le payload du message JOIN_ACK
	p2p_addr left = p2p_addr_create();
	memcpy(left, ack_payload, 8);
	p2p_addr right = p2p_addr_create();
	memcpy(right, &ack_payload[8], 8);
	
	//préparation des messages link update
	p2p_msg link_msg = p2p_msg_create();
	char link_payload[12];
	
	//pour mon nouveau gauche   
	if (p2p_msg_init(link_msg, P2P_MSG_LINK_UPDATE, P2P_MSG_TTL_ONE_HOP, 
		sp->p2pMyId, left) != P2P_OK) return P2P_ERROR;
	memcpy(link_payload, sp->p2pMyId, 8);
	unsigned long int type = htonl(0x0000FFFF); // adresse du lien droit 
	memcpy(&link_payload[8], &type, 4);
	if (p2p_msg_init_payload(link_msg, 12, link_payload) != P2P_OK) 
		return P2P_ERROR;
	//envoi du message
	if ( p2p_addr_is_equal(sp->p2pMyId, p2p_msg_get_dst(link_msg))==0 ) {
		if (p2p_tcp_msg_send(sp, link_msg) != P2P_OK) {
			return P2P_ERROR;
		}
	}
                        
	//pour son ancien droit   
	if (p2p_msg_init(link_msg, P2P_MSG_LINK_UPDATE, P2P_MSG_TTL_ONE_HOP, 
		sp->p2pMyId, right) != P2P_OK) return P2P_ERROR;
	memcpy(link_payload, sp->right_neighbor, 8);
	type = htonl(0xFFFF0000);//adresse du lien gauche
	memcpy(&link_payload[8], &type, 4);
	if (p2p_msg_init_payload(link_msg, 12, link_payload) != P2P_OK) 
		return P2P_ERROR;
	//envoi du message
	if ( p2p_addr_is_equal(sp->p2pMyId, p2p_msg_get_dst(link_msg))==0 ) {
		if (p2p_tcp_msg_send(sp, link_msg) != P2P_OK)
			return P2P_ERROR;
	}
	
	//pour mon ancien gauche   
	if (p2p_msg_init(link_msg, P2P_MSG_LINK_UPDATE, P2P_MSG_TTL_ONE_HOP, 
		sp->p2pMyId, sp->left_neighbor) != P2P_OK) return P2P_ERROR;
	memcpy(link_payload, right, 8);
	type = htonl(0x0000FFFF); // adresse du lien droit 
	memcpy(&link_payload[8], &type, 4);
	if (p2p_msg_init_payload(link_msg, 12, link_payload) != P2P_OK) 
		return P2P_ERROR;
	//envoi du message
	if ( p2p_addr_is_equal(sp->p2pMyId, p2p_msg_get_dst(link_msg))==0 ) {
		if (p2p_tcp_msg_send(sp, link_msg) != P2P_OK)
			return P2P_ERROR;
	} else {
		p2p_addr_delete(sp->right_neighbor);
		sp->right_neighbor=p2p_addr_duplicate(right);
	}
	
	//pour moi
	p2p_addr_delete(sp->left_neighbor);
	sp->left_neighbor  = left;
	
	//free
	p2p_addr_delete(right);
	p2p_msg_delete(link_msg);
	
  return(P2P_OK);
}

//Traitement du GET
void p2p_do_get() { 
    
}


//Traitement du LINK UPDATE
int p2p_do_link_update(server_params *sp, p2p_msg link_update_msg) { 
	
	p2p_addr new_addresse = p2p_addr_create();
	memcpy(new_addresse, p2p_get_payload(link_update_msg), 8);
	
	//Recuperation du type du voisin
	unsigned long int neighbor_type;
	memcpy(&neighbor_type,&(p2p_get_payload(link_update_msg)[8]), 4);
	neighbor_type=ntohl(neighbor_type);
	
	if (neighbor_type==0xFFFF0000) {
		//voisin gauche
		p2p_addr_copy(sp->left_neighbor, new_addresse);
		VERBOSE(sp,VMCTNT,"LEFT NEIGHBOR UPDATE\n\n");
	} else if (neighbor_type==0x0000FFFF) {
		// voisin droit	
		p2p_addr_copy(sp->right_neighbor, new_addresse);
		VERBOSE(sp,VMCTNT,"RIGHT NEIGHBOR UPDATE\n\n");
	} else {
		VERBOSE(sp,VMCTNT,"!! ERROR PARSING NEIGHBOR TYPE !!\n\n");
	}
	
	//vidage de la memoire
	p2p_addr_delete(new_addresse);
	
	return P2P_OK;

}

//Traitement du SEARCH
int p2p_do_search(server_params *sp, p2p_msg search_msg) {
    
    int name_size, file_size;
    char * file_name;
    char * buffer;
    p2p_addr src_adresse, dst_adresse;
    p2p_msg reply_message;

    printf("\n!************************************************************!\n");
    printf("              FUNCTION DO SEARCH\n");
    printf("!**************************************************************!\n");

    // On verifie que le mesg recu n'est pas le notre
    src_adresse = p2p_addr_create(0);
    memcpy(src_adresse, p2p_get_payload(search_msg), P2P_ADDR_SIZE);
    if (!p2p_addr_is_equal(src_adresse, sp->p2pMyId)){

            // On recupere le nom du fichier demande
            name_size = p2p_msg_get_length(search_msg) - P2P_ADDR_SIZE - P2P_HDR_BITFIELD_SIZE;
            file_name = (char *)malloc(name_size +1);
            memcpy(file_name,p2p_get_payload(search_msg) + P2P_ADDR_SIZE + P2P_HDR_BITFIELD_SIZE, name_size);
            file_name[name_size] = '\0';
            printf("Fichier recherche: %s\n",file_name);

            // On teste si le fichier est present    
            if (p2p_file_is_available(sp,file_name,&file_size)==P2P_OK) {

                    printf("Fichier existant !\n");
                    file_size = htonl(file_size);

                    // Creation du messge reply
                    reply_message = p2p_msg_create();
                    
                    // On recupere l'adresse de l'emetteur de la recherche
                    
                    dst_adresse = p2p_addr_create();
                    memcpy(dst_adresse,p2p_get_payload(search_msg),P2P_ADDR_SIZE);
                    p2p_msg_init(reply_message,P2P_MSG_REPLY,P2P_MSG_TTL_MAX,sp->p2pMyId,dst_adresse);
                    
                    // Creation du payload
                    buffer = (char *)malloc(P2P_HDR_BITFIELD_SIZE + P2P_INT_SIZE);
                    memcpy(buffer, p2p_get_payload(search_msg) + P2P_ADDR_SIZE, P2P_HDR_BITFIELD_SIZE);
                    memcpy(buffer + P2P_HDR_BITFIELD_SIZE, &file_size, P2P_INT_SIZE);
                    p2p_msg_init_payload(reply_message, P2P_HDR_BITFIELD_SIZE + P2P_INT_SIZE, buffer);

                    // Envoi du message
                    p2p_udp_msg_send(sp,reply_message);
                    printf("Reponse a l'emmeteur de la recherche\n");
                    
                    // Ne pas oublier de liberer la mémoire !
                    /*free(buffer);
                    p2p_addr_delete(dst);
                    p2p_msg_delete(reply);*/

            } else {
                    printf("Fichier inconnu !\n");
                    if(file_size != 403) VERBOSE(sp,VMCTNT,"Erreur de type %d\n",file_size);
            }  
           
            //On fait suivre le message aux autres noeud
            p2p_udp_msg_rebroadcast (sp, search_msg);

            // Ne pas oublier de liberer la mémoire !
            free(file_name);

    } else {
        
        VERBOSE(sp,VMCTNT,"!! I'VE SEND THIS SEARCH_MESSAGE !!\n\n");
       
    }
    
    // Ne pas oublier de liberer la mémoire !
    p2p_addr_delete(src_adresse);
    
    return P2P_OK;
 
}

//Traitement du REPLY  
int p2p_do_reply(server_params *sp, p2p_msg reply_msg) {
    
        printf("\n!************************************************************!\n");
        printf("              FUNCTION DO REPLY\n");
        printf("!**************************************************************!\n");

        int file_size, search_id;
        p2p_addr file_owner;

        //Recupératiion de la taille de fichier
        memcpy(&file_size, p2p_get_payload(reply_msg) + P2P_HDR_BITFIELD_SIZE, P2P_INT_SIZE);
        file_size=ntohl(file_size);
        
        // On va chercher le nom du fichier correspondant a la recherche
        memcpy(&search_id, p2p_get_payload(reply_msg), P2P_INT_SIZE);
        file_owner = p2p_addr_duplicate(p2p_msg_get_src(reply_msg));
        search_id = ntohl(search_id);
        printf("ID de la recherche : %d\n",search_id);
        printf("Taille du fichier : %d\n",file_size);

        /* TODO : ajouter l'id et ficheir a la liste des recherche du noeud (sp->p2p_search_list), ... */
        
        // Clean
        p2p_addr_delete(file_owner);

        return P2P_OK;
}

//TRAITEMENT DU NEIGHBORS_REQ
int p2p_do_neighbors_req(server_params *sp, p2p_msg neighbors_req_msg) {
    
    return P2P_OK;
    
}

//TRAITEMENT DU NEIGHBORS_LIST
int p2p_do_neighbors_list(server_params *sp, p2p_msg neighbors_list_msg) {
    
    return P2P_OK;
    
}
