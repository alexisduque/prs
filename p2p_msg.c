/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_msg
   PURPOSE
     
   NOTES
     
   HISTORY
     Revision 1.1  2005/02/21 18:34:32  afraboul
     ajout des sources qui seront distribuees aux etudiants

     Revision 1.11  2004/12/26 16:15:15  afraboul
 ***/

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

#include "p2p_common.h"
#include "p2p_addr.h"
#include "p2p_msg.h"
#include "p2p_options.h"


#define MIN(a,b)    (((a)<(b))?(a):(b))

//Definition de la structure de l'entete d'un message P2P

struct p2p_msg_hdr_struct {
    unsigned char version_type; /* Les champs Version et CmdType sont
				   codes tous les deux sur 1 octet */
    unsigned char ttl; /* Le champ  TTTL*/
    unsigned short length; /* Le champ longueur */
    p2p_addr src; /* Le champ adresse source */
    p2p_addr dst; /* Le champ adresse destination */
};

//Definition du type p2p_msg_hdr qui est un pointeur sur la structure
//p2p_msg_hdr_struct 
typedef struct p2p_msg_hdr_struct p2p_msg_hdr;

//Definition de la structure d'un message P2P

struct p2p_msg_struct {
    p2p_msg_hdr hdr; /* Un entete */
    unsigned char *payload; /* Un payload qui un pointeur sur une
				   zone memoire de unsigned char */
};

unsigned char* p2p_get_payload(p2p_msg msg) {
    return msg->payload;
}

p2p_msg
p2p_msg_create() {
    p2p_msg msg;

    if ((msg = (p2p_msg) malloc(sizeof (struct p2p_msg_struct))) == NULL)
        return NULL;

    p2p_msg_set_version(msg, P2P_VERSION);
    p2p_msg_set_type(msg, P2P_MSG_UNDEFINED);
    p2p_msg_set_ttl(msg, P2P_MSG_TTL_MAX);
    /*  p2p_msg_set_length  (msg,payload_size);    */
    assert(msg->hdr.src = p2p_addr_create());
    assert(msg->hdr.dst = p2p_addr_create());
    msg->payload = NULL;

    return msg;
} /* p2p_msg_create */

void
p2p_msg_delete(p2p_msg msg) {
    p2p_addr_delete(msg->hdr.src);
    p2p_addr_delete(msg->hdr.dst);
    if (msg->payload != NULL)
        free(msg->payload);
    free(msg);
} /* p2p_msg_free */

p2p_msg
p2p_msg_duplicate(const p2p_msg msg) {
    p2p_msg msgDuplicata;

    if ((msgDuplicata = p2p_msg_create()) == NULL)
        return NULL;

    p2p_msg_set_version(msgDuplicata, p2p_msg_get_version(msg));
    p2p_msg_set_type(msgDuplicata, p2p_msg_get_type(msg));
    /* p2p_msg_set_ttl    (msgDuplicata,p2p_msg_get_ttl    (msg)); */

    msgDuplicata->hdr.src = p2p_addr_duplicate(msg->hdr.src);
    msgDuplicata->hdr.dst = p2p_addr_duplicate(msg->hdr.dst);

    /* assert(msgDuplicata->payload = (char*)malloc(sizeof(char)*p2p_msg_get_length(msg))); */
    /* memcpy(msgDuplicata->payload, msg->payload, p2p_msg_get_length(msg)); */
    return msgDuplicata;
} /* p2p_msg_duplicate */

int
p2p_msg_init(p2p_msg msg,
        unsigned int type, unsigned int ttl,
        const p2p_addr src, const p2p_addr dst) {
    p2p_msg_set_version(msg, P2P_VERSION);
    p2p_msg_set_type(msg, type);
    p2p_msg_set_ttl(msg, ttl);
    p2p_addr_copy(msg->hdr.src, src);
    p2p_addr_copy(msg->hdr.dst, dst);

    return P2P_OK;
} /* p2p_msg_init */

int
p2p_msg_init_payload(p2p_msg msg,
        const unsigned short int length,
        unsigned char* payload) {
    p2p_msg_set_length(msg, length);
    free(msg->payload);
    assert(msg->payload = (unsigned char*) malloc(sizeof (unsigned char)*length));
    memcpy(msg->payload, payload, length);
    return P2P_OK;
} /* p2p_msg_init_payload */

/*********************************************************/
/*               Fonctions sur les headers               */
/*********************************************************/

/********************/
/* VERSION | TYPE   */

/********************/
unsigned char
p2p_msg_get_version(const p2p_msg msg) {
    return (msg->hdr.version_type & 0xF0) >> 4;
}

void
p2p_msg_set_version(p2p_msg msg, unsigned char version) {
    msg->hdr.version_type = ((version & 0x0F) << 4) | p2p_msg_get_type(msg);
}

unsigned char
p2p_msg_get_type(const p2p_msg msg) {
    return msg->hdr.version_type & 0x0F;
}

void
p2p_msg_set_type(p2p_msg msg, unsigned char type) {
    msg->hdr.version_type = (p2p_msg_get_version(msg) << 4) | (type & 0x0F);
}

//renvoie le TTL de msg

unsigned char p2p_msg_get_ttl(const p2p_msg msg) {
    return msg->hdr.ttl;
}

//initialise le TTL de msg a ttl

void p2p_msg_set_ttl(p2p_msg msg, unsigned char ttl) {
    msg->hdr.ttl = ttl;
}

//renvoie la longueur de l'entete de msg

unsigned short p2p_msg_get_length(const p2p_msg msg) {
    return (msg->hdr.length);
}

//initialise la longueur de l'entete de msg a length

void p2p_msg_set_length(p2p_msg msg, unsigned short length) {
    msg->hdr.length = htons(length);
}

//renvoie l'adresse source de msg

p2p_addr p2p_msg_get_src(const p2p_msg msg) {
    return msg->hdr.src;
}

//initialise l'adresse source de msg a src

void p2p_msg_set_src(p2p_msg msg, p2p_addr src) {
    p2p_addr_copy(msg->hdr.src, src);
}

//renvoie l'adresse destination de msg

p2p_addr p2p_msg_get_dst(const p2p_msg msg) {
    return msg->hdr.dst;

}

//initialise l'adrersse destination de msg a dst

void p2p_msg_set_dst(p2p_msg msg, p2p_addr dst) {
    p2p_addr_copy(msg->hdr.dst, dst);
}

int p2p_msg_display(p2p_msg message) {
    printf("\n-----------------------------\n");
    printf("Message Content : \n");
    printf("Version :%d ", p2p_msg_get_version(message));
    printf("Type : %d \n", p2p_msg_get_type(message));
    printf("TTL :%d ", p2p_msg_get_ttl(message));
    printf("Length : %d \n", p2p_msg_get_length(message));
    printf("Source address : %s \n", p2p_addr_get_str(p2p_msg_get_src(message)));
    printf("Destination address : %s \n", p2p_addr_get_str(p2p_msg_get_dst(message)));
    //printf("Payload : %s \n\n", p2p_get_payload(message));
    printf("--------------------------------\n\n");
    //raw_print((char*)p2p_get_payload(message),p2p_msg_get_length(message) );
    return P2P_OK;
}


/*********************************************************/
/*               Fonctions sur les debugs                */
/*********************************************************/


// ecrit le message msg dans le fichier fd.

void p2p_msg_dumpfile(const p2p_msg msg, const FILE* fd, int print_payload) {
    
    fprintf((FILE*) fd, "|%7d", p2p_msg_get_version(msg));
    fprintf((FILE*) fd, "|%8d", p2p_msg_get_type(msg));
    fprintf((FILE*) fd, "|%18d|\n", p2p_msg_get_ttl(msg));
    fprintf((FILE*) fd, "|%35d|\n", p2p_msg_get_length(msg));
    p2p_addr_dumpfile(p2p_msg_get_src(msg), fd);
    p2p_addr_dumpfile(p2p_msg_get_dst(msg), fd);

    if (print_payload != 0)
        fprintf((FILE*) fd, "|%s|\n", msg->payload);
}


//ecrit l'entete du message msg en hexa. 

int p2p_msg_hexdumpheader(const p2p_msg msg, const FILE* fs) {
    unsigned char *message;
    printf("MSG:: ");
    message = (unsigned char*) malloc(P2P_ADDR_SIZE);
    memcpy(&message[0], &(msg->hdr.version_type), 1);
    fprintf((FILE*) fs, "Ox%.2X:", *message);
    memcpy(&message[0], &(msg->hdr.ttl), 1);
    fprintf((FILE*) fs, "%.2X:", *message);
    memcpy(&message[0], &(msg->hdr.length), 2);
    int i;
    for (i = 0; i < 2; i++) {
        fprintf((FILE*) fs, "%.2X:", message[i]);
    }
    memcpy(&message[0], (msg->hdr.src), P2P_ADDR_SIZE);
    for (i = 0; i < P2P_ADDR_SIZE; i++) {
        fprintf((FILE*) fs, "%.2X:", message[i]);
    }
    memcpy(&message[0], (msg->hdr.dst), P2P_ADDR_SIZE);
    for (i = 0; i < P2P_ADDR_SIZE; i++) {
        fprintf((FILE*) fs, "%.2X:", message[i]);
    }

    fprintf((FILE*) fs, "\n");
    free(message);
    return P2P_OK;
}

/*** Méthode socket pour TCP ***/
//Crée une socket TCP vers le noeud P2P dst.

int p2p_tcp_socket_create(server_params* sp, p2p_addr dst) {

    // Definition des variables locales
    struct sockaddr_in adresse;
    int port, desc;
    int lg = sizeof (adresse);
    struct hostent *hp;
    char * ip;

    // Creation et attachement de la socket sur un port quelconque 
    port = 0;
    if ((desc = creer_socket(SOCK_STREAM, port)) == P2P_ERROR) {
        perror("tcp_socket_create : Error creating the socket\n");
        return P2P_ERROR;
    }

    // Recherche de l'adresse internet du serveur 
    ip = p2p_addr_get_ip_str(dst);
    if ((hp = gethostbyname(ip)) == NULL) {
        printf("tcp_socket_create : Computer %s unknown\n", ip);
        return P2P_ERROR;
    }

    // Preparation de l'adresse destinatrice 
    port = p2p_addr_get_tcp_port(dst);
    adresse.sin_family = AF_INET;
    adresse.sin_port = htons(port);
    memcpy(&(adresse.sin_addr.s_addr), hp->h_addr, hp->h_length);

    // Demande de connexion au serveur 
    if (connect(desc, (struct sockaddr*) &adresse, lg) == -1) {
        perror("tcp_socket_create : Error connecting to server\n");
        return P2P_ERROR;
    }
    VERBOSE(sp, VPROTO, "SOCKET CREATED\n");
    // On renvoie le descripteur de socket
    return desc;

}

//Fermeture de la socket donnée par le descripteur fd

int p2p_tcp_socket_close(server_params* sp, int fd) {
    if (close(fd) == -1) {
        perror("tcp_socket_close : Error closing TCP socket\n");
        VERBOSE(sp, CLIENT, "tcp_socket_close : Error closing TCP socket\n");
        VERBOSE(sp, CLIENT, "END_OF_TRANSMISSION\n");
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VSYSCL, "TCP socket disconnected %d\n", fd);
        return P2P_OK;
    }

}

//Envoi du message msg via la socket tcp fd

int p2p_tcp_msg_sendfd(server_params* sp, p2p_msg msg, int fd) {
    VERBOSE(sp, VPROTO, "TRY TO SEND TCP msg ...\n");
    //On verifie que l'on essaie pas d'envoyer un message à nous même
    if (p2p_addr_is_equal(sp->p2pMyId, p2p_msg_get_dst(msg)) != 0) {
        VERBOSE(sp, VPROTO, "ERROR : SENDING TCP msg YOURSELF\n");
        return P2P_ERROR;
    }

    //On remplit le buffer toWrite, avec les infos contenues dans le msg en paramètre, selon le format du CDC

    //allocation de la mémoire pour le buffer
    unsigned short int message_size = ntohs(p2p_msg_get_length(msg));
    unsigned char* toWrite = (unsigned char*) malloc(P2P_HDR_SIZE + message_size);

    // ajout du champs "version" au buffer
    memcpy(toWrite, &(msg->hdr.version_type), P2P_HDR_BITFIELD_SIZE);
    // ajout du champs "Adresse Source"
    memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE], p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    //ajout du champs "Adresse Dest"
    memcpy(&toWrite[P2P_HDR_BITFIELD_SIZE + P2P_ADDR_SIZE], p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    // Si contenu du message non vide, ajout du champs "Message"
    if (message_size > 0) {
        memcpy(&toWrite[P2P_HDR_SIZE], p2p_get_payload(msg), message_size);
    }


    // On envoie via le socket tcp fd, le message contenu dans le buffer, sinon message d'erreur
    if (write(fd, toWrite, P2P_HDR_SIZE + message_size) != (P2P_HDR_SIZE + message_size)) {
        VERBOSE(sp, VPROTO, "Unable to send msg to the socket\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VPROTO, "TCP MSG SUCCESFULL SEND\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        return P2P_OK;
    }



}

// Recoie dans msg un message depuis la socket fd

int p2p_tcp_msg_recvfd(server_params* sp, p2p_msg msg, int fd) {
    int tot = 0;
    int i = 0;
    unsigned short int length = 0;
    unsigned char* data_payload = NULL;
    read(fd, msg, P2P_HDR_BITFIELD_SIZE);
    read(fd, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    read(fd, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    length = p2p_msg_get_length(msg);
    length = ntohs(length);
    data_payload = (unsigned char *) malloc (sizeof(unsigned char) * P2P_MSG_MAX_SIZE);
    memset (data_payload, 0, P2P_MSG_MAX_SIZE * sizeof (char));
    if (length > 0) {
        while (tot < length)
        {
            i = read (fd, data_payload + tot, length - tot);
            tot += i;
        }
        p2p_msg_init_payload(msg, length, data_payload);
    }
    
    //read(fd, data_payload, length);

    p2p_msg_display(msg);
    free(data_payload);
    VERBOSE(sp, VMCTNT, "RECV MSG OK\n");
    return P2P_OK;
}

// Envoi du message msg via tcp au noeud destination indiquée dans le champ dst de msg

int p2p_tcp_msg_send(server_params* sp, const p2p_msg msg) {

    int socketTMP = p2p_tcp_socket_create(sp, p2p_msg_get_dst(msg));
    if (socketTMP == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "TCP socket creation impossible \n");
        //printf("Impossible de créer la socket TCP \n");
        return (P2P_ERROR);
    }

    if (p2p_tcp_msg_sendfd(sp, msg, socketTMP) != P2P_OK) {
        return (P2P_ERROR);
    }
    p2p_tcp_socket_close(sp, socketTMP);
    VERBOSE(sp, VPROTO, "SEND msg DONE\n");
    return P2P_OK;
}


/*** Communication via UDP ***/
//Cree une socket UDP vers le noeud P2P dst.

int p2p_udp_socket_create(server_params* sp, p2p_addr dst) {
    int sock_udp;
    struct sockaddr_in adresse;
    socklen_t longueur = sizeof (struct sockaddr_in);
    int port = 0;

    if ((sock_udp = creer_socket(SOCK_DGRAM, port)) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "UDP socket creation impossible \n");
        return P2P_ERROR;
    }

    adresse.sin_family = AF_INET;
    inet_aton(p2p_addr_get_ip_str(dst), &adresse.sin_addr);
    adresse.sin_port = htons(p2p_addr_get_udp_port(dst));

    if (connect(sock_udp, (struct sockaddr*) &adresse, longueur) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to connect the socket \n");
        close(sock_udp);
        return P2P_ERROR;
    }
    VERBOSE(sp, VSYSCL, "SOCKET UDP created \n");
    return sock_udp;
}

//Ferme la socket donnée par le descripteur fd

int p2p_udp_socket_close(server_params* sp, int fd) {
    close(fd);
    VERBOSE(sp, VSYSCL, "UDP socket disconnected %d\n", fd);
    return P2P_OK;
}

//Envoie le message msg via la socket UDP fd

int p2p_udp_msg_sendfd(server_params* sp, p2p_msg msg, int fd) {
    VERBOSE(sp, VPROTO, "TRY TO SEND UDP MSG ...\n");
    int message_size = p2p_msg_get_length(msg);
    message_size = ntohs(message_size);
    char toWrite [P2P_HDR_SIZE + sizeof (char)*message_size];

    memcpy(toWrite, msg, P2P_HDR_BITFIELD_SIZE);
    memcpy(&toWrite[4], p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[12], p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[20], p2p_get_payload(msg), message_size);

    if (write(fd, toWrite, P2P_HDR_SIZE + message_size) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to send msg\n");
        //   free(toWrite);
        return P2P_ERROR;
    }
    p2p_msg_display(msg);
    //free(toWrite);
    VERBOSE(sp, VPROTO, "UDP MSG SEND\n\n");
    return P2P_OK;

}

//recoie dans msg un message depuis la socket UDP fd

int p2p_udp_msg_recvfd(server_params* sp, p2p_msg msg, int fd) {
    VERBOSE(sp, VMCTNT, "TRY TO RECEIVE MSG ...\n");

    //Declaration du buffer
    char data[200];
    //free(msg->payload);
    // Allocation de la mémoire pour le payload
    msg->payload = (unsigned char*) malloc(sizeof (unsigned char)*200);

    //Lecture de la soccket et remplissage du buffer
    recv(fd, &data, sizeof (data), 0);

    //Remplissage des champs du message à partir du buffert
    memcpy(&(msg->hdr), data, P2P_HDR_BITFIELD_SIZE);
    memcpy(msg->hdr.src, &data[4], P2P_ADDR_SIZE);
    memcpy(msg->hdr.dst, &data[12], P2P_ADDR_SIZE);
    memcpy(msg->payload, &data[20], sizeof (data) - 20);
    p2p_msg_display(msg);
    VERBOSE(sp, VMCTNT, "RECVD MSG OK\n");

    return P2P_OK;

}

//envoie le message msg via udp au noeud destination indique dans le
//champ dst de msg

int p2p_udp_msg_send(server_params* sp, p2p_msg msg) {
    int sock;
    if ((sock = p2p_udp_socket_create(sp, msg->hdr.dst)) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to send UDP_MSG\n");
        return P2P_ERROR;
    };

    p2p_udp_msg_sendfd(sp, msg, sock);
    p2p_udp_socket_close(sp, sock);
    VERBOSE(sp, VSYSCL, "Send MSG done \n");
    return P2P_OK;
}

//rebroadcast le message msg

int p2p_udp_msg_rebroadcast(server_params* sp, p2p_msg msg) {

    printf("----------------------Rebroadcast-----------------------------\n");

    int fd;
    p2p_addr src = p2p_msg_get_src(msg);
    printf("Message Source : %s\n", p2p_addr_get_str(src));
    printf("Right ngb : %s\n", p2p_addr_get_str(sp->p2p_neighbors.right_neighbor));
    printf("Left ngb : %s\n", p2p_addr_get_str(sp->p2p_neighbors.left_neighbor));

    p2p_addr initiator = p2p_addr_create();
    memcpy(initiator, p2p_get_payload(msg), P2P_ADDR_SIZE);


    printf("initiator = %s\n\n", p2p_addr_get_str(initiator));
    printf("equal(me, right)  = %d\n", p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.right_neighbor));
    printf("equal(src, right)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor));
    printf("equal(init, right)  = %d\n", p2p_addr_is_equal(initiator, sp->p2p_neighbors.right_neighbor));
    printf("equal(me, left)  = %d\n", p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.left_neighbor));
    printf("equal(src, left)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor));
    printf("equal(init, left)  = %d\n\n", p2p_addr_is_equal(initiator, sp->p2p_neighbors.left_neighbor));

    if ((p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.right_neighbor) || p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor) || p2p_addr_is_equal(initiator, sp->p2p_neighbors.right_neighbor)) != 1) {

        p2p_msg_set_src(msg, sp->p2pMyId);
        fd = p2p_udp_socket_create(sp, sp->p2p_neighbors.right_neighbor);
        printf("Send to right\n");
        printf("Equal(src, right)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor));

        if (p2p_udp_msg_sendfd(sp, msg, fd) != P2P_OK) {
            printf("UDP_rebroadcast : sending FAILED\n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.right_neighbor));
        }

        p2p_udp_socket_close(sp, fd);

    }

    if ((p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(initiator, sp->p2p_neighbors.left_neighbor)) != 1) {

        p2p_msg_set_src(msg, sp->p2pMyId);
        printf("Send to left\n");
        printf("Equal(src, left)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor));
        fd = p2p_udp_socket_create(sp, sp->p2p_neighbors.left_neighbor);

        if (p2p_udp_msg_sendfd(sp, msg, fd) != P2P_OK) {
            printf("UDP rebroadcast : Sending FAILED \n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.left_neighbor));
        }

        p2p_udp_socket_close(sp, fd);

    }
    p2p_addr_delete(initiator);
    //p2p_addr_delete(src);

    return P2P_OK;

}

