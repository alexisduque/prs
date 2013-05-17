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


// Insertion d'une nouvelle recherche dans la structure

int p2p_add_search(search_list *pliste, int id, char file_name[30]) {

    search_result *newelem;
    search_list liste;
    // On déréférence le pointeur
    liste = *pliste;

    // Création de la nouvelle entrée
    newelem = (search_result *) malloc(sizeof (search_result));
    if (newelem == 0) {
        perror("p2p_insert_new_search : Memory FULL");
        return P2P_ERROR;
    }

    // Initialisation
    newelem->search_id = id;
    newelem->nb_reply = 0;
    strcpy(newelem->file_name, file_name);
    newelem->list_owners = NULL;

    // Ajout a la liste
    newelem->next = liste;
    liste = newelem;

    *pliste = liste;
    return (P2P_OK);
}


// Affichage de la liste des résultats

void p2p_list_search(server_params *sp) {
    struct search_result *visitor;

    VERBOSE(sp, CLIENT, "\nResearch List : :\n");
    VERBOSE(sp, CLIENT, "   ID : File's name [Nb rep]\n");

    // On fait pointer visitor sur le début de la liste
    visitor = sp->p2pSearchList;

    // On teste si des recherches ont déjà été faites
    if (visitor == NULL) {
        VERBOSE(sp, CLIENT, "   !! No research done for the moment !\n");
    }

    // On parcourt la liste
    while (visitor != NULL) {
        VERBOSE(sp, CLIENT, "   %d : %s [%d]\n", visitor->search_id, visitor->file_name, visitor->nb_reply);
        // On passe ensuite à la recherche suivante
        visitor = visitor->next;
    }

    // Fin
    VERBOSE(sp, CLIENT, "\n");
}

// Récupération des infos sur un fichier

int p2p_get_owner_file(search_list liste, int search_id, int reply_id, char** file_name, p2p_addr * owner) {

    search_result *visitor;
    search_quidonc *quidonc;
    visitor = liste;

    // On parcourt la liste
    while (visitor != NULL) {
        if (visitor->search_id == search_id) {
            // On récupère les infos sur le fichier
            *file_name = malloc((strlen(visitor->file_name)) + 1);
            memcpy(*file_name, visitor->file_name, strlen(visitor->file_name));
            (*file_name)[strlen(visitor->file_name)] = '\0';
            // On parcourt les réponses
            quidonc = visitor->list_owners;
            while (quidonc != NULL) {
                if (reply_id == quidonc->reply_id) {
                    // On récupère l'adresse du proprio
                    p2p_addr_copy(*owner, quidonc->file_owner);
                    //*owner = p2p_addr_duplicate(quidonc->file_owner);
                    return quidonc->filesize;
                }
                if (visitor->list_owners->next != NULL) {
                    quidonc = visitor->list_owners->next;
                } else {
                    quidonc = NULL;
                }
            }
        }
        visitor = visitor->next;
    }
    free(visitor);
    free(quidonc);
    // Rien trouvé
    return P2P_ERROR;
}


// Insertion d'une réponse

int p2p_insert_reply(search_list *pliste, int id, p2p_addr file_owner, int taille_fichier) {
    search_quidonc *newelem;
    search_list liste;
    liste = *pliste;

    search_result *visitor;
    search_quidonc *parcouror;
    int dejala = 0;

    visitor = liste;

    // On cherche la recherche correspondante
    while ((visitor != NULL) && (visitor->search_id != id)) {
        visitor = visitor->next;
    }

    // On regarde si la réponse n'est pas déja la
    parcouror = visitor->list_owners;
    while (parcouror != NULL) {
        if (p2p_addr_is_equal(parcouror->file_owner, file_owner)) {
            dejala = 1;
        }
        parcouror = parcouror->next;
    }

    // Si non, on l'ajoute
    if (dejala == 0) {
        newelem = (search_quidonc *) malloc(sizeof (search_quidonc));
        if (newelem == 0) perror("p2p_search_insert_reply : MEMORY FULL");
        newelem->reply_id = ++visitor->nb_reply;
        newelem->filesize = taille_fichier;
        newelem->file_owner = p2p_addr_duplicate(file_owner);
        newelem->next = visitor->list_owners;
        visitor->list_owners = newelem;

        *pliste = liste;

    }
    return P2P_OK;

}


// Affichage de la liste des résultats

int p2p_list_results(server_params *sp, int id) {

    struct search_result *visitor;
    search_quidonc *terminator;
    visitor = sp->p2pSearchList;

    // Initialisation de la chaine resultat
    VERBOSE(sp, CLIENT, "\nResearch results %d :\n", id);
    VERBOSE(sp, CLIENT, "   ID : Owner [Length]\n");

    while ((visitor != NULL) && (visitor->search_id != id)) {
        visitor = visitor->next;
    }
    if (visitor == NULL) {
        VERBOSE(sp, CLIENT, "   !! There isnt research for this ID!\n");
        VERBOSE(sp, CLIENT, "END_OF_TRANSMISSION\n");
        return P2P_OK;
    }


    // On fait pointer terminator sur le début de la liste
    terminator = visitor->list_owners;

    // On teste si des recherches ont déjà été faites
    if (terminator == NULL) {
        VERBOSE(sp, CLIENT, "   !! No answer for this research !\n");
    }

    // On parcourt la liste

    while (terminator != NULL) {
        VERBOSE(sp, CLIENT, "   %d : %s [%d o]\n", terminator->reply_id, p2p_addr_get_str(terminator->file_owner), terminator->filesize);
        // On passe ensuite à la recherche suivante
        terminator = terminator->next;
    }
    VERBOSE(sp, CLIENT, "\n");
    VERBOSE(sp, CLIENT, "END_OF_TRANSMISSION\n");
    return P2P_OK;
}

