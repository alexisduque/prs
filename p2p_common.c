/* Copyright (c) 2004 by ARES Inria.  All Rights Reserved */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h>

#include "p2p_common.h"
#include "p2p_options.h"
/****************************************************/
/* 
   get_tokens: a peu pres similaire a strtok_r mais 
   ne modifie pas la chaine str
 */

/****************************************************/

int
get_tokens(const char *str, char tok[MAX_TOK][MAX_TOKLEN], int (*test_delim)(char)) {
    int i = 0;
    int token = 0;
    int index = 0;

    while (str[i] && token < MAX_TOK) {
        /* strip spaces */
        while (str[i] && test_delim(str[i])) {
            i++;
        }

        index = 0;
        while (str[i] && !test_delim(str[i]) && index < MAX_TOKLEN) {
            tok[token][index++] = str[i++];
        }
        tok[token++][index] = '\0';
    }
    return token;
}

/****************************************************/
/****************************************************/

#define MAX_VNSPRINTF_BUF_LENGTH 300

void
VERBOSE(server_params* sp, int level, char* fmt, ...) {
    FILE* out = stderr;
    int length;
    char buf[MAX_VNSPRINTF_BUF_LENGTH + 1];
    va_list ap;

    va_start(ap, fmt); // va_start sert a gerer la va_list:
    // list d'un nombre variable d'argument
    length = vsnprintf(buf, MAX_VNSPRINTF_BUF_LENGTH, fmt, ap);
    if (length >= MAX_VNSPRINTF_BUF_LENGTH)
        length = MAX_VNSPRINTF_BUF_LENGTH;
    va_end(ap);

    if (level == CLIENT) {
        if (buf[length - 1] == '\n') {
            buf[length - 1] = '\r';
            buf[length ] = '\n';
            buf[length + 1] = '\0';
            length++;
        }
        write(sp->client_ui, buf, length);
        return;
    }

    if (sp->verbosity >= level) {
        int i;
        fprintf(out, "%s", sp->server_name);
        for (i = 0; i < level; i++)
            fprintf(out, "  ");
        fprintf(out, "** ");
        fprintf(out, "%s", buf);
        return;
    }
}

/****************************************************/
/* 
   raw_print: affichage propre en hexadacimal et dans l'ordre reel
   des octets d'une portion de memoire 
 */

/****************************************************/

void raw_print(char *buf, int size) {
    int i;
    char *visitor;

    visitor = buf;
    for (i = 0; i < size; i++) {
        printf("%02x ", *visitor & 0xff);
        visitor++;
        if (i % 16 == 15) printf("\n");
    }
    printf("\n");
}

/****************************************************/

/* 
   creer_socket: creation d'une socket
 * type : type de la socket a creer.  
 * port : le numero de port desire. O pour un port aléatoire
 *******************************************************************/

int creer_socket(int type, int port) {
    int desc;
    int valid;
    int longueur = sizeof (struct sockaddr_in);
    struct sockaddr_in adresse;

    /* Creation de la socket */
    if ((desc = socket(AF_INET, type, 0)) == -1) {
        perror("Impossible to create the socket");
        return -1;
    }

    valid = 1;
    if (setsockopt(desc, SOL_SOCKET, SO_REUSEADDR, (void*) &valid, sizeof (valid)) < 0) {
        perror("Could'nt setsockopt");
        close(desc);
        return -1;
    }

    /* Preparation de l'adresse d'attachement */
    adresse.sin_family = AF_INET;
    /* Conversion (representation interne) -> (reseau) avec htonl et htons */
    adresse.sin_addr.s_addr = htonl(INADDR_ANY);
    adresse.sin_port = htons(port);

    /* Demande d'attachement de la socket */
    if (bind(desc, (struct sockaddr*) &adresse, longueur) == -1) {
        perror(" Socket attachement failed");
        close(desc);
        return -1;
    }

    return desc;
}

/* max :  retourne la valeur max de 2 entiers, -1 si ils sont egaux */

int max(int a, int b) {

    if (a < b) {

        return b;

    } else if (a > b) {

        return a;

    } else return -1;

}