/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_addr
   PURPOSE
     abstract a p2p_addr
   NOTES
     
   HISTORY
 ***/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "p2p_common.h"
#include "p2p_addr.h"

struct p2p_addr_struct {
    struct in_addr ip; /* IP stored in network order */
    uint16_t tcp_port;
    uint16_t udp_port;
};

p2p_addr p2p_addr_create() {
    p2p_addr a;
    a = (p2p_addr) malloc(sizeof (struct p2p_addr_struct));
    p2p_addr_set_undefined(a);
    return a;
}

void p2p_addr_delete(p2p_addr addr) {
    free(addr);
}

void p2p_addr_copy(p2p_addr dst, p2p_addr src) {
    memcpy(dst, src, sizeof (struct p2p_addr_struct));
}

p2p_addr p2p_addr_duplicate(p2p_addr orig) {
    p2p_addr cpy;
    assert(cpy = p2p_addr_create());
    p2p_addr_copy(cpy, orig);
    return cpy;
}

int p2p_addr_is_equal(const p2p_addr addr1, const p2p_addr addr2) {
    return ((addr1->ip.s_addr == addr2->ip.s_addr) &&
            (addr1->tcp_port == addr2->tcp_port) &&
            (addr1->udp_port == addr2->udp_port));
}

int p2p_addr_is_broadcast(const p2p_addr addr) {
    struct p2p_addr_struct b;
    p2p_addr_set_broadcast(&b);
    return p2p_addr_is_equal(addr, &b);
}

p2p_addr p2p_addr_broadcast() {
    static struct p2p_addr_struct a;
    p2p_addr_set_broadcast(&a);
    return &a;
}

int p2p_addr_is_undefined(const p2p_addr addr) {
    struct p2p_addr_struct u;
    p2p_addr_set_undefined(&u);
    return p2p_addr_is_equal(addr, &u);
}

p2p_addr p2p_addr_undefined() {
    static struct p2p_addr_struct a;
    p2p_addr_set_undefined(&a);
    return &a;
}

int p2p_addr_set(p2p_addr dst, const char* ip_str,
        unsigned short tcp, unsigned short udp) {
    if (inet_aton(ip_str, & dst->ip) == 0) {
        return P2P_ERROR;
    }
    dst->tcp_port = htons(tcp);
    dst->udp_port = htons(udp);
    return P2P_OK;
}

/****************************************************/

/****************************************************/

int test_delim(char c) {
    return (c == ':');
}

int p2p_addr_setstr(p2p_addr dst, const char* p2p_str) {
    char tokens[MAX_TOK][MAX_TOKLEN];
    //fprintf(stderr,"-%s-\n",p2p_str);
    if (get_tokens(p2p_str, tokens, test_delim) == 3) {
        return p2p_addr_set(dst, tokens[0], atoi(tokens[1]), atoi(tokens[2]));
    } else {
        return P2P_ERROR;
    }
}

void p2p_addr_set_undefined(p2p_addr addr) {
    p2p_addr_set(addr, "0.0.0.0", 0, 0);
}

void p2p_addr_set_broadcast(p2p_addr addr) {
    p2p_addr_set(addr, "255.255.255.255", 0, 0);
}

char* p2p_addr_get_str(p2p_addr addr) {
    static char str[15 + 1 + 5 + 1 + 5 + 1];
    sprintf(str, "%s:%d:%d",
            p2p_addr_get_ip_str(addr),
            p2p_addr_get_tcp_port(addr),
            p2p_addr_get_udp_port(addr));
    return str;
}

char* p2p_addr_get_ip_str(p2p_addr addr) {
    return inet_ntoa(addr->ip);
}

unsigned short p2p_addr_get_tcp_port(p2p_addr addr) {
    return ntohs(addr->tcp_port);
}

unsigned short p2p_addr_get_udp_port(p2p_addr addr) {
    return ntohs(addr->udp_port);
}

void p2p_addr_dump(const p2p_addr addr, int fd) {
    char buf[1024];
    int length;

    length = sprintf(buf, "%s:%d:%d",
            p2p_addr_get_ip_str(addr),
            p2p_addr_get_tcp_port(addr),
            p2p_addr_get_udp_port(addr));
    write(fd, buf, length);
}

void p2p_addr_dumpfile(const p2p_addr addr, const FILE *fd) {
    (void) fprintf((FILE*) fd, "|%35s|\n", p2p_addr_get_ip_str(addr));
    (void) fprintf((FILE*) fd, "|%18d", p2p_addr_get_tcp_port(addr));
    (void) fprintf((FILE*) fd, "|%16d|\n", p2p_addr_get_udp_port(addr));
    (void) fprintf((FILE*) fd, "+++++++++++++++++++++++++++++++++++++\n");
}
