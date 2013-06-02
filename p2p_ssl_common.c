/* 
 * File:   p2p_common_ssl.h
 * Author: alexis
 *
 * Created on 19 mai 2013, 14:45
 * 
 * Function for SSL support
 *  */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netinet/in.h>
#include <netdb.h> 
#include <assert.h>
#include <arpa/inet.h>

#include "p2p_msg.h"
#include "p2p_common.h"
#include "p2p_options.h"
#include "p2p_ssl_common.h"
#include "p2p_addr.h"
#include "p2p_file.h"

#include <openssl/rand.h>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/err.h> 
#include <errno.h>

void
p2p_ssl_handle_error(const char *file, int lineno, const char *msg) {
    fprintf(stderr, "** %s:%i %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    return P2P_ERROR;
}

#define int_error(msg) p2p_ssl_handle_error(__FILE__, __LINE__, msg)

#define PKEY_FILE "./keys/newPrivKey.pem"
#define REQ_FILE "./keys/newCSR.pem"
#define CERT_FILE "./keys/newCert.pem"

struct entry {
    char *key;
    char *value;
};

struct entry ext_ent[EXT_COUNT] = {
    { "basicConstraints", "CA:FALSE"},
    { "nsComment", "\"OpenSSL Generated Certificate\""},
    { "subjectKeyIdentifier", "hash"},
    { "authorityKeyIdentifier", "keyid,issuer:always"},
    { "keyUsage", "nonRepudiation, digitalSignature, keyEncipherment"}
};

struct entry entries[ENTRY_COUNT] = {

    { "countryName", "FR"},
    { "stateOrProvinceName", "69"},
    { "localityName", "Villeurbanne"},
    { "organizationName", "Insa de Lyon"},
    { "organizationalUnitName", "TC"},
    { "commonName", "name"},
};

// password callback pour les clee privee
int p2p_ssl_pass_cb(char *buf, int size, int rwflag, char *u) {
    
    int len;
    char *tmp;
    printf("Enter pass phrase for \"%s\"\n", u);

    /* get pass phrase, length 'len' into 'tmp' */
    tmp = "alex";
    len = strlen(tmp);

    if (len <= 0) return 0;

    /* if too long, truncate */
    if (len > size) len = size;
    memcpy(buf, tmp, len);
    return len;
}


// Change le certificate utiliser par default

X509* p2p_ssl_load_cert(server_params* sp, char* file) {

    VERBOSE(sp, VSYSCL, "Load SSL Certificate from file : %s\n\n", file);
    FILE *fpem;
    X509 *cert;

    if (!(fpem = fopen(file, "r"))) {
        VERBOSE(sp, VSYSCL, "Couldn't open the PEM file: %s\n", file);
        return NULL;
    }

    if (!(cert = PEM_read_X509(fpem, NULL, NULL, NULL))) {
        fclose(fpem);
        VERBOSE(sp, VSYSCL, "Couldn't read the PEM file: %s\n", file);
        return NULL;
    }

    return cert;
}

//Genère une clé privée, et demande la certification à l'AC Root

int p2p_ssl_gen_privatekey(server_params* sp) {

    VERBOSE(sp, VSYSCL, "Generating RSA Private Key ....\n");

    int i, keylen,subjAltName_pos;
    long serial = 1;
    char *pem_key;
    FILE *fp, *fs;
    RSA *rsa;
    BIO *bio, *bio2, *out;
    X509_REQ *req = NULL;
    X509_NAME *subj, *name;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *CApkey = NULL;
    EVP_PKEY *pubkey = NULL;
    const EVP_MD *digest;
    X509 *cert, *CAcert;
    X509V3_CTX ctx;
    X509_EXTENSION *subjAltName;
    STACK_OF (X509_EXTENSION) * req_exts;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    ERR_load_BIO_strings();

    //creation de la clef privee sur 1024 bits
    rsa = RSA_generate_key(1024, 65537, 0, 0);
    bio = BIO_new(BIO_s_mem());

    //conversion de la clee RSA en chaine de caracteres et affichage
    PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, "alex");
    keylen = BIO_pending(bio);
    pem_key = calloc(keylen + 1, 1);
    BIO_read(bio, pem_key, keylen);
    VERBOSE(sp, CLIENT, "%s", pem_key);
    BIO_free(bio);
    free(pem_key);
    VERBOSE(sp, VSYSCL, "New RSA Key create\n");

    //conversion de la clee privee au format EVP
    bio2 = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio2, rsa, NULL, NULL, 0, NULL, "alex");
    if (!(pkey = PEM_read_bio_PrivateKey(bio2, NULL, 0, 0)))
        printf("Error reading private key in bio\n");
    
    //ecriture de la clee privee dans le fichier PEM
    if (!(fp = fopen(PKEY_FILE, "w")))
        int_error("Error writing to PEM file");
    if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, 0, "alex") != 1)
        int_error("Error while writing PrivateKey");
    fclose(fp);
    
    
    //lecture de la clee privee depuis le fichier creer
    if (!(fp = fopen(PKEY_FILE, "r")))
        int_error("Error reading private key file");
    if (!(pkey = PEM_read_PrivateKey(fp, NULL, NULL, "alex")))
        int_error("Error reading private key in file");
    fclose(fp);
    
    //creation de du CSR et ajout de la cle public, extraite de la cle privee
    if (!(req = X509_REQ_new()))
        int_error("Failed to create X509_REQ object");
    X509_REQ_set_pubkey(req, pkey);

    //ajout du champs subject_name
    if (!(subj = X509_NAME_new()))
        int_error("Failed to create X509_NAME object");

    for (i = 0; i < ENTRY_COUNT; i++) {
        int nid;
        X509_NAME_ENTRY *ent;

        if ((nid = OBJ_txt2nid(entries[i].key)) == NID_undef) {
            fprintf(stderr, "Error finding NID for %s\n", entries[i].key);
            int_error("Error on lookup");
        }
        if (!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC,
                entries[i].value, -1)))
            int_error("Error creating Name entry from NID");
        if (X509_NAME_add_entry(subj, ent, -1, 0) != 1)
            int_error("Error adding entry to Name");
    }
    if (X509_REQ_set_subject_name(req, subj) != 1)
        int_error("Error adding subject to request");

    // ajout de l'extension (pour X509 v3)
    {
        X509_EXTENSION *ext;
        STACK_OF(X509_EXTENSION) * extlist;
        char *name = "subjectAltName";
        char *value = "DNS:splat.zork.org";

        extlist = sk_X509_EXTENSION_new_null();

        if (!(ext = X509V3_EXT_conf(NULL, NULL, name, value)))
            int_error("Error creating subjectAltName extension");

        sk_X509_EXTENSION_push(extlist, ext);

        if (!X509_REQ_add_extensions(req, extlist))
            int_error("Error adding subjectAltName to the request");
        sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);
    }

    //Ajout du type de chiffrement utilise
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA)
        digest = EVP_dss1();
    else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
        digest = EVP_sha1();
    else
        int_error("Error checking public key for a valid digest");
    if (!(X509_REQ_sign(req, pkey, digest)))
        int_error("Error signing request");

    //creation du fichier
    if (!(fp = fopen(REQ_FILE, "w")))
        int_error("Error writing to request file");
    if (PEM_write_X509_REQ(fp, req) != 1)
        int_error("Error while writing request");
    fclose(fp);

    RSA_free(rsa);
    BIO_free_all(bio2);
    EVP_PKEY_free(pkey);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);

    // creation du BIO en output
    if (!(out = BIO_new_fp(stdout, BIO_NOCLOSE)))
        int_error("Error creating stdout BIO");

    // lecture du fichier de demande de signature
    if (!(fp = fopen(REQ_FILE, "r")))
        int_error("Error reading request file");
    if (!(req = PEM_read_X509_REQ(fp, NULL, NULL, "alex")))
        int_error("Error reading request in file");
    fclose(fp);

    //verification de la signature et cle public
    if (!(pkey = X509_REQ_get_pubkey(req)))
        int_error("Error getting public key from request");
    if (X509_REQ_verify(req, pkey) != 1)
        int_error("Error verifying signature on certificate");

    // ouverture et lecture du certficat de l'AC
    if (!(fp = fopen(CAFILE, "r")))
        int_error("Error reading CA certificate file");
    if (!(CAcert = PEM_read_X509(fp, NULL, NULL, "alex")))
        int_error("Error reading CA certificate in file");
    fclose(fp);

    //lecture de sa clee privee
    if (!(fp = fopen(CAKEY, "r")))
        int_error("Error reading CA private key file");
    if (!(CApkey = PEM_read_PrivateKey(fp, NULL, NULL, "alex")))
        int_error("Error reading CA private key in file");
    fclose(fp);

    //affche des subject_name
    if (!(name = X509_REQ_get_subject_name(req)))
        int_error("Error getting subject name from request");
    X509_NAME_print(out, name, 0);
    fputc('\n', stdout);
    if (!(req_exts = X509_REQ_get_extensions(req)))
        int_error("Error getting the request's extensions");
    subjAltName_pos = X509v3_get_ext_by_NID(req_exts,
            OBJ_sn2nid("subjectAltName"), -1);
    subjAltName = X509v3_get_ext(req_exts, subjAltName_pos);
    X509V3_EXT_print(out, subjAltName, 0, 0);
    fputc('\n', stdout);

    //creation du certifixazt X509
    if (!(cert = X509_new()))
        int_error("Error creating X509 object");

   //ajout des info necessaire au certificat
    if (X509_set_version(cert, 2L) != 1)
        int_error("Error settin certificate version");
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);

    if (!(name = X509_REQ_get_subject_name(req)))
        int_error("Error getting subject name from request");
    if (X509_set_subject_name(cert, name) != 1)
        int_error("Error setting subject name of certificate");
    if (!(name = X509_get_subject_name(CAcert)))
        int_error("Error getting subject name from CA certificate");
    if (X509_set_issuer_name(cert, name) != 1)
        int_error("Error setting issuer name of certificate");

    // ajout de la cle public
    if (X509_set_pubkey(cert, pkey) != 1)
        int_error("Error setting public key of the certificate");

    //ajout de la duree de validite du cert
    if (!(X509_gmtime_adj(X509_get_notBefore(cert), 0)))
        int_error("Error setting beginning time of the certificate");
    if (!(X509_gmtime_adj(X509_get_notAfter(cert), EXPIRE_SECS)))
        int_error("Error setting ending time of the certificate");

    //jout des extensions pour la v3
    X509V3_set_ctx(&ctx, CAcert, cert, NULL, NULL, 0);
    for (i = 0; i < EXT_COUNT; i++) {
        X509_EXTENSION *ext;
        if (!(ext = X509V3_EXT_conf(NULL, &ctx,
                ext_ent[i].key, ext_ent[i].value))) {
            fprintf(stderr, "Error on \"%s = %s\"\n",
                    ext_ent[i].key, ext_ent[i].value);
            int_error("Error creating X509 extension object");
        }
        if (!X509_add_ext(cert, ext, -1)) {
            fprintf(stderr, "Error on \"%s = %s\"\n",
                    ext_ent[i].key, ext_ent[i].value);
            int_error("Error adding X509 extension to certificate");
        }
        X509_EXTENSION_free(ext);
    }


    if (!X509_add_ext(cert, subjAltName, -1))
        int_error("Error adding subjectAltName to certificate");

    //signature avec la cle prive de l'AC
    if (EVP_PKEY_type(CApkey->type) == EVP_PKEY_DSA)
        digest = EVP_dss1();
    else if (EVP_PKEY_type(CApkey->type) == EVP_PKEY_RSA)
        digest = EVP_sha1();
    else
        int_error("Error checking CA private key for a valid digest");
    if (!(X509_sign(cert, CApkey, digest)))
        int_error("Error signing certificate");

    //creation du fichier
    if (!(fp = fopen(CERT_FILE, "w")))
        int_error("Error writing to certificate file");
    if (PEM_write_X509(fp, cert) != 1)
        int_error("Error while writing certificate");
    //lecture de la clee privee depuis le fichier creer
    if (!(fs = fopen(PKEY_FILE, "r")))
        int_error("Error reading private key file");
    //chainage du certificat avec la cle privee
    p2p_file_cat(fs, fp);
    
    fclose(fs);
    fclose(fp);

    EVP_PKEY_free(pubkey);
    EVP_PKEY_free(CApkey);
    X509_REQ_free(req);
    BIO_free_all(out);
    return P2P_OK;
}


// Initialise le contexte SSL pour le serveur

int p2p_ssl_init_server(server_params* sp, int meth) {

    //Chargement des librairies
    VERBOSE(sp, VSYSCL, "SSL Loading Library...\n");
    SSL_library_init();
    SSL_load_error_strings();
    switch (meth) {
            VERBOSE(sp, VSYSCL, "SSL INIT server SSLv3 methods\n");
        case SSL23_METH: sp->node_meth = SSLv23_server_method();
            break;
        case DTLS_METH: sp->node_meth = DTLSv1_server_method();
            VERBOSE(sp, VSYSCL, "SSL INIT server DTLSv1 methods\n");
            break;
    }


    sp->ssl_node_ctx = SSL_CTX_new(sp->node_meth);


    if (!sp->ssl_node_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    VERBOSE(sp, VSYSCL, "SSL : Loading Certificat\n");
    //Ajout des certificats serveur 
    if (SSL_CTX_load_verify_locations(sp->ssl_node_ctx, CAFILE, CADIR) != 1)
        perror("Error loading CA file and/or directory");

    //Ajout des certificats serveur 
    SSL_CTX_set_default_passwd_cb_userdata(sp->ssl_node_ctx, KEY_PASSWD);

    if (SSL_CTX_set_default_verify_paths(sp->ssl_node_ctx) != 1)
        perror("Error loading default CA file and/or directory");

    if (SSL_CTX_use_certificate_chain_file(sp->ssl_node_ctx, sp->node_cert) != 1)
        perror("Error loading certificate from file");

    if (SSL_CTX_use_PrivateKey_file(sp->ssl_node_ctx, sp->node_cert, SSL_FILETYPE_PEM) != 1)
        perror("Error loading private key from file");

    //Demande la verification des crificats du clients si verify_peer est ON
    if (sp->verify_peer) {
        SSL_CTX_set_verify(sp->ssl_node_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(sp->ssl_node_ctx, 4);
    }

    VERBOSE(sp, VSYSCL, "SSL : Certificat Loaded\n\n");
    return P2P_OK;

}

//Initialisation du contexte SSL client

int p2p_ssl_init_client(server_params* sp, int meth) {

    //Charement des librairies
    VERBOSE(sp, VSYSCL, "SSL Loading library\n");
    SSL_library_init();
    SSL_load_error_strings();
    switch (meth) {
            VERBOSE(sp, VSYSCL, "SSL INIT client SSLv3 methods\n");
        case SSL23_METH: sp->node_meth = SSLv23_client_method();
            break;
        case DTLS_METH: sp->node_meth = DTLSv1_client_method();
            VERBOSE(sp, VSYSCL, "SSL INIT client DTLSv1 methods\n");
            break;
    }

    sp->ssl_node_ctx = SSL_CTX_new(sp->node_meth);

    if (!sp->ssl_node_ctx) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    //Si la verification des crtificats est activée, on ajoute les certificats au contexte
    if (sp->verify_peer) {
        VERBOSE(sp, VSYSCL, "SSL : Loading Certificat\n");
        SSL_CTX_set_default_passwd_cb_userdata(sp->ssl_node_ctx, KEY_PASSWD);

        if (SSL_CTX_load_verify_locations(sp->ssl_node_ctx, CAFILE, CADIR) != 1)
            perror("Error loading CA file and/or directory");

        if (SSL_CTX_set_default_verify_paths(sp->ssl_node_ctx) != 1)
            perror("Error loading default CA file and/or directory");

        if (SSL_CTX_use_certificate_chain_file(sp->ssl_node_ctx, sp->node_cert) != 1)
            printf("Error loading certificate from file : %s\n", sp->node_cert);

        if (SSL_CTX_use_PrivateKey_file(sp->ssl_node_ctx, sp->node_cert, SSL_FILETYPE_PEM) != 1)
            printf("Error loading private key from file : %s\n", sp->node_cert);

        SSL_CTX_set_verify(sp->ssl_node_ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(sp->ssl_node_ctx, 4);
        VERBOSE(sp, VSYSCL, "SSL : Certificat Loaded\n\n");
    }

    return P2P_OK;
}

//Envoi du message msg via la stracture SSL clientssl

int p2p_ssl_tcp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* clientssl) {

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
    if (SSL_write(clientssl, toWrite, P2P_HDR_SIZE + message_size) != (P2P_HDR_SIZE + message_size)) {
        VERBOSE(sp, VPROTO, "Unable to send msg to the socket\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        return P2P_ERROR;
    } else {
        VERBOSE(sp, VPROTO, "TCP MSG SUCCESFULL SEND\n\n");
        //Liberation de la memoire du buffer
        free(toWrite);
        //Fermeture de la connexion SSL
        SSL_shutdown(clientssl);
        return P2P_OK;
    }


}

// Initialise la connexion SSL coté client avec la socket fd

int p2p_ssl_tcp_client_init_sock(server_params* sp, SSL* clientssl, int fd) {

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE ... \n");
    int ret;
    if ((ret = SSL_set_fd(clientssl, fd)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL: SetFD ERROR %d\n", SSL_get_error(clientssl, ret));
        return P2P_ERROR;
    }

    if ((ret = SSL_connect(clientssl)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(clientssl, ret));
        return P2P_ERROR;
    }

    if (sp->verify_peer) {

        X509 *ssl_client_cert = NULL;

        ssl_client_cert = SSL_get_peer_certificate(clientssl);

        if (ssl_client_cert) {
            long verifyresult;
            p2p_ssl_showCerts(sp, clientssl);
            verifyresult = SSL_get_verify_result(clientssl);
            if (verifyresult == X509_V_OK) {
                VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
            } else {
                VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                X509_free(ssl_client_cert);
                return (P2P_ERROR);
            }
        } else {
            VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
            return (P2P_ERROR);
        }
    }

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;
}

// Initialise la connexion SSL coté server avec la socket fd

int p2p_ssl_tcp_server_init_sock(server_params* sp, SSL* ssl, int fd) {

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE... \n");
    int ret;
    if ((ret = SSL_set_fd(ssl, fd)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL: SetFD ERROR %d\n", SSL_get_error(ssl, ret));
        return (P2P_ERROR);
    }


    if ((ret = SSL_accept(ssl)) != 1) {
        VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(ssl, ret));
        return (P2P_ERROR);
    }


    if (sp->verify_peer) {

        X509 *ssl_client_cert = NULL;
        ssl_client_cert = SSL_get_peer_certificate(ssl);

        if (ssl_client_cert) {

            long verifyresult;
            p2p_ssl_showCerts(sp, ssl);
            verifyresult = SSL_get_verify_result(ssl);

            if (verifyresult == X509_V_OK) {
                VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
            } else {
                VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                SSL_shutdown(ssl);
                X509_free(ssl_client_cert);
                return (P2P_ERROR);
            }

        } else {
            VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
            SSL_shutdown(ssl);
            return (P2P_ERROR);
        }
    }

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;

}

//Ferme la connection SSL

void p2p_ssl_tcp_close(server_params* sp, SSL* ssl) {
    SSL_shutdown(ssl);
    // SSL_free(ssl);
    SSL_clear(ssl);
    VERBOSE(sp, VSYSCL, "SSL : Connection successful closed\n");
}

// Recois dans msg un message depuis la connection ssl serverssl

int p2p_ssl_tcp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* serverssl) {

    int tot = 0;
    int i = 0;
    unsigned short int length = 0;
    unsigned char* data_payload = NULL;
    if (SSL_read(serverssl, msg, P2P_HDR_BITFIELD_SIZE) == 0) return P2P_ERROR;
    SSL_read(serverssl, p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    SSL_read(serverssl, p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    length = p2p_msg_get_length(msg);
    length = ntohs(length);
    data_payload = (unsigned char *) malloc(sizeof (unsigned char) * P2P_MSG_MAX_SIZE);
    memset(data_payload, 0, P2P_MSG_MAX_SIZE * sizeof (char));
    if (length > 0) {
        while (tot < length) {
            i = SSL_read(serverssl, data_payload + tot, length - tot);
            tot += i;
        }
        p2p_msg_init_payload(msg, length, data_payload);
    }

    p2p_msg_display(msg);
    free(data_payload);
    VERBOSE(sp, VMCTNT, "RECV MSG OK\n");
    return P2P_OK;

}


// Envoi du message msg via tcp au noeud destination indiquée dans le champ dst de msg

int p2p_ssl_tcp_msg_send(server_params* sp, const p2p_msg msg) {

    SSL *clientssl = SSL_new(sp->ssl_node_ctx);

    VERBOSE(sp, VPROTO, "DEST : %s\n", p2p_addr_get_str(p2p_msg_get_dst(msg)));
    int socketTMP = p2p_tcp_socket_create(sp, p2p_msg_get_dst(msg));

    if (socketTMP == P2P_ERROR) {
        VERBOSE(sp, VSYSCL, "SSL : TCP socket creation impossible \n");
        //printf("Impossible de créer la socket TCP \n");
        return (P2P_ERROR);
    }
    if (p2p_ssl_tcp_client_init_sock(sp, clientssl, socketTMP) != P2P_OK) {
        VERBOSE(sp, VSYSCL, "SSL : INIT Impossible \n");
        return (P2P_ERROR);
    }
    if (p2p_ssl_tcp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
        return (P2P_ERROR);
    }

    p2p_ssl_tcp_close(sp, clientssl);
    p2p_tcp_socket_close(sp, socketTMP);
    VERBOSE(sp, VPROTO, "SEND msg DONE\n\n");
    return P2P_OK;
}

//Affiche le certificat du peer

void p2p_ssl_showCerts(server_params* sp, SSL* ssl) {

    X509 *cert;
    char *line;
    //obtient le certiication du paire connecté
    cert = SSL_get_peer_certificate(ssl);

    if (cert != NULL) {
        VERBOSE(sp, VMCTNT, "------------------Peer certificates ----------------------\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        VERBOSE(sp, VMCTNT, "Subject: %s\n", line);
        //libère la mémoire allouée 
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        VERBOSE(sp, VMCTNT, "Issuer: %s\n", line);
        VERBOSE(sp, VMCTNT, "-----------------------------------------------------------\n");
        //libère la mémoire allouée
        free(line);
        X509_free(cert);
    } else
        VERBOSE(sp, VMCTNT, "No certificates.\n");
}

/* 
 * 
 ****************  UDP Functions  *******************************************
 * 
 *   TODO
 * 
 * 
 */

/****************************************************************************
int p2p_ssl_udp_msg_sendfd(server_params* sp, p2p_msg msg, SSL* clientssl) {

    VERBOSE(sp, VPROTO, "TRY TO SEND UDP MSG ...\n");
    int message_size = p2p_msg_get_length(msg);
    message_size = ntohs(message_size);
    char toWrite [P2P_HDR_SIZE + sizeof (char)*message_size];

    memcpy(toWrite, msg, P2P_HDR_BITFIELD_SIZE);
    memcpy(&toWrite[4], p2p_msg_get_src(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[12], p2p_msg_get_dst(msg), P2P_ADDR_SIZE);
    memcpy(&toWrite[20], p2p_get_payload(msg), message_size);

    int err = SSL_write(clientssl, toWrite, P2P_HDR_SIZE + message_size);
    if (err <= 0) {
        err = SSL_get_error(clientssl, err);
        fprintf(stderr, "SSL_write: error %d\n", err);
        ERR_print_errors_fp(stderr);
        if (err == SSL_ERROR_SYSCALL)
            fprintf(stderr, "errno: %s\n", strerror(errno));
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

int p2p_ssl_udp_msg_recvfd(server_params* sp, p2p_msg msg, SSL* clientssl) {
    VERBOSE(sp, VMCTNT, "TRY TO RECEIVE MSG ...\n");

    //Declaration du buffer
    char data[200];
    //free(msg->payload);
    // Allocation de la mémoire pour le payload
    msg->payload = (unsigned char*) malloc(sizeof (unsigned char)*200);

    //Lecture de la soccket et remplissage du buffer
    int err = SSL_read(clientssl, &data, sizeof (data));
    if (err <= 0) {
        err = SSL_get_error(clientssl, err);
        fprintf(stderr, "SSL_read: error %d\n", err);
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "%s", data);
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

int p2p_ssl_udp_msg_send(server_params* sp, p2p_msg msg) {

    int sock = -1;
    SSL *clientssl = SSL_new(sp->ssl_node_ctx);

    if ((sock = p2p_udp_socket_create(sp, msg->hdr.dst)) == P2P_ERROR) {
        VERBOSE(sp, VPROTO, "Unable to send UDP_MSG\n");
        return P2P_ERROR;
    }
    if (p2p_ssl_udp_client_init_sock(sp, clientssl, sock, (p2p_msg_get_dst(msg))) != P2P_OK) {
        VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
        return (P2P_ERROR);
    }

    p2p_ssl_udp_msg_sendfd(sp, msg, clientssl);
    p2p_ssl_close(sp, clientssl);
    p2p_udp_socket_close(sp, sock);

    VERBOSE(sp, VSYSCL, "Send MSG done \n");
    return P2P_OK;
}

//rebroadcast le message msg

int p2p_ssl_udp_msg_rebroadcast(server_params* sp, p2p_msg msg) {

    printf("----------------------Rebroadcast-----------------------------\n");

    int fd;
    SSL *clientssl = SSL_new(sp->ssl_node_ctx);

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

        if (p2p_ssl_udp_client_init_sock(sp, clientssl, fd, sp->p2p_neighbors.right_neighbor) != P2P_OK) {
            VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
            return (P2P_ERROR);
        }
        printf("Send to right\n");
        printf("Equal(src, right)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.right_neighbor));

        if (p2p_ssl_udp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
            printf("UDP_rebroadcast : sending FAILED\n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.right_neighbor));
        }

        p2p_ssl_close(sp, clientssl);
        p2p_udp_socket_close(sp, fd);

    }

    if ((p2p_addr_is_equal(sp->p2pMyId, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor) || p2p_addr_is_equal(initiator, sp->p2p_neighbors.left_neighbor)) != 1) {

        p2p_msg_set_src(msg, sp->p2pMyId);
        printf("Send to left\n");
        printf("Equal(src, left)  = %d\n", p2p_addr_is_equal(src, sp->p2p_neighbors.left_neighbor));

        fd = p2p_udp_socket_create(sp, sp->p2p_neighbors.left_neighbor);

        if (p2p_ssl_udp_client_init_sock(sp, clientssl, fd, sp->p2p_neighbors.left_neighbor) != P2P_OK) {
            VERBOSE(sp, VSYSCL, "SSL/DTLS : INIT Impossible \n");
            return (P2P_ERROR);
        }
        if (p2p_ssl_udp_msg_sendfd(sp, msg, clientssl) != P2P_OK) {
            printf("UDP rebroadcast : Sending FAILED \n\n");
            return P2P_ERROR;
        } else {
            printf("Message sent to %s\n\n", p2p_addr_get_str(sp->p2p_neighbors.left_neighbor));
        }

        p2p_ssl_close(sp, clientssl);
        p2p_udp_socket_close(sp, fd);

    }
    p2p_addr_delete(initiator);
    //p2p_addr_delete(src);

    return P2P_OK;

}

int p2p_ssl_udp_client_init_sock(server_params* sp, SSL* clientssl, int fd, p2p_addr dest) {

    BIO* conn = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (conn == NULL) {
        fprintf(stderr, "error creating bio\n");
        return P2P_ERROR;
    }

    printf("PORT UDP: %d\n", p2p_addr_get_udp_port(dest));
    struct sockaddr_in dst;
    struct sockaddr* d = (struct sockaddr*) &dst;
    dst.sin_family = AF_INET;
    dst.sin_port = htons(p2p_addr_get_udp_port(dest));
    inet_aton(p2p_addr_get_ip_str(dest), &dst.sin_addr);

    int err = BIO_dgram_set_peer(conn, d);
    fprintf(stderr, "BIO dgram set peer: %d\n", err);

    SSL_set_bio(clientssl, conn, conn);

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE ... \n");
    SSL_set_connect_state(clientssl);

        int ret;

        if ((ret = SSL_connect(clientssl)) != 1) {
            VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(clientssl, ret));
            return P2P_ERROR;
        }
    

        if (sp->verify_peer) {

            X509 *ssl_client_cert = NULL;

            ssl_client_cert = SSL_get_peer_certificate(clientssl);

            if (ssl_client_cert) {
                long verifyresult;
                p2p_ssl_showCerts(sp, clientssl);
                verifyresult = SSL_get_verify_result(clientssl);
                if (verifyresult == X509_V_OK) {
                    VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
                } else {
                    VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                    X509_free(ssl_client_cert);
                    return (P2P_ERROR);
                }
            } else {
                VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
                return (P2P_ERROR);
            }
        }
    

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;
}

// Initialise la connexion SSL coté server avec la socket fd

int p2p_ssl_udp_server_init_sock(server_params* sp, SSL* ssl, int fd) {

    VERBOSE(sp, VSYSCL, "SSL UDP SERVER INIT... \n");


    BIO* conn = BIO_new_dgram(fd, BIO_NOCLOSE);
    if (conn == NULL) {
        fprintf(stderr, "error creating bio\n");
        return P2P_ERROR;
    }


    SSL_set_bio(ssl, conn, conn);
    SSL_set_accept_state(ssl);

    VERBOSE(sp, VSYSCL, "DTLS LISTEN... \n");
    while (!DTLSv1_listen(ssl, &client_addr));
    
        int ret;

        if ((ret = SSL_accept(ssl)) != 1) {
           VERBOSE(sp, VSYSCL, "SSL : HANDSHAKE ERROR %d\n", SSL_get_error(ssl, ret));
            return (P2P_ERROR);
        }

    
        if (sp->verify_peer) {

            X509 *ssl_client_cert = NULL;
            ssl_client_cert = SSL_get_peer_certificate(ssl);

            if (ssl_client_cert) {
            
                long verifyresult;
                p2p_ssl_showCerts(sp, ssl);
                verifyresult = SSL_get_verify_result(ssl);
            
                if (verifyresult == X509_V_OK) {
                    VERBOSE(sp, VSYSCL, "SSL : Certificate Verify SUCCESS\n");
                } else {
                    VERBOSE(sp, VSYSCL, "SSL: Certificate Verify FAILED\n");
                    SSL_shutdown(ssl);
                    X509_free(ssl_client_cert);
                    return (P2P_ERROR);
                }
        
            } else {
                VERBOSE(sp, VSYSCL, "SSL : NO client certificate\n");
                SSL_shutdown(ssl);
                return (P2P_ERROR);
            } 
        }    
     

    VERBOSE(sp, VSYSCL, "SSL HANDSHAKE DONE\n\n");
    return P2P_OK;

}

 *******************************************************************************/