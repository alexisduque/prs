/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_file
   PURPOSE
     
   NOTES
     
   HISTORY
     efleury - May 02, 2004: Created.

     Revision 1.5  2004/07/26 08:24:34  afraboul
 ***/
#include <stdlib.h>
#include <search.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "p2p_common.h"
#include "p2p_file.h"

#define DIR_SEPARATOR '/'

char* complete_path(server_params*sp, const char* file) {
    char* ptr;
    char* fullpath;

    if ((ptr = strrchr(file, DIR_SEPARATOR)) != NULL) {
        ptr++; /* skip last '/' */
    } else {
        ptr = (char*) file;
    }

    fullpath = (char*) malloc(sizeof (char)*(strlen(sp->dir_name) + 1 + strlen(ptr) + 1));

    sprintf(fullpath, "%s/%s", sp->dir_name, ptr);
    return fullpath;
}

int
p2p_file_is_available(server_params *sp, const char* file, int *filesize) {
    int fd;
    int ret = P2P_OK;
    char* fullpath;
    struct stat buf;

    *filesize = 0;
    fullpath = complete_path(sp, file);
    VERBOSE(sp, VSYSCL, "** p2p_file lookup for %s\n", fullpath);
    fd = open(fullpath, O_RDONLY);
    if (fd == -1) {
        ret = P2P_ERROR;
        switch (errno) {
            case EACCES:
                *filesize = P2P_DATA_FORBIDDEN;
                break;
            case ENAMETOOLONG:
                *filesize = P2P_REQUEST_URI_TOO_LARGE;
                break;
            case ENOENT:
                *filesize = P2P_DATA_NOT_FOUND;
                break;
            case ENOTDIR:
                *filesize = P2P_BAD_REQUEST;
                break;
            default:
                *filesize = P2P_INTERNAL_SERVER_ERROR;
                break;
        }
    } else {
        if (stat(fullpath, &buf)) {
            ret = P2P_ERROR;
            switch (errno) {
                case EACCES:
                    *filesize = P2P_DATA_FORBIDDEN;
                    break;
                case ENAMETOOLONG:
                    *filesize = P2P_REQUEST_URI_TOO_LARGE;
                    break;
                case ENOENT:
                    *filesize = P2P_DATA_NOT_FOUND;
                    break;
                case ENOTDIR:
                    *filesize = P2P_BAD_REQUEST;
                    break;
                default:
                    *filesize = P2P_INTERNAL_SERVER_ERROR;
                    break;
            }
        } else {
            *filesize = buf.st_size;
        }
        close(fd);
    }
    free(fullpath);
    return ret;
}

int
p2p_file_get_chunck(server_params* sp, const char* file, int boffset, int eoffset, unsigned char** data) {
    int size;
    FILE* fd;
    char* fullpath;
    fullpath = complete_path(sp, file);
    size = eoffset - boffset + 1;
    VERBOSE(sp, VSYSCL, "%d bytes requested start:%d end:%d\n", size, boffset, eoffset);
    if ((*data = (unsigned char*) malloc(size)) == NULL)
        return P2P_ERROR;
    VERBOSE(sp, VSYSCL, "memory allocation ok\n");
    if ((fd = fopen(fullpath, "r+")) == NULL) {
        free(*data);
        *data = NULL;
        return P2P_ERROR;
    }
    VERBOSE(sp, VSYSCL, "fopen ok\n");
    fseek(fd, boffset, SEEK_SET);
    fread(*data, 1, size, fd);
    fclose(fd);
    free(fullpath);
    return P2P_OK;
}

int
p2p_file_create_file(server_params* sp, const char* file, int size) {
    FILE* fd;
    char* fullpath;
    fullpath = complete_path(sp, file);
    if ((fd = fopen(fullpath, "a+b")) == NULL) {
        free(fullpath);
        return P2P_ERROR;
    }
    fclose(fd);
    free(fullpath);
    return P2P_OK;
}

int
p2p_file_set_chunck(server_params* sp, const char* file, int boffset, int eoffset, unsigned char* data) {
    FILE* fd;
    char* fullpath;
    fullpath = complete_path(sp, file);
    if ((fd = fopen(fullpath, "a+b")) == NULL) {
        free(fullpath);
        return P2P_ERROR;
    }
    fseek(fd, boffset, SEEK_SET);
    fwrite(data, 1, eoffset - boffset + 1, fd);
    fclose(fd);
    free(fullpath);
    return P2P_OK;
}

int
p2p_file_cat(FILE *fpe, FILE *fps) {
    int c;
    while ((c = fgetc(fpe)) != EOF)
        fputc(c, fps);
    return P2P_OK;
}


/***************************************************************************/
/***************************************************************************/

