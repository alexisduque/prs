/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_file
   PURPOSE
     
   NOTES
     
   HISTORY
     efleury - May 01, 2004: Created.
***/
#ifndef __P2P_FILE
#define __P2P_FILE

#define P2P_FILE_NB_ELT 255

int p2p_file_is_available(server_params* sp, const char* file, int* filesize);
int p2p_file_get_chunck  (server_params* sp, const char* file, int boffset, int eoffset, unsigned char** data);
int p2p_file_create_file (server_params* sp, const char* file, int size);
int p2p_file_set_chunck  (server_params* sp, const char* file, int boffset, int eoffset, unsigned char* data);
int p2p_file_cat(FILE *fpe, FILE *fps);
#endif /* __P2P_FILE */
