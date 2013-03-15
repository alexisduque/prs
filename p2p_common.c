/* Copyright (c) 2004 by ARES Inria.  All Rights Reserved */

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "p2p_common.h"

/****************************************************/
/* 
   get_tokens: à peu près similaire à strtok_r mais 
   ne modifie pas la chaîne str
 */
/****************************************************/

int
get_tokens(const char *str, char tok[MAX_TOK][MAX_TOKLEN], int (*test_delim)(char))
{
  int i     = 0;
  int token = 0;
  int index = 0;

  while (str[i] && token < MAX_TOK) 
    {
      /* strip spaces */
      while (str[i] && test_delim(str[i])) {
	i++;
      }

      index = 0;
      while (str[i] && !test_delim(str[i]) && index < MAX_TOKLEN) 
	{
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
VERBOSE(server_params* sp, int level, char* fmt, ...)
{
  FILE* out = stderr;
  int length;
  char buf[MAX_VNSPRINTF_BUF_LENGTH + 1];
  va_list ap;

  va_start(ap, fmt);   // va_start sert à gerer la va_list:
                       // list d'un nombre variable d'argument
  length = vsnprintf(buf,MAX_VNSPRINTF_BUF_LENGTH,fmt,ap);
  if (length >= MAX_VNSPRINTF_BUF_LENGTH)
    length = MAX_VNSPRINTF_BUF_LENGTH;
  va_end(ap);

  if (level == CLIENT)
    {
      if (buf[length-1] == '\n')
	{
	  buf[length-1] = '\r';
	  buf[length  ] = '\n';
	  buf[length+1] = '\0';
	  length ++;
	}
      write(sp->client_ui,buf,length);
      return;
    }

  if (sp->verbosity >= level)
    {
      int i;
      fprintf(out,"%s",sp->server_name);
      for(i=0; i<level; i++)
	fprintf(out,"  ");
      fprintf(out,"** ");
      fprintf(out,"%s",buf);
      return;
    }
}

/****************************************************/
/* 
   raw_print: affichage propre en hexadécimal et dans l'ordre réèl
   des octets d'une portion de mémoire 
 */
/****************************************************/

void raw_print(char *buf,int size)
{
  int i; 
  char *visitor;

  visitor=buf;
  for (i=0;i<size;i++)
    {
      printf("%02x ", *visitor & 0xff);
      visitor++;
      if (i%16==15) printf("\n");
    }
  printf("\n");
}
