/* Copyright (c) 2004 by Dept TC INSA Lyon.  All Rights Reserved */

/***
   NAME
     p2p_ui.h
   PURPOSE
     
   NOTES
     
   HISTORY
     Revision 1.1  2005/02/21 18:34:33  afraboul
     ajout des sources qui seront distribuées aux étudiants

     Revision 1.4  2004/07/26 08:24:38  afraboul
***/
#ifndef __P2P_UI
#define __P2P_UI

#include "p2p_common.h"

#define P2P_UI_OK    P2P_OK
#define P2P_UI_ERROR P2P_ERROR
#define P2P_UI_QUIT  20
#define P2P_UI_KILL  30

int ui_command(server_params *sp);

#endif
