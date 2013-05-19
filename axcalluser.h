#ifndef AXCALLUSER_H
#define AXCALLUSER_H

/* Simple functions to return userid of a callsign, and */
/* username of a userid, by reading appropriate files.  */
/* Surely there's a better way to do 'getusername', but */
/* this works.                                          */
/* Dave Brown N2RJT 5/5/96                              */

/* return userid of given callsign, or -1 if not found */
int axcalluserid(char *callsign);

/* return username of given userid, or NULL if not found */
char *getusername(int userid);

#endif
