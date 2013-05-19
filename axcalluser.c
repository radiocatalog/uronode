/* axcalluser.c - determine username corresponding to callsign */
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "axcalluser.h"

int axcalluserid(char *call)
{
	char callsign[10];
	char username[80];
	int id;
	int userid = -1;
	FILE *f = fopen(PROC_AX25_CALLS_FILE,"r");
	if (f) {
		fgets(username,79,f);
		while (fscanf(f," %d %9s",&id,callsign) != EOF) {
			char *a,*b;
			for (a=call,b=callsign;
                             *a && *b && toupper(*a)==toupper(*b) && *b!='-';
                             a++,b++) ;
			if (!isalnum(*a) && !isalnum(*b)) {
				userid = id;
			}
		}

	}
	fclose(f);
	return userid;
}
char *getusername(int userid)
{
	int colons;
	int c,i;
	char token[80];
	static char name[80];
	char *retval = NULL;
	FILE *f;
	f = fopen("/etc/passwd","r");
	if (f) {
		i = 0;
		colons = 0;
		while ((c = getc(f)) != EOF) {
			switch (c) {
				case ':':
					token[i] = '\0';
					colons++;
					if (colons == 3) {
						if (userid == atoi(token)) {
							retval = name;
							goto endloop;
						}
					} else if (colons == 1) {
						strcpy(name,token);
					}
					i = 0;
					break;
				case '\n':
					colons = 0;
					i = 0;
					break;
				default:
					token[i++] = c;
					break;
			}
		}
		endloop:
		fclose(f);
	}
	return retval;
}
