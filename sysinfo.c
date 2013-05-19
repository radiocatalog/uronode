/*
 * This code is slightly modified from the procps package.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <unistd.h>
#include <fcntl.h>
#include <utmp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include "node.h"
#include "sysinfo.h"

char *xmalloc(size_t);
char *fixup_null_alloc(size_t);
int read_utmp(char *);
int list_entries(int);
int who(void);

#define UPTIME_FILE  "/proc/uptime"
#define LOADAVG_FILE "/proc/loadavg"
#define MEMINFO_FILE "/proc/meminfo"

#define STRUCT_UTMP struct utmp
static STRUCT_UTMP *utmp_contents;

#ifndef UTMP_FILE
#define UTMP_FILE "/var/run/utmp"
#endif

#ifndef EMAILLEN
#define EMAILLEN 64
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef S_IWGRP
#define S_IWGRP 020
#endif

static char buf[300];

/* This macro opens FILE only if necessary and seeks to 0 so that successive
   calls to the functions are more efficient.  It also reads the current
   contents of the file into the global buf.
*/
#define FILE_TO_BUF(FILE) {					\
    static int n, fd = -1;					\
    if (fd == -1 && (fd = open(FILE, O_RDONLY)) == -1) {	\
	close(fd);						\
	return 0;						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((n = read(fd, buf, sizeof buf - 1)) < 0) {		\
	close(fd);						\
	fd = -1;						\
	return 0;						\
    }								\
    buf[n] = '\0';						\
}

#define SET_IF_DESIRED(x,y)  if (x) *(x) = (y)	/* evals 'x' twice */

int uptime(double *uptime_secs, double *idle_secs) {
    double up=0, idle=0;
    
    FILE_TO_BUF(UPTIME_FILE)
    if (sscanf(buf, "%lf %lf", &up, &idle) < 2) {
	printf("Bad data in %s\n", UPTIME_FILE );
	return 0;
    }
    SET_IF_DESIRED(uptime_secs, up);
    SET_IF_DESIRED(idle_secs, idle);
    return up;	/* assume never be zero seconds in practice */
}

int loadavg(double *av1, double *av5, double *av15) {
    double avg_1=0, avg_5=0, avg_15=0;
    
    FILE_TO_BUF(LOADAVG_FILE)
    if (sscanf(buf, "%lf %lf %lf", &avg_1, &avg_5, &avg_15) < 3) {
	printf("Bad data in %s\n", LOADAVG_FILE );
	return 0;
    }
    SET_IF_DESIRED(av1,  avg_1);
    SET_IF_DESIRED(av5,  avg_5);
    SET_IF_DESIRED(av15, avg_15);
    return 1;
}

/* The following /proc/meminfo parsing routine assumes the following format:
   [ <label> ... ]				# header lines
   [ <label> ] <num> [ <num> ... ]		# table rows
   [ repeats of above line ]
   
   Any lines with fewer <num>s than <label>s get trailing <num>s set to zero.
   The return value is a NULL terminated unsigned** which is the table of
   numbers without labels.  Convenient enumeration constants for the major and
   minor dimensions are available in the header file.  Note that this version
   requires that labels do not contain digits.  It is readily extensible to
   labels which do not *begin* with digits, though.
*/

#define MAX_ROW 3	/* these are a little liberal for flexibility */
#define MAX_COL 7

unsigned** meminfo(void) {
    static unsigned *row[MAX_ROW + 1];		/* row pointers */
    static unsigned num[MAX_ROW * MAX_COL];	/* number storage */
    char *p;
    int i, j, k, l;
    
    FILE_TO_BUF(MEMINFO_FILE)
    if (!row[0])				/* init ptrs 1st time through */
	for (i=0; i < MAX_ROW; i++)		/* std column major order: */
	    row[i] = num + MAX_COL*i;		/* A[i][j] = A + COLS*i + j */
    p = buf;
    for (i=0; i < MAX_ROW; i++)			/* zero unassigned fields */
	for (j=0; j < MAX_COL; j++)
	    row[i][j] = 0;
    for (i=0; i < MAX_ROW && *p; i++) {		/* loop over rows */
	while(*p && !isdigit(*p)) p++;		/* skip chars until a digit */
	for (j=0; j < MAX_COL && *p; j++) {	/* scanf column-by-column */
	    l = sscanf(p, "%u%n", row[i] + j, &k);
	    p += k;				/* step over used buffer */
	    if (*p == '\n' || l < 1)		/* end of line/buffer */
		break;
	}
    }
/*    row[i+1] = NULL;	terminate the row list, currently unnecessary */
    return row;					/* NULL return ==> error */
}

int system_user_count(void)
{
  int users;

  users=who();
  return users;
}

int who(void)
{
  int users;

  users=read_utmp(UTMP_FILE);
  return list_entries(users);
}

int read_utmp (filename)
        char *filename;
{
  FILE *utmp;
  struct stat file_stats;
  int n_read;
  size_t size;

  utmp = fopen (filename, "r");
  if (utmp == NULL) return 0;

  fstat (fileno (utmp), &file_stats);
  size = file_stats.st_size;
  if (size > 0)
    utmp_contents = (STRUCT_UTMP *) xmalloc (size);
  else
    {
      fclose (utmp);
      return 0;
    }

  /* Use < instead of != in case the utmp just grew.  */
  n_read = fread (utmp_contents, 1, size, utmp);
  if (ferror (utmp) || fclose (utmp) == EOF || n_read < size) return 0;

  return size / sizeof (STRUCT_UTMP);
}
int list_entries (n)
     int n;
{
  register STRUCT_UTMP *this = utmp_contents;
  register int entries = 0;

  while (n--)
    {
      if (this->ut_name[0]
#ifdef USER_PROCESS
          && this->ut_type == USER_PROCESS
#endif
         )
        {
          char trimmed_name[sizeof (this->ut_name) + 1];
          int i;

          strncpy (trimmed_name, this->ut_name, sizeof (this->ut_name));
          trimmed_name[sizeof (this->ut_name)] = ' ';
          for (i = 0; i <= sizeof (this->ut_name); i++)
            {
              if (trimmed_name[i] == ' ')
                break;
            }
          trimmed_name[i] = '\0';

          /* tprintf("%s ", trimmed_name); */
          entries++;
        }
      this++;
    }
  return entries;
}

char *fixup_null_alloc (n)
     size_t n;
{
  char *p;

  p = 0;
  if (n == 0)
    p = malloc ((size_t) 1);
  if (p == 0) return NULL;
  return p;
}

/* Allocate N bytes of memory dynamically, with error checking.  */

char *xmalloc (n)
     size_t n;
{
  char *p;

  p = malloc (n);
  if (p == 0)
    p = fixup_null_alloc (n);
  return p;
}
