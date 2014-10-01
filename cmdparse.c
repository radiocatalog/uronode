#include <stdlib.h>
#include <ctype.h>
#include <string.h>


#include <sys/socket.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>

#include "node.h"

static void expand_string(char *dest, char *src, int argc, char **argv)
{
  char tmpbuf[64], def[64];
  char *p1, *p2, *cp;
  int n, skip, nocopy;

  if (strchr(src, '%') == NULL) {
    strcpy(dest, src);
    return;
  }
  p1 = src;
  p2 = dest;
  while (*p1) {
    if (*p1 == '%') {
      nocopy=1;
      p1++;
      skip = 1;
      def[0] = 0;
      if (*p1 == '{') {
	p1++;
	if ((cp = strchr(p1, '}')) != NULL) {
	  skip = cp - p1 + 1;
	  cp = p1;
	  if (*++cp == ':') {
	    cp++;
	    n = min(skip - 3, 63);
	    strncpy(def, cp, n);
	    def[n] = 0;
	  }
	}
      }
      switch (*p1) {
      case 'u':
      case 'U':
	strcpy(tmpbuf, User.call);
	if ((cp = strrchr(tmpbuf, '-'))) *cp = 0;
	break;
      case 's':
      case 'S':
	strcpy(tmpbuf, User.call);
	break;
      case 'p':
      case 'P':
	strcpy(tmpbuf, User.ul_name);
	if ((cp = strrchr(tmpbuf, '-'))) *cp = 0;
	break;
      case 'r':
      case 'R':
	strcpy(tmpbuf, User.ul_name);
	break;
      case 't':
      case 'T':
	switch (User.ul_type) {
	case AF_FLEXNET:
	  strcpy(tmpbuf, "flexnet");
	  break;
	case AF_AX25:
	  strcpy(tmpbuf, "ax25");
	  break;
	case AF_NETROM:
	  strcpy(tmpbuf, "netrom");
	  break;
#ifdef HAVE_ROSE	  
	case AF_ROSE:
	  strcpy(tmpbuf, "rose");
	  break;
#endif	  
	case AF_INET:
	  strcpy(tmpbuf, "inet");
	  break;
	case AF_UNSPEC:
	  strcpy(tmpbuf, "host");
	  break;
	}
	break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
	n = *p1 - '0';
	if (n < argc) strcpy(tmpbuf, argv[n]);
	else          strcpy(tmpbuf, def);
	break;
      case '*':
	nocopy=0;
	for(n=2;n<argc;n++) {
	  if (argv[n]==NULL) break;
	  strcpy(tmpbuf, argv[n]);
	  if (isalpha(*p1)) {
	    if (isupper(*p1)) strupr(tmpbuf);
	    else              strlwr(tmpbuf);
	  }
	  strcpy(p2, tmpbuf);
	  p2 += strlen(tmpbuf);
	}
	break;
      default:
	strcpy(tmpbuf, "%");
	break;
      }
      if (nocopy==1) {
	if (isalpha(*p1)) {
	  if (isupper(*p1)) strupr(tmpbuf);
	  else              strlwr(tmpbuf);
	}
	strcpy(p2, tmpbuf);
	p2 += strlen(tmpbuf);
      }
      p1 += skip;
    } else
      *p2++ = *p1++;
  }
  *p2 = 0;
  return;
}

/* This function is straight from *NOS */

static char *parse_string(char *str)
{
  char *cp = str;
  unsigned long num;

  while (*str != '\0' && *str != '\"') {
    if (*str == '\\') {
      str++;
      switch (*str++) {
      case 'n':  *cp++ = '\n';   break;
      case 't':  *cp++ = '\t';   break;
      case 'v':  *cp++ = '\v';   break;
      case 'b':  *cp++ = '\b';   break;
      case 'r':  *cp++ = '\r';   break;
      case 'f':  *cp++ = '\f';   break;
      case 'a':  *cp++ = '\007'; break;
      case '\\': *cp++ = '\\';   break;
      case '\"': *cp++ = '\"';   break;
      case 'x':
	num = strtoul(--str, &str, 16);
	*cp++ = (char) num;
	break;
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
	num = strtoul(--str, &str, 8);
	*cp++ = (char) num;
	break;
      case '\0':
	return NULL;
      default:
	*cp++ = *(str - 1);
	break;
      };
    } else {
      *cp++ = *str++;
    }
  }
  if (*str == '\"') str++; /* skip final quote */
  *cp = '\0';	        /* terminate string */
  return str;
}

int parse_args(char **argv, char *cmd)
{
  int ct = 0;
  int quoted;

  while (ct < 31) {
    quoted = 0;
    while (*cmd && isspace(*cmd)) cmd++;
    if (*cmd == 0) break;
    if (*cmd == '"') {
      quoted++;
      cmd++;
    }
    argv[ct++] = cmd;
    if (quoted) {
      if ((cmd = parse_string(cmd)) == NULL)
	return 0;
    } else {
      while (*cmd && !isspace(*cmd)) cmd++;
    }
    if (*cmd) *cmd++ = 0;
  }
  argv[ct] = NULL;
  return ct;
}

int cmdparse(struct cmd *list, char *cmdline)
{
  struct cmd *cmdp;
  int argc;
  char *argv[32];
  static char cmdbuf[1024];

  /* convert cmdline to argc,argv[]  if '#' or empty: return */
  if ((argc = parse_args(argv, cmdline)) == 0 || *argv[0] == '#') return 2;
  /* check if the command in argv[0] is in the list */
  for (cmdp = list; cmdp != NULL; cmdp = cmdp->next) {
    if (strlen(argv[0]) < cmdp->len || strlen(argv[0]) > strlen(cmdp->name)) continue;
    if (strncasecmp(cmdp->name, argv[0], strlen(argv[0])) == 0) break;
  }
  if (cmdp == NULL) return -1;
  strlwr(argv[0]);
  switch (cmdp->type) {
  case CMD_INTERNAL: /* execute internal command */
    return (*cmdp->function)(argc, argv);
  case CMD_ALIAS:
    /* evaluate arguments */
    expand_string(cmdbuf, cmdp->command, argc, argv);
    aliascmd=1;
    /* re-execute the command */
    return cmdparse(list, cmdbuf);
  case CMD_EXTERNAL:
    /* evaluate arguments */
    expand_string(cmdbuf, cmdp->command, argc, argv);
    /* convert the cmdline to argc,argv[] */
    argc = parse_args(argv, cmdbuf);
    /* execute an external command */
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;32mExecuting command...\e[0m\n");
    } else {
      axio_puts("Executing command... \n", NodeIo);
    }
    return extcmd(cmdp, argv);
  }
  return -1;
}

void insert_cmd(struct cmd **list, struct cmd *new)
{
  struct cmd *tmp, *p;

  if (*list == NULL || strcasecmp(new->name, (*list)->name) < 0) {
    tmp = *list;
    *list = new;
    new->next = tmp;
  } else {
    for (p = *list; p->next != NULL; p = p->next)
      if (strcasecmp(new->name, p->next->name) < 0) break;
    tmp = p->next;
    p->next = new;
    new->next = tmp;
  }
}

int add_internal_cmd(struct cmd **list, char *name, int len, int (*function) (int argc, char **argv))
{
  struct cmd *new;

  if ((new = calloc(1, sizeof(struct cmd))) == NULL) {
    node_perror("add_internal_cmd: calloc", errno);
    return -1;
  }
  new->name = strdup(name);
  new->len = len;
  new->type = CMD_INTERNAL;
  new->function = function;
  insert_cmd(list, new);
  return 0;
}

void free_cmdlist(struct cmd *list)
{
  struct cmd *tmp;

  while (list != NULL) {
    free(list->name);
    free(list->command);
    free(list->path);
    tmp = list;
    list = list->next;
    free(tmp);
  }
}
