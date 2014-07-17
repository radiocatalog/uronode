#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <netax25/ax25.h>			/* axutils.h needs this...	*/
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>

#include "node.h"

long IdleTimeout	= 360L;		/* default to 6 mins */
long ConnTimeout	= 300L;		/* default to 5 mins */
int ReConnectTo		= 0;
int LogLevel		= LOGLVL_ERROR;
int EscChar		= 20;		/* CTRL-T */

char *Email		= NULL;
char *HostName		= NULL;
char *NodeId		= NULL;
char *NrPort		= NULL;		/* first netrom port */
char *FlexId		= NULL;

#ifdef HAVEMOTD
char *Prompt		= "\n=> ";        /* Prompt by IZ5AWZ */
#else
char *Prompt		= "\n";
#endif
char *PassPrompt	= "\nPassword >";      /* Prompt Password by IZ5AWZ */

static unsigned long Permissions	= 0L;
static unsigned long LocalNet		= 0L;
static unsigned long LocalMask		= ~0L;
static char *HiddenPorts[32]		= {0};

/*
 * Return non-zero if `port' is a hidden port.
 */
int is_hidden(const char *port)
{
  int i;

  for (i = 0; HiddenPorts[i] != NULL && i < 31; i++)
    if (!strcmp(port, HiddenPorts[i]))
      return 1;
  return 0;
}

/*
 * Return non-zero if peer is on "local" or loopback network.
 */
static int is_local(unsigned long peer)
{
  return ((peer & LocalMask) == LocalNet) || ((peer & 0xff) == 127);
}

/*
 * Return non-zero if peer is on amprnet.
 */
static int is_ampr(unsigned long peer)
{
  return ((peer & 0xff) == 44);
}

/*
 * Convert NOS style width to a netmask in network byte order.
 */
static unsigned long bits_to_mask(int bits)
{
  return htonl(~0L << (32 - bits));
}

int check_perms(int what, unsigned long peer)
{
  if (what == PERM_TELNET) {
    if (is_local(peer)) {
      if (Permissions & PERM_TELNET_LOCAL)
	return 0;
    } else if (is_ampr(peer)) {
      if (Permissions & PERM_TELNET_AMPR)
	return 0;
    } else {
      if (Permissions & PERM_TELNET_INET)
	return 0;
    }
    return -1;
  }
  if ((Permissions & what) == 0) {
    return -1;
  }
  return 0;
}

/*
 * Read permissions file and return a password if needed or "*" if not.
 * If user access is denied return NULL.
 */
char *read_perms(struct user *up, unsigned long peer)
{
  FILE *fp;
  char line[256], *argv[32], *cp;
  int argc, n = 0;

  if ((fp = fopen(CONF_NODE_PERMS_FILE, "r")) == NULL) {
    node_perror(CONF_NODE_PERMS_FILE, errno);
    return NULL;
  }
  if ((cp = strchr(up->call, '-')) != NULL)
    *cp = 0;
  while (fgets(line, 256, fp) != NULL) {
    n++;
    argc = parse_args(argv, line);
    if (argc == 0 || *argv[0] == '#')
      continue;
    if (argc != 5) {
      node_msg("Configuration error");
      node_log(LOGLVL_ERROR, "Syntax error in permission file at line %d", n);
      break;
    }
    if (strcmp(argv[0], "*") && strcasecmp(argv[0], up->call))
      continue;
    switch (up->ul_type) {
    case AF_FLEXNET:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "flexnet"))
	break;
      continue;
    case AF_AX25:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "ax25"))
	break;
      continue;
    case AF_NETROM:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "netrom"))
	break;
      continue;
#ifdef HAVE_ROSE			
    case AF_ROSE:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "rose"))
	break;
      continue;
#endif			
    case AF_INET:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "local") && is_local(peer))
	break;
      if (!strcasecmp(argv[1], "ampr") && is_ampr(peer))
	break;
      if (!strcasecmp(argv[1], "inet") && !is_local(peer) && !is_ampr(peer))
	break;
      continue;
    case AF_UNSPEC:
      if (!strcmp(argv[1], "*"))
	break;
      if (!strcasecmp(argv[1], "host"))
	break;
      continue;
    }
    if (up->ul_type == AF_AX25) {
      if (strcmp(argv[2], "*") && strcmp(argv[2], up->ul_name))
	continue;
    }
    if (cp != NULL)
      *cp = '-';
    if ((Permissions = strtoul(argv[4], NULL, 10)) == 0)
      return NULL;
    else
      return strdup(argv[3]);
  }
  return NULL;
}

static int do_alias(int argc, char **argv)
{
  struct cmd *new;
  int len = 0;

  if (argc < 3)
    return -1;
  if ((new = calloc(1, sizeof(struct cmd))) == NULL) {
    node_perror("do_alias: malloc", errno);
    return -2;
  }
  new->name = strdup(argv[1]);
  while (isupper(new->name[len]))
    len++;
  /* Ok. So they can't read... */
  if (len == 0) {
    strupr(new->name);
    len = strlen(new->name);
  }
  new->len = len;
  new->command = strdup(argv[2]);
  new->type = CMD_ALIAS;
  insert_cmd(&Nodecmds, new);
  return 0;
}

static int do_loglevel(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  LogLevel = atoi(argv[1]);
  return 0;
}

int get_escape(char *s)
{
  int escape;
  char *endptr[1];

  if (isdigit(*s)) {
    escape = strtol(s, endptr, 0);
    if (**endptr)
      return -2;
    else
      return escape;
  }

  if (strlen(s) == 1)
    return *s;

  if (strlen(s) == 2 && *s == '^')
    return (toupper(*++s) - 'A' + 1);

  if (strcasecmp(s, "off") == 0 || strcmp(s, "-1") == 0)
    return -1;

  return -2;
}


static int do_escapechar(int argc, char **argv)
{
  if (argc < 2)
    return -1;

  EscChar = get_escape(argv[1]);

  if (EscChar < -1 || EscChar > 255) {
    node_msg("Configuration error");
    node_log(LOGLVL_ERROR, "do_escapechar: Invalid escape character %s",
	     argv[1]);
    return -2;
  }

  return 0;
}

static int do_idletimeout(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  IdleTimeout = atol(argv[1]);
  return 0;
}

static int do_conntimeout(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  ConnTimeout = atol(argv[1]);
  return 0;
}

static int do_hostname(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  HostName = strdup(argv[1]);
  return 0;
}

static int do_localnet(int argc, char **argv)
{
  char *cp;

  if (argc < 2)
    return -1;
  if ((cp = strchr(argv[1], '/')) != NULL) {
    *cp = 0;
    LocalMask = bits_to_mask(atoi(++cp));
  }
  LocalNet = inet_addr(argv[1]);
  LocalNet &= LocalMask;
  return 0;
}

static int do_reconnect(int argc, char **argv)
{
#ifdef HAVEMOTD
  if (argc < 2)
    return -1;
  if (!strcasecmp(argv[1], "on"))
    ReConnectTo = 1;
  else
#endif
    ReConnectTo = 0;
  return 0;
}

static int do_hiddenports(int argc, char **argv)
{
  int i;

  if (argc < 2)
    return -1;
  for (i = 1; i < argc && i < 31; i++) {
    if (ax25_config_get_dev(argv[i]) == NULL) {
      node_msg("Configuration error");
      node_log(LOGLVL_ERROR, "do_hiddenports: invalid port %s", argv[i]);
      return -2;
    }
    HiddenPorts[i - 1] = strdup(argv[i]);
  }
  HiddenPorts[i - 1] = NULL;
  return 0;
}

static int do_extcmd(int argc, char **argv)
{
  struct cmd *new;
  struct passwd *pw;
  char buf[1024];
  int i, len;

  if (argc < 6)
    return -1;
  if ((new = calloc(1, sizeof(struct cmd))) == NULL) {
    node_perror("do_extcmd: malloc", errno);
    return -2;
  }
  new->name = strdup(argv[1]);
  len = 0;
  while (isupper(new->name[len]))
    len++;
  /* Ok. So they can't read... */
  if (len == 0) {
    strupr(new->name);
    len = strlen(new->name);
  }
  new->len = len;
  new->flags = atoi(argv[2]);
  if ((pw = getpwnam(argv[3])) == NULL) {
    node_msg("Configuration error");
    node_log(LOGLVL_ERROR, "do_extcmd: Unknown user %s", argv[3]);
    return -2;
  }
  new->uid = pw->pw_uid;
  new->gid = pw->pw_gid;
  new->path = strdup(argv[4]);
  len = 0;
  for (i = 0; argv[i + 5] != NULL; i++) {
    sprintf(&buf[len], "\"%s\" ", argv[i + 5]);
    len = strlen(buf);
  }
  new->command = strdup(buf);
  new->type = CMD_EXTERNAL;
  insert_cmd(&Nodecmds, new);
  return 0;
}

static int do_nodeid(int argc, char **argv)
{
  if (User.ul_type == AF_NETROM) {
    if (argc < 2) 
      return -1;
    NodeId = strdup(argv[1]);
  }  else  if (User.ul_type != AF_NETROM) {
    NodeId = strdup(argv[1]);
  } 
  return 0;
}

static int do_flexid(int argc, char **argv)
{
  if (argc < 2 )
    return -1;
  FlexId = ("%s ;" , strdup(argv[1]));
  return 0;
}

static int do_prompt(int argc, char **argv)
{
  if ((User.ul_type != AF_NETROM) || (User.ul_type != AF_INET)) {
    if (argc < 2) {
      return -1;
      Prompt = strdup(argv[1]);
      return 0;
    }
  }
} 

static int do_passprompt(int argc, char **argv)
{
  if (User.ul_type != AF_NETROM) {
    if (argc < 2)
      return -1;
    PassPrompt = strdup(argv[1]);
    return 0;
  }
}

static int do_nrport(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  NrPort = strdup(argv[1]);
  return 0;
}

static int do_email(int argc, char **argv)
{
  if (argc < 2)
    return -1;
  Email = strdup(argv[1]);
  return 0;
}

int read_config(void)
{
  struct cmd *cfg_cmds = NULL;
  FILE *fp;
  char line[256];
  int ret, n = 0;

  add_internal_cmd(&cfg_cmds, "alias",       5,  do_alias);
  add_internal_cmd(&cfg_cmds, "conntimeout", 11, do_conntimeout);
  add_internal_cmd(&cfg_cmds, "email",	   5,  do_email);
  add_internal_cmd(&cfg_cmds, "escapechar",  10, do_escapechar);
  add_internal_cmd(&cfg_cmds, "extcmd",      6,  do_extcmd);
  add_internal_cmd(&cfg_cmds, "hiddenports", 11, do_hiddenports);
  add_internal_cmd(&cfg_cmds, "hostname",    8,  do_hostname);
  add_internal_cmd(&cfg_cmds, "idletimeout", 11, do_idletimeout);
  add_internal_cmd(&cfg_cmds, "localnet",    8,  do_localnet);
  add_internal_cmd(&cfg_cmds, "loglevel",    8,  do_loglevel);
  add_internal_cmd(&cfg_cmds, "nodeid",      6,  do_nodeid);
  add_internal_cmd(&cfg_cmds, "flexid",      6,  do_flexid); 
  add_internal_cmd(&cfg_cmds, "prompt",      6,  do_prompt);
  add_internal_cmd(&cfg_cmds, "nrport",      6,  do_nrport);
  add_internal_cmd(&cfg_cmds, "reconnect",   8,  do_reconnect);
  add_internal_cmd(&cfg_cmds, "passprompt",  6,  do_passprompt);

  if ((fp = fopen(CONF_NODE_FILE, "r")) == NULL) {
    node_perror(CONF_NODE_FILE, errno);
    return -1;
  }
  while (fgets(line, 256, fp) != NULL) {
    n++;
    ret = cmdparse(cfg_cmds, line);
    if (ret == -1) {
      node_msg("Configuration error");
      node_log(LOGLVL_ERROR, "Syntax error in config file at line %d: %s", n, line);
    }
    if (ret < 0) {
      fclose(fp);
      return -1;
    }
  }
  fclose(fp);
  free_cmdlist(cfg_cmds);
  cfg_cmds = NULL;
  return 0;
}
