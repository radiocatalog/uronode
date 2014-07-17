#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>
#include <netax25/mheard.h>

#include "node.h"
#include "procinfo.h"
#include "sysinfo.h"

struct cmd *Nodecmds = NULL;

void init_nodecmds(void)
{
  add_internal_cmd(&Nodecmds, "?",        1, do_help);
  add_internal_cmd(&Nodecmds, "Bye",      1, do_bye);
  add_internal_cmd(&Nodecmds, "Escape",   1, do_escape);
  if (User.ul_type == AF_INET) {
    add_internal_cmd(&Nodecmds, "EXit",	  1, do_bye);
  }
  add_internal_cmd(&Nodecmds, "Help",     1, do_help);
  add_internal_cmd(&Nodecmds, "Info",     1, do_help);
  add_internal_cmd(&Nodecmds, "Quit",     1, do_bye);
  add_internal_cmd(&Nodecmds, "Status",   1, do_status);
  add_internal_cmd(&Nodecmds, "Version",  1, do_version);
#ifdef HAVEMOTD
  add_internal_cmd(&Nodecmds, "Who",      1, do_last);
#endif
  add_internal_cmd(&Nodecmds, "MSg",	  2, do_msg);
#ifdef HAVE_AX25
  add_internal_cmd(&Nodecmds, "Connect",  1, do_connect);
  add_internal_cmd(&Nodecmds, "Links",    1, do_links);
  add_internal_cmd(&Nodecmds, "INTerfaces",    3, do_ports);
  add_internal_cmd(&Nodecmds, "SEssions", 2, do_sessions);
  add_internal_cmd(&Nodecmds, "Users",    1, nuser_list);
#ifdef HAVE_FLEX
  add_internal_cmd(&Nodecmds, "Desti",    1, do_dest);
#endif
#ifdef HAVE_MHEARD
  add_internal_cmd(&Nodecmds, "MHeard",   2, do_mheard);
#endif
#ifdef HAVE_NETROM
  add_internal_cmd(&Nodecmds, "Nodes",    1, do_nodes);
  add_internal_cmd(&Nodecmds, "Routes",   1, do_routes);
#endif
#endif
#ifdef HAVE_TCPIP
  add_internal_cmd(&Nodecmds, "Finger",   1, do_finger); 
  add_internal_cmd(&Nodecmds, "HOst",     2, do_host);
  add_internal_cmd(&Nodecmds, "Ping",     1, do_ping);
  add_internal_cmd(&Nodecmds, "Telnet",   1, do_connect);
#endif
#ifdef HAVE_ZLIB_H
  add_internal_cmd(&Nodecmds, "ZConnect", 1, do_connect);
  add_internal_cmd(&Nodecmds, "ZTelnet",  1, do_connect);
#endif
};

void node_prompt(const char *fmt, ...)
{
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if ((User.ul_type == AF_INET) && (check_perms(PERM_ANSI, 0L) != -1)) {
    axio_printf(NodeIo,"\r\n\e[01;31m%s\e[0m@\e[01;34m%s\e[0m:/uronode$ ",User.call, HostName);
  }
  if ((User.ul_type == AF_INET) && (check_perms(PERM_ANSI, 0L) == -1)) {
    axio_printf(NodeIo,"\r\n%s@%s:/uronode$ ", User.call, HostName);
  }
  if ((User.ul_type == AF_AX25) && (check_perms(PERM_ANSI, 0L) != -1)) {
    axio_printf(NodeIo,"\e[01;33m");
  }
  if (User.ul_type == AF_AX25) {
    axio_printf(NodeIo,"%s",Prompt);
  }
  /*	if ((User.ul_type == AF_AX25) && (check_perms(PERM_ANSI, 0L) != -1)) {
	axio_printf(NodeIo,"\e[0m \b");
	}  
  */
  axio_flush(NodeIo);
}

void node_logout(char *reason)
{
#ifdef HAVEMOTD
  if (User.ul_type == AF_INET) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[03;36m");
    }
    axio_printf(NodeIo, "Thank you %s, for connecting to the \n%s URONode packet shell.\n", User.call, HostName);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
  } 
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"");
  } 
  if ((User.ul_type == AF_FLEXNET) || (User.ul_type == AF_AX25)) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[03;36m");
    }
    axio_printf(NodeIo, "%s de %s\n73!  ", User.call, FlexId);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
  }
#endif
  axio_flush(NodeIo);
  axio_end_all();
  logout_user();
  ipc_close();
  node_log(LOGLVL_LOGIN, "%s @ %s logged out", User.call, User.ul_name);
  node_log(LOGLVL_LOGIN, "%s %s", NodeId, reason);
  free_cmdlist(Nodecmds);
  Nodecmds = NULL;
  exit(0);
}

int do_bye(int argc, char **argv)
{
  node_logout("User hit bye or quit");
  return 0;	/* Keep gcc happy */
}

int do_escape(int argc, char **argv)
{
  int now = 0;

  if (argc > 1) {
    EscChar = get_escape(argv[1]);
    now = 1;
  }
  if (EscChar < -1 || EscChar > 255) {
    if (User.ul_type == AF_NETROM) {
      node_msg("%s} ", NodeId);
    }
    node_msg("Invalid escape character: %s", argv[1]);
    return 0;
  }
  
  if (EscChar == -1) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    axio_printf(NodeIo,"The escape mechanism is %sdisabled", now ? "now " : "");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo, "%s} ", NodeId);
  }
  axio_printf(NodeIo,"The escape character is %s%s%c", 
	      now ? "now " : "",
	      EscChar < 32 ? "CTRL-" : "",
	      EscChar < 32 ? (EscChar + 'A' - 1) : EscChar);
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_help(int argc, char **argv)
{
  FILE *fp;
  char fname[256], line[256];
  struct cmd *cmdp;
  int i = 0;

  if (*argv[0] == '?') {                          /* "?"          */
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    if (User.ul_type == AF_INET)  {
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[01;37m");
      }
      axio_printf(NodeIo, "Shell ");
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;37m");
    }
    axio_printf(NodeIo,"Commands:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    for (cmdp = Nodecmds; cmdp != NULL; cmdp = cmdp->next) {
      axio_printf(NodeIo,"%s%s", i ? ", " : "\n", cmdp->name);
      if (++i == 10) {
	axio_printf(NodeIo,"");
	i = 0;
      }
    }
    if (i) axio_printf(NodeIo,"");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if (argv[1] && strchr(argv[1], '/')) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    node_msg("Invalid command %s", argv[1]);
    return 0;
  }
  if (*argv[0] == 'i') {                          /* "info"       */
    strcpy(fname, CONF_NODE_INFO_FILE);
    if (User.ul_type == AF_NETROM) {

      axio_printf(NodeIo,"%s} ", NodeId);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;37m");
    }
    axio_printf(NodeIo,"System Information:\n");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"%s - %s \n", VERSION, COMPILING);
  } else if (!argv[1]) {                 /* "help"       */
    strcpy(fname, DATA_NODE_HELP_DIR "help.hlp");
  } else {                               /* "help <cmd>" */
    strlwr(argv[1]);
    snprintf(fname, sizeof(fname), DATA_NODE_HELP_DIR "%s.hlp", argv[1]);
    fname[sizeof(fname) - 1] = 0;
  }
  if ((fp = fopen(fname, "r")) == NULL) {
    if (*argv[0] != 'i')
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
    axio_printf(NodeIo,"No help for command %s", argv[1] ? argv[1] : "help");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if (*argv[0] != 'i')
    node_msg("Help for command %s", argv[1] ? argv[1] : "help"); 
  while (fgets(line, 256, fp) != NULL)
    axio_puts(line,NodeIo);
  fclose(fp);
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_host(int argc, char **argv)
{
  struct hostent *h;
  struct in_addr addr;
  char **p, *cp;
  
  if (argc < 2) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    node_msg("Usage: host <hostname>|<ip address>");
    return 0;
  }
  if (inet_aton(argv[1], &addr) != 0)
    h = gethostbyaddr((char *)&addr, sizeof(addr), AF_INET);
  else
    h = gethostbyname(argv[1]);
  if (h == NULL) {
    switch (h_errno) {
    case HOST_NOT_FOUND:
      cp = "Unknown host";
      break;
    case TRY_AGAIN:
      cp = "Temporary name server error";
      break;
    case NO_RECOVERY:
      cp = "Non-recoverable name server error";
      break;
    case NO_ADDRESS:
      cp = "No address";
      break;
    default:
      cp = "Unknown error";
      break;
    }
    node_msg("%s", cp);
    return 0;
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  node_msg("Host name information for %s:", argv[1]);
  axio_printf(NodeIo,"Hostname:    %s", h->h_name); 
  axio_puts("\nAliases:    ",NodeIo);
  p = h->h_aliases;
  while (*p != NULL) {
    axio_printf(NodeIo," %s", *p);
    p++;
  }
  axio_puts("\nAddress(es):",NodeIo);
  p = h->h_addr_list;
  while (*p != NULL) {
    addr.s_addr = ((struct in_addr *)(*p))->s_addr;
    axio_printf(NodeIo," %s", inet_ntoa(addr));
    p++;
  }
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_ports(int argc, char **argv)
{
  struct proc_ax25 *ax, *ax_list;
  struct proc_dev *dev, *dev_list;
  char *cp = NULL;
  int n, tx, rx;
  
  ax_list=read_proc_ax25();
  dev_list=read_proc_dev();
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[01;35m");
  }
  node_msg("Interfaces:");
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[0;m");
  }
  axio_printf(NodeIo,"Name    Description                                 QSO  RX packets  TX packets\n");
  axio_printf(NodeIo,"------- ------------------------------------------ ---- ----------- -----------");
  while ((cp = ax25_config_get_next(cp)) != NULL) {
    n=0;
    if (ax_list) for (ax=ax_list;ax!=NULL;ax=ax->next) {
	//      		if (strcmp(ax25_config_get_name(ax->dev), cp)==0 && strcmp(ax->dest_addr, "*")!=0) n++;
	if (strcmp(ax->dest_addr, "*")!=0 && strcmp(ax25_config_get_name(ax->dev), cp)==0) n++;
      }
    tx=0; rx=0;
    if (dev_list) for (dev=dev_list;dev!=NULL;dev=dev->next) {
	if (strcmp(dev->interface, ax25_config_get_dev(cp))==0) {
	  tx=dev->tx_packets;
	  rx=dev->rx_packets;
	}
      }
    if (is_hidden(cp) && check_perms(PERM_HIDDEN, 0L) == -1)
      continue;
    axio_printf(NodeIo,"\n%-7.7s %-42.42s %4d %11d %11d", cp, ax25_config_get_desc(cp), n, rx, tx);
  }

  free_proc_ax25(ax_list);
  free_proc_dev(dev_list);
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_sessions(int argc, char **argv)
{
  struct proc_ax25 *ax_p, *ax_list;
#ifdef HAVE_NETROM
  struct proc_nr *nr_p, *nr_list;
#endif
  char *cp;

  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} %s\n", NodeId, VERSION);
  }
  if ((ax_list = read_proc_ax25()) == NULL) {
    if (errno) node_perror("sessions: read_proc_ax25:", errno);
    else axio_printf (NodeIo,"No such AX25 sessions actives.");
    
  } else {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;33m");
    }
    node_msg("AX.25 Sessions:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[0;m");
    }
    axio_printf(NodeIo,"Int.    Dest addr Src addr  State        Unack T1      Retr   Rtt Snd-Q Rcv-Q\n");
    axio_printf(NodeIo,"------- --------- --------- ------------ ----- ------- ------ --- ----- -----\n");
    for (ax_p = ax_list; ax_p != NULL; ax_p = ax_p->next) {
      if (argc > 1 && strcasecmp(argv[1], "*") && strcasecmp(ax_p->dest_addr, argv[1]) && 
	  strcasecmp(ax_p->src_addr, argv[1])) continue;
      if ((argc < 2) && !strcmp(ax_p->dest_addr, "*"))
	continue;
      cp = ax25_config_get_name(ax_p->dev);
      axio_printf(NodeIo,"%-7s %-9s %-9s ", cp, ax_p->dest_addr, ax_p->src_addr);
      if (!strcmp(ax_p->dest_addr, "*")) {
	axio_printf(NodeIo,"Listening\n");
	continue;
      }
      switch (ax_p->st) {
      case 0:
	cp = "Disconnected";
	break;
      case 1:
	cp = "Conn pending";
	break;
      case 2:
	cp = "Disc pending";
	break;
      case 3:
	cp = "Connected   ";
	break;
      case 4:
	cp = "Recovery    ";
	break;
      default:
	cp = "Unknown     ";
	break;
      }
      axio_printf(NodeIo,"%s %02d/%02d %03d/%03d %02d/%03d %3d %5ld %5ld\n",
		  cp,
		  ax_p->vs < ax_p->va ? ax_p->vs - ax_p->va + 8 : ax_p->vs - ax_p->va,
		  ax_p->window,
		  ax_p->t1timer, ax_p->t1,
		  ax_p->n2count, ax_p->n2,
		  ax_p->rtt,
		  ax_p->sndq, ax_p->rcvq);
    }
    free_proc_ax25(ax_list);
    axio_puts("",NodeIo);
  }

#ifdef HAVE_NETROM
  if ((nr_list = read_proc_nr()) == NULL) {
    if (errno) node_perror("sessions: read_proc_nr", errno);
    else axio_printf (NodeIo,"No such NET/ROM sessions actives.\n");
  } else {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;36m");
    }
    node_msg("\nNET/ROM Sessions:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"User addr Dest node Src node  State        Unack T1      Retr   Snd-Q Rcv-Q\n");
    axio_printf(NodeIo,"--------- --------- --------- ------------ ----- ------- ------ ----- -----");
    for (nr_p = nr_list; nr_p != NULL; nr_p = nr_p->next) {
      if (argc > 1 && strcasecmp(argv[1], "*") && strcasecmp(nr_p->user_addr, argv[1]) && 
	  strcasecmp(nr_p->dest_node, argv[1]) && strcasecmp(nr_p->src_node, argv[1])) continue;
      if ((argc < 2) && !strcmp(nr_p->user_addr, "*")) continue;
      cp = nr_config_get_name(nr_p->dev);
      axio_printf(NodeIo,"\n%-9s %-9s %-9s ", nr_p->user_addr, nr_p->dest_node, nr_p->src_node);
      if (!strcmp(nr_p->user_addr, "*")) {
	axio_printf(NodeIo,"Listening\n");
	continue;
      }
      switch (nr_p->st) {
      case 0:
	cp = "Disconnected";
	break;
      case 1:
	cp = "Conn pending";
	break;
      case 2:
	cp = "Disc pending";
	break;
      case 3:
	cp = "Connected   ";
	break;
      case 4:
	cp = "Recovery    ";
	break;
      default:
	cp = "Unknown     ";
	break;
      }
      axio_printf(NodeIo,"%s %02d/%02d %03d/%03d %02d/%03d %5ld %5ld",
		  cp,
		  nr_p->vs < nr_p->va ? nr_p->vs - nr_p->va + 8 : nr_p->vs - nr_p->va,
		  nr_p->window,
		  nr_p->t1timer, nr_p->t1,
		  nr_p->n2count, nr_p->n2,
		  nr_p->sndq, nr_p->rcvq);
    }
    free_proc_nr(nr_list);
  }

#endif
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_routes(int argc, char **argv)
{
  struct proc_nr *nr, *nr_list;
  struct proc_nr_neigh *nrh, *nrh_list;
  struct proc_nr_nodes *nrn, *nrn_list;
  struct proc_ax25 *ap;
  char *cp, portcall[10];
  int link, n;

  nr_list=read_proc_nr();
  nrn_list=read_proc_nr_nodes();
  if ((nrh_list = read_proc_nr_neigh()) == NULL) {
    if (errno) node_perror("do_routes: read_proc_nr_neigh", errno);
    else 
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
    axio_printf (NodeIo,"No such routes");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    free_proc_nr_neigh(nrh_list);
    free_proc_nr_nodes(nrn_list);
    free_proc_nr(nr_list);

    return 0;
  }
  /*	if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[01;33m");
	} */
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[01;36m");
  }
  node_msg("Routes:");
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[0;m");
  }
  axio_printf(NodeIo,"Link Intface Callsign  Qual Nodes Lock  QSO\n");
  axio_printf(NodeIo,"---- ------- --------- ---- ----- ----  ---");
  strcpy(portcall,nr_config_get_addr(nr_config_get_next(NULL)));
  if (strchr(portcall, '-')==NULL) strcat(portcall, "-0");  
  for (nrh = nrh_list; nrh != NULL; nrh = nrh->next) {
    link=0; n=0;
    if ((ap = find_link(portcall, nrh->call, nrh->dev)) != NULL && ap->st >= 3) link = 1;
    if ((ap = find_link(nrh->call, portcall, nrh->dev)) != NULL && ap->st >= 3) link = 2;
    cp = ax25_config_get_name(nrh->dev);

    if (nr_list) for (nr=nr_list;nr!=NULL;nr=nr->next) {
	if (strcmp(nr->dest_node, nrh->call)==0) {
	  n++;
	} else {
	  if (nrn_list) for(nrn=nrn_list;nrn!=NULL;nrn=nrn->next) {
	      if (strcmp(nrn->call, nr->dest_node)==0) {
		switch(nrn->w) {
		case 1: if (nrn->addr1==nrh->addr) n++; break;
		case 2: if (nrn->addr2==nrh->addr) n++; break;
		case 3: if (nrn->addr3==nrh->addr) n++; break;
		}
	      }
	    }
	}
      }
    
    axio_printf(NodeIo,"\n%c    %-7s %-9s %4d %5d    %c %4d",
		link == 0 ? ' ' : '>',
		cp,
		nrh->call,
		nrh->qual,
		nrh->cnt,
		nrh->lock == 1 ? '!' : ' ',
		n);
  }

  free_proc_nr_neigh(nrh_list);
  free_proc_nr_nodes(nrn_list);
  free_proc_nr(nr_list);
  free_proc_ax25(ap);
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_nodes(int argc, char **argv)
{
  struct proc_nr_nodes *p, *list;
  struct proc_nr_neigh *np, *nlist;
  int i = 0;
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if ((list = read_proc_nr_nodes()) == NULL) {
    if (errno)
      node_perror("do_nodes: read_proc_nr_nodes", errno);
    else 
      axio_printf(NodeIo,"No known nodes");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  /* "nodes" */
  if (argc == 1) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;36m");
    } else if (check_perms(PERM_ANSI, 0L) == -1) {
      axio_printf(NodeIo, "");
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;36m");
    }
    node_msg("Nodes:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    for (p = list; p != NULL; p = p->next) {
      axio_printf(NodeIo,"%-16.16s %c",print_node(p->alias, p->call),(++i % 4) ? ' ' : '\n');
    }
    if ((User.ul_type == AF_NETROM) && (i % 4) != 0) {
	node_msg("");
    }
    free_proc_nr_nodes(list);
    return 0;
  }
  if ((nlist = read_proc_nr_neigh()) == NULL) {
    node_perror("do_nodes: read_proc_nr_neigh", errno);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    } 
    return 0; 
  }
  /* "nodes *" */
  if (*argv[1] == '*') {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;36m");
    }

    node_msg("Detailed nodes listing:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Node              Qual Obs Intface Neighbour\n");
    axio_printf(NodeIo,"----------------- ---- --- ------- ---------");
    for (p = list; p != NULL; p = p->next) {
      axio_printf(NodeIo,"\n%-16.16s  ", print_node(p->alias, p->call));
      if ((np = find_neigh(p->addr1, nlist)) != NULL) {
	axio_printf(NodeIo,"%4d %3d %-7s %s",p->qual1,p->obs1,ax25_config_get_name(np->dev),np->call);
      }
      else if (p->n > 1 && (np = find_neigh(p->addr2, nlist)) != NULL) {
	axio_printf(NodeIo,"                  ");
	axio_printf(NodeIo,"%7d %12d %-7s %s",p->qual2, p->obs2,ax25_config_get_name(np->dev),np->call);
      }
      else if (p->n > 2 && (np = find_neigh(p->addr3, nlist)) != NULL) {
	axio_printf(NodeIo,"                  ");
	axio_printf(NodeIo,"%7d %12d %-7s %s",p->qual3, p->obs3,ax25_config_get_name(np->dev),np->call);
      }
      else if (p->n == 0) axio_puts("",NodeIo); 
    }
    free_proc_nr_nodes(list);
    free_proc_nr_neigh(nlist);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  /* "nodes <node>" */
  p = find_node(argv[1], list);
  if (p != NULL) {
    if (p->n == 0)  axio_printf(NodeIo,"Local node without routes: %s", print_node(p->alias, p->call));
    else {
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[01;36m");
      }
      node_msg("Routes to: %s", print_node(p->alias, p->call));
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[0;m");
      }
      axio_printf(NodeIo,"Which Qual Obs Intface Neighbour\n");
      axio_printf(NodeIo,"----- ---- --- ------- ---------");

      if ((np = find_neigh(p->addr1, nlist)) != NULL) {
	axio_printf(NodeIo,"\n%c     %4d %3d %-7s %s",p->w == 1 ? '>' : ' ',p->qual1,p->obs1,
		    ax25_config_get_name(np->dev),np->call);
      }
      if (p->n > 1 && (np = find_neigh(p->addr2, nlist)) != NULL) {
	axio_printf(NodeIo,"\n%c     %4d %3d %-7s %s",p->w == 2 ? '>' : ' ',p->qual2, p->obs2,
		    ax25_config_get_name(np->dev),np->call);
      }
      if (p->n > 1 && (np = find_neigh(p->addr3, nlist)) != NULL) {
	axio_printf(NodeIo,"\n%c     %4d %3d %-7s %s",p->w == 3 ? '>' : ' ',p->qual3, p->obs3,
		    ax25_config_get_name(np->dev),np->call);
      }
    }
  } else {
    axio_printf(NodeIo,"No such node");
  }
  free_proc_nr_nodes(list);
  free_proc_nr_neigh(nlist);
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

/*
 * by Heikki Hannikainen <hessu@pspt.fi> 
 * The following was mostly learnt from the procps package and the
 * gnu sh-utils (mainly uname).
 */
int do_status(int argc, char **argv)
{
  int upminutes, uphours, updays;
  double uptime_secs, idle_secs;
  double av[3];
  unsigned **mem;
  struct utsname name;
  time_t t;
#ifdef HAVE_AX25
  struct flex_dst *fd, *fd_list;
  struct ax_routes *ar, *ar_list;
  struct proc_ax25 *ax, *ax_list;
#ifdef HAVE_NETROM
  struct proc_nr *nr, *nr_list;
  struct proc_nr_nodes *nop, *nolist;
  struct proc_nr_neigh *nep, *nelist;
  int n, r, nn;
#endif
  int na, nl, nd;
#endif
  int ma, mu, mf, sa, su, sf;
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[01;37m");
  }
  node_msg("Status:");
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[0;m");
  }
  time(&t);
  axio_printf(NodeIo,"System time:       %s", ctime(&t));
  if (uname(&name) == -1) axio_printf(NodeIo,"Cannot get system name\n");
  else {
    axio_printf(NodeIo,"Hostname:          %s\n", HostName);  
    axio_printf(NodeIo,"Operating system:  %s %s (%s)\n", name.sysname, name.release, name.machine);
  }
  /* read and calculate the amount of uptime and format it nicely */
  uptime(&uptime_secs, &idle_secs);
  updays = (int) uptime_secs / (60*60*24);
  upminutes = (int) uptime_secs / 60;
  uphours = upminutes / 60;
  uphours = uphours % 24;
  upminutes = upminutes % 60;
  axio_printf(NodeIo,"Uptime:            ");
  if (updays) axio_printf(NodeIo,"%d day%s, ", updays, (updays != 1) ? "s" : "");
  if(uphours) axio_printf(NodeIo,"%d hour%s ", uphours, (uphours != 1) ? "s" : "");
  axio_printf(NodeIo,"%d minute%s\n", upminutes, (upminutes != 1) ? "s" : "");
  loadavg(&av[0], &av[1], &av[2]);
  axio_printf(NodeIo,"Load average:      %.2f, %.2f, %.2f\n", av[0], av[1], av[2]);
  axio_printf(NodeIo,"Users:             %d node, %d system\n", user_count(), system_user_count());

  if (!(mem = meminfo()) || mem[meminfo_main][meminfo_total] == 0) {
    /* cannot normalize mem usage */
    axio_printf(NodeIo,"Cannot get memory information!\n"); 
  } else  {
    ma = mem[meminfo_main][meminfo_total];
    mu = (mem[meminfo_main][meminfo_total] - mem[meminfo_free][meminfo_total]);
    mf = mem[meminfo_free][meminfo_total];
    axio_printf(NodeIo,"Memory:            Available  Used       Free       perc. Used\n");
    axio_printf(NodeIo,"------------------ ---------- ---------- ---------- ----------\n");
    axio_printf(NodeIo,"Physical:          %-7d kB %-7d kB %-7d kB %3d %%\n", ma, mu, mf, (mu*100)/ma);
    
    if  (!(mem = meminfo()) || mem[meminfo_stotal][meminfo_total] != 0) 
{ 
    sa = mem[meminfo_stotal][meminfo_total]; 
    su = (mem[meminfo_stotal][meminfo_total] - mem[meminfo_sfree][meminfo_total]);
    sf = mem[meminfo_sfree][meminfo_total];
    axio_printf(NodeIo,"Swap:              %-7d kB %-7d kB %-7d kB %3d %%\n",sa,su,sf,(su*100)/sa);   
    } 
    else 
/*    axio_printf(NodeIo,"Cannot get swap information!\n"); */
      axio_printf(NodeIo," ");
    
  }

#ifdef HAVE_AX25
#ifdef HAVE_NETROM
  if ((nolist = read_proc_nr_nodes()) == NULL && errno != 0)
    node_perror("sessions: read_proc_nr_nodes", errno);
  n = 0;
  for (nop = nolist; nop != NULL; nop = nop->next)
    n++;
  free_proc_nr_nodes(nolist);
  if ((nelist = read_proc_nr_neigh()) == NULL && errno != 0)
    node_perror("sessions: read_proc_nr_neigh", errno);
  r = 0;
  for (nep = nelist; nep != NULL; nep = nep->next)
    r++;
  free_proc_nr_neigh(nelist);
#endif
  na=0;
  ax_list=read_proc_ax25();
  if (ax_list) for (ax=ax_list;ax!=NULL;ax=ax->next) {
      if (strcmp(ax->dest_addr, "*")==0) continue;
      na++;
    }
  free_proc_ax25(ax_list);
#ifdef HAVE_NETROM
  nn=0;
  nr_list=read_proc_nr();
  if (nr_list) for (nr=nr_list;nr!=NULL;nr=nr->next) {
      if (strcmp(nr->dest_node, "*")==0) continue;
      nn++;
    }
  free_proc_nr(nr_list);
#endif
  nl=0;
  ar_list=read_ax_routes();
  if (ar_list) for (ar=ar_list;ar!=NULL;ar=ar->next) {
      nl++;
    }
  free_ax_routes(ar_list);
  nd=0;
  fd_list=read_flex_dst();
  if (fd_list) for (fd=fd_list;fd!=NULL;fd=fd->next) {
      nd++;
    }
  free_flex_dst(fd_list);

  axio_printf(NodeIo,"Sockets:           Sessions   Dest/Nodes Links/Routes\n");
  axio_printf(NodeIo,"------------------ ---------- ---------- ------------\n");
  axio_printf(NodeIo,"AX25:              %-10d %-10d %-10d\n",na,nd,nl);
#ifdef HAVE_NETROM
  axio_printf(NodeIo,"NET/ROM:           %-10d %-10d %-10d",nn,n,r);
#endif
#endif
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int do_version(int argc, char **argv)
{
  if (User.ul_type != AF_NETROM) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;37mShell    : %s\n\e[01;35mHostname : %s\n\e[01;33max25/Flex: %s\n\e[01;36mNetRom   : %s\e[0;m", VERSION, HostName, FlexId, NodeId); 
      return 0;
    }
    if (check_perms(PERM_ANSI, 0L) == -1) {
      axio_printf(NodeIo,"Shell    : %s\nHostname : %s\nax25/Flex: %s\nNetRom   : %s", VERSION, HostName, FlexId, NodeId);
      return 0;
    }
    /*
      if (User.ul_type != AF_NETROM) {
      axio_printf(NodeIo, "Version  : %s\nax25/Flex: %s\nNetRom   : %s", VERSION, FlexId, NodeId);
      return 0;
      }
    */
  } else
    axio_printf(NodeIo,"%s} ", NodeId);
  if (check_perms(PERM_ANSI ,0L) != -1) {
    axio_printf(NodeIo,"\e[01;37m");
  }
  axio_printf(NodeIo,"%s", VERSION);
  node_msg("");
  if (check_perms(PERM_ANSI ,0L) != -1) {
    axio_printf(NodeIo,"\e[0;m");
  }
  return 0;
}
int nuser_list(int argc, char **argv)
{
  FILE *f;
  struct user u;
  struct tm *tp;
  struct proc_nr_nodes *np;
  char buf[80];
  long l;
  axio_puts("",NodeIo);
  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return 0;
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo, "%s} ", NodeId);
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[01;37m");
  } 
  if (User.ul_type == AF_NETROM) {
    /*	   axio_printf(NodeIo, "\e[0;m%s} %s", NodeId, VERSION); */
    axio_printf(NodeIo, "%s", VERSION);
  } else {
    axio_printf(NodeIo, "Current users:");
  }
  if (user_count() == 0) {
    axio_printf(NodeIo, " No users online.\n");
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo,"\e[0;m");
  }
  if (user_count() != 0) /* axio_printf(NodeIo,"") */ ;
  while (fread(&u, sizeof(u), 1, f) == 1) {
    if (u.pid == -1 || (kill(u.pid, 0) == -1 && errno == ESRCH))
      continue;
    switch (u.ul_type) {
    case AF_FLEXNET:
      sprintf(buf, "\nFlexNet (%.9s)",
	      u.call);
      break;
    case AF_AX25:
      sprintf(buf, "\nUplink (%.9s on interface %.10s)",
	      u.call, u.ul_name);
      break;
    case AF_NETROM:
      if ((np = find_node(u.ul_name, NULL)) != NULL) {
	sprintf(buf, "\nCircuit (%.9s %.18s)",
		u.call,
		print_node(np->alias, np->call));
      } else {
	sprintf(buf, "\nCircuit (%.9s %.18s)",
		u.call, u.ul_name);
      }
      break;
#ifdef HAVE_ROSE
    case AF_ROSE:
      sprintf(buf, "\nROSE (%.9s %.18s)",
	      u.call, u.ul_name);
      break;
#endif
    case AF_INET:
      sprintf(buf, "\nTelnet (%.9s @ %.16s)",
	      u.call, u.ul_name);
      break;
    case AF_UNSPEC:
      sprintf(buf, "\nHost (%.9s on local)",
	      u.call);
      break;
    default:
      sprintf(buf, "\n?????? (%.9s %.18s)",
	      u.call, u.ul_name);
      break;
    }
    axio_printf(NodeIo,"%-37.37s ", buf);
    switch (u.state) {
    case STATE_QUIT:
      logout_user();
      break;
    case STATE_LOGIN:
      axio_puts("  -> Logging in",NodeIo);
      break;
    case STATE_IDLE:
      time(&l);
      l -= u.cmdtime;
      tp = gmtime(&l);
      axio_printf(NodeIo,"  -> Idle (%d:%02d:%02d:%02d)",
		  tp->tm_yday, tp->tm_hour,
		  tp->tm_min, tp->tm_sec);
      break;
    case STATE_TRYING:
      switch (u.dl_type) {
      case AF_FLEXNET:
	axio_printf(NodeIo,"  -> Trying (%s)",
		    u.dl_name);
	break;
      case AF_AX25:
	axio_printf(NodeIo,"  -> Trying (%s on interface %s)",
		    u.dl_name, u.dl_port);
	break;
      case AF_NETROM:
	axio_printf(NodeIo,"  -> Trying (%s)",
		    u.dl_name);
	break;
#ifdef HAVE_ROSE
      case AF_ROSE:
	axio_printf(NodeIo,"  -> Trying (%s)",
		    u.dl_name);
	break;
#endif
      case AF_INET:
	axio_printf(NodeIo,"  -> Trying (%s:%s)",
		    u.dl_name, u.dl_port);
	break;
      default:
	axio_puts("  -> ???",NodeIo);
	break;
      }
      break;
    case STATE_CONNECTED:
      switch (u.dl_type) {
      case AF_FLEXNET:
	axio_printf(NodeIo,"<--> FlexNet (%s)",
		    u.dl_name);
	break;
      case AF_AX25:
	axio_printf(NodeIo,"<--> Downlink (%s on interface %s)",
		    u.dl_name, u.dl_port);
	break;
      case AF_NETROM:
	axio_printf(NodeIo,"<--> Circuit (%s)",
		    u.dl_name);
	break;
#ifdef HAVE_ROSE
      case AF_ROSE:
	axio_printf(NodeIo,"<--> ROSE (%s)",
		    u.dl_name);
	break;
#endif
      case AF_INET:
	axio_printf(NodeIo,"<--> Telnet (%s:%s)",
		    u.dl_name, u.dl_port);
	break;
      default:
	axio_printf(NodeIo,"<--> ???");
	break;
      }
      break;
    case STATE_PINGING:
      axio_printf(NodeIo,"<--> Pinging (%s)", u.dl_name);
      break;
    case STATE_EXTCMD:
      axio_printf(NodeIo,"<--> Extcmd  (%s)", u.dl_name);
      break;
    }
    axio_puts("",NodeIo);
  }
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  fclose(f);
  return 0;
}
