#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>

#include "procinfo.h"
#include "node.h"

static void invert_ssid(char *out, char *in)
{
  char *cp;

  if ((cp = strchr(in, '-')) != NULL) {
    *cp = 0;
    sprintf(out, "%s-%d", in, 15 - atoi(cp + 1));
    *cp = '-';
  } else {
    sprintf(out, "%s-15", in);
  }
}

/*
 * Initiate a AX.25, NET/ROM, ROSE or TCP connection to the host
 * specified by `address'.
 */
static ax25io *connect_to(char **addr, int family, int escape, int compr)
{
  int fd;
  ax25io *riop;
  fd_set read_fdset;
  fd_set write_fdset;
  int salen;
  union {
    struct full_sockaddr_ax25 ax;
#ifdef HAVE_ROSE
    struct sockaddr_rose      rs;
#endif		
    struct sockaddr_in        in;
  } sa;
  char call[10], path[20], *cp, *eol;
  int ret, retlen = sizeof(int);
  int paclen;
  struct hostent *hp;
  struct servent *sp;
  struct user u;
#ifdef HAVE_NETROM
  struct proc_nr_nodes *np;
#endif

  strcpy(call, User.call);
  /*
   * Fill in protocol spesific stuff.
   */
  switch (family) {
#ifdef HAVE_ROSE	
  case AF_ROSE:
    if (aliascmd==0) {
      if (check_perms(PERM_ROSE, 0L) == -1) {
	axio_printf(NodeIo,"Permission denied");
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	node_log(LOGLVL_GW, "Permission denied: rose");
	return NULL;
      }
    }
    if ((fd = socket(AF_ROSE, SOCK_SEQPACKET, 0)) < 0) {
      node_perror("connect_to: socket", errno);
      return NULL;
    }
    sa.rs.srose_family = AF_ROSE;
    sa.rs.srose_ndigis = 0;
    ax25_aton_entry(call, sa.rs.srose_call.ax25_call);
    rose_aton(rs_config_get_addr(NULL), sa.rs.srose_addr.rose_addr);
    salen = sizeof(struct sockaddr_rose);
    if (bind(fd, (struct sockaddr *)&sa, salen) == -1) {
      node_perror("connect_to: bind", errno);
      close(fd);
      return NULL;
    }
    memset(path, 0, 11);
    memcpy(path, rs_config_get_addr(NULL), 4);
    salen = strlen(addr[1]);
    if ((salen != 6) && (salen != 10))
      {
	axio_printf(NodeIo,"Invalid ROSE address");
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	return(NULL);
      }
    memcpy(path + (10-salen), addr[1], salen);
    sprintf(User.dl_name, "%s @ %s", addr[0], path);
    sa.rs.srose_family = AF_ROSE;
    sa.rs.srose_ndigis = 0;
    if (ax25_aton_entry(addr[0], sa.rs.srose_call.ax25_call) < 0) {
      close(fd);
      return NULL;
    }
    if (rose_aton(path, sa.rs.srose_addr.rose_addr) < 0) {
      close(fd);
      return NULL;
    }
    if (addr[2] != NULL) {
      if (ax25_aton_entry(addr[2], sa.rs.srose_digi.ax25_call) < 0) {
	close(fd);
	return NULL;
      }
      sa.rs.srose_ndigis = 1;
    }
    salen = sizeof(struct sockaddr_rose);
    paclen = rs_config_get_paclen(NULL);
    eol = ROSE_EOL;
    /* Uncomment the below if you wish to have the node show a 'Trying' state */
    /*    node_msg("%s Trying %s... Type <RETURN> to abort", User.dl_name); */
    break;
#endif		
#ifdef HAVE_NETROM
  case AF_NETROM:
    if (aliascmd==0) {
      if (check_perms(PERM_NETROM, 0L) == -1) {
	axio_printf(NodeIo,"Permission denied");
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	node_log(LOGLVL_GW, "Permission denied: netrom");
	return NULL;
      }
    }
    if ((fd = socket(AF_NETROM, SOCK_SEQPACKET, 0)) < 0) {
      node_perror("connect_to: socket", errno);
      return NULL;
    }
    /* Why on earth is this different from ax.25 ????? */
    sprintf(path, "%s %s", nr_config_get_addr(NrPort), call); 
    ax25_aton(path, &sa.ax);
    sa.ax.fsa_ax25.sax25_family = AF_NETROM;
    salen = sizeof(struct full_sockaddr_ax25);
    if (bind(fd, (struct sockaddr *)&sa, salen) == -1) {
      node_perror("connect_to: bind", errno);
      close(fd);
      return NULL;
    }
    if ((np = find_node(addr[0], NULL)) == NULL) {
      axio_printf(NodeIo,"No such node");
      if (User.ul_type == AF_NETROM) {
	node_msg("");
      }
      return NULL;
    }
    strcpy(User.dl_name, print_node(np->alias, np->call));
    if (ax25_aton(np->call, &sa.ax) == -1) {
      close(fd);
      return NULL;
    }
    sa.ax.fsa_ax25.sax25_family = AF_NETROM;
    salen = sizeof(struct sockaddr_ax25);
    paclen = nr_config_get_paclen(NrPort); 
    eol = NETROM_EOL;
    /* Uncomment the below if you wish the node to show a 'Trying' state */
    if (check_perms(PERM_ANSI, 0L) != -1) {
      if (User.ul_type == AF_NETROM) {
	break;
      }
      node_msg("\e[01;36mTrying %s... hit <Enter> to abort", User.dl_name);
    }
    break;
#endif
#ifdef HAVE_AX25
  case AF_FLEXNET:
  case AF_AX25:
    if (aliascmd==0) {    
      if (check_perms(PERM_AX25, 0L) == -1 || (is_hidden(addr[0]) && check_perms(PERM_HIDDEN, 0L) == -1)) {
	axio_printf(NodeIo,"Permission denied");
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	node_log(LOGLVL_GW, "Permission denied: ax.25 port %s", addr[0]);
	return NULL;
      }
    }
    if (ax25_config_get_addr(addr[0]) == NULL) {
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
      axio_printf(NodeIo,"Invalid port");
      if (User.ul_type == AF_NETROM) {
      	node_msg("");
      }
      return NULL;
    }
    if ((fd = socket(AF_AX25, SOCK_SEQPACKET, 0)) < 0) {
      node_perror("connect_to: socket", errno);
      return NULL;
    }
    /*
     * Invert the SSID only if user is coming in with AX.25
     * and going out on the same port he is coming in via.
     */
    if (User.ul_type == AF_AX25 && !strcasecmp(addr[0], User.ul_name))
      invert_ssid(call, User.call);
    sprintf(path, "%s %s", call, ax25_config_get_addr(addr[0]));
    ax25_aton(path, &sa.ax);
    sa.ax.fsa_ax25.sax25_family = AF_AX25;
    salen = sizeof(struct full_sockaddr_ax25);
    if (bind(fd, (struct sockaddr *)&sa, salen) < 0) {
      node_perror("connect_to: bind", errno);
      close(fd);
      return NULL;
    }
    if (ax25_aton_arglist((const char **)addr+1, &sa.ax) < 0) {
      close(fd);
      return NULL;
    }
    strcpy(User.dl_name, strupr(addr[1]));
    strcpy(User.dl_port, strlwr(addr[0]));
    sa.ax.fsa_ax25.sax25_family = AF_AX25;
    salen = sizeof(struct full_sockaddr_ax25);
    paclen = ax25_config_get_paclen(addr[0]);
    eol = AX25_EOL;
    /* Uncomment the below if you wish the node to show a 'Trying' state */
    /*    if (family==AF_FLEXNET) node_msg("Trying %s via FlexNet... Type <RETURN> to abort", User.dl_name); */
    if ((family==AF_FLEXNET) || (family == AF_AX25)) { 
      if (!strcmp(User.dl_port,User.ul_name)) {
        if (check_perms(PERM_ANSI, 0L) != -1) {
	  axio_printf(NodeIo, "\e[05;31m");
	}
        axio_printf(NodeIo,"\aLoop detected on ");
      }
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[0;m");
      }
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo, "%s} ", NodeId);
      }
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo, "\e[01;33m");
      }
      axio_printf(NodeIo,"link setup (%s)...", User.dl_port);
    }
    /*    else node_msg("Trying %s on %s... Type <RETURN> to abort", User.dl_name, User.dl_port); */
    break;
#endif
  case AF_INET:
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      node_perror("connect_to: socket", errno);
      return NULL;
    }
    if ((hp = gethostbyname(addr[0])) == NULL) {
      if (User.ul_type == AF_NETROM) {
      	axio_printf(NodeIo, "%s} ", NodeId);
      }
      axio_printf(NodeIo,"Unknown host %s", addr[0]);
      if (User.ul_type == AF_NETROM) {
	node_msg("");
      }
      close(fd);
      return NULL;
    }
    sa.in.sin_family = AF_INET;
    sa.in.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
    sp = NULL;
    if (addr[1] == NULL)
      sp = getservbyname("telnet", "tcp");
    if (sp == NULL)
      sp = getservbyname(addr[1], "tcp");
    if (sp == NULL)
      sp = getservbyport(htons(atoi(addr[1])), "tcp");
    if (sp != NULL) {
      sa.in.sin_port = sp->s_port;
    } else if (atoi(addr[1]) != 0) {
      sa.in.sin_port = htons(atoi(addr[1]));
    } else {
      axio_printf(NodeIo,"%s Unknown service %s", NodeId, addr[1]);
      if (User.ul_type == AF_NETROM) {
	node_msg("");
      }
      close(fd);
      return NULL;
    }
    strcpy(User.dl_name, inet_ntoa(sa.in.sin_addr));
    if (sp != NULL)
      strcpy(User.dl_port, sp->s_name);
    else
      sprintf(User.dl_port, "%d", ntohs(sa.in.sin_port));
    salen = sizeof(struct sockaddr_in);
    paclen = 1024;
    eol = INET_EOL;
    if (aliascmd==0) {
      if (check_perms(PERM_TELNET, sa.in.sin_addr.s_addr) == -1) {
	if (User.ul_type == AF_NETROM) {
	  axio_printf(NodeIo,"%s} ", NodeId);
	}	 
	axio_printf(NodeIo,"Permission denied");
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	node_log(LOGLVL_GW, "Permission denied: telnet %s", User.dl_name);
	close(fd);
	return NULL;
      }
    }
    /*    if ((check_perms(PERM_ANSI, 0L) != -1) && (family == AF_NETROM)) {
	  axio_printf(NodeIo,"\e[01;36m%s Trying %s... Type <RETURN> to abort. (Escape: %s%c) \n",NodeId,
	  User.dl_name,
	  escape < 32 ? "CTRL-" : "",
	  escape < 32 ? (escape + 'A' - 1) : escape);
	  axio_flush(NodeIo);
	  } */
    break;
  default:
    axio_printf(NodeIo,"%s Unsupported address family", NodeId);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return NULL;
  }
  axio_flush(NodeIo);
  /*
   * Ok. Now set up a non-blocking connect...
   */
  if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
    node_perror("connect_to: fcntl - fd", errno);
    close(fd);
    return NULL;
  }
  if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1) {
    node_perror("connect_to: fcntl - stdin", errno);
    close(fd);
    return NULL;
  }
  if (connect(fd, (struct sockaddr *)&sa, salen) == -1 && errno != EINPROGRESS) {
    node_perror("Duplicate connection not allowed", errno);
    close(fd);
    return NULL;
  }
  User.dl_type = family;
  User.state = STATE_TRYING;
  update_user();
  /*
   * ... and wait for it to finish (or user to abort).
   */
  while (1) {
    FD_ZERO(&read_fdset);
    FD_ZERO(&write_fdset);
    FD_SET(fd, &write_fdset);
    FD_SET(STDIN_FILENO, &read_fdset);
    if (select(fd + 1, &read_fdset, &write_fdset, 0, 0) == -1) {
      node_perror("connect_to: select", errno);
      break;
    }
    if (FD_ISSET(fd, &write_fdset)) {
      /* See if we got connected or if this was an error */
      getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &retlen);
      if (ret != 0) {
	/*
	 * This is STUPID !!!!
	 * FBB interprets "Connection refused" as
	 * success because it contains the string
	 * "Connect"...
	 * But I'm NOT going to toss away valuable
	 * information (the strerror() info).
	 * Fortunately (???) FBB is case sensitive
	 * when examining the return string so
	 * simply converting the strerror() message
	 * to lower case fixes the problem. Ugly
	 * but it _should_ work.
	 */
	cp = strdup(strerror(ret));
	strlwr(cp);
	if (family==AF_FLEXNET) {
	  axio_printf(NodeIo,"\n*** failure with %s", User.dl_name); 
	  if (User.ul_type == AF_NETROM) {
	    node_msg("");
	  }
	} 
	else  
	  if (User.ul_type == AF_NETROM) {
	    axio_printf(NodeIo, "\n%s} Failure with %s: %s\n", NodeId, User.dl_name, cp);
	  } else {
	    axio_printf(NodeIo,"\nFailure with %s: %s", User.dl_name, cp);
	  }
	node_log(LOGLVL_GW, "Failure with %s: %s", User.dl_name, cp);
	free(cp);
	close(fd);
	return NULL;
      }
      break;
    }
    if (FD_ISSET(STDIN_FILENO, &read_fdset)) {
      errno = 0;
      if (axio_getline(NodeIo) != NULL) {
        if (User.ul_type == AF_NETROM) {
	  axio_printf(NodeIo,"%s} ", NodeId);
	}
	if (check_perms(PERM_ANSI, 0L) != -1) {
	  axio_printf(NodeIo, "\e[05;31m");
	}
	axio_printf(NodeIo,"Aborted");
	if (check_perms(PERM_ANSI, 0L) != -1) {
	  axio_printf(NodeIo, "\e[0;m");
	}
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	close(fd);
	return NULL;
      } else if (errno != EAGAIN) {
	close(fd);
	return NULL;
      }
    }
  }
  if (User.dl_type == AF_INET) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;32m");
    }
    node_msg("Socket established to %s:%s", User.dl_name, User.dl_port);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[0;m");
    }
  }
  else
    if (family==AF_FLEXNET) {
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo,"\e[01;32m");
      }
      node_msg("\n*** connected to %s", User.dl_name);
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo,"\e[0;m");
      }
    }
    else
      if (family==AF_AX25) {
        if (check_perms(PERM_ANSI, 0L) != -1) {
	  axio_printf(NodeIo,"\e[01;32m");
	}
	node_msg("\n*** connected to %s", User.dl_name);
	if (check_perms(PERM_ANSI, 0L) != -1) {
	  axio_printf(NodeIo,"\e[0;m");
	}
      }
      else 
	if (family == AF_NETROM) {
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo,"\e[01;32m");
	  }
	  if (User.ul_type == AF_INET) {
	    axio_printf(NodeIo,"Virtual circuit established to %s\n", User.dl_name);
	  }
	  if (User.ul_type == AF_NETROM) {
	    if (check_perms(PERM_ANSI, 0L) != -1) {
	      axio_printf(NodeIo,"\e[0;m");
            }
	    axio_printf(NodeIo,"%s} ", NodeId);
	    if (check_perms(PERM_ANSI, 0L) != -1) {
	      axio_printf(NodeIo,"\e[01;32m");
	    }
	    axio_printf(NodeIo, "Connected to %s\n", User.dl_name);
	  } 
	  if ((User.ul_type == AF_AX25) || (User.ul_type == AF_ROSE)) {
	    node_msg("*** connected to %s", User.dl_name);
	  } 
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo,"\e[0;m");
	  }
	}
  /*
    else
    if (family == AF_NETROM) {
    node_msg("%s} Connected to %s\n", NodeId, User.dl_name);
    } else {
    if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo,"\e[01;32m");
    }
    node_msg("*** connected to %s\n",
    User.dl_name,
    escape < 32 ? "CTRL-" : "",
    escape < 32 ? (escape + 'A' - 1) : escape);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[0;m");
    }
  */
  axio_flush(NodeIo);
  node_log(LOGLVL_GW, "%s Connected to %s", NodeId, User.dl_name);
  errno = 0;
  if ((riop = axio_init(fd, fd, paclen, eol)) == NULL) {
    node_perror("connect_to: Initializing I/O failed", errno);
    close(fd);
    return NULL;
  }
  
  if (compr && axio_compr(riop, compr) < 0)
    node_msg("connect_to: axio_compr failed");

  User.state = STATE_CONNECTED;
  update_user();
  return riop;
}

int do_connect(int argc, char **argv)
{
  int i, k;
  ax25io *riop;
  struct ax_routes *ax;
  struct flex_dst *flx;
  struct flex_gt *flgt;
  int c, compress, family = AF_UNSPEC, stay, escape;
  char *nodoconn = NULL;  
  fd_set fdset;
  char *connstr = NULL;
  axio_puts("",NodeIo);
 
  stay = ReConnectTo;
  if (!strcasecmp(argv[argc - 1], "s")) {
    stay = 1;
    argv[--argc] = NULL;
  } else if (!strcasecmp(argv[argc - 1], "d")) {
    stay = 0;
    argv[--argc] = NULL;
  }
  compress = 0;
  c = argv[0][0];
#ifdef HAVE_ZLIB_H
  if (*argv[0] == 'z') {
    compress = 1;
    c = argv[0][1];
  }
#endif

  if (argc < 2) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    if (c == 't')
      axio_printf(NodeIo,"Usage: telnet <host> [<port>] [d|s]");
    else
      axio_printf(NodeIo,"Usage: connect [<port>] <call> [via <call1> ...] [d|s]");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if (c == 't')
    family = AF_INET;
  else if (argc > 2) {
    // #ifdef HAVE_ROSE		
    if (strspn(argv[2], "0123456789") == strlen(argv[2]))
      family = AF_ROSE;
    else		
      // #endif
      family = AF_AX25;
  }
  else if (argc == 2) { /* Determine destination */
    static char call[2];
    strcpy(call, strupr(argv[1]));

    /*    if (find_node(argv[1], NULL)!=NULL) { 
	  family = AF_NETROM;
	  }
	  else */

    if ((flx=find_dest(argv[1], NULL))!=NULL) {  /* Check FlexNet */
      k=1;
      flgt=find_gateway(flx->addr, NULL);
      argv[k++]=ax25_config_get_name(flgt->dev);
      argv[k++]=call;
      while((k-3)<AX25_MAX_DIGIS&&flgt->digis[k-3][0]!='\0') argv[k]=flgt->digis[(k++)-3];
      argv[k++]=flgt->call;
      argv[k]=NULL;
      argc=k;
      family = AF_FLEXNET;
    }
    else if (find_node(argv[1], NULL)!=NULL) {
      family = AF_NETROM;
    }	

    else if ((ax=find_route(argv[1], NULL))!=NULL) {  /* Check AX25 Links */
      k=1;

      switch(*ax->conn_type)  { 
      case CONN_TYPE_DIRECT:
	{
	  argv[k++]=ax->dev;
	  argv[k++]=ax->dest_call;
	  break;  
	} 
      case CONN_TYPE_DIGI:
	{
	  argv[k++]=ax->dev;
	  argv[k++]=ax->dest_call; 
	  while((k-3)<AX25_MAX_DIGIS&&ax->digis[k-3][0]!='\0') argv[k]=ax->digis[(k++)-3];
	  break;
	}
      case CONN_TYPE_NODE:
	{  
	  argv[k++]=ax->dev;
	  argv[k++]=ax->digis[0];
	  nodoconn=ax->dest_call;
	  break;
	}
      }
      argv[k]=NULL;
      argc=k;
      family = AF_AX25;
    } 
    /* else if ((flx=find_dest(argv[1], NULL))!=NULL) {   Check FlexNet 
       k=1;
       flgt=find_gateway(flx->addr, NULL);      
       argv[k++]=ax25_config_get_name(flgt->dev);
       argv[k++]=call;
       while((k-3)<AX25_MAX_DIGIS&&flgt->digis[k-3][0]!='\0') argv[k]=flgt->digis[(k++)-3];
       argv[k++]=flgt->call;
       argv[k]=NULL;
       argc=k;
       family = AF_FLEXNET; 
       else if (find_node(argv[1], NULL)!=NULL) { 
       family = AF_NETROM;
       } */
	
    else if ((ax=find_mheard(argv[1]))!=NULL) { /* Check Mheard database */
      k=1;
      /*	K2MF supplied code	*/
      /*	This code *actually* reads mheard.dat and fixes
       *	the digi path the way it should be.  -N1URO 	*/
      argv[k++] = ax->dev;
      argv[k++] = ax->dest_call;

      /* First count the number of digipeaters in the path
       * from the destination */
      i = k - 3;

      while(i < AX25_MAX_DIGIS) {
	if(ax->digis[i][0] == '\0')
	  break;

	i++;
      }
      /* Then construct the reverse digipeater path back to
       * the destination */
      while(i && ax->digis[i - 1][0] != '\0')
	argv[k++] = ax->digis[--i];
      /*   end K2MF code   */                
      argv[k]=NULL; 
      argc=k;
      family = AF_AX25;
    } else {  /* Give up */
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
      axio_printf(NodeIo,"%s not in Desti, Nodes, or MHeard tables.", call);
      family = AF_UNSPEC;
      //      free_flex_dst(flx);
      //      free_ax_routes(ax);
      if (User.ul_type == AF_NETROM) {
	node_msg("");
      }
      return 0;
    }
  }

  if (family == AF_INET && argc > 3) connstr = argv[3];
  escape = (check_perms(PERM_NOESC, 0L) == 0) ? -1 : EscChar;
  riop = connect_to(++argv, family, escape, compress);
  if (riop == NULL) {
    if (fcntl(STDIN_FILENO, F_SETFL, 0) == -1)
      node_perror("do_connect: fcntl - stdin", errno);
    return 0;
  }
  if (family == AF_INET)
    axio_tnmode(riop, 1);
  if (connstr) {
    axio_printf(riop, "%s\n", connstr);
    axio_flush(riop);
  } 

  /*
   * If eol conventions are compatible, switch to binary mode,
   * else switch to special gateway mode.
   */
  if (axio_cmpeol(riop, NodeIo) == 0) {
    axio_eolmode(riop, EOLMODE_BINARY);
    axio_eolmode(NodeIo, EOLMODE_BINARY);
  } else {
    axio_eolmode(riop, EOLMODE_GW);
    axio_eolmode(NodeIo, EOLMODE_GW);
  }
  if (nodoconn != NULL) axio_printf(riop, "C %s\n",nodoconn); 
  
  while (1) {
    FD_ZERO(&fdset);
    FD_SET(riop->ifd, &fdset);
    FD_SET(STDIN_FILENO, &fdset);
    if (select(32, &fdset, 0, 0, 0) == -1) {
      node_perror("do_connect: select", errno);
      break;
    }
    if (FD_ISSET(riop->ifd, &fdset)) {
      alarm(ConnTimeout);
      while((c = axio_getc(riop)) != -1)
	axio_putc(c, NodeIo);
      if (errno != EAGAIN) {
	if (errno && errno != ENOTCONN)
	  axio_printf(NodeIo,"%s", strerror(errno));
	break;
      }
    }
    if (FD_ISSET(STDIN_FILENO, &fdset)) {
      alarm(ConnTimeout);
      while((c = axio_getc(NodeIo)) != -1) {
	if (escape != -1 && c == escape) break;
	axio_putc(c, riop);
      }
      if (escape != -1 && c == escape) {
	axio_eolmode(NodeIo, EOLMODE_TEXT);
	axio_getline(NodeIo);
	break;
      }
      if (errno != EAGAIN) {
	stay = 0;
	break;
      }
    }
    axio_flush(riop);
    axio_flush(NodeIo);
  }
  axio_end(riop);
  node_log(LOGLVL_GW, "Disconnected from %s", User.dl_name);
#ifdef HAVEMOTD 
  /*  if (User.ul_type != AF_NETROM) {  */
  /*  if (stay) { */
  axio_eolmode(NodeIo, EOLMODE_TEXT);
  if (fcntl(STDIN_FILENO, F_SETFL, 0) == -1)
    node_perror("do_connect: fcntl - stdin", errno);
  if (User.ul_type == AF_INET) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;31m");
    }
    axio_printf(NodeIo,"\nReturning you to the shell... ");
  } else
    if (User.ul_type == AF_AX25) {
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo,"\e[01;31m");
      }
      axio_printf(NodeIo,"\n*** reconnected to %s", FlexId);
      if (check_perms(PERM_ANSI, 0L) != -1) {
	axio_printf(NodeIo,"\e[0;m");
      }
    }
  if (User.ul_type == AF_INET) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0m");
    }
  } 
  /*     }	*/
  /*  } */
  if ((User.ul_type == AF_NETROM) && (!stay)) {
    node_logout("No reconnect");
  } 
  if ((User.ul_type == AF_NETROM) && (stay)) {
    axio_printf(NodeIo,"%s} ", NodeId);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;31mWelcome back.\n\e[0;m");
    }
    if (check_perms(PERM_ANSI, 0L) == -1) {
      axio_printf(NodeIo,"Welcome back.\n");	
    }	
  }
#else 
  node_logout("No reconnect"); 
#endif 
  //      free_flex_dst(flx);
  //      free_ax_routes(ax);
  return 0;
}
int do_finger(int argc, char **argv)
{
  ax25io *riop;
  int i, compress;
  char *name, *addr[3], *cp;
  compress = 0; 
  
  /*  if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
      }  */
  axio_puts("",NodeIo);
  if (argc < 2) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Usage: finger user@<hostname or ip address>.");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  } else if ((cp = strchr(argv[1], '@')) != NULL) {
    *cp = 0;
    name = argv[1];
    addr[0] = ++cp;
  } else {
    name = argv[1];
    addr[0] = "localhost"; 
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Usage: finger user@<hostname or ip address>.");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  addr[1] = "finger";
  addr[2] = NULL;
  riop = connect_to(addr, AF_INET, 0, compress);
  /* If you uncommented 'Trying' state on, uncomment this also. */
  /*  escape = (check_perms(PERM_NOESC, 0L) == 0) ? -1 : EscChar; */
  if (riop != NULL) {
    if (fcntl(riop->ifd, F_SETFL, 0) == -1)
      node_perror("do_finger: fcntl - fd", errno);
    axio_printf(NodeIo,"[%s]\n", addr[0]);
    axio_printf(riop, "%s\n", name);
    axio_flush(riop);
    while((i = axio_getc(riop)) != -1)
      axio_putc(i, NodeIo);
    axio_end(riop);
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;31m");
    }
    axio_printf(NodeIo,"Finger complete.");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  }
  axio_eolmode(NodeIo, EOLMODE_TEXT);
  if (fcntl(STDIN_FILENO, F_SETFL, 0) == -1)
    node_perror("do_finger: fcntl - stdin", errno);
  return 0;
}

/*
 * Returns difference of tv1 and tv2 in milliseconds.
 */
static long calc_rtt(struct timeval tv1, struct timeval tv2)
{
  struct timeval tv;

  tv.tv_usec = tv1.tv_usec - tv2.tv_usec;
  tv.tv_sec = tv1.tv_sec - tv2.tv_sec;
  if (tv.tv_usec < 0) {
    tv.tv_sec -= 1L;
    tv.tv_usec += 1000000L;
  }
  return ((tv.tv_sec * 1000L) + (tv.tv_usec / 1000L));
}

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
static unsigned short in_cksum(unsigned char *addr, int len)
{
  register int nleft = len;
  register unsigned char *w = addr;
  register unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += (*(w + 1) << 8) + *(w);
    w     += 2;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    sum += *w;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
  sum += (sum >> 16);                     /* add carry */
  answer = ~sum;                          /* truncate to 16 bits */
  return answer;
}

int do_ping(int argc, char **argv)
{
  static int sequence = 0;
  unsigned char buf[256];
  struct hostent *hp;
  struct sockaddr_in to, from;
  struct protoent *prot;
  struct icmphdr *icp;
  struct timeval tv1, tv2;
  struct iphdr *ip;
  fd_set fdset;
  int fd, i, id, len = sizeof(struct icmphdr);
  int salen = sizeof(struct sockaddr);

  /*  if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
      } */
  axio_puts("",NodeIo);
  if (argc < 2) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Usage: ping <host> [<size>]");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if (argc > 2) {
    len = atoi(argv[2]) + sizeof(struct icmphdr);
    if (len > 256) {
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
      axio_printf(NodeIo,"Maximum size is %d", 256 - sizeof(struct icmphdr));
      if (User.ul_type == AF_NETROM) {
	node_msg("");
      }
      return 0;
    }
  }
  if ((hp = gethostbyname(argv[1])) == NULL) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Unknown host %s", argv[1]);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  memset(&to, 0, sizeof(to));
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = ((struct in_addr *)(hp->h_addr))->s_addr;
  if ((prot = getprotobyname("icmp")) == NULL) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Unknown protocol icmp");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if ((fd = socket(AF_INET, SOCK_RAW, prot->p_proto)) == -1) {
    node_perror("do_ping: socket", errno);
    return 0;
  }
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo,"\e[01;35mICMP Echo request sent to: \e[0m");
  }
  if (check_perms(PERM_ANSI, 0L) == -1) {
    axio_printf(NodeIo, "ICMP Echo request sent to: ");
  }
  node_msg("%s", inet_ntoa(to.sin_addr));
  axio_flush(NodeIo);
  strcpy(User.dl_name, inet_ntoa(to.sin_addr));
  User.dl_type = AF_INET;
  User.state = STATE_PINGING;
  update_user();
  /*
   * Fill the data portion (if any) with some garbage.
   */
  for (i = sizeof(struct icmphdr); i < len; i++)
    buf[i] = (i - sizeof(struct icmphdr)) & 0xff;
  /*
   * Fill in the icmp header.
   */
  id = getpid() & 0xffff;
  icp = (struct icmphdr *)buf;
  icp->type = ICMP_ECHO;
  icp->code = 0;
  icp->checksum = 0;
  icp->un.echo.id = id;
  icp->un.echo.sequence = sequence++;
  /*
   * Calculate checksum.
   */
  icp->checksum = in_cksum(buf, len);
  /*
   * Take the time and send the packet.
   */
  gettimeofday(&tv1, NULL);
  if (sendto(fd, buf, len, 0, (struct sockaddr *)&to, salen) != len) {
    node_perror("do_ping: sendto", errno);
    close(fd);
    return 0;
  }
  /*
   * Now wait for it to come back (or user to abort).
   */
  if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1) {
    node_perror("do_ping: fcntl - stdin", errno);
    close(fd);
    return 0;
  }
  while (1) {
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);
    FD_SET(STDIN_FILENO, &fdset);
    if (select(fd + 1, &fdset, 0, 0, 0) == -1) {
      node_perror("do_ping: select", errno);
      break;
    }
    if (FD_ISSET(fd, &fdset)) {
      if ((len = recvfrom(fd, buf, 256, 0, (struct sockaddr *)&from, &salen)) == -1) {
	node_perror("do_ping: recvfrom", errno);
	break;
      }
      gettimeofday(&tv2, NULL);
      ip = (struct iphdr *)buf;
      /* Is it long enough? */
      if (len >= (ip->ihl << 2) + sizeof(struct icmphdr)) {
	len -= ip->ihl << 2;
	icp = (struct icmphdr *)(buf + (ip->ihl << 2));
	/* Is it ours? */
	if (icp->type == ICMP_ECHOREPLY && icp->un.echo.id == id && icp->un.echo.sequence == sequence - 1) {
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo,"\e[01;35mICMP Echo reply received from: \e[0m");
	  }
	  if (check_perms(PERM_ANSI, 0L) == -1) {
	    axio_printf(NodeIo, "ICMP Echo reply received from: ");
	  }
          node_msg("%s", inet_ntoa(to.sin_addr));
	  if (User.ul_type == AF_NETROM) {
	    axio_printf(NodeIo,"%s} ", NodeId);
	  }
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo, "\e[01;31m");
	  }
	  /*	  if (User.ul_type == AF_NETROM) {
		  axio_printf(NodeIo,"%s} ", NodeId);
		  }  */
	  axio_printf(NodeIo, "Ping completed in: %ldms (ttl=%d)", calc_rtt(tv2, tv1), ip->ttl);
	  if (User.ul_type == AF_NETROM) {
	    node_msg("");
	  }  
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo, "\e[0;m");
	  }
	  break;
	}
      }
    }
    if (FD_ISSET(STDIN_FILENO, &fdset)) {
      if (axio_getline(NodeIo) != NULL) {
        if (User.ul_type ==  AF_NETROM){
	  axio_printf(NodeIo,"%s} ", NodeId);
	}
	if (User.ul_type == AF_INET) {
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo, "\e[05;38m");
	  }
	}
	axio_printf(NodeIo,"Aborted");
	if (User.ul_type == AF_INET) {
	  if (check_perms(PERM_ANSI, 0L) != -1) {
	    axio_printf(NodeIo, "\e[0;m");
	  }
	}
	if (User.ul_type == AF_NETROM) {
	  node_msg("");
	}
	break;
      } else if (errno != EAGAIN) {
	break;
      }
    }
  }
  if (fcntl(STDIN_FILENO, F_SETFL, 0) == -1)
    node_perror("do_ping: fcntl - stdin", errno);
  close(fd);
  return 0;
}

