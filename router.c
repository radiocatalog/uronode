#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netax25/ax25.h>
#include <netrose/rose.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include "procinfo.h"

#include "node.h"


int do_links(int argc, char **argv)
{
  struct ax_routes *axrt, *p;
  char digipath[AX25_MAX_DIGIS*10];
  char tipoconn[9];  
  int i=0;

  axio_puts("",NodeIo);
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if ((axrt=read_ax_routes()) == NULL) {
    if (errno) node_perror("do_links: read_ax_routes", errno);
    else axio_printf(NodeIo,"No known links");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  /* "links" */
  if (check_perms(PERM_ANSI, 0L) != -1) {
    axio_printf(NodeIo, "\e[01;33m");
  }
  if (argc == 1) {
    node_msg("AX25 Links:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Call      Alias     Description\n");
    axio_printf(NodeIo,"--------- --------- -----------");                        
    for(p=axrt;p!=NULL;p=p->next) 
      axio_printf(NodeIo,"\n%-9s %-9s %s", p->dest_call, p->alias, p->description);
    free_ax_routes(axrt);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  
  /* "links d" */
  if ((*argv[1]=='d') && (strlen(argv[1])==1)) {
    node_msg("AX25 Direct Links:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Call      Alias     Interf  Description\n");
    axio_printf(NodeIo,"--------- --------- ------- -----------");
    for(p=axrt;p!=NULL;p=p->next) 
      {  if (*p->conn_type==CONN_TYPE_DIRECT)  axio_printf(NodeIo,"\n%-9s %-9s %-7s %s", p->dest_call, p->alias, p->dev, p->description); }
    free_ax_routes(axrt);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  
  
  /* "links n" */
  if ((*argv[1]=='n') && (strlen(argv[1])==1)) {
    node_msg("AX25 Links via other nodes:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Call      Alias     Interf  Routing   Description\n");
    axio_printf(NodeIo,"--------- --------- ------- --------- -----------");
    for(p=axrt;p!=NULL;p=p->next) 
      { if (*p->conn_type==CONN_TYPE_NODE) axio_printf(NodeIo,"\n%-9s %-9s %-7s %-9s %s", p->dest_call, p->alias, p->dev, p->digis[0], p->description); }
    free_ax_routes(axrt);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  
  
  
  /* "links v" */
  if ((*argv[1]=='v') && (strlen(argv[1])==1)) {
    node_msg("AX25 Links via digipeaters:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Call      Alias     Interf  Digipeaters\n");
    axio_printf(NodeIo,"--------- --------- ------- -----------");
    for(p=axrt;p!=NULL;p=p->next) {
      *digipath='\0';
      for(i=0;i<AX25_MAX_DIGIS;i++) {
	if (p->digis[i]==NULL) break;
	if (i!=0) strcat(digipath," ");
	strcat(digipath, p->digis[i]);
      }
      if (*p->conn_type==CONN_TYPE_DIGI) axio_printf(NodeIo,"\n%-9s %-9s %-7s %s", p->dest_call, p->alias,  p->dev, digipath);
    }
    free_ax_routes(axrt);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  /* "links <call>" */
  p=find_route(argv[1], axrt);
  if(p!=NULL) {
    node_msg("AX25 Link to %s:", p->dest_call);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Call      Alias     Interf  Type     Description\n");
    axio_printf(NodeIo,"--------- --------- ------- -------- -----------");
    switch(*p->conn_type) {
    case CONN_TYPE_DIRECT:
      { strcpy(tipoconn,"Direct"); break; }
    case CONN_TYPE_NODE:
      { strcpy(tipoconn,"Via Node"); break; }
    case CONN_TYPE_DIGI:
      { strcpy(tipoconn,"Via Digi"); break; }
    }
    axio_printf(NodeIo,"\n%-9s %-9s %-7s %-8s %s", p->dest_call, p->alias, p->dev, tipoconn, p->description);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  } else {
    axio_printf(NodeIo,"No such link");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  }

  free_ax_routes(axrt);
  return 0;
}

int do_dest(int argc, char **argv)
{
  struct flex_dst *fdst, *p;
  struct flex_gt *flgt, *q;
  char ssid[5];
  int i=0;

  axio_puts("",NodeIo);
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  if ((fdst=read_flex_dst()) == NULL) {
    axio_printf(NodeIo,"No known destinations");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  /* "dest" */
  if (argc == 1) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;33m");
    }
    if (User.ul_type != AF_AX25) {
      axio_printf(NodeIo,"FlexNet Destinations:\n");
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    for (p=fdst;p!=NULL;p=p->next) {
      sprintf(ssid, "%d-%d", p->ssida, p->sside);
      axio_printf(NodeIo,"%-7s %-5s %4ld%s",p->dest_call,ssid,p->rtt,(++i % 4) ? "  " : "\n");
    }
    if ((i % 4) != 0) axio_printf(NodeIo,""); 
    free_flex_dst(fdst);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  if ((flgt=read_flex_gt()) == NULL) {
    node_perror("do_dest: read_flex_gt", errno);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  /* "dest *" */
  if (*argv[1]=='*') {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;33m");
    }
    node_msg("FlexNet Destinations:");
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Dest     SSID    RTT Gateway\n");
    axio_printf(NodeIo,"-------- ----- ----- --------");
    for(p=fdst;p!=NULL;p=p->next) {
      sprintf(ssid, "%d-%d", p->ssida, p->sside);
      q=find_gateway(p->addr,flgt);
      axio_printf(NodeIo,"\n%-8s %-5s %5ld %-8s", p->dest_call, ssid, 
		  p->rtt, q!=NULL?q->call:"?");
    }
    free_flex_dst(fdst);
    free_flex_gt(flgt);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }
  /* "dest <call>" */
  p=find_dest(argv[1], fdst);
  if(p!=NULL) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;33m");
    }
    node_msg("FlexNet Destination %s:", p->dest_call);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0;m");
    }
    axio_printf(NodeIo,"Dest     SSID    RTT Gateway\n");
    axio_printf(NodeIo,"-------- ----- ----- -------");
    sprintf(ssid, "%d-%d", p->ssida, p->sside);
    q=find_gateway(p->addr,flgt);
    axio_printf(NodeIo,"\n%-8s %-5s %5ld %-8s", p->dest_call, ssid, p->rtt, q!=NULL?q->call:"?");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  } else {
    axio_printf(NodeIo,"No such destination");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  }

  free_flex_dst(fdst);
  free_flex_gt(flgt);

  return 0;
}


