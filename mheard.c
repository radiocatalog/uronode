/* Routine rewritten mainly by Barry K2MF (Mr. MFNOS) and Brian N1URO */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netax25/ax25.h>
#include <netrose/rose.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/mheard.h>

#include "procinfo.h"
#include "node.h"

struct mheard_list {
  struct mheard_struct data;
  struct mheard_list *next;
};

int do_mheard (int argc,char **argv) {
  FILE *fp;
  struct mheard_struct mh;
  struct mheard_list *list = NULL, *new, *tmp, *p;
  char *s, *t, *u;
  int mhcount = 0;

  axio_puts("",NodeIo);

  if(User.ul_type == AF_NETROM)
    axio_printf(NodeIo,"%s} ",NodeId);

  if(argc > 1) {
    if(ax25_config_get_dev(argv[1]) == NULL
       || (check_perms(PERM_HIDDEN, 0) == -1
	   && is_hidden(argv[1]))) {
      axio_printf(NodeIo,"Invalid port: %s",argv[1]);

      if(User.ul_type == AF_NETROM)
	node_msg("");
		
      return 0;
    }
  }
  if((fp = fopen(DATA_MHEARD_FILE,"r")) == NULL) {
    node_perror(DATA_MHEARD_FILE,errno);
    return 0;
  }
  while(mhcount < 20 && fread(&mh,sizeof(struct mheard_struct),1,fp)
	== 1) {
    if(argc > 1) {
      if(strcmp(argv[1],mh.portname))
	continue;
    }
    if(check_perms(PERM_HIDDEN,0) == -1 && is_hidden(mh.portname))
      continue;

    if((new = calloc(1,sizeof(struct mheard_list))) == NULL) {
      node_perror("do_mheard: calloc",errno);
      break;
    }
    new->data = mh;

    if(list == NULL || mh.last_heard > list->data.last_heard) {
      tmp = list;
      list = new;
    } else {
      for(p = list; p->next != NULL; p = p->next) {
	if(mh.last_heard > p->next->data.last_heard)
	  break;
      }
      tmp = p->next;
      p->next = new;
    }
    new->next = tmp;
    mhcount++;
  }
  fclose(fp);

  if(check_perms(PERM_ANSI,0L) != -1)
    axio_printf(NodeIo,"\e[01;33m");

  node_msg("MHeard list:");

  if(check_perms(PERM_ANSI,0L) != -1)
    axio_printf(NodeIo,"\e[0;m");

  axio_printf(NodeIo,"Callsign  Device Packets  Date & Time     Frame Type(s)\n");
  axio_printf(NodeIo,"--------- ------ -------- --------------- -------------");

  while(list != NULL) {
    s = ctime(&list->data.last_heard);
    s[19] = 0;
    s += 4;
    t = ax25_ntoa(&list->data.from_call);

    if((u = strstr(t,"-0")) != NULL)
      *u = '\0';

    axio_printf(NodeIo,"\n%-9s %-6s %-8d %s",t,list->data.portname,list->data.count,s);

    if(list->data.mode & MHEARD_MODE_ARP)
      axio_printf(NodeIo," ARP");

    if(list->data.mode & MHEARD_MODE_FLEXNET)
      axio_printf(NodeIo," FlexNet");

    if(list->data.mode & MHEARD_MODE_IP_DG)
      axio_printf(NodeIo," IP-DG");

    if(list->data.mode & MHEARD_MODE_IP_VC)
      axio_printf(NodeIo," IP-VC");

    if(list->data.mode & MHEARD_MODE_NETROM)
      axio_printf(NodeIo," NetRom");

    if(list->data.mode & MHEARD_MODE_ROSE)
      axio_printf(NodeIo," Rose");

    if(list->data.mode & MHEARD_MODE_SEGMENT)
      axio_printf(NodeIo," Segment");

    if(list->data.mode & MHEARD_MODE_TEXNET)
      axio_printf(NodeIo," TexNet");

    if(list->data.mode & MHEARD_MODE_TEXT)
      axio_printf(NodeIo," Text");

    if(list->data.mode & MHEARD_MODE_PSATFT)
      axio_printf(NodeIo," PacsatFT");

    if(list->data.mode & MHEARD_MODE_PSATPB)
      axio_printf(NodeIo," PacsatPB");

    if(list->data.mode & MHEARD_MODE_UNKNOWN)
      axio_printf(NodeIo," Unknown");

    tmp = list;
    list = list->next;
    free(tmp);

  }
  if(User.ul_type == AF_NETROM)
    node_msg("");
  return 0;
}
