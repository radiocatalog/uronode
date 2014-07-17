#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/mheard.h>

#include "procinfo.h"

#include "node.h"


/*
 * Version of atoi() that returns zero if s == NULL.
 */
int safe_atoi(const char *s)
{
  return (s == NULL) ? 0 : atoi(s);
}

/*
 * Version of strncpy() that returns NULL if either src or dest is NULL
 * and also makes sure destination string is always terminated.
 */
char *safe_strncpy(char *dest, char *src, int n)
{
  if (dest == NULL || src == NULL) return NULL;
  dest[n] = 0;
  return strncpy(dest, src, n);
}

struct proc_dev *read_proc_dev(void)
{
  FILE *fp;
  char buffer[256];
  struct proc_dev *p;
  struct proc_dev *list = NULL;
  int i = 0;
  
  errno = 0;
  if ((fp = fopen(PROC_DEV_FILE, "r")) == NULL) return NULL;
  while (fgets(buffer, 256, fp) != NULL) {
    if (i++<2) continue;
    if ((p = calloc(1, sizeof(struct proc_dev))) == NULL) break;

    safe_strncpy(p->interface, strtok(buffer, ":\n\r"), 6);
    while (*p->interface==' ') strcpy(p->interface, p->interface+1);
    p->rx_bytes = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_packets = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_errs = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_drop = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_fifo = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_frame = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_compressed = safe_atoi(strtok(NULL, " \t\n\r"));
    p->rx_multicast = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_bytes = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_packets = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_errs = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_drop = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_fifo = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_colls = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_carrier = safe_atoi(strtok(NULL, " \t\n\r"));
    p->tx_compressed = safe_atoi(strtok(NULL, " \t\n\r"));
    p->next = list;
    list = p;
  }
  fclose(fp);
  return list;
}

void free_proc_dev(struct proc_dev *ap)
{
  struct proc_dev *p;
  
  while (ap != NULL) {
    p = ap->next;
    free(ap);
    ap = p;
  }
}

struct flex_gt *read_flex_gt(void)
{
  FILE *fp;
  char buffer[256], *cp;
  struct flex_gt *p=NULL, *list = NULL, *new_el;
  int i = 0, k;
  
  errno = 0;
  if ((fp = fopen(FLEX_GT_FILE, "r")) == NULL) return NULL;
  while (fgets(buffer, 256, fp) != NULL) {
    if (i++<1) continue;
    if ((new_el = calloc(1, sizeof(struct flex_gt))) == NULL) break;

    new_el->addr = safe_atoi(strtok(buffer, " \t\n\r"));
    safe_strncpy(new_el->call, strtok(NULL, " \t\n\r"), 9);
    safe_strncpy(new_el->dev, strtok(NULL, " \t\n\r"), 4);
    
    k=0;
    while((cp=strtok(NULL, " \t\n\r"))!=NULL&&k<AX25_MAX_DIGIS) safe_strncpy(new_el->digis[k++],cp,9);
    while(k<AX25_MAX_DIGIS) strcpy(new_el->digis[k++],"\0");

    if(list==NULL) {
      list=new_el;
      p=list;
    } else {
      p->next = new_el;
      p=p->next;
    }
  }
  fclose(fp);
  return list;
}

void free_flex_gt(struct flex_gt *fp)
{
  struct flex_gt *p;
  
  while (fp != NULL) {
    p = fp->next;
    free(fp);
    fp = p;
  }
}

struct flex_dst *read_flex_dst(void)
{
  FILE *fp;
  char buffer[256];
  struct flex_dst *p=NULL, *list = NULL, *new_el;
  int i = 0;
  
  errno = 0;
  if ((fp = fopen(FLEX_DST_FILE, "r")) == NULL) return NULL;
  while (fgets(buffer, 256, fp) != NULL) {
    if (i++<1) continue;
    if ((new_el = calloc(1, sizeof(struct flex_dst))) == NULL) break;

    safe_strncpy(new_el->dest_call, strtok(buffer, " \t\n\r"), 9);
    new_el->ssida = safe_atoi(strtok(NULL, " -\t\n\r"));
    new_el->sside = safe_atoi(strtok(NULL, " -\t\n\r"));
    new_el->rtt = safe_atoi(strtok(NULL, " \t\n\r"));
    new_el->addr = safe_atoi(strtok(NULL, " \t\n\r"));

    if(list==NULL) {
      list=new_el;
      p=list;
    } else {
      p->next = new_el;
      p=p->next;
    }
  }
  fclose(fp);
  return list;
}

void free_flex_dst(struct flex_dst *fp)
{
  struct flex_dst *p;
  
  while (fp != NULL) {
    p = fp->next;
    free(fp);
    fp = p;
  }
}

struct ax_routes *read_ax_routes(void)
{
  FILE *fp;
  char buffer[256], *cp, *cmd;
  struct ax_routes *p=NULL, *list = NULL, *new_el;
  int i = 0, k;
  
  errno = 0;
  if ((fp = fopen(AX_ROUTES_FILE, "r")) == NULL) return NULL;
  while (fgets(buffer, 256, fp) != NULL) {
    if (i++<1) continue;

    if(*buffer=='#' || *buffer==' ' ) continue; /* commented line */
    cp=strchr(buffer, '#'); /* ignore comments */
    if (cp) *cp='\0';

    cmd=strtok(buffer, " \t\n\r");
    if(cmd==NULL) continue; /* empty line */

    if (strcasecmp(cmd,"route")==0) { /* add route */
      if ((new_el = calloc(1, sizeof(struct ax_routes))) == NULL) break;
      safe_strncpy(new_el->dest_call, strupr(strtok(NULL, " \t\n\r")), 9);
      safe_strncpy(new_el->alias, strupr(strtok(NULL, " \t\n\r")), 9);
      safe_strncpy(new_el->dev, strtok(NULL, " \t\n\r"), 13);
      safe_strncpy(new_el->conn_type, strupr(strtok(NULL, " \t\n\r")), 1);
      safe_strncpy(new_el->description, strtok(NULL, "'\t\n\r"), 50);
      if (new_el->description==NULL) strcpy(new_el->description," ");
      
      switch(*new_el->conn_type) {
      case CONN_TYPE_DIRECT: 
	{ 
	  break;
	}
      case CONN_TYPE_NODE:
	{
	  safe_strncpy(new_el->digis[0], strupr(strtok(NULL, " \t\n\r")), 9);
      
	  break;
	}
      case CONN_TYPE_DIGI:
	{
	  k=0;      
	  while((cp=strtok(NULL, " \t\n\r"))!=NULL&&k<AX25_MAX_DIGIS) 
	    safe_strncpy(new_el->digis[k++],strupr(cp),9);
	  while(k<AX25_MAX_DIGIS) strcpy(new_el->digis[k++],"\0");
	  break;
	}
      default: 
	{
	  return NULL;
	  break;
	}
      }

      
      if(list==NULL) {
	list=new_el;
	p=list;
      } else {
	p->next = new_el;
	p=p->next;
      }
    }
  }
  fclose(fp);
  return list;
}

void free_ax_routes(struct ax_routes *ap)
{
  struct ax_routes *p;
  
  while (ap != NULL) {
    p = ap->next;
    free(ap);
    ap = p;
  }
}

struct ax_routes *find_route(char *dest_call, struct ax_routes *list)
{
  static struct ax_routes a;
  struct ax_routes *axrt=NULL, *p;
  char *cp, call[10];

  safe_strncpy(call,dest_call,9);

  if ((cp = strchr(call, '-')) != NULL && *(cp + 1) == '0') *cp = 0;
  axrt=list?list:read_ax_routes();
  for (p=axrt;p!=NULL;p=p->next) {
    if (!strcasecmp(call, p->dest_call)) {
      a = *p;
      a.next = NULL;
      p = &a;
      break;
    }
    if (!strcasecmp(call, p->alias)) {
      a = *p;
      a.next = NULL;
      p = &a;
      break;
    }
 
  }
  if (list==NULL) free_ax_routes(axrt);
  return p;
}

struct flex_dst *find_dest(char *dest_call, struct flex_dst *list)
{
  static struct flex_dst f;
  struct flex_dst *fdst=NULL, *p;
  char *cp, call[10];
  int ssid;

  safe_strncpy(call, dest_call, 9);
  cp=strchr(call,'-'); 
  if (cp==NULL) ssid=0;
  else {
    ssid=safe_atoi(cp+1);
    *cp='\0';
  }

  fdst=list?list:read_flex_dst();
  for (p=fdst;p!=NULL;p=p->next) {
    if (!strcasecmp(call, p->dest_call) && (ssid>=p->ssida && ssid<=p->sside)) {
      f = *p;
      f.next = NULL;
      p = &f;
      break;
    }
  }
  if (list==NULL) free_flex_dst(fdst);
  return p;
}

struct flex_gt *find_gateway(int addr, struct flex_gt *list)
{
  static struct flex_gt f;
  struct flex_gt *flgt=NULL, *p;

  flgt=list?list:read_flex_gt();
  for (p=flgt;p!=NULL;p=p->next) {
    if (addr==p->addr) {
      f = *p;
      f.next = NULL;
      p = &f;
      break;
    }
  }
  if (list==NULL) free_flex_gt(flgt);
  return p;
}

struct ax_routes *find_mheard(char *dest_call)
{
  FILE *fp;
  static struct ax_routes a;
  struct mheard_struct mh;
  char call[12];
  char *cp;
  int k;

  if ((fp = fopen(DATA_MHEARD_FILE, "r")) == NULL) {
    return NULL;
  }
  
  safe_strncpy(call,dest_call,9);
  cp=strchr(call, '-');
  if (cp==NULL) strcat(call,"-0");

  while (fread(&mh, sizeof(struct mheard_struct), 1, fp) == 1) {
    if (strcasecmp(call, ax25_ntoa(&mh.from_call))==0) {
      fclose(fp);
      safe_strncpy(a.dest_call, ax25_ntoa(&mh.from_call), 9);
      safe_strncpy(a.dev, mh.portname, 13);
      for(k=0;k<AX25_MAX_DIGIS;k++) {
	if (k<=mh.ndigis) safe_strncpy(a.digis[k],ax25_ntoa(&mh.digis[k]),9);
	else strcpy(a.digis[k],"\0");
      }
      return &a;
    }
  }
  fclose(fp);

  return NULL;
}
