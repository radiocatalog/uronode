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
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>
#include <netax25/daemon.h>

#include "config.h"
#include "procinfo.h"

#define DEFAULT_POLL_TIME 600
#define MINIMUM_POLL_TIME 300

int poll_time=DEFAULT_POLL_TIME;
char flexgate[10]="\0";
char mycall[10]="\0";
struct ax_routes *gw;
int s;
void (*sigterm_defhnd)(int);

void read_conf(void)
{
  FILE *fp, *fgt;
  char buf[1024], line[1024], *cp;
  int i=0,k;
  char digipath[AX25_MAX_DIGIS*10];

  if ((fp=fopen(FLEXD_CONF_FILE, "r")) == NULL) {
    fprintf(stderr, "flexd config: Cannot open config file: %s\n", FLEXD_CONF_FILE);
    exit(1);
  }  
  if ((fgt=fopen(FLEX_GT_FILE, "w")) == NULL) {
    fprintf(stderr, "flexd config: Cannot open flexnet gateways file: %s\n", FLEX_GT_FILE);
    fclose(fp);
    exit(1);
  }

  fputs("addr  callsign  dev  digipeaters\n", fgt);
  
  while(fgets(buf, sizeof(buf), fp)) {
    if(*buf=='#' || *buf==' ') continue; /* comment line/empty line */
    cp=strchr(buf, '#');
    if (cp) *cp='\0';
    cp=strtok(buf, " \t\n\r");
    if(cp==NULL) continue; /* empty line */

    if(strcasecmp(cp,"pollinterval")==0) { /* set poll interval */
      cp=strtok(NULL, " \t\n\r");
      if(cp==NULL) {
	fprintf(stderr, "flexd config: PollInterval needs an argument\n");
	fclose(fp);
	fclose(fgt);
	exit(1);        
      }
      poll_time=safe_atoi(cp);
      if (poll_time<MINIMUM_POLL_TIME) poll_time=MINIMUM_POLL_TIME;
    }
    if(strcasecmp(cp,"mycall")==0) { /* set connect call for download */
      cp=strtok(NULL, " \t\n\r");
      if(cp==NULL) {
	fprintf(stderr, "flexd config: MyCall needs an argument\n");
	fclose(fp);
	fclose(fgt);
	exit(1);        
      }
      safe_strncpy(mycall, cp, 9);
    }
    if(strcasecmp(cp,"flexgate")==0) { /* set flexnet gateway */
      cp=strtok(NULL, " \t\n\r");
      if(cp==NULL) {
	fprintf(stderr, "flexd config: FlexGate needs an argument\n");
	fclose(fp);
	fclose(fgt);
	exit(1);        
      }      
      safe_strncpy(flexgate, cp, 9);
      gw=find_route(flexgate, NULL);
      if (gw==NULL) {
	fprintf(stderr, "flexd config: FlexGate %s not found in route file: %s\n", flexgate, AX_ROUTES_FILE);
	fclose(fp);
	fclose(fgt);
	exit(1);
      } else {
	*digipath='\0';
	for(k=0;k<AX25_MAX_DIGIS;k++) {
	  if (gw->digis[k]==NULL) break;
	  strcat(digipath," ");
	  strcat(digipath, gw->digis[k]);
	}
	sprintf(line, "%05d %-8s %4s %s\n", i++, gw->dest_call, ax25_config_get_dev(gw->dev), digipath);
	fputs(line, fgt);
      }
    }
  }	 

  fclose(fgt);
  fclose(fp);
}

int download_dest(char *gateway, char *fname)
{
  FILE *tmp;
  char buffer[1024], port[14], path[AX25_MAX_DIGIS*10];
  char *addr, *commands[10], *dlist[9]; /* Destination + 8 digipeaters */
  fd_set read_fd;
  int n, addrlen, cmd_send=0, cmd_ack=0, c, k;
  struct full_sockaddr_ax25 axbind, axconnect;
  struct timeval tv;

  gw=find_route(gateway, NULL);
  if (gw==NULL) {
    fprintf(stderr, "flexd connect: FlexGate %s not found in route file: %s\n", gateway, AX_ROUTES_FILE);
    return 1;
  } else {
    *path='\0';
    for(k=0;k<AX25_MAX_DIGIS;k++) {
      if (gw->digis[k][0]=='\0') dlist[k+1]=NULL;
      else dlist[k+1]=gw->digis[k];
    }
    dlist[0]=gw->dest_call;
    strcpy(port,gw->dev);
  }

  if ((addr = ax25_config_get_addr(port)) == NULL) {
    sprintf(buffer, "flexd connect: invalid AX.25 port name - %s\r\n", port);
    write(STDOUT_FILENO, buffer, strlen(buffer));
    return 1;
  }
  
  /*
   * Open the socket into the kernel.
   */
  if ((s = socket(AF_AX25, SOCK_SEQPACKET, 0)) < 0) {
    sprintf(buffer, "flexd connect: cannot open AX.25 socket, %s\r\n", strerror(errno));
    write(STDOUT_FILENO, buffer, strlen(buffer));
    return 1;
  }
  
  /*
   * Set our AX.25 callsign and AX.25 port callsign accordingly.
   */
  if (*mycall=='\0') sprintf(buffer, "%s %s", addr, addr);
  else sprintf(buffer, "%s %s", mycall, addr);
  ax25_aton(buffer, &axbind);
  axbind.fsa_ax25.sax25_family = AF_AX25;
  addrlen=sizeof(struct full_sockaddr_ax25);
  
  if (bind(s, (struct sockaddr *)&axbind, addrlen) != 0) {
    sprintf(buffer, "flexd connect: cannot bind AX.25 socket, %s\r\n", strerror(errno));
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(s);
    return 1;
  }
  
  /*
   * Lets try and connect to the far end.
   */
  addrlen=sizeof(struct full_sockaddr_ax25);
  axconnect.fsa_ax25.sax25_family = AF_AX25;
  
  if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
    sprintf(buffer, "flexd connect: fcntl on socket: %s\r\n", strerror(errno));
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(s);
    return 1;
  }

  if (ax25_aton_arglist((const char **)dlist, &axconnect) == -1) {
    sprintf(buffer, "flexd connect: invalid destination callsign or digipeater\r\n");
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(s);
    return 1;
  }
  
  if (connect(s, (struct sockaddr *)&axconnect, addrlen) == -1 && errno != EINPROGRESS) {
    switch (errno) {
    case ECONNREFUSED:
      strcpy(buffer, "*** Connection refused - aborting\r\n");
      break;
    case ENETUNREACH:
      strcpy(buffer, "*** No known route - aborting\r\n");
      break;
    case EINTR:
      strcpy(buffer, "*** Connection timed out - aborting\r\n");
      break;
    default:
      sprintf(buffer, "*** Cannot connect, %s\r\n", strerror(errno));
      break;
    }
    
    write(STDOUT_FILENO, buffer, strlen(buffer));
    close(s);
    return 1;
  }
  
  while (1) {
    FD_ZERO(&read_fd);
    FD_SET(s, &read_fd);

    tv.tv_sec=180;
    tv.tv_usec=0;
    
    k=select(s + 3, &read_fd, NULL, 0, &tv);
    
    if (k<1) { /* error or timeout */
      break;
    }
    if (FD_ISSET(s, &read_fd)) {
      int ret, retlen;
      char *cp;
      
      /* See if we got connected or if this was an error */
      getsockopt(s, SOL_SOCKET, SO_ERROR, &ret, &retlen);
      if (ret != 0) {
	cp = strdup(strerror(ret));
	strlwr(cp);
	sprintf(buffer, "flexd connect: Failure with %s: %sr\r\n", gateway, cp);
	write(STDOUT_FILENO, buffer, strlen(buffer));
	free(cp);
	close(s);
	return 1;
      }
     break;
    }
  }
  
  commands[0]="d\r\n";
  commands[1]="q\r\n";
  commands[2]=NULL;
  
  /*
   * Loop until one end of the connection goes away.
   */

  if ((tmp=fopen(fname, "w")) == NULL) {
    fprintf(stderr, "flexd connect: Cannot open temporary file: %s\n", fname);
    close(s);
    return 1;
  }
  
  for (;;) {
    FD_ZERO(&read_fd);
    FD_SET(s, &read_fd);
    
    tv.tv_sec=180;
    tv.tv_usec=0;
    
    k=select(s + 1, &read_fd, NULL, NULL, &tv);
    
    if (k<1) { /* error or timeout */
      break;
    }
    
    if (FD_ISSET(s, &read_fd)) {
      if ((n = read(s, buffer, 512)) == -1) break;
      for(c=0;c<n;c++) { 
	if (buffer[c]=='\r') buffer[c]='\n';
	if (buffer[c]=='=' && c<n-1 && buffer[c+1]=='>') {
	  /* fprintf(stderr, "flex interact: ack[%d]\n", cmd_ack); */
	  cmd_ack++;
	}
      }
      fwrite(buffer, sizeof(char), n, tmp);
    }
 
    if (cmd_ack!=0) {
      if (commands[cmd_send]!=NULL) {
	write(s, commands[cmd_send], 2);
	/* fprintf(stderr, "flexd interact: send[%d]: %s\n", cmd_send, commands[cmd_send]); */
	cmd_send++;
      }
      cmd_ack=0;
    }
  }
  
  close(s);

  fputs("\n",tmp);

  fclose(tmp);
  return 0;
}

int parse_dest(char *gateway, char *fname)
{
  FILE *fdst, *tmp;
  char *call, *ssid, *rtt, *cp, buf[1024], line[1024], ax[10];
  int i=0;

  if ((tmp=fopen(fname, "r")) == NULL) {
    fprintf(stderr, "flexd update: Cannot open temporary file: %s\n", fname);
    return 1;
  }
  
  if ((fdst=fopen(FLEX_DST_FILE, "w")) == NULL) {
    fprintf(stderr, "flexd update: Cannot open flexnet destinations file: %s\n", FLEX_DST_FILE);
    fclose(tmp);
    return 1;
  }
  
  fputs("callsign  ssid     rtt  gateway\n", fdst);
/*   fprintf(fdst, "%s	  %s	     0	  00000\n", mygate, myrange); */
  while(fgets(buf, sizeof(buf), tmp)) {
    cp=strtok(buf, " \t\n\r");
    if(cp==NULL) continue; /* empty line */
    if(strstr(cp,"=>")) i++; /* system prompt */
    if(i==0) continue; /* skip connect text */
    if(*cp=='#' || *cp=='=' || *cp==' ' || *cp=='*' || *cp=='-' || *cp==':') continue; /* comment line/system prompt */
    if(strncmp(cp,"73!",3)==0) continue; /* End greeting */

    /* CALL SSID-ESID RTT */
    do {
      call=cp;
      if (call==NULL) break;
      if (strlen(call)>6) break;
      if (strchr(call,'-')) break;
      if (ax25_aton_entry(call,ax)!=0) break;
      if (!ax25_validate(ax)) break;
      ssid=strtok(NULL, " \t\n\r");
      if (ssid==NULL) break;
      if (!strchr(ssid,'-')) break;
      rtt=strtok(NULL, " \t\n\r");
      if (rtt==NULL) break;
      if (atoi(rtt)==0) break;
      sprintf(line, "%-8s  %-5s %6d    %05d\n", call, ssid, safe_atoi(rtt), 0);
      fputs(line, fdst);
      cp=strtok(NULL, " \t\n\r");
    } while(cp!=NULL);
  }	 

  fclose(fdst);
  fclose(tmp);

  return 0;
}

int update_flex(void)
{
  char fname[80];

  sprintf(fname, "%s/.session.%s", FLEXD_TEMP_PATH, flexgate);

  if (download_dest(flexgate, fname)==0) parse_dest(flexgate, fname);
  remove(fname);

  return 0;
}

void hup_handler(int sig)
{
  signal(SIGHUP, SIG_IGN);
  
  read_conf();
  
  signal(SIGHUP, hup_handler); /* Restore hangup handler */
}

void alarm_handler(int sig)
{
  signal(SIGALRM, SIG_IGN);

  update_flex();

  signal(SIGALRM, alarm_handler); /* Restore alarm handler */
  alarm(poll_time); 
}

void quit_handler(int sig) 
{
  signal(SIGTERM, SIG_IGN);

  unlink(FLEXD_PID_FILE);
  
  signal(SIGTERM, sigterm_defhnd);
  raise(SIGTERM);
}

int main(int argc, char *argv[])
{       
  FILE *pidfile; 

 signal(SIGPIPE, SIG_IGN);

  if (ax25_config_load_ports() == 0) {
    fprintf(stderr, "flexd error: No AX25 port data configured\n");
    return 1;
  }

  read_conf();

  if (!daemon_start(TRUE)) {
    fprintf(stderr, "flexd: cannot become a daemon\n");
    return 1;
  }

  signal(SIGTERM, quit_handler);
  pidfile = fopen(FLEXD_PID_FILE, "w");
  fprintf(pidfile, "%d\n", (int)getpid());
  fclose(pidfile);

  update_flex();
  
  signal(SIGHUP, hup_handler);
  signal(SIGALRM, alarm_handler);
  sigterm_defhnd = signal(SIGTERM, quit_handler);
  if (sigterm_defhnd == SIG_ERR)
    sigterm_defhnd = SIG_DFL;
  alarm(poll_time); 
  
  for(;;) pause();

  return 0;
}

