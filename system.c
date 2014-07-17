#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/param.h>

#include <fcntl.h>
#include <ctype.h>
#include <signal.h>

#include <paths.h>
#include <pwd.h>
#include <utmp.h>
#include <time.h>

#include <termios.h>
#include <unistd.h>

#include "md2.c"
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>

#include "node.h"
#include "procinfo.h"

#define DATA_NODE_LAST_FILE "/var/ax25/node/lastlog"
#define DATA_NODE_IP_FILE "/var/ax25/node/iplog"
#define CONF_USERS_FILE "/etc/ax25/uronode.users"
#define USER_NOBODY "nobody"

#define NUMPTY 176
#define SYSTEM_TIMEOUT 7200
#define LAST_DATA_SIZE 120

int shell=0;
char *envp[16], *argp[16], mbox[40];
char other_id[20];
int in_queue=0;
int pid=-1;
char ptyname[80], Password[256];
int ptyfd;

/*---------------------------------------------------------------------------*/

int cusgets(char *buf, int buflen, ax25io *iop)
{
  int c, len = 0;

  while (len < (buflen - 1)) {
    c = axio_getc(iop);
    if (c == -1) {
      if (len > 0) {
        buf[len] = 0;
        return (len);
      } else return -1;
    }
    /* NULL also interpreted as EOL */
    if (c == '\n' || c == '\r' || c == 0) {
      buf[len++] = c;
      buf[len] = 0;
      return (len);
    }
    buf[len++] = c;
  }
  buf[buflen - 1] = 0;
  return (buflen-1);
}

/*---------------------------------------------------------------------------*/

int find_pty(char *ptyname)
{
  char master[80];
  int fd;
  int num;
  static int lastnum = -1;

  for(num = lastnum + 1; ; num++) {
    if (num >= NUMPTY) num = 0;
    sprintf(master, "/dev/pty%c%x", 'p' + (num >> 4), num & 0xf);
    if ((fd = open(master, O_RDWR | O_NONBLOCK, 0600)) >= 0) {
      sprintf(ptyname, "/dev/tty%c%x", 'p' + (num >> 4), num & 0xf);
      lastnum = num;
      return fd;
    }
    if (num == lastnum) break;
  }

  return -1;
}

/*---------------------------------------------------------------------------*/

void login_close(void)
{
  struct utmp utmpbuf, *ut;
  FILE *fp;

  if (ptyfd > 0) {
    chown(ptyname, 0, 0);
    chmod(ptyname, 0666);
    ioctl(ptyfd, TCFLSH, 2);
    close(ptyfd);
  }
  if (pid>0) {
    kill(pid, SIGHUP);
    pid=0;
  }

  memset(&utmpbuf, 0, sizeof(utmpbuf));
  setutent();
  utmpbuf.ut_type=LOGIN_PROCESS;
  strcpy(utmpbuf.ut_line, ptyname+5);
  strcpy(utmpbuf.ut_id, ptyname+strlen(ptyname)-2);
  ut=getutid(&utmpbuf);
  ut->ut_type=DEAD_PROCESS;
  memset(ut->ut_host,0,UT_HOSTSIZE);
  memset(ut->ut_user,0,UT_NAMESIZE);
  time(&ut->ut_time); 
/*  ut->ut_xtime = (unsigned int)time(NULL); */
  pututline(ut);
  endutent();
  if ((fp = fopen(_PATH_WTMP, "r+")) != NULL) {
    fseek(fp, 0L, SEEK_END);
    fwrite(ut, sizeof(utmpbuf), 1, fp);
    fclose(fp);
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} Welcome back.\n", NodeId);
  } else {
    axio_printf(NodeIo,"Welcome back.");
  }
}

/*---------------------------------------------------------------------------*/

int login_open(struct passwd *pw, char *command)
{
  if ((ptyfd=find_pty(ptyname)) < 0) {
    syslog(LOG_ERR, "Error opening pseudo terminal for %s", pw->pw_name);
    return -1;
  }

  syslog(LOG_INFO, "Opened pseudo terminal (%s) for %s", ptyname, pw->pw_name);

  pid=fork();
  
  if (pid==-1) { 
    syslog(LOG_ERR, "Cannot fork for %s", pw->pw_name);
    return -1;
  }

  if (pid==0) { /* child */
    struct termios termios;
    struct utmp utmpbuf;
    int i;

    for(i=0;i<FD_SETSIZE;i++) close(i);
    setsid();
    open(ptyname, O_RDWR, 0666);
    dup(0);
    dup(0);
    chmod(ptyname, 0622);
    ioctl(0, TIOCSCTTY, 0);
    
    memset(&termios, 0 , sizeof(termios));
    termios.c_iflag = ICRNL | IXOFF;
    termios.c_oflag = OPOST | ONLCR | TAB3;
    termios.c_cflag = CS8 | CREAD | CLOCAL;
    termios.c_lflag = ISIG | ICANON;

    termios.c_cc[VINTR] = 127;
    termios.c_cc[VQUIT] = 28;
    termios.c_cc[VERASE] = 8;
    termios.c_cc[VKILL] = 24;
    termios.c_cc[VEOF] = 4;

    cfsetispeed(&termios, B38400);
    cfsetospeed(&termios, B38400);
    tcsetattr(0, TCSANOW, &termios);

    memset(&utmpbuf, 0, sizeof(utmpbuf));
    utmpbuf.ut_type=USER_PROCESS;                          /* Type of login */
    utmpbuf.ut_pid=getpid();                               /* Pid of login process */
    strcpy(utmpbuf.ut_line, ptyname+5);                    /* Devicename of tty */
    strcpy(utmpbuf.ut_id, ptyname+strlen(ptyname)-2);      /* Inittab id */
    strcpy(utmpbuf.ut_user, pw->pw_name);                  /* Username */
    strcpy(utmpbuf.ut_host, "local:uronode");
    utmpbuf.ut_addr=0x7f000000;
    time(&utmpbuf.ut_time);                                /* Time entry was made */
/*    utmpbuf.ut_xtime = (unsigned int)time(NULL); */

    setutent();
    pututline(&utmpbuf);
    endutent();

    setgid(pw->pw_gid);
    setuid(pw->pw_uid);

    execve(command, argp, envp);
    exit(1);
  }

  if (pid!=0) {
    int k, cnt;
    fd_set fds_read, fds_err;
    struct timeval tv;
    char buf[1500];

    while(1) {
      FD_ZERO(&fds_read);
      FD_ZERO(&fds_err);
      FD_SET(STDIN_FILENO, &fds_read);
      /* FD_SET(User.fd, &fds_err); */
      FD_SET(ptyfd, &fds_read);
      /* FD_SET(ptyfd, &fds_err); */

      if (User.ul_type==AF_INET) {
	tv.tv_usec=25; 
	tv.tv_sec=0;
      } else {
	tv.tv_usec=750; 
	tv.tv_sec=0;
      }

      if (in_queue>0) k=select(ptyfd+1, &fds_read, NULL, &fds_err, &tv);
      else k=select(ptyfd+1, &fds_read, NULL, &fds_err, NULL);
					  
      if (k == -1) {
	if (errno!=EINTR) {
	  syslog(LOG_DEBUG,"I/O select");
	  break;
	}
      }

      if (k == 0) {
	if (in_queue>0) {
	  axio_flush(NodeIo);
	  in_queue=0;
	}
      }

      /*      if (FD_ISSET(User.fd, &fds_err)) {    
	      syslog(LOG_DEBUG,"I/O end: error channel, user");
	      break;
	      }
      
	      if (FD_ISSET(ptyfd, &fds_err)) {
	      syslog(LOG_DEBUG,"I/O end: error channel, application");
	      break;
	      } */

      if (FD_ISSET(STDIN_FILENO, &fds_read)) {
        alarm(SYSTEM_TIMEOUT);
	cnt=cusgets(buf, sizeof(buf), NodeIo);
	if (cnt < 0)
	  {   
	    syslog(LOG_DEBUG,"I/O end: stdio channel, user");
	    break;
	  } else {
	  write(ptyfd, buf, cnt);
	}   
      }
      
      if (FD_ISSET(ptyfd, &fds_read)) {
        alarm(SYSTEM_TIMEOUT);
	cnt = read(ptyfd, buf, sizeof(buf));
	if (cnt < 0) {
	  syslog(LOG_DEBUG,"I/O end: stdio channel, application");
	  break;
	}
	for(k = 0 ; k < cnt ; k++) {
	  if (buf[k]=='\n' && (User.ul_type==AF_AX25 || User.ul_type==AF_FLEXNET || User.ul_type==AF_NETROM)) continue;
	  axio_putc(buf[k], NodeIo);
	}
	in_queue+=cnt;
      }
    }

    login_close();
  }

  return 0;
}

/*---------------------------------------------------------------------------*/

int check_passwd(void)
{
  char buffer[400]="",
    tmp[100]="";
  int  pass[5],
    level,i;
  long timet;

  char answer[81]="";
  char buf[2048];

  unsigned char MD2digest[16];
  MD2_CTX context;

  level=strlen(Password);
  timet=time(NULL);
  srandom((int) timet);
  for(i=0;i<5;i++) pass[i]=(int) (level * (random()/(RAND_MAX+1.0)));
	
  sprintf(buffer,"%10.10ld%s",timet,Password);
  MD2Init(&context);
  MD2Update(&context,(unsigned char *)buffer,level+10);
  MD2Final(MD2digest,&context);
	
  for(i=0;i<16;i++) sprintf(&tmp[i*2],"%02x",MD2digest[i]);

  axio_printf(NodeIo,"%s %d %d %d %d %d [%010.10ld]\n",
	      PassPrompt,pass[0]+1,pass[1]+1,pass[2]+1,pass[3]+1,pass[4]+1,timet);
	
  sprintf(answer,"%c%c%c%c%c",Password[pass[0]],Password[pass[1]],Password[pass[2]],Password[pass[3]],Password[pass[4]]);

  axio_flush(NodeIo);
  axio_gets(buf, sizeof(buf), NodeIo);
  

  if(strlen(buf)==32) i=strcmp(buf,tmp);					/* yes, use md2 password, ignoring case */
  else	i=strcmp(buf,answer);

  if(i)	{
    axio_printf(NodeIo,"Password incorrect!");
    return 0;
  }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  axio_printf(NodeIo,"URONode Shell engaged - use EXTREME caution! \n\n");
  return 1;
} 

/*---------------------------------------------------------------------------*/

int do_system(int argc, char **argv)
{
  int i;
  struct passwd *pw=NULL;
  argp[0]=argv[0];
  for(i=1;i<(argc);i++) argp[i]=argv[i];
  argp[argc]=NULL;

  axio_puts("",NodeIo);
  if (other_id!=NULL && strcmp(other_id, USER_NOBODY)!=0) pw=getpwnam(other_id);

  if (pw==NULL) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    } 
    node_msg("Permission denied\n");
    syslog(LOG_INFO, "system: %s attempted command %s", User.call, argv[0]);
    axio_puts("",NodeIo);
    return 1;
  }
  if (strncmp(argv[0],"sysop",strlen(argv[0]))==0) 
    {
      if (shell==1) {
	User.state = STATE_EXTCMD;
	User.dl_type = AF_UNSPEC;
	strcpy(User.dl_name, "sysop");
	strupr(User.dl_name);
	update_user();
	if (check_passwd()==0) return 0; 
	login_open(pw, "/bin/bash");
	axio_puts("",NodeIo);
	return 0;
      } else {
	if (User.ul_type == AF_NETROM) {
	  axio_printf(NodeIo,"%s} ", NodeId);
	}
	node_msg("permission denied");
	axio_puts("",NodeIo);
	return 1;
      };
    }
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo,"%s} ", NodeId);
  }
  node_msg("unknown command");

  return 0;
}

int examine_user(void)
{
  FILE *users;
  char call[10], buf[1024], *cp, *ep;
  char flags[40];

  strcpy(other_id, USER_NOBODY);

  if ((users=fopen(CONF_USERS_FILE, "r"))==NULL) {
    node_msg("system: cannot open authority file: %s", CONF_USERS_FILE);
    syslog(LOG_ERR, "system: cannot open authority file: %s", CONF_USERS_FILE);
    axio_puts("",NodeIo);
    return 1;
  }

  strcpy(call, User.call);
  cp=strchr(call, '-');
  if (cp) *cp='\0';

  while(fgets(buf, 1024, users)) {
    ep=strchr(buf, '#');
    if (ep) *ep='\0';
    if (*buf==0) continue;
    cp=strtok(buf, ":\t\n\r");
    if (cp==NULL) continue;
    if (strcasecmp(cp, call)==0) {
      cp=strtok(NULL, ":\t\n\r");
      if (cp==NULL) continue;
      strcpy(Password, cp);
      cp=strtok(NULL, ":\t\n\r");
      if (cp==NULL) continue;
      strcpy(other_id, cp);
      cp=strtok(NULL, ":\t\n\r");
      if (cp==NULL) continue;
      strcpy(flags, cp);
    }
  }

  if (strcmp(other_id, USER_NOBODY)==0) return 0;
  
  cp=strtok(flags, " ,;-/\t\n\r");
  if (cp==NULL) return 0;
  do {
    if (strcmp(cp, "shell")==0) {
      shell=1;
      add_internal_cmd(&Nodecmds, "SYSop",	1, do_system);
    }
    cp=strtok(NULL, " ,;-/\t\n\r");
  } while(cp!=NULL);

  return 0;
}

struct nodelastlog {
  char ll_user[8];
  long ll_time;
  char ll_line[LAST_DATA_SIZE];
  char ll_host[LAST_DATA_SIZE];
  int  ll_count;
};

struct ipheardlastlog {
  char ii_host[LAST_DATA_SIZE];
};

void lastlog(void)
{
  struct nodelastlog ll;
  int last;
  int count=0;
  int hit=0;
  int UserId=0;
  char tty[LAST_DATA_SIZE];
  char hostname[LAST_DATA_SIZE];
  char usercall[10];
  char *cp;
  int escape;
  strcpy(usercall, User.call);  
  cp=strchr(usercall, '-');
  if (cp) *cp='\0';
  strcpy(tty, "");
  switch (User.ul_type) {
  case AF_FLEXNET: strcpy(hostname, "FlexNet");
    break;
  case AF_AX25: strcpy(hostname, "[");
    strcat(hostname, "AX25");
    strcat(hostname, "] ");
    strcat(hostname, User.call);
    if (strlen(User.ul_name)>0) {
      strcat(hostname, " via ");
      strcat(hostname, User.ul_name);
    }
    break;
  case AF_NETROM: strcpy(hostname, "<");
    strcat(hostname, User.ul_port);
    strcat(hostname, "> ");
    strcat(hostname, User.call);
    if (strlen(User.ul_name)>0) {
      strcat(hostname, "@");
      strcat(hostname, User.ul_name);
    }
    break;
#ifdef HAVE_ROSE
  case AF_ROSE:   strcpy(hostname, User.call);
    if (strlen(User.ul_name)>0) {
      strcat(hostname, " at ");
      strcat(hostname, User.ul_name);
    }
    break;
#endif    
  case AF_INET:   strcpy(hostname, User.ul_name);
    break;
  case AF_UNSPEC: strcpy(hostname, User.call);
    strcat(hostname, " on local");
    break;
  default:        strcpy(hostname, "");
    break;
  }

  if ((last = open(DATA_NODE_LAST_FILE, O_RDWR, 0)) >= 0) { 
    lseek(last, (off_t)UserId * sizeof(ll), L_SET);
    while (read(last, (char *)&ll, sizeof(ll)) == sizeof(ll) && ll.ll_time != 0) {
      if (strcmp(ll.ll_user,usercall)==0) {
	escape = (check_perms(PERM_NOESC, 0L) == 0) ? -1 : EscChar;
#ifdef HAVEMOTD
	/*
	  if (User.ul_type != AF_NETROM) {
	  axio_printf(NodeIo," Escape is: %s%c\n", escape < 32 ? "CTRL-" : "", escape < 32 ? (escape + 'A' - 1) : escape);
	  axio_printf(NodeIo,"Last login: %.*s ",24-5,(char *)ctime(&ll.ll_time));
	  if (*ll.ll_host != '\0') axio_printf(NodeIo,"\n      From: %.*s\n",(int)sizeof(ll.ll_host), ll.ll_host);
	  else                     axio_printf(NodeIo," on %.*s\n",(int)sizeof(ll.ll_line), ll.ll_line); 
	  }
	*/
#endif
        count=ll.ll_count;
        hit++;
        break;
      } else UserId++;
    }
    lseek(last, (off_t)UserId * sizeof(ll), L_SET); 
  }
  memset((char *)&ll, 0, sizeof(ll)); 
  if ((hit==0) && (User.ul_type != AF_NETROM)) {
    axio_printf(NodeIo,"Welcome, new user! Please use the Info and ? commands.\n\n");
    count=0;
  }
  ll.ll_count=count+1;
  (void)time(&ll.ll_time);
  strncpy(ll.ll_line, tty, sizeof(ll.ll_line));
  strncpy(ll.ll_user, usercall, sizeof(ll.ll_user));
  if (hostname) strncpy(ll.ll_host, hostname, sizeof(ll.ll_host));
  write(last, (char *)&ll, sizeof(ll));
  close(last);
}

int do_last(int argc, char **argv)
{
  int last;
  struct nodelastlog ll;
  int Entries=0;
  char call[10], *cp;

  if ((last = open(DATA_NODE_LAST_FILE, O_RDONLY, 0)) <= 0) {
    node_perror(DATA_NODE_LAST_FILE, errno);
    return -1;
  }

  if (argc < 2) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    axio_printf(NodeIo,"Usage: Who <callsign or *>");
    close(last);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  if (strcmp(argv[1],"*")==0) {
    cp=NULL;
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo,"%s} ", NodeId);
    }
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;37m");
    }
    axio_printf(NodeIo,"Logins for ALL:\n", call);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[0m");
    }
  } else {
    if (!ax25_aton_entry(argv[1], call)) {
      strcpy(call,strupr(argv[1]));
      cp=strchr(call,'-');
      if (cp) *cp='\0';
      cp=call;
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
      if (check_perms(PERM_ANSI, 0L) != -1) {
        axio_printf(NodeIo, "\e[01;37m");
      }
      axio_printf(NodeIo,"Last online information for %s:\n", call);
      if (check_perms(PERM_ANSI, 0L) != -1) {
        axio_printf(NodeIo, "\e[0m");
      }
    } else {
      if (User.ul_type == AF_NETROM) {
	axio_printf(NodeIo,"%s} ", NodeId);
      }
      axio_printf(NodeIo,"Usage: Who <callsign or *>\n");
      if (User.ul_type == AF_NETROM) {
      	node_msg("");
      }
      close(last);
      return -1;
    }
  }
  
  lseek(last, (off_t)Entries * sizeof(ll), L_SET);
  /*  while (Entries < 20 && (read(last, (char *)&ll, sizeof(ll)) == sizeof(ll) && ll.ll_time != 0)) {  */
  while (read(last, (char *)&ll, sizeof(ll)) == sizeof(ll) && ll.ll_time !=0) {
    if (cp && strcasecmp(cp,ll.ll_user)!=0) continue;
    if (Entries==0) {
      axio_printf(NodeIo,"User       Last Online          Count  From\n");
      axio_printf(NodeIo,"------     -------------------- -----  -----------------------------");
    }
    axio_printf(NodeIo,"\n%-10s ", ll.ll_user); 
    axio_printf(NodeIo,"%.*s  ",24-5,(char *)ctime(&ll.ll_time));
    axio_printf(NodeIo,"%-5d ",ll.ll_count);
    if (*ll.ll_host != '\0') axio_printf(NodeIo," %.*s",(int)sizeof(ll.ll_host), ll.ll_host);
    else axio_printf(NodeIo," on %.*s",(int)sizeof(ll.ll_line), ll.ll_line);
    Entries++;
  }
  lseek(last, (off_t)Entries * sizeof(ll), L_SET);
  
  close(last);
  if (!cp && Entries==0) axio_printf(NodeIo,"No users in the lastlog database.");
  if (cp && Entries==0) axio_printf(NodeIo,"%s Never logged in.", call);

  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}
