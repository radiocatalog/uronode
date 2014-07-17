#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <signal.h>
#include <netax25/procutils.h>
#include <netax25/axlib.h>

#include "node.h"
#include "sysinfo.h"

struct user User	= {0};
static long CallerPos	= -1L;

void login_user(void)
{
  FILE *f;
  struct user u;
  long pos = 0L;
  long free = -1L;
  struct stat statbuf;

  if (stat(DATA_NODE_LOGIN_FILE, &statbuf) == -1) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return;
  }
  if (statbuf.st_size % sizeof(struct user) != 0) {
    node_msg("%s: Incorrect size", DATA_NODE_LOGIN_FILE);
    node_log(LOGLVL_ERROR, "%s: Incorrect size", DATA_NODE_LOGIN_FILE);
    return;
  }
  time(&User.logintime);
  User.cmdtime = User.logintime;
  User.pid     = getpid();
  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r+")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return;
  }
  if (flock(fileno(f), LOCK_EX) == -1) {
    node_perror("login_user: flock", errno);
    fclose(f);
    return;
  }
  while (fread(&u, sizeof(u), 1, f) == 1) {
    if (u.pid == -1 || (kill(u.pid, 0) == -1 && errno == ESRCH)) {
      free = pos;
      break;
    }
    pos += sizeof(u);
  }
  if (free != -1L && fseek(f, free, 0L) == -1) {
    node_perror("login_user: fseek", errno);
    fclose(f);
    return;
  }
  fflush(f);
  CallerPos = ftell(f);	
  fwrite(&User, sizeof(User), 1, f);
  fflush(f);
  flock(fileno(f), LOCK_UN);
  fclose(f);
}

void logout_user(void)
{
  FILE *f;

  if (CallerPos == -1L)
    return;
  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r+")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return;
  }
  if (fseek(f, CallerPos, 0) == -1) {
    node_perror("logout_user: fseek", errno);
    fclose(f);
    return;
  }
  User.pid = -1;
  fwrite(&User, sizeof(User), 1, f);
  fclose(f);
}

void update_user(void)
{
  FILE *f;

  if (CallerPos == -1L)
    return;
  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r+")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return;
  }
  if (fseek(f, CallerPos, 0) == -1) {
    node_perror("update_user: fseek", errno);
    fclose(f);
    return;
  }
  fwrite(&User, sizeof(User), 1, f);
  fclose(f);
}

int user_count(void)
{
  FILE *f;
  struct user u;
  int cnt = 0;

  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return 0;
  }
  while (fread(&u, sizeof(u), 1, f) == 1)
    if (u.pid != -1 && (kill(u.pid, 0) != -1 || errno != ESRCH))
      cnt++;
  fclose(f);
  return cnt;
}

int user_list(int argc, char **argv)
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
    axio_printf(NodeIo, "%s} %s", NodeId, VERSION);
  }
  if (User.ul_type == AF_INET)  {
    axio_printf(NodeIo, "\e[01;35m"); 
  } else {
    axio_printf(NodeIo, "Current users:");
  }
  if (user_count() == 0) {
    axio_printf(NodeIo, " No users online.\n");
  }
  if (User.ul_type == AF_INET) {
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
    default:
      axio_puts("  -> ??????",NodeIo);
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

