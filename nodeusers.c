#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <signal.h>
#include <syslog.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/procutils.h>

#include "node.h"
#include "config.h"

char *NodeId		= "Nodeusers:";
int LogLevel		= LOGLVL_NONE;
ax25io *NodeIo		= NULL;
static void pipe_handler(int sig)
{
  syslog(LOG_ERR, "received SIGPIPE");
  axio_end(NodeIo);
  exit(1);
}

int main(int argc, char **argv)
{
  int n, len = 1024;
  char *cp = UNSPEC_EOL;
  int inet = 0;
  int logging = 0;

  while ((n = getopt(argc, argv, "ail")) != -1) {
    switch (n) {
    case 'a':
      cp = AX25_EOL;
      len = 128;
      break;
    case 'i':
      cp = INET_EOL;
      inet = 1;
      break;
    case 'l':
      logging = 1;
      break;

    default:
      fprintf(stderr, "usage: nodeusers [-a] [-i] [-l]\r\n");
      return 1;
    }
  }
  if (logging)
    openlog("nodeusers", LOG_PID, LOG_DAEMON);
  signal(SIGPIPE, pipe_handler);
  NodeIo = axio_init(STDIN_FILENO, STDOUT_FILENO, len, cp);
  if (NodeIo == NULL) {
    fprintf(stderr, "nodeusers: axio_init failes\r\n");
    return 1;
  }
  if (inet && axio_getline(NodeIo) == NULL) {
    if (logging)
      syslog(LOG_ERR, "axio_getline: %m");
    axio_printf(NodeIo,"\n");
    axio_end(NodeIo);
    return 1;
  }
  n = user_count();
  axio_printf(NodeIo,"\n%s (%s), %d user%s.\n",
	      VERSION, COMPILING, n, n == 1 ? "" : "s");
  user_list(0, NULL);
  if (n > 0)
    axio_printf(NodeIo,"\n");
  if (axio_flush(NodeIo) == -1 && logging)
    syslog(LOG_ERR, "axio_flush: %m");
  axio_end(NodeIo);
  usleep(500000L);
  closelog();
  return 0;
}
