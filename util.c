#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <sys/file.h>

#include <sys/socket.h>
#include <netax25/kernel_ax25.h>
#include <netax25/kernel_rose.h>
#include <netax25/axlib.h>

#include "node.h"
#include "sysinfo.h"
#include "procinfo.h"

static char buf[256];
char *HostName;
char *Prompt;

void node_msg(const char *fmt, ...)
{
  va_list args;
	
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  axio_printf(NodeIo,"%s\n", buf);
}
/*
  void node_prompt(const char *fmt, ...)
  {
  va_list args;
  va_start(args, fmt);
  vsprintf(buf, fmt, args);
  va_end(args);
  if (User.ul_type == AF_NETROM) {
  axio_printf(NodeIo,"%s} ", NodeId);
  }
  if ((User.ul_type == AF_INET) && (check_perms(PERM_ANSI, 0L) != -1)) {
  axio_printf(NodeIo,"\n\e[01;31m%s\e[0m@\e[01;34m%s\e[0m:/uronode$ ",User.call, HostName);
  } 
  if ((User.ul_type == AF_INET) && (check_perms(PERM_ANSI, 0L) == -1)) {
  axio_printf(NodeIo,"\n%s@%s:/uronode$ ", User.call, HostName);
  }
  if (User.ul_type == AF_AX25) {
  axio_printf(NodeIo,"%s",Prompt);
  }
  }
*/
void node_perror(char *str, int err)
{
  int oldmode;

  oldmode = axio_eolmode(NodeIo, EOLMODE_TEXT);
  buf[0] = 0;
  if (str)
    strcpy(buf, str);
  if (str && err != -1)
    strcat(buf, ": ");
  if (err != -1)
    strcat(buf, strerror(err));
  axio_printf(NodeIo,"\nERROR; %s\n", buf);
  axio_eolmode(NodeIo, oldmode);
  axio_flush(NodeIo);
  node_log(LOGLVL_ERROR, buf);
}

char *print_node(const char *alias, const char *call)
{
  static char node[17];

  sprintf(node, "%s%s%s",
	  !strcmp(alias, "*") ? "" : alias,
	  !strcmp(alias, "*") ? "" : ":",
	  call);
  return node;
}

void node_log(int loglevel, const char *fmt, ...)
{
  static int opened = 0;
  va_list args;
  int pri;

  if (LogLevel < loglevel)
    return;
  if (!opened) {
    openlog("uronode", LOG_PID, LOG_LOCAL7);
    opened = 1;
  }
  switch (loglevel) {
  case LOGLVL_ERROR:
    pri = LOG_ERR;
    break;
  case LOGLVL_LOGIN:
    pri = LOG_NOTICE;
    break;
  case LOGLVL_GW:
    pri = LOG_INFO;
    break;
  default:
    pri = LOG_INFO;
    break;
  }
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  buf[sizeof(buf) - 1] = 0;
  va_end(args);	
  syslog(pri, "%s", buf);

}

