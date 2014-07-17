#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <grp.h>
#include <sys/wait.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>

#include "node.h"

#define ECMD_PIPE	1		/* Run through pipe 		*/

#ifdef HAVEMOTD
#define ECMD_RECONN	2		/* */
#endif

static int norm_extcmd(struct cmd *cmdp, char **argv)
{
  int pid;

  alarm(0L);
  pid = fork();
  if (pid == -1) {
    /* fork error */
    node_perror("norm_extcmd: fork", errno);
    return 0;
  }
  if (pid == 0) {
    /* child */
    setgroups(0, NULL);
    setgid(cmdp->gid);
    setuid(cmdp->uid);
    execve(cmdp->path, argv, NULL);
    node_perror("norm_extcmd: execve", errno);
    exit(1);
  }
  /* parent */
  waitpid(pid, NULL, 0);
  return 0;
}

static int pipe_extcmd(struct cmd *cmdp, char **argv)
{
  ax25io *iop;
  int pipe_in[2], pipe_out[2];
  int pid, c;
  fd_set fdset;

  if (pipe(pipe_in) == -1) {
    node_perror("pipe_extcmd: pipe_in", errno);
    return 0;
  }
  if (pipe(pipe_out) == -1) {
    node_perror("pipe_extcmd: pipe_out", errno);
    return 0;
  }
  signal(SIGCHLD, SIG_IGN);
  pid = fork();
  if (pid == -1) {
    /* fork error */
    node_perror("pipe_extcmd: fork", errno);
    signal(SIGCHLD, SIG_DFL);
    return 0;
  }
  if (pid == 0) {
    /* child */
    /*
     * Redirect childs output to the pipes closing
     * stdin/out/err as we go.
     */
    dup2(pipe_in[0], STDIN_FILENO);
    dup2(pipe_out[1], STDOUT_FILENO);
    dup2(pipe_out[1], STDERR_FILENO);
    /* Close the other ends */
    close(pipe_in[1]);
    close(pipe_out[0]);
    setgroups(0, NULL);
    setgid(cmdp->gid);
    setuid(cmdp->uid);
    execve(cmdp->path, argv, NULL);
    perror("pipe_extcmd: execve");
    exit(1);
  }
  /* parent */
  close(pipe_in[0]);
  close(pipe_out[1]);
  if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1 ||
      fcntl(pipe_out[0], F_SETFL, O_NONBLOCK) == -1) {
    node_perror("pipe_extcmd: fcntl - pipe_out", errno);
    goto end;
  }
  iop = axio_init(pipe_out[0], pipe_in[1], 1024, UNSPEC_EOL);
  if (iop == NULL) {
    node_perror("pipe_extcmd: Error initializing I/O", -1);
    goto end;
  }
  while (1) {
    FD_ZERO(&fdset);
    FD_SET(STDIN_FILENO, &fdset);
    FD_SET(pipe_out[0], &fdset);
    if (select(32, &fdset, 0, 0, 0) == -1) {
      node_perror("pipe_extcmd: select", errno);
      break;
    }
    if (FD_ISSET(STDIN_FILENO, &fdset)) {
      alarm(ConnTimeout);
      while((c = axio_getc(NodeIo)) != -1)
	axio_putc(c, iop);
      if (errno != EAGAIN)
	break;
    }
    if (FD_ISSET(pipe_out[0], &fdset)) {
      alarm(ConnTimeout);
      while((c = axio_getc(iop)) != -1)
	axio_putc(c, NodeIo);
      if (errno != EAGAIN) {
	if (errno)
	  node_msg("%s", strerror(errno));
	break;
      }
    }
    axio_flush(NodeIo);
    axio_flush(iop);
  }
#ifdef HAVEMOTD
  if (User.ul_type == AF_NETROM) {
    axio_printf(NodeIo, "%s} ", NodeId);
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;31mWelcome back.\e[0m");
    } else {
      axio_printf(NodeIo, "Welcome back.");
    }

  } else if (User.ul_type == AF_INET) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo, "\e[01;31m");
    }  
    axio_printf(NodeIo, "Returning you to the shell... ");
  } else if (User.ul_type == AF_AX25) {
    if (check_perms(PERM_ANSI, 0L) != -1) {
      axio_printf(NodeIo,"\e[01;31m");
    } 
    axio_printf(NodeIo,"Welcome back to %s.", FlexId);
  }
#endif
  axio_end(iop);
 end:
  signal(SIGCHLD, SIG_DFL);
  kill(pid, SIGKILL);
  close(pipe_in[1]);
  close(pipe_out[0]);
  if (fcntl(STDIN_FILENO, F_SETFL, 0) == -1)
    node_perror("pipe_extcmd: fcntl - stdin", errno);
  return 0;
}

int extcmd(struct cmd *cmdp, char **argv)
{
  int ret;

  User.state = STATE_EXTCMD;
  User.dl_type = AF_UNSPEC;
  strcpy(User.dl_name, cmdp->name);
  strupr(User.dl_name);
  update_user();
  if (cmdp->flags & ECMD_PIPE)
    ret = pipe_extcmd(cmdp, argv);
  else
    ret = norm_extcmd(cmdp, argv);

#ifdef HAVEMOTD
  if (cmdp->flags & ECMD_RECONN) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} Welcome back.", NodeId);
    }
  }
  else if (User.ul_type == AF_AX25) { 
    /*		axio_printf(NodeIo, "Welcome back to %s.", FlexId); */
  }
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
#else
  if (cmdp->flags)
    node_logout("");
#endif
  return ret;
}
