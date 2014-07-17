/* oringinal by Heikki Hannikainen, modified by Brian Rogers */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <netax25/ax25.h>
#include <netrose/rose.h>
#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>

#include "node.h"

#define FIRST_KEY (3694	- 1)		/* Where to start looking for a key */
#define LAST_KEY (FIRST_KEY + 200) 	/* How far to search */
#define M_LEN 1024			/* Largest message transferred */

struct nmsgbuf {
  long mtype;		/* message type, must be > 0 */
  char mtext[M_LEN];	/* message data */
};

static int ipc_id = -1;

static void usr2_handler(int sig)
{
  struct nmsgbuf buf;
	
  if (msgrcv(ipc_id, (struct msgbuf *)&buf, M_LEN, 0, IPC_NOWAIT|MSG_NOERROR) != -1) {
    node_msg("%s", buf.mtext);
    if (User.ul_type != AF_NETROM) {
      node_prompt();
    }
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    axio_flush(NodeIo);
  } else
    node_log(LOGLVL_ERROR, "usr2_handler: Caught SIGUSR2, but couldn't receive a message");

  signal(SIGUSR2, usr2_handler); /* Restore handler */
}

int ipc_send(key_t key, long mtype, char *mtext)
{
  struct nmsgbuf buf;
  int id;
	
  if ((id = msgget(key, S_IRWXU)) == -1) {
    node_perror("ipc_send: Could not get transmit channel", errno);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return -1;
  }
	
  buf.mtype = mtype;
  strncpy(buf.mtext, mtext, M_LEN);
	
  if (msgsnd(id, (struct msgbuf *)&buf, M_LEN, 0) == -1) {
    node_perror("ipc_send: Could not send message", errno);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return -1;
  }
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  return 0;
}

int ipc_open(void)
{
  key_t key = FIRST_KEY;
	
  do {
    key++;
    ipc_id = msgget(key, S_IRWXU | IPC_CREAT | IPC_EXCL);
  } while ((ipc_id == -1) && (key != LAST_KEY));

  if (ipc_id == -1)
    node_perror("ipc_open: Could not get an IPC channel", errno);

#if 0
  node_msg("debug: ipc_id=%d key=%d", ipc_id, key);
#endif

  User.ipc_key = key;

  if (key != -1)
    signal(SIGUSR2, usr2_handler);
  else
    signal(SIGUSR2, SIG_IGN);

  return 0;
}

int ipc_close(void)
{
  struct msqid_ds buf;
	
  if (ipc_id != -1)	/* Remove the IPC channel */
    if (msgctl(ipc_id, IPC_RMID, &buf) == -1) {
      node_log(LOGLVL_ERROR, "ipc_close: Could not remove IPC channel: %s", strerror(errno)); 
      return -1;
    } else {
      node_log(LOGLVL_ERROR, "ipc_close: Removing IPC channel for %s", User.call);
    }
  return 0;
}

int do_msg(int argc, char **argv)
{
  FILE *f;
  struct user u;
  char call[10];
  char mtext[M_LEN];
  int i, hits = 0, sent = 0;

  if (argc < 3) {
    node_msg("Usage: msg <call> <your text msg>");
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
    return 0;
  }

  if ((f = fopen(DATA_NODE_LOGIN_FILE, "r")) == NULL) {
    node_perror(DATA_NODE_LOGIN_FILE, errno);
    return 0;
  }
  sprintf(mtext, "\n*** Msg from %s:\n\a", User.call);
  for (i = 2; i < argc; i++) {
    strncat(mtext, argv[i], M_LEN - strlen(mtext));
    strncat(mtext, " ", M_LEN - strlen(mtext));
  }
  strncat(mtext, "\n*** End of msg.", M_LEN - strlen(mtext));
  mtext[M_LEN - 1] = 0;
	
  strncpy(call, argv[1], 9);
  call[9] = 0;

  while (fread(&u, sizeof(u), 1, f) == 1) {
    if (u.pid == -1 || (kill(u.pid, 0) == -1 && errno == ESRCH))
      continue;
    if (!strcasecmp(u.call, call)) {
      hits++;
      if (u.ipc_key != -1 && u.state == STATE_IDLE) {
	ipc_send(u.ipc_key, 1, mtext);
	kill(u.pid, SIGUSR2);
	sent++;
      }
    }
  }
  fclose(f);
  if (hits == 0) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    axio_printf(NodeIo, "%s is not on the node now.\a", call);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  } else if (sent == 0) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    axio_printf(NodeIo, "%s is busy and not accepting msgs now.\a", call);
    if (User.ul_type == AF_NETROM) {
      node_msg("");
    }
  } else if (sent != 0) {
    if (User.ul_type == AF_NETROM) {
      axio_printf(NodeIo, "%s} ", NodeId);
    }
    axio_printf(NodeIo, "Msg sent to %s.\a", call);
  } 
  if (User.ul_type == AF_NETROM) {
    node_msg("");
  }
  axio_flush(NodeIo);
  return 0;
}
