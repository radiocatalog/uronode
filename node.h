#define VERSION                "URONode v2.1"
#define COMPILING	       "September 9, 2013"

#define STATE_IDLE	0
#define STATE_TRYING	1
#define STATE_CONNECTED	2
#define STATE_PINGING	3
#define STATE_EXTCMD	4
#define STATE_LOGIN	5
#define STATE_QUIT	6

#define LOGLVL_NONE	0
#define LOGLVL_ERROR	1
#define LOGLVL_LOGIN	2
#define LOGLVL_GW	3

#define PERM_LOGIN		1	/* Permit login			*/
#define PERM_AX25		2	/* AX.25 gatewaying		*/
#define PERM_NETROM		4	/* NETROM gatewaying		*/
#define PERM_TELNET_LOCAL	8	/* Telnet to "local" hosts	*/
#define PERM_TELNET_AMPR	16	/* Telnet to 44.xx.xx.xx hosts	*/
#define PERM_TELNET_INET	32	/* Telnet to other hosts	*/
#define PERM_HIDDEN		64	/* Use hidden ports		*/
#define PERM_ROSE		128	/* ROSE gatewaying		*/
#define PERM_NOESC		256	/* No escape character		*/
#define PERM_ANSI		512	/* Ansi Color Graphics		*/

#define PERM_TELNET (PERM_TELNET_LOCAL & PERM_TELNET_AMPR & PERM_TELNET_INET)

/* Fake id for Flexnet */
#define AF_FLEXNET 128

#include <sys/types.h>
#include <sys/ipc.h>	/* for key_t */
#include <errno.h>

#include <netax25/ax25io.h>

#include "config.h"

struct user
{
        pid_t           pid;
        key_t           ipc_key;
        time_t          logintime;
        time_t          cmdtime;
        unsigned char   state;
        char            call[10];
        unsigned short  ul_type;
        unsigned short  dl_type;
        char            ul_name[32];
        char            dl_name[32];
        char            ul_port[32];
        char            dl_port[32];

        char            unused[92];
};

extern struct user User;

extern ax25io *NodeIo;

extern long IdleTimeout;
extern long ConnTimeout;
extern int ReConnectTo;
extern int LogLevel;
extern int EscChar;
extern int aliascmd;

extern char *Email;
extern char *HostName;
extern char *NodeId;
extern char *FlexId;
extern char *NrPort;
extern char *Prompt;
extern char *PassPrompt;

#define	CMD_INTERNAL	1
#define	CMD_ALIAS	2
#define	CMD_EXTERNAL	3

struct cmd {
	char	*name;
	int	len;
	int	type;
	int	(*function) (int argc, char **argv);
	char	*command;
	int	flags;
	int	uid;
	int	gid;
	char	*path;

	struct cmd *next;
};

extern struct cmd *Nodecmds;

#define min(a,b)	((a) < (b) ? (a) : (b))
#define max(a,b)	((a) > (b) ? (a) : (b))

/* in cmdparse.c */
void free_cmdlist(struct cmd *list);
extern void insert_cmd(struct cmd **list, struct cmd *new);
extern int add_internal_cmd(struct cmd **list, char *name, int len, int (*function) (int argc, char **argv));
/* extern char *expand_string(char *str, int argc, char **argv); */
extern int parse_args(char **argv, char *cmd);
extern int cmdparse(struct cmd *cmdp, char *cmdline);

/* in util.c */
extern void node_msg(const char *fmt, ...);
extern void node_perror(char *str, int err);
extern char *print_node(const char *alias, const char *call);
extern void node_log(int, const char *, ...);

/* in user.c */
extern void login_user(void);
extern void logout_user(void);
extern void update_user(void);
extern int user_list(int argc, char **argv);
extern int user_count(void);
extern int system_user_count(void);

/* in config.c */
extern int is_hidden(const char *port);
extern int check_perms(int what, unsigned long peer);
extern char *read_perms(struct user *up, unsigned long peer);
extern int read_config(void);
extern int get_escape(char *s);

/* in command.c */
void init_nodecmds(void);
extern void node_logout(char *reason);
extern int nuser_list(int argc, char **argv);
extern int do_bye(int argc, char **argv);
extern int do_escape(int argc, char **argv);
extern int do_help(int argc, char **argv);
extern int do_host(int argc, char **argv);
extern int do_ports(int argc, char **argv);
extern int do_sessions(int argc, char **argv);
extern int do_routes(int argc, char **argv);
extern int do_nodes(int argc, char **argv);
extern int do_status(int argc, char **argv);
extern int do_version(int argc, char **argv);
extern int do_last(int argc, char **last);

/* in gateway.c */
extern int do_connect(int argc, char **argv);
extern int do_finger(int argc, char **argv);
extern int do_ping(int argc, char **argv);

/* in router.c */
extern int do_links(int argc, char **argv);
extern int do_dest(int argc, char **argv);

/* in ipc.c */
extern int ipc_open(void);
extern int ipc_close(void);
extern int do_msg(int argc, char **argv);

/* in extcmd.c */
extern int extcmd(struct cmd *cmdp, char **argv);

/* in system.c */
extern int do_system(int argc, char **argv);
extern int examine_user(void);
extern void newmail(void);
extern void mailcheck(void);
extern void lastlog(void);

/* in mheard.c */
extern int do_mheard(int argc, char **argv);
