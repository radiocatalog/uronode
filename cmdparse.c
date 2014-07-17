#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netax25/axlib.h>

#include "node.h"

#define safe_strcpy(a, b)	strncpy(a, b, sizeof(a)); a[sizeof(a)-1] = 0;

static unsigned char parsechr(char *str, char **endptr)
{
	switch (*str) {
	case 'n':
		*endptr = ++str;
		return '\n';
	case 't':
		*endptr = ++str;
		return '\t';
	case 'v':
		*endptr = ++str;
		return '\v';
	case 'b':
		*endptr = ++str;
		return '\b';
	case 'r':
		*endptr = ++str;
		return '\r';
	case 'f':
		*endptr = ++str;
		return '\f';
	case 'a':
		*endptr = ++str;
		return '\007';
	case '\\':
		*endptr = ++str;
		return '\\';
	case '\"':
		*endptr = ++str;
		return '\"';
	case 'x':
		return strtoul(str, endptr, 16);
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		return strtoul(str, endptr, 8);
	case '\0':
		return 0;
	default:
		*endptr = str + 1;
		return *str;
	}
	/* NOTREACHED */
	return 0;
}

static char *parsestr(char *str, char **endptr, int argc, char **argv)
{
	static char buf[256];
	char def[256];
	char *p;
	int n, skip;
	time_t t;

	skip = 1;
	buf[0] = 0;
	def[0] = 0;

	if (*str == '{') {
		str++;
		if ((p = strchr(str, '}')) != NULL) {
			skip = p - str + 1;
			p = str + 1;
			if (*p == ':') {
				p++;
				n = min(skip - 3, sizeof(def) - 1);
				strncpy(def, p, n);
				def[n] = 0;
			}
		}
	}

	switch (*str) {
	case 'n':
	case 'N':
		safe_strcpy(buf, NodeId);
		break;

	case 'i':
	case 'I':
		time(&t);
		p = ctime(&t);
		strncpy(buf, p + 11, 8);
		buf[8] = 0;
		break;

	case 'h':
	case 'H':
		safe_strcpy(buf, HostName);
		if ((p = strchr(buf, '.')))
			*p = 0;
		break;

	case 'f':
	case 'F':
		safe_strcpy(buf, HostName);
		break;

	case 'u':
	case 'U':
		safe_strcpy(buf, User.call);
		if ((p = strrchr(buf, '-')))
			*p = 0;
		break;

	case 's':
	case 'S':
		safe_strcpy(buf, User.call);
		break;

	case 'p':
	case 'P':
		safe_strcpy(buf, User.ul_name);
		if ((p = strrchr(buf, '-')))
			*p = 0;
		break;

	case 'r':
	case 'R':
		safe_strcpy(buf, User.ul_name);
		break;

	case 't':
	case 'T':
		switch (User.ul_type) {
		case AF_AX25:
			strcpy(buf, "ax25");
			break;
		case AF_NETROM:
			strcpy(buf, "netrom");
			break;
		case AF_ROSE:
			strcpy(buf, "rose");
			break;
		case AF_INET:
			strcpy(buf, "inet");
			break;
		case AF_UNSPEC:
			strcpy(buf, "host");
			break;
		}
		break;

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		n = *str - '0';
		if (argv == NULL || n > argc - 1)
			strcpy(buf, def);
		else
			safe_strcpy(buf, argv[n]);
		break;

	default:
		strcpy(buf, "%");
		break;
	}
	if (isalpha(*str)) {
		if (isupper(*str))
			strupr(buf);
		else
			strlwr(buf);
	}
	*endptr = str + skip;
	return buf;
}

char *expand_string(char *str, int argc, char **argv)
{
	char buf[1024];
	char *p, *src, *dst;
	int len, buflen;

	if (strcspn(str, "%\\\'") == strlen(str))
		return strdup(str);

	src    = str;
	dst    = buf;
	len    = 0;
	buflen = sizeof(buf) - 8;	/* Slightly on the safe side... */

	while (*src && (len < buflen)) {
		switch (*src) {
		case '\'':
			*dst++ = *src++;
			len++;
			while (*src && (*src != '\'') && (len < buflen)) {
				*dst++ = *src++;
				len++;
			}
			if (*src) {
				*dst++ = '\'';
				len++;
			}
			break;

		case '\\':
			src++;
			*dst++ = parsechr(src, &src);
			len++;
			break;

		case '%':
			src++;
			p = parsestr(src, &src, argc, argv);
			strncpy(dst, p, min(strlen(p), buflen - len));
			dst += min(strlen(p), buflen - len);
			len += min(strlen(p), buflen - len);
			break;

		default:
			*dst++ = *src++;
			len++;
			break;
		}
	}

	*dst = 0;
	return strdup(buf);
}

int parse_args(char **argv, char *cmd)
{
	int ct = 0;
	char quote;
	char *p;

	while (ct < 31) {
		while (*cmd && isspace(*cmd))
			cmd++;
		if (*cmd == 0)
			break;
		argv[ct++] = cmd;
		quote = 0;
		p = cmd;
		while (*cmd) {
			if (quote == 0) {
				if (isspace(*cmd))
					break;
				if (*cmd == '\"' || *cmd == '\'')
					quote = *cmd;
				else
					*p++ = *cmd;
			} else {
				if (*cmd == quote)
					quote = 0;
				else
					*p++ = *cmd;
			}
			cmd++;
		}
		if (*cmd == 0) {
			*p = 0;
			break;
		}
		*p = 0;
		*cmd++ = 0;
	}
	argv[ct] = NULL;
	return ct;
}

int cmdparse(struct cmd *list, char *cmdline)
{
	struct cmd *cmdp;
	int ret, argc;
	char *argv[32];
	char *cmdbuf = NULL;
	char *aliasbuf = NULL;

	while (*cmdline && isspace(*cmdline))
		cmdline++;
	if (*cmdline == 0 || *cmdline == '#')
		return 0;
	cmdbuf = expand_string(cmdline, 0, NULL);
	if ((argc = parse_args(argv, cmdbuf)) == 0)
		return 0;
	for (cmdp = list; cmdp != NULL; cmdp = cmdp->next) {
		if (strlen(argv[0]) < cmdp->len ||
		    strlen(argv[0]) > strlen(cmdp->name))
			continue;
		if (strncasecmp(cmdp->name, argv[0], strlen(argv[0])) == 0)
			break;
	}
	if (cmdp == NULL) {
		free(cmdbuf);
		return -1;
	}
	strlwr(argv[0]);
	switch (cmdp->type) {
	case CMD_INTERNAL:
		ret = (*cmdp->function)(argc, argv);
		break;
	case CMD_ALIAS:
		aliasbuf = expand_string(cmdp->command, argc, argv);
		ret = cmdparse(list, aliasbuf);
		break;
	case CMD_EXTERNAL:
		aliasbuf = expand_string(cmdp->command, argc, argv);
		argc = parse_args(argv, aliasbuf);
		ret = extcmd(cmdp, argv);
		break;
	default:
		ret = -1;
		break;
	}
	free(cmdbuf);
	free(aliasbuf);
	return ret;
}

void insert_cmd(struct cmd **list, struct cmd *new)
{
	struct cmd *tmp, *p;

	if (*list == NULL || strcasecmp(new->name, (*list)->name) < 0) {
		tmp = *list;
		*list = new;
		new->next = tmp;
	} else {
		for (p = *list; p->next != NULL; p = p->next)
			if (strcasecmp(new->name, p->next->name) < 0)
				break;
		tmp = p->next;
		p->next = new;
		new->next = tmp;
	}
}

int add_internal_cmd(struct cmd **list, char *name, int len, int (*function) (int argc, char **argv))
{
	struct cmd *new;

	if ((new = calloc(1, sizeof(struct cmd))) == NULL) {
		node_perror("add_internal_cmd: calloc", errno);
		return -1;
	}
	new->name = strdup(name);
	new->len = len ? len : strlen(name);
	new->type = CMD_INTERNAL;
	new->function = function;
	insert_cmd(list, new);
	return 0;
}

void free_cmdlist(struct cmd *list)
{
	struct cmd *tmp;

	while (list != NULL) {
		free(list->name);
		free(list->command);
		free(list->path);
                tmp = list;
		list = list->next;
		free(tmp);
	}
}
