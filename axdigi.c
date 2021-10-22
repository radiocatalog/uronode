/* 
 * axdigi: Cross and straight port digipeater program
 * Copyright (C) 1995 Craig Small VK2XLZ
 * modificatioins 2012-present Brian N1URO
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  JSN - Small tweaks to ensure compilation and execution under Linux 2.1.x.
 *        12th June 1997.
 *
 *  Thanks to Helmut Grohne for a minor patch
 *
 */

#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
/* below added by N1URO */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#include <signal.h>
#include <linux/ax25.h>
/* added by N1URO */
#include <netax25/daemon.h>
#include "node.h"
int recv_packet(unsigned char *buf, int size, unsigned char *port);
void print_call(unsigned char *buf);
unsigned char *find_call(char *port);
void add_port(char *call, char *port);
void get_interfaces(int skt);

/*
 * The defines we use
 */
#define AXALEN 7
#define E_BIT 0x01	/* Address extension bit */
#define REPEATED 0x80	/* Has-been-repeated bit */
#define MAX_PORTS 16
// #define VERSION "0.3"
#define AXDIGI_PID_FILE  "/var/run/axdigi.pid"
int port_count = 0;
unsigned char portname[MAX_PORTS][20];
unsigned char portcall[MAX_PORTS][8];

void(*sigterm_defhnd)(int);

void quit_handler(int sig)
{
  unlink(AXDIGI_PID_FILE);
  signal(SIGTERM, SIG_IGN);
  fprintf(stderr, "axDigi quitting.\n\r");
  signal(SIGTERM, sigterm_defhnd);
  raise(SIGTERM);
  return;
}

void hup_handler(int sig)
{
  signal(SIGHUP, SIG_IGN);
  fprintf(stderr, "SIGHUP caught by axDigi.\n\r");
  signal(SIGHUP, hup_handler); /* Restore hangup handler */
}


int main(int argc, char *argv[])
{
  int skt;
  int size, rt;
  unsigned char buf[4096];
  struct sockaddr sa;
  int asize;


  FILE *pidfile;

  /* Check our huge range of flags */
  if (argc > 1)
    {
      if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "-h") ==0)
	{
	  printf("axdigi: version %s.\n\r", VERSION);
	  printf("Copywrite (c) 1995 Craig Small - VK2XLZ\n\r");
	  printf("modificatiions Copyright (C) 2012-present by Brian N1URO\n\n");
	  printf("axdigi comes with ABSOLUTELY NO WARRANTY.\n\r");
	  printf("This is free software, and you are welcome to redistribute it\n\r");
	  printf("under the terms of GNU General Public Licence as published\n\r");
	  printf("by Free Software Foundation; either version 2 of the License, or\n\r");
	  printf("(at your option) any later version.\n\r");
	  return 0;
	}
    }

/* Routine to daemonize - added by N1URO */

if (!daemon_start(TRUE)) {
   fprintf(stderr, "Sorry, axdigi cannot become a daemon\n");
   return 1;
   }

/* Change to keep code more modern - N1URO */
  if ((skt = socket(PF_PACKET, SOCK_PACKET, htons(ETH_P_AX25))) == -1)
    {
      perror("socket");
      return(1);
    }

  pidfile = fopen(AXDIGI_PID_FILE, "w");
  fprintf(pidfile, "%d\n", (int)getpid());
  fprintf(stderr, "axDigi started. \n");
  fclose(pidfile);

  signal(SIGHUP, hup_handler);
  sigterm_defhnd = signal(SIGTERM, quit_handler);

  get_interfaces(skt);
	
  while(1)
    {
      asize = sizeof(sa);

      if ((size = recvfrom(skt, buf, sizeof(buf), 0, &sa, &asize)) == -1)
	{
	  perror("recv");
	  exit(1);
	}
      if ((rt = recv_packet(buf, size, sa.sa_data)) >= 0)
	{
	  if (rt < port_count)
	    {
	      asize = sizeof(sa);
	      strcpy(sa.sa_data, portname[rt]);
	      if (sendto(skt, buf, size, 0, &sa, asize) == -1)
		perror("sendto");
	      continue;
	    }
	  /*			printf("Unknown port %s\n", sa.sa_data);*/
	} /* recv_packet true */
    } /* while(1) */

  close(skt);
}

int recv_packet(unsigned char *buf, int size, unsigned char *port)
{
  unsigned char *bptr;
  int count, i;
  unsigned char *call;
	
  /*	printf("Got packet size %d\n", size);*/
	
  /*
   * Decode the AX.25 Packet 
   */
  /* Find packet, skip over flag */
  bptr = buf+1;
  /* Now at destination address */
  /*	print_call(bptr);
	printf("<-");*/
  bptr += AXALEN;
	
  /* Now at source address */
  /*	print_call(bptr);*/
  if (bptr[6] & E_BIT)
    {
      /*		printf("\n");*/
      return -1;	/* No digis, we're not interested */
    }
  /*	printf(" ");*/
  bptr += AXALEN;
  /* Now at digipeaters */
	
  count = 0;
  while( count < AX25_MAX_DIGIS && ( (bptr - buf) < size))
    {
      /*		print_call(bptr);
			printf(", ");*/
      if (bptr[6] & REPEATED)
	{
	  /* This one has been repeated, move to next one */
	  bptr += AXALEN;
	  count++;
	  continue;
	}
      /* Check to see if callsign is one of ours */
      for (i = 0; i < port_count; i++)
	{
	  /*			printf("compare ");
				print_call(bptr);
				printf(" ");
				print_call(portcall[i]);
				printf("\n");*/
	  if ( (bcmp(bptr, portcall[i], AXALEN-1) == 0) && ((bptr[6] & 0x1e) == portcall[i][6]))
	    {
	      /* Copy new address over and turn on repeated bit*/
	      call = find_call(port);
	      if (call == NULL)
		return -1;
	      bcopy(call, bptr, AXALEN-1);
	      bptr[6] = (bptr[6] & ~0x1e) | call[6];
	      bptr[6] |= REPEATED;
	      return i;
	    }
	} /* for */
      return -1;
    }
  return -1;
}	
	
void print_call(unsigned char *bptr)
{
  printf("%c%c%c%c%c%c-%d", bptr[0] >> 1, bptr[1] >> 1,
	 bptr[2] >> 1, bptr[3] >> 1, bptr[4] >> 1, bptr[5] >> 1,
	 (bptr[6] >> 1) & 0xf);
}	

void add_port(char *call, char *port)
{
  unsigned char *s;
  int n;
	
  if (port_count == MAX_PORTS)
    return;
	
  s = portcall[port_count];
	
  while( (*call != '-') && ( (int)(s - portcall[port_count])< 6))
    *s++ = (*call++) << 1;
  call++; /* skip over dash */
  n = atoi(call);
  *s = n << 1;	

  strcpy(portname[port_count], port);
  port_count++;
}	
	
	
unsigned char *find_call(char *port)
{
  static unsigned char callsign[8];
  int i;
	
  for(i = 0; i < port_count; i++)
    {
      if (strcmp(port, portname[i]) == 0)
	{
	  bcopy(portcall[i], callsign, 7);
	  return callsign;
	}
    }
  return (char*)NULL;
}

void get_interfaces(int skt)
{
  char buf[1024];
  struct ifconf ifc;
  struct ifreq *ifr;
  int i;
	
  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(skt, SIOCGIFCONF, &ifc) < 0)
    {
      perror("ioctl");
      exit(1);
    }
	
  ifr = ifc.ifc_req;
  for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
    {
      if (ioctl(skt, SIOCGIFHWADDR, ifr) < 0)
	continue;
      if (ifr->ifr_hwaddr.sa_family == AF_AX25)
	{
	  /* AX25 port, add to list */
	  if (port_count < MAX_PORTS)
	    {
	      bcopy(ifr->ifr_hwaddr.sa_data, portcall[port_count], 7);
	      strcpy(portname[port_count], ifr->ifr_name);
	      port_count++;
	    }	
	}
    } /* for */
}	

void(*sigterm_defhnd)(int);
