/*
 * calibrate : Modem calibration utility
 * Most code is portion of beacon.c of the standard ax25-utils package
 * F1OAT 980321
 * mods by N1URO 151123
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>

#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <netax25/axlib.h>
#include <netax25/axconfig.h>
#include <netax25/nrconfig.h>
#include <netax25/rsconfig.h>
#include <netax25/procutils.h>
#include <netax25/mheard.h>
#include <netax25/daemon.h>

#define BUFLEN 256
#define NBFRAMES 100
#define TEMPO 1000


static void Usage(void)
{
	fprintf(stderr, "Usage : calibrate [-t ms] interface\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct full_sockaddr_ax25 dest;
	struct full_sockaddr_ax25 src;
	int i, s, dlen, len, tempo = TEMPO;
	char *port;
	char *srccall = NULL, *destcall = "CAL";
	char buffer[BUFLEN];
	fd_set rfds;
	struct timeval tv;

	if (argc < 2) Usage();
	
	while ((s = getopt(argc, argv, "t:")) != -1) {
		switch (s) {
			case 't':
				tempo = atoi(optarg);
				break;
			case ':':
				fprintf(stderr, "calibrate: option -t needs a duration in ms\n");
				return 1;
			case '?':
				Usage();
				return 1;
		}
	}

    if (optind == argc) {
		Usage();
		return 1;
    }
	
    port = argv[optind];
	
	if (ax25_config_load_ports() == 0) {
		fprintf(stderr, "calibrate: no AX.25 interfaces defined\n");
		return 1;
	}

	if ((srccall = ax25_config_get_addr(port)) == NULL) {
		fprintf(stderr, "calibrate: invalid AX.25 interface setting - %s\n", port);
		return 1;
	}

	if ((dlen = ax25_aton(destcall, &dest)) == -1) {
		fprintf(stderr, "calibrate: unable to convert callsign '%s'\n", destcall);
		return 1;
	}

	if ((len = ax25_aton(srccall, &src)) == -1) {
		fprintf(stderr, "calibrate: unable to convert callsign '%s'\n", srccall);
		return 1;
	}

	if ((s = socket(AF_AX25, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
		return 1;
	}

	if (bind(s, (struct sockaddr *)&src, len) == -1) {
		perror("bind");
		return 1;
	}
	
	printf("Press return to stop calibrate\n");
	
	for (i = 0 ; i < BUFLEN ; i++)
		buffer[i] = 0x55;
		
	for (i = 0 ; i < NBFRAMES ; i++) {
/*		fd_set rfds;
		struct timeval tv;
*/		
		tv.tv_sec = tempo / 1000;
		tv.tv_usec = (tempo % 1000) * 1000;
		
		FD_ZERO(&rfds);
		FD_SET(0, &rfds);

		if (select(1, &rfds, NULL, NULL, &tv) == 1) break;	
		
		buffer[0] = (i / 100) + '0';
		buffer[1] = ((i % 100) / 10) + '0';
		buffer[2] = (i % 10) + '0';
		
		if (sendto(s, buffer, BUFLEN, 0, (struct sockaddr *)&dest, dlen) == -1) {
			perror("sendto");
		}
	}
	
	close(s);

	return 0;
}
