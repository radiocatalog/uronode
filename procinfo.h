#ifndef _PROCINFO_H
#define _PROCINFO_H

#define PROC_NR_FILE  "/proc/net/nr"
#define PROC_DEV_FILE "/proc/net/dev"

#define FLEX_GT_FILE  "/var/ax25/flex/gateways"
#define FLEX_DST_FILE "/var/ax25/flex/destinations"

#define AX_ROUTES_FILE "/etc/ax25/uronode.routes"

#ifndef DATA_MHEARD_FILE
#define DATA_MHEARD_FILE "/var/ax25/mheard/mheard.dat"
#endif

#define CONN_TYPE_DIRECT 'D'
#define CONN_TYPE_NODE 'N'
#define CONN_TYPE_DIGI 'V'

struct proc_dev {
  char          interface[6];
  int           rx_bytes;
  int           rx_packets;
  int           rx_errs;
  int           rx_drop;
  int           rx_fifo;
  int           rx_frame;
  int           rx_compressed;
  int           rx_multicast;
  int           tx_bytes;
  int           tx_packets;
  int           tx_errs;
  int           tx_drop;
  int           tx_fifo;  
  int           tx_colls;  
  int           tx_carrier;  
  int           tx_compressed;

  struct proc_dev  *next;
};


/*
 * /var/ax25/flex/gateways: (example)
 * addr  callsign  dev  dest  digipeaters
 * 00001 PI4TUE    ax1   935
 */

struct flex_gt {
  int                     addr;
  char                    call[10];
  char                    dev[14];
  char                    digis[AX25_MAX_DIGIS][10];
  
  struct flex_gt          *next;
};

/*
 * /var/ax25/flex/destinations: (example)
 * callsign  ssid    rtt  gateway
 * 9A0XZG    0-15   2575    00001
 * DB0AAA    0-0      63    00001
 */

struct flex_dst {
  char                    dest_call[10];
  unsigned short          ssida;
  unsigned short          sside;
  unsigned long           rtt;
  int                     addr;
  
  struct flex_dst         *next;
};

struct ax_routes {
  char                    dest_call[10];
  char 			  alias[10]; 
  char                    dev[14];  
  char			  conn_type[1];  
  char 			  description[50];
  char                    digis[AX25_MAX_DIGIS][10];

  struct ax_routes        *next;
};

extern int safe_atoi(const char *s);
extern char *safe_strncpy(char *dest, char *src, int n);

extern struct proc_dev *read_proc_dev(void);
extern void free_proc_dev(struct proc_dev *ap);

extern struct flex_gt *read_flex_gt(void);
extern void free_flex_gt(struct flex_gt *fp);

extern struct flex_dst *read_flex_dst(void);
extern void free_flex_dst(struct flex_dst *fp);

extern struct ax_routes *read_ax_routes(void);
extern void free_ax_routes(struct ax_routes *ap);

extern struct ax_routes *find_route(char *dest_call, struct ax_routes *list);
extern struct flex_dst *find_dest(char *dest_call, struct flex_dst *list);
extern struct flex_gt *find_gateway(int addr, struct flex_gt *list);
extern struct ax_routes *find_mheard(char *dest_call);

#endif  /* _PROCINFO_H */
