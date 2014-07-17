#ifndef SYSINFO_H
#define SYSINFO_H

int        loadavg(double *av1, double *av5, double *av15);
int        uptime (double *uptime_secs, double *idle_secs);

unsigned** meminfo(void);

enum meminfo_row { meminfo_main = 0, meminfo_free, meminfo_buffers, 
		meminfo_cached, meminfo_scached, meminfo_active,
		meminfo_inactive, meminfo_htotal, meminfo_hfree,
		meminfo_ltotal, meminfo_lfree, meminfo_stotal, 
		meminfo_sfree, meminfo_dirty, meminfo_writeback,
		meminfo_anonpages, meminfo_mapped, meminfo_slab,
		meminfo_sreclaim, meminfo_sunreclaim, meminfo_pagetables,
		meminfo_nfs_unstab, meminfo_bounce, meminfo_climit,
		meminfo_cas, meminfo_vmtotal, meminfo_vmused, 
		meminfo_vmchunk 
};

enum meminfo_col { meminfo_total = 0
}; 

unsigned read_total_main(void);

#endif /* SYSINFO_H */
