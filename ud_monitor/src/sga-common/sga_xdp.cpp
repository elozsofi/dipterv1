#include <stdio.h>
#include <net/if.h>
#include "sga_xdp.h"
#include <errno.h>

using namespace std;

bool sga_xdp::load_program(const char *filename, const char *btf_file, const char *iface, unsigned int load_mode)
{
	struct bpf_object_open_opts openopts = { 0, };
	int err;

	acfg.ifindex = if_nametoindex(iface);
	acfg.load_mode = load_mode;
	
	bpf_xdp_detach(acfg.ifindex, acfg.load_mode, NULL);

	openopts.sz = sizeof(struct bpf_object_open_opts);
	
	acfg.obj = bpf_object__open_file(filename, &openopts);
	err = libbpf_get_error(acfg.obj);

	if (err) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: failed to open bpf object file: %d\n", err);
		goto cleanup;
	}

	acfg.prog = bpf_object__next_program(acfg.obj, NULL);

	bpf_program__set_type(acfg.prog, BPF_PROG_TYPE_XDP);

	err = bpf_object__load(acfg.obj);
	if (err) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: failed to load bpf object file: %d\n", err);
		goto cleanup;
	}

	acfg.prog_fd = bpf_program__fd(acfg.prog);
	
	err = bpf_xdp_attach(acfg.ifindex, acfg.prog_fd, acfg.load_mode, NULL);
	if (err < 0) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: failed to attach program %d\n", err);
		goto cleanup;
	}

	bpf_obj_get_info_by_fd(acfg.prog_fd, &acfg.info, &acfg.info_len);

	return true;


cleanup:	
	if (acfg.obj)
		bpf_object__close(acfg.obj);

	return false;

}

bool sga_xdp::unload_program()
{
	bpf_xdp_detach(acfg.ifindex, acfg.load_mode, NULL);
	bpf_object__close(acfg.obj);
	acfg.obj = NULL;
	acfg.prog = NULL;
	acfg.prog_fd = -1;
	return true;
}

int sga_xdp::open_global(const char *name)
{
	int fd;
	char gname[128];
	
	sprintf(gname, "%s/%s", GLOBAL_PATH, name);
	fd = bpf_obj_get(gname);
	if (fd < 0)
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: Can't open: %s\n", gname);
		return -1;
	}
	return fd;
}

int sga_xdp::open_object(const char *name)
{
	if (acfg.type == TC)
	{
		return open_global(name);
	}

	struct bpf_map *pmap = bpf_object__find_map_by_name(acfg.obj, name);
	int fd;

	if (!pmap) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: Can't find %s in the xdp program!\n", name);
		return -1;
	}
	fd = bpf_map__fd(pmap);
	if (fd < 0) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: %s map file descriptor: %s\n", name, strerror(fd));
		return -1;
	}
	return fd;
}

bool sga_xdp::check_ebpf_running()
{
	struct bpf_xdp_query_opts opts = {66,};
	opts.sz = sizeof(opts);

	if (bpf_xdp_query(acfg.ifindex, 0, &opts))
		return false;
	
	return (opts.attach_mode!=0)?true:false;
}

bool sga_xdp::update_object(int fd, void *key, void *pvalue)
{
	int	err = bpf_map_update_elem(fd, key, pvalue, 0);
	if (err) 
	{
		plogger->WRITE_LOG(LOG_ERR, "Unable to update %d: %s\n", fd, strerror(-err));
		return false;
	}
	return true;
}

bool sga_xdp::update_object(int fd, void *key, unsigned int *pvalue)
{
	int	err = bpf_map_update_elem(fd, key, pvalue, 0);
	if (err) 
	{
		plogger->WRITE_LOG(LOG_ERR, "Unable to update %d: %s\n", fd, strerror(-err));
		return false;
	}
	return true;
}

bool sga_xdp::lookup_object(int fd, void *key, void *pvalue)
{
	return (bpf_map_lookup_elem(fd, key, pvalue)!=0)?true:false;
}

bool sga_xdp::delete_object(int fd, void *key)
{
	return (bpf_map_delete_elem(fd, key)!=0)?true:false;
}


bool sga_xdp::walk_object(int fd, void *key, void *next_key)
{
	return (bpf_map_get_next_key(fd, key, next_key) == 0)?true:false;
}

bool sga_xdp::clear_object(int fd)
{
	char next_key[512]; // should be enough to store keyz...

	while (bpf_map_get_next_key(fd, NULL, &next_key) == 0)
	{
		if (bpf_map_delete_elem(fd, &next_key)) return false;
	}
	return true;
}

unsigned long long sga_xdp::get_filetime_to_uptime_delta(void)
{
/*struct timespec ts;
unsigned long long uptime;
unsigned long long epoch = (time(NULL) + cuSecFrom1601To1970) * 10000000ULL;

clock_gettime(CLOCK_MONOTONIC, &ts);

uptime = ts.tv_sec * 10000000ULL + ts.tv_nsec;

return epoch - uptime;*/
return (cuSecFrom1601To1970 * 10000000ULL);
}

bool sga_xdp::setup_perfbuffer(int fd, phandle_perf_event callback)
{

	adump.exit_xdpdump = false;
	adump.actx.epoch_delta = get_filetime_to_uptime_delta();
	adump.actx.captured = 0;
	adump.actx.lost_xdp = 0;
	adump.actx.lost_app = 0;

	struct perf_event_attr       perf_attr = {};

	perf_attr.size = sizeof(struct perf_event_attr);
	perf_attr.type = PERF_TYPE_SOFTWARE;
	perf_attr.config = PERF_COUNT_SW_BPF_OUTPUT;
	perf_attr.sample_period = 1;
	perf_attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_TIME;
	perf_attr.wakeup_events = 1;


	/* the configure check looks for the 6-argument variant of the function */
	adump.perf_buf = perf_buffer__new_raw(fd,
					PERF_MMAP_PAGE_COUNT,
					&perf_attr, callback,
					&adump.actx, NULL);

	if (adump.perf_buf == NULL) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: Failed to allocate raw perf buffer: %s(%d)",	strerror(errno), errno);
		return false;
	}
	adump.athr = thread(&sga_xdp::loop_perfbuffer, this);

return true;
}

bool sga_xdp::loop_perfbuffer()
{
int cnt;
		/* Loop trough the dumper */
	while (!adump.exit_xdpdump) 
	{
		cnt = perf_buffer__poll(adump.perf_buf, 1000);
		if (cnt < 0 && errno != EINTR) 
		{
			plogger->WRITE_LOG(LOG_ERR, "ERROR: Perf buffer polling failed: %s(%d)",	strerror(errno), errno);
			return false;
		}
	}
#ifdef HAVE_LIBBPF_PERF_BUFFER__CONSUME
	perf_buffer__consume(adump.perf_buf);
#endif
	return true;
}

bool sga_xdp::end_perfbuffer()
{
	adump.exit_xdpdump = true;
	adump.athr.join();
	perf_buffer__free(adump.perf_buf);
	return true;
}

// ringbuffer
bool sga_xdp::setup_ringbuffer(int fd, phandle_ring_event callback)
{

	adump.exit_xdpdump = false;
	adump.actx.epoch_delta = get_filetime_to_uptime_delta();
	adump.actx.captured = 0;
	adump.actx.lost_xdp = 0;
	adump.actx.lost_app = 0;

	adump.ring_buf = ring_buffer__new(fd, callback, &adump.actx, NULL);

	if (adump.ring_buf == NULL) 
	{
		plogger->WRITE_LOG(LOG_ERR, "ERROR: Failed to allocate raw ring buffer: %s(%d)",	strerror(errno), errno);
		return false;
	}
	adump.athr = thread(&sga_xdp::loop_ringbuffer, this);

return true;
}

bool sga_xdp::loop_ringbuffer()
{
int cnt;
		/* Loop trough the dumper */
	while (!adump.exit_xdpdump) 
	{
		cnt = ring_buffer__poll(adump.ring_buf, 100);
		if (cnt < 0 && errno != EINTR) 
		{
			plogger->WRITE_LOG(LOG_ERR, "ERROR: Ring buffer polling failed: %s(%d)",	strerror(errno), errno);
			return false;
		}
	}
	return true;
}

bool sga_xdp::end_ringbuffer()
{
	adump.exit_xdpdump = true;
	adump.athr.join();
	ring_buffer__free(adump.ring_buf);
	return true;
}