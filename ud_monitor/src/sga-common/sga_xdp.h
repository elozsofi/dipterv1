#include <string>
#include <thread>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include "../logger-common.h"

#define cuSecFrom1601To1970 11644473600

typedef enum tyeBPF : unsigned short
{
	XDP = 0,
	TC = 1
} tyeBPF;

typedef struct xdp_config
{
	unsigned int ifindex;
	unsigned int load_mode;
	struct bpf_object  *obj;
	struct bpf_program *prog;
	struct bpf_prog_info info;
	unsigned int info_len;
	int prog_fd;
	tyeBPF type;
} xdp_config;

typedef struct xdp_ctx
{
	unsigned long long epoch_delta;
	unsigned long long captured;
	unsigned long long lost_xdp;
	unsigned long long lost_app;
	// eBPF stats
	unsigned long long ebpf_packets;
	unsigned long long ebpf_events;
} xdp_ctx;

typedef struct xdp_dump
{
	bool exit_xdpdump;
	struct perf_buffer          *perf_buf;
	struct ring_buffer 			*ring_buf;
	std::thread athr;
	xdp_ctx actx;
} xdp_dump;

typedef enum bpf_perf_event_ret (*phandle_perf_event)(void *, int, struct perf_event_header *);
typedef int (*phandle_ring_event)(void *, void *, size_t);

#define PERF_MMAP_PAGE_COUNT	256

static const char GLOBAL_PATH[] = "/sys/fs/bpf";

class sga_xdp
{
public:
 sga_xdp(SGA_Logger *plog, tyeBPF atype) { plogger = plog; acfg.type = atype; }
 ~sga_xdp() {}

bool load_program(const char *filename, const char *btf_file, const char *iface, unsigned int load_mode);
bool unload_program();
int open_object(const char *name);
bool update_object(int fd, void *key, void *pvalue);
bool update_object(int fd, void *key, unsigned int *pvalue);
bool lookup_object(int fd, void *key, void *pvalue);
bool delete_object(int fd, void *key);
bool walk_object(int fd, void *key, void *next_key);
bool clear_object(int fd);

bool setup_perfbuffer(int fd, phandle_perf_event callback);
bool loop_perfbuffer();
bool end_perfbuffer();

bool setup_ringbuffer(int fd, phandle_ring_event callback);
bool loop_ringbuffer();
bool end_ringbuffer();

// TC specific (open global PIN-ed object)
int open_global(const char *name);

unsigned long long get_filetime_to_uptime_delta(void);

xdp_ctx *get_context() { return &adump.actx; }
bool check_ebpf_running();


bool get_ebpfstats();

private:
	xdp_config acfg;
	xdp_dump adump;
	SGA_Logger *plogger;
};