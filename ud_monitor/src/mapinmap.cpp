#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <json-c/json.h>
#include <net/if.h>
#include <atomic>
#include <array>

#include "sga_tctap.hpp"
//#include "../tmp/mapinmap.skel.h"
#include <sys/select.h>
#include "sga_etc.h"

using namespace std;

std::atomic<bool> inner_factory_running(false);
pthread_t inner_factory_thread;

static std::array<std::atomic_uint8_t, MAPID_THREADS> g_hk_can_write;

static inline void hk_init_flags()
{
    for (auto &f : g_hk_can_write) {
        f.store(0, std::memory_order_relaxed);
    }
}

/* GC threads call this func, for housekeeping thread to push in freelist */
static inline void mark_thread_writable(uint32_t tid)
{
    if (tid < MAPID_THREADS)
        g_hk_can_write[tid].store(1, std::memory_order_release);
}

// counter for successfully loaded inner maps into outer_map
std::atomic<int> inner_maps_loaded(0);
// GC aggregate counters
std::atomic<uint64_t> gc_total_scanned(0);
std::atomic<uint64_t> gc_total_cleaned(0);
std::atomic<uint64_t> gc_total_wiped(0);

/* ---- Single stop flag for all threads ---- */
std::atomic<bool> exiting(false);
pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- Housekeeping thread state (single consumer for freelist updates) --- */
typedef struct {
    int freelist_fd;
} hk_arg_t;

static pthread_t g_hk_thread = 0;
static hk_arg_t g_hk_args;

static inline uint64_t now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

SGA_Logger *plog = NULL;
volatile int ctrlc = 0;

static inline uint64_t rdtsc2()
{
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)hi << 32 | lo;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) 
{
    if (level > LIBBPF_INFO)
    { // Ignore debug-level libbpf logs
        return 0;
    }
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    struct rlimit flim_new = {
        .rlim_cur = 4000,
        .rlim_max = 4000,
    };
    struct rlimit tlim_new = {
        .rlim_cur = 4000,
        .rlim_max = 4000,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
    if (setrlimit(RLIMIT_NOFILE, &flim_new))
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to increase RLIMIT_NOFILE limit!\n");
        exit(1);
    }
    if (setrlimit(RLIMIT_NPROC, &tlim_new))
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to increase RLIMIT_NPROC limit!\n");
        exit(1);
    }
}

static void sig_handler(int sig)
{
    (void)sig;
    exiting.store(true);
    ctrlc = 1;
}

void convert_ns_to_iso8601(unsigned long long nanoseconds, char *buffer, size_t buffer_size)
{
    // Convert nanoseconds to seconds and remaining nanoseconds
    time_t seconds = nanoseconds / 1000000000L;
    long ns_part = nanoseconds % 1000000000L;

    // Convert time_t to struct tm
    struct tm time_info;
    gmtime_r(&seconds, &time_info); // Use localtime_r for local time

    // Format the time into ISO 8601 without nanoseconds
    strftime(buffer, buffer_size, "%Y-%m-%dT%H:%M:%S", &time_info);

    // Append the nanoseconds part
    snprintf(buffer + strlen(buffer), buffer_size - strlen(buffer), ".%09ldZ", ns_part);
}

struct free_ptr 
{
    struct bpf_spin_lock semaphore;
    __u32 free;
};

void init_freepointers(int freelist_fd)
{
    struct free_ptr first = { .free = 0, };
    struct free_ptr last = { .free = MAX_USERS, };

    __u32 first_key = 0;
    __u32 last_key = 1;

    if (bpf_map_update_elem(freelist_fd, &first_key, &first, BPF_ANY) < 0 ||
        bpf_map_update_elem(freelist_fd, &last_key, &last, BPF_ANY) < 0)
    {
        plog->WRITE_LOG(LOG_ERR, "freelist_map init failed");
    }
}

// Update last write pointer after GC
void push_free_mapid(int freelist_fd)
{
    __u32 key_last = 1;
    struct free_ptr last_free = {0};

    if (bpf_map_lookup_elem(freelist_fd, &key_last, &last_free) < 0)
    {
        plog->WRITE_LOG(LOG_ERR, "lookup last_free failed");
        return;
    }

    // get next free idx and write into map
    __u32 next_idx = (last_free.free + 1) % MAX_USERS;
    last_free.free = next_idx;

    // update last_free pointer
    if (bpf_map_update_elem(freelist_fd, &key_last, &last_free, BPF_ANY) < 0) {
        plog->WRITE_LOG(LOG_ERR, "update last_free failed");
        return;
    }
}

/* outer map stores inner map IDs; lookup map_num -> inner_map_id -> get fd -> iterate & delete */
static void wipe_inner_map(int outer_fd, uint32_t map_num)
{
    int null_map = bpf_map_create(
        BPF_MAP_TYPE_HASH,
        "inner_map_struct",
        sizeof(struct service_meta),
        sizeof(struct service_info),
        MAX_SERVICES,
        0);

    if (null_map < 0) {
        plog->WRITE_LOG(LOG_ERR, "Failed to create new inner map: %s\n", strerror(errno));
        return;
    }

    // 2) outer map key -> new inner_fd
    if (bpf_map_update_elem(outer_fd, &map_num, &null_map, BPF_ANY) < 0)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to update outer map with new inner map: %s\n", strerror(errno));
        close(null_map);
        return;
    }

    // 3) close old map file descriptor
    unsigned int old_inner_map_id = 0;
    if (bpf_map_lookup_elem(outer_fd, &map_num, &old_inner_map_id) == 0)
    {
        int old_fd = bpf_map_get_fd_by_id(old_inner_map_id);
        if (old_fd > 0)
        {
            close(old_fd);
        }
    }

    close(null_map);
}

pthread_mutex_t file_mutex;
FILE *fdp;
// #define USER_REC_MAX_BYTE 64*1024

void *dump_user_to_json(const struct user_reverse_lookup &rev, const mapid_session &sess, int outer_fd, uint64_t boot_delta)
{
    // while cycle variables
    struct service_meta service_key = {0}, service_nextkey = {0};
    struct service_info service_value;

    char ip_str[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, &rev.user_addr.data, ip_str, sizeof(ip_str)) == NULL)
    {
        strncpy(ip_str, "<invalid>", sizeof(ip_str));
    }

    // init json objects
    json_object *user_obj = json_object_new_object();
    json_object *services_obj = json_object_new_object();
    if (!user_obj || !services_obj)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to create JSON object\n");
        json_object_put(user_obj);
        json_object_put(services_obj);
        return NULL;
    }

    char rx_ts[64] = {0}, tx_ts[64] = {0}, rx_ts_latest[64] = {0}, tx_ts_latest[64] = {0};
    __u64 rx_first_ts = 0, rx_latest_ts = 0, tx_first_ts = 0, tx_latest_ts = 0;

    json_object_object_add(user_obj, "UserIP", json_object_new_string(ip_str));
    json_object_object_add(user_obj, "UserIMSI", json_object_new_string("Under development"));
    json_object_object_add(user_obj, "UserIMEI", json_object_new_string("Under development"));

    const char *roaming = (sess.flags & 0x0003) == 0x0003 ? "Inbound" : (sess.flags & 0x0001) ? "Local"
                                                                    : (sess.flags & 0x0002)   ? "Outbound"
                                                                                              : "Unknown";
    json_object_object_add(user_obj, "Roaming", json_object_new_string(roaming));

    const char *technology = (sess.flags & 0x400) ? "2G" : (sess.flags & 0x800)            ? "3G"
                                                       : (sess.flags & 0x1000)             ? "4G"
                                                       : (sess.flags & 0x2000)             ? "5G"
                                                       : ((sess.flags & 0x3C00) == 0x3C00) ? "Mixed"
                                                                                           : "Unkown";
    json_object_object_add(user_obj, "Technology", json_object_new_string(technology));

    json_object_object_add(user_obj, "Services", services_obj);

    unsigned int inner_map_id = 0;
    if (bpf_map_lookup_elem(outer_fd, &sess.map_num, &inner_map_id) != 0)
    {
        plog->WRITE_LOG(LOG_WARNING, "Outer map lookup failed\n");
        json_object_put(user_obj);
        return NULL;
    }

    unsigned int inner_fd = bpf_map_get_fd_by_id(inner_map_id);
    if (inner_fd < 0)
    {
        plog->WRITE_LOG(LOG_WARNING, "bpf_map_get_fd_by_id failed: %s\n", strerror(errno));
        json_object_put(user_obj);
        return NULL;
    }

    while (bpf_map_get_next_key(inner_fd, &service_key, &service_nextkey) == 0)
    {
        if (bpf_map_lookup_elem(inner_fd, &service_nextkey, &service_value) < 0)
        {
            service_key = service_nextkey;
            continue;
        }

        char inner_addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &service_nextkey.service_addr, inner_addr_str, sizeof(inner_addr_str));
        char service_key_str[128];
        snprintf(service_key_str, sizeof(service_key_str),
                 "%s:%d %s",
                 inner_addr_str, ntohs(service_nextkey.service_port),
                 service_nextkey.protocol == 6 ? "TCP" : (service_nextkey.protocol == 17 ? "UDP" : "Other"));

        json_object *service_data = json_object_new_object();
        if (!service_data)
        {
            plog->WRITE_LOG(LOG_INFO, "Failed to allocate service_data\n");
            service_key = service_nextkey;
            continue;
        }

        if (service_value.rx_first_ts)
        {
            rx_first_ts = boot_delta + service_value.rx_first_ts;
            convert_ns_to_iso8601(rx_first_ts, rx_ts, sizeof(rx_ts));
            json_object_object_add(service_data, "RX first timestamp", json_object_new_string(rx_ts));
        }
        if (service_value.rx_latest_ts)
        {
            rx_latest_ts = boot_delta + service_value.rx_latest_ts;
            convert_ns_to_iso8601(rx_latest_ts, rx_ts_latest, sizeof(rx_ts_latest));
            json_object_object_add(service_data, "RX latest timestamp", json_object_new_string(rx_ts_latest));
        }
        if (service_value.tx_first_ts)
        {
            tx_first_ts = boot_delta + service_value.tx_first_ts;
            convert_ns_to_iso8601(tx_first_ts, tx_ts, sizeof(tx_ts));
            json_object_object_add(service_data, "TX first timestamp", json_object_new_string(tx_ts));
        }
        if (service_value.rx_latest_ts)
        {
            tx_latest_ts = boot_delta + service_value.tx_latest_ts;
            convert_ns_to_iso8601(tx_latest_ts, tx_ts_latest, sizeof(tx_ts_latest));
            json_object_object_add(service_data, "TX latest timestamp", json_object_new_string(tx_ts_latest));
        }

        json_object_object_add(service_data, "RX bytes", json_object_new_uint64(service_value.rx_bytes));
        json_object_object_add(service_data, "TX bytes", json_object_new_uint64(service_value.tx_bytes));

        json_object_object_add(service_data, "RX packets", json_object_new_int(service_value.rx_packets));
        json_object_object_add(service_data, "TX packets", json_object_new_int(service_value.tx_packets));

        json_object_object_add(service_data, "RX packet loss", json_object_new_int(service_value.rx_tcp_retrans));
        json_object_object_add(service_data, "TX packet loss", json_object_new_int(service_value.tx_tcp_retrans));

        if (service_value.jit_calc.rx_jitter > 0)
        {
            uint64_t jitter_ms = service_value.jit_calc.rx_jitter / 1000000ULL;
            json_object_object_add(service_data, "Jitter (ms)", json_object_new_uint64(jitter_ms));
        }

        if (service_value.rtt_measuring / 1000000ULL < 500 && (service_value.rtt_measuring / 1000000ULL != 0))
        {
            json_object_object_add(service_data, "Round-trip time (ms)", json_object_new_uint64(service_value.rtt_measuring / 1000000ULL));
        }

        if (*service_value.sni)
        {
            json_object_object_add(service_data, "SNI", json_object_new_string(service_value.sni));
        }

        json_object_object_add(services_obj, service_key_str, service_data);
        service_key = service_nextkey;
    }
    close(inner_fd);

    const char *json_str = json_object_to_json_string_ext(user_obj, JSON_C_TO_STRING_PRETTY);
    if (json_str)
    {
        FILE *fp = fopen("userdata.json", "a");
        if (fp) {
            fwrite(json_str, sizeof(char), strlen(json_str), fp);
            fwrite("\n", sizeof(char), 1, fp);
            fclose(fp);
        }
    }

    json_object_put(user_obj);
    return NULL;
}

/* Housekeeping thread:
 - scans hk array for freed mapid slots
 - calls push_free_mapid() for each free found
 - resets array entry to 0
 -> freelist map is only modified by this thread (single-consumer)
 -> GC workers only mark slots as free here 
 -> starting push_free from last free index  */
        // todo: ha flag 0, break
static void *housekeeping_worker(void *arg) 
{
    hk_arg_t *a = (hk_arg_t *)arg;
    const useconds_t pause_us = 2000;

    while (!exiting.load()) {
        if (a->freelist_fd < 0) {
            usleep(pause_us);
            continue;
        }

        // 1) read last pointer
        __u32 key_last = 1;
        free_ptr last_free = {};
        if (bpf_map_lookup_elem(a->freelist_fd, &key_last, &last_free) < 0) {
            usleep(pause_us);
            continue;
        }

        // 2) start thread from the last_free index.
        uint32_t start_tid = last_free.free % MAPID_THREADS;
        uint32_t next_tid  = (start_tid + 1) % MAPID_THREADS;

        // 3) if the next one is not ready, there is nothing to advance
        if (g_hk_can_write[next_tid].load(std::memory_order_acquire) == 0) {
            usleep(pause_us);
            continue;
        }

        // 4) go until last writable found
        uint32_t advanced = 0;
        uint32_t cur = next_tid;

        while (g_hk_can_write[cur].load(std::memory_order_acquire)) {
            g_hk_can_write[cur].store(0, std::memory_order_release);
            advanced++;
            cur = (cur + 1) % MAPID_THREADS;
            if (advanced >= MAPID_THREADS) { break; }
        }

        // 5) update writable pointers
        for (uint32_t i = 0; i < advanced; ++i) {
            push_free_mapid(a->freelist_fd);
        }
        usleep(pause_us);
    }
    return NULL;
}

static void *gc_worker(void *arg)
{
    gc_arg_t *a = (gc_arg_t *)arg;
    const uint64_t ttl_ns = (uint64_t)AGGR_TIME * 1000000000ULL;
    const uint32_t max_idx = MAX_USERS;     // MAX_USERS = reverse lookup max_entries
    const useconds_t pause_us = 100 * 1000; // 100 ms polling
    int err = 0;
    int gc_counter = 0;
    uint64_t local_scanned = 0;
    uint32_t local_cleaned = 0;
    uint32_t local_wiped = 0;
    uint32_t local_maps_replaced = 0;
    while (!exiting.load())
    {
        uint64_t t = now_ns();
        uint64_t min_ts = UINT64_MAX;
        uint32_t min_idx = UINT32_MAX;
        struct user_reverse_lookup rev = {};

        // 1) look for min first_ts
        for (uint32_t idx = a->wid; idx < max_idx && !exiting.load(); idx += a->workers) // idx ≡ wid (mod workers)
        { 
            if (bpf_map_lookup_elem(a->rev_fd, &idx, &rev) != 0) {
                continue;
            }

            local_scanned++;
            
            if (rev.first_ts == 0) { // empty slot
                continue;
            } 

            if (rev.first_ts < min_ts) {
                min_ts = rev.first_ts;
                min_idx = idx;
                break;
            }
        }

        // 2) check min ts
        if (min_idx != UINT32_MAX) {
            if (t - min_ts >= ttl_ns) { // aggr. time is over

                mapid_session sess = {};
                uint32_t map_num = min_idx;
                if (bpf_map_lookup_elem(a->mapid_fd, &rev.user_addr, &sess) == 0) {
                    map_num = sess.map_num;
                }

                // save to JSON here before deleting
                dump_user_to_json(rev, sess, a->outer_fd, t);

                // update counters
                local_cleaned++;
                gc_counter++;
                local_wiped++;


                // log which thread is doing GC and what ip it's cleaning
                char ip_str[INET6_ADDRSTRLEN] = {0}; // try to get printable IP for logging
                if (inet_ntop(AF_INET6, &rev.user_addr.data, ip_str, sizeof(ip_str)) == NULL) {
                    strncpy(ip_str, "<invalid>", sizeof(ip_str));
                }
                plog->WRITE_LOG(LOG_INFO, "GC thread %u cleaned #%d: rev_idx=%u map_num=%u ip=%s (scanned=%llu cleaned=%u wiped=%u)\n", a->wid, gc_counter, min_idx, map_num, ip_str, (unsigned long long)local_scanned, local_cleaned, local_wiped);

                // clear inner_map & delete its entry from mapid+rev
                wipe_inner_map(a->outer_fd, map_num);
                local_maps_replaced++;

                err = bpf_map_delete_elem(a->mapid_fd, &rev.user_addr);
                if (err < 0) {
                    plog->WRITE_LOG(LOG_WARNING, "failed to delete user entry in mapid, errno = %d\n", errno);
                }

                user_reverse_lookup empty = {};
                if (bpf_map_update_elem(a->rev_fd, &min_idx, &empty, BPF_ANY) < 0) {
                    plog->WRITE_LOG(LOG_WARNING, "failed to clear user entry in rev, errno = %d\n", errno);
                }

                // update global aggregates occasionally
                if ((local_cleaned & 0xFF) == 0) { // every 256 cleans
                    gc_total_scanned.fetch_add(local_scanned);
                    gc_total_cleaned.fetch_add(local_cleaned);
                    gc_total_wiped.fetch_add(local_wiped);
                    local_scanned = 0;
                    local_cleaned = 0;
                    local_wiped = 0;
                }

                // update read pointer
                // GC threads mark this mapid as free in hk_array
                // freelist_map will be updated by housekeeping thread
                mark_thread_writable(a->wid);
            }
        }
        if (exiting.load()) { break; }
        local_scanned++; // increment scanned count a bit to reflect work done in loop
        usleep(pause_us);
    }
    // flush any remaining local counters to globals and log summary
    if (local_scanned || local_cleaned || local_wiped) {
        gc_total_scanned.fetch_add(local_scanned);
        gc_total_cleaned.fetch_add(local_cleaned);
        gc_total_wiped.fetch_add(local_wiped);
    }
    plog->WRITE_LOG(LOG_INFO, "GC thread %u exiting: scanned=%llu cleaned=%u wiped=%u maps_replaced=%u | global_totals scanned=%llu cleaned=%llu wiped=%llu\n",
                    a->wid,
                    (unsigned long long)local_scanned,
                    local_cleaned,
                    local_wiped,
                    local_maps_replaced,
                    (unsigned long long)gc_total_scanned.load(),
                    (unsigned long long)gc_total_cleaned.load(),
                    (unsigned long long)gc_total_wiped.load());
    return NULL;
}

static pthread_t g_gc_threads[MAPID_THREADS];
static gc_arg_t g_gc_args[MAPID_THREADS];

static void start_mapid_gc(int rev_fd, int mapid_fd, int outer_fd, int freelist_fd)
{
    if (rev_fd < 0 || mapid_fd < 0 || outer_fd < 0) {
        plog->WRITE_LOG(LOG_WARNING, "start_mapid_gc: invalid fd(s): rev=%d mapid=%d outer=%d\n", rev_fd, mapid_fd, outer_fd);
        return;
    }

    /* starting housekeeping thread (single consumer for freelist_map) */
    hk_init_flags();
    g_hk_args.freelist_fd = freelist_fd;
    int rc = pthread_create(&g_hk_thread, NULL, housekeeping_worker, &g_hk_args);
    if (rc != 0) {
        plog->WRITE_LOG(LOG_ERR, "Failed to create housekeeping thread: %s\n", strerror(rc));
        g_hk_thread = 0;
    }

    /* GC worker threads (multi-producer, only writes slot_state_map) */
    for (uint32_t i = 0; i < MAPID_THREADS; ++i) {
        g_gc_args[i].rev_fd = rev_fd;
        g_gc_args[i].mapid_fd = mapid_fd;
        g_gc_args[i].outer_fd = outer_fd;
        g_gc_args[i].freelist_fd = freelist_fd;
        g_gc_args[i].wid = i;
        g_gc_args[i].workers = MAPID_THREADS;

        rc = pthread_create(&g_gc_threads[i], NULL, gc_worker, &g_gc_args[i]);
        usleep(1000); // delay to avoid simultaneous start
        if (rc != 0) {
            plog->WRITE_LOG(LOG_ERR, "Failed to create GC thread %u: %s\n", i, strerror(rc));
            g_gc_threads[i] = 0;
        }
    }
}

static void stop_mapid_gc(void)
{
    exiting.store(true);
    for (uint32_t i = 0; i < MAPID_THREADS; ++i)
    {
        if (g_gc_threads[i])
        {
            pthread_join(g_gc_threads[i], NULL);
            g_gc_threads[i] = 0;
        }
    }

    if (g_hk_thread) {
        pthread_join(g_hk_thread, NULL);
        g_hk_thread = 0;
    }

    plog->WRITE_LOG(LOG_INFO, "For cycle exited in stop_mapid_gc\n");
    plog->WRITE_LOG(LOG_INFO, "GC aggregate totals: scanned=%llu cleaned=%llu wiped=%llu\n",
                    (unsigned long long)gc_total_scanned.load(),
                    (unsigned long long)gc_total_cleaned.load(),
                    (unsigned long long)gc_total_wiped.load());
}


/* Find and attach program to interface */
int tc_loader(const char *iface, bool use_wire_monitor)
{
    struct bpf_object *obj = nullptr;
    struct bpf_tc_opts opts = {0};
    struct bpf_tc_hook hook = {0};
    struct bpf_program *prog, *prog1 = nullptr;
    int err;
    int ret;
    __u32 index;
    int prog_fd;

    const char *filename = "../tmp/mapinmap.bpf.o";

    /* Open the BPF object file */
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        plog->WRITE_LOG(LOG_ERR, "Error opening BPF object file: %s\n", strerror(errno));
        return 1;
    }

    /* Load the BPF object */
    err = bpf_object__load(obj);
    if (err) {
        plog->WRITE_LOG(LOG_ERR, "Error loading BPF object: %s\n", strerror(errno));
        return 1;
    }

    int func_fd = bpf_obj_get("/sys/fs/bpf/func_map");
    if (func_fd < 0) {
        plog->WRITE_LOG(LOG_WARNING, "Function fd fail\n");
        return 1;
    }

    /* Retrieve and count the programs */
    int prog_count = 0;
    bpf_object__for_each_program(prog, obj) {
        plog->WRITE_LOG(LOG_INFO, "Program [%d]: %s\n", prog_count, bpf_program__name(prog));

        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            plog->WRITE_LOG(LOG_WARNING, "Failed to get prog1 file descriptor\n");
            bpf_object__close(obj);
            close(func_fd);
            return 1;
        }

        const char *prog_name = bpf_program__name(prog);
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            plog->WRITE_LOG(LOG_WARNING, "Failed to get prog1 file descriptor\n");
            return 1;
        }
        if (strcmp(prog_name, "monitor_mnet") == 0) {
            index = 0;
            if (!use_wire_monitor) {
                prog1 = prog; // only attach if no -w flag was given by user
            }
        }
        else if (strcmp(prog_name, "monitor_wnet") == 0) {
            index = WIRE_MONITOR;
            if (use_wire_monitor) {
                prog1 = prog; // only attach if -w flag was given by user
            }
        }
        else if (strcmp(prog_name, "qos_logic") == 0) {
            index = QOS_LOGIC;
        }
        else if (strcmp(prog_name, "dns_capture") == 0) {
            index = DNS_CAP;
        }
        else if (strcmp(prog_name, "gtpc_assembler") == 0) {
            index = GTPC_ASS;
        }
        else if (strcmp(prog_name, "sni_extractor") == 0) {
            index = SNI_EXTR;
        }
        else if (strcmp(prog_name, "debug_trace") == 0) {
            index = DEBUG_TR;
        }
        else if (strcmp(prog_name, "lawful_interception") == 0) {
            index = LAW_INTER;
        }
        else {
            plog->WRITE_LOG(LOG_WARNING, "Unknown program: %s\n", prog_name);
            // return -1;
            continue;
        }
        ret = bpf_map_update_elem(func_fd, &index, &prog_fd, BPF_ANY);
        if (ret < 0) {
            plog->WRITE_LOG(LOG_WARNING, "bpf_map_update_elem fail\n");
            bpf_object__close(obj);
            close(func_fd);
            return 1;
        }
        prog_count++;
    }

    close(func_fd);
    plog->WRITE_LOG(LOG_INFO, "Total programs loaded: %d\n", prog_count);

    if (prog_count < 8) {
        plog->WRITE_LOG(LOG_ERR, "Error: less than 8 programs found in the BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    if (!prog1) {
        plog->WRITE_LOG(LOG_ERR, "Error: No suitable program selected for attachment\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Get file descriptor for the first program to attach */
    prog_fd = bpf_program__fd(prog1);
    if (prog_fd < 0) {
        plog->WRITE_LOG(LOG_WARNING, "Failed to get %s file descriptor\n", bpf_program__name(prog1));
        bpf_object__close(obj);
        return 1;
    }

    if (!iface || iface[0] == '\0') {
        printf("Invalid ifname\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Set up the TC hook */
    hook = {
        .sz = sizeof(hook),
        .ifindex = static_cast<int>(if_nametoindex(iface)),
        .attach_point = BPF_TC_INGRESS,
    };
    if (hook.ifindex == 0) {
        plog->WRITE_LOG(LOG_WARNING, "Unkown interface: %s\n", iface);
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        plog->WRITE_LOG(LOG_ERR, "Failed to create TC hook: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Attach the BPF program to the TC hook */
    opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
        .flags = BPF_TC_F_REPLACE,
    };

    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        plog->WRITE_LOG(LOG_ERR, "Failed to attach TC program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    plog->WRITE_LOG(LOG_INFO, "Program attached successfully to interface %s\n", iface);

    return 0;
}

/* Write user data into json file */
void *main_stater2(void *arg)
{
    struct dispatcher_arg *args = (struct dispatcher_arg *)arg;
    struct service_meta service_key = {0}, service_nextkey = {0};
    struct service_info service_value;
    unsigned int outer_value = 0; // inner map id
    unsigned int inner_fd = 0;    // inner map fd
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &args->uIP.data, addr_str, sizeof(addr_str));
    const char *json_str = NULL;

    // init json objects
    json_object *user_obj = json_object_new_object();
    json_object *services_obj = json_object_new_object();
    if (!user_obj || !services_obj)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to create JSON objects\n");
        json_object_put(user_obj);
        json_object_put(services_obj);
        return NULL;
    }

    char rx_ts[64] = {0}, tx_ts[64] = {0}, rx_ts_latest[64] = {0}, tx_ts_latest[64] = {0};
    __u64 rx_first_ts = 0, rx_latest_ts = 0, tx_first_ts = 0, tx_latest_ts = 0;

    json_object_object_add(user_obj, "UserIP", json_object_new_string(addr_str));
    json_object_object_add(user_obj, "UserIMSI", json_object_new_string("Under development"));
    json_object_object_add(user_obj, "UserIMEI", json_object_new_string("Under development"));

    const char *roaming = (args->user_info.flags & 0x0003) == 0x0003 ? "Inbound" : (args->user_info.flags & 0x0001) ? "Local"
                                                                               : (args->user_info.flags & 0x0002)   ? "Outbound"
                                                                                                                    : "Unknown";
    json_object_object_add(user_obj, "Roaming", json_object_new_string(roaming));

    const char *technology = (args->user_info.flags & 0x400) ? "2G" : (args->user_info.flags & 0x800)            ? "3G"
                                                                  : (args->user_info.flags & 0x1000)             ? "4G"
                                                                  : (args->user_info.flags & 0x2000)             ? "5G"
                                                                  : ((args->user_info.flags & 0x3C00) == 0x3C00) ? "Mixed"
                                                                                                                 : "Unknown";
    json_object_object_add(user_obj, "Technology", json_object_new_string(technology));
    json_object_object_add(user_obj, "Services", services_obj);

    if (bpf_map_lookup_elem(args->outer_fd, &args->user_info.map_num, &outer_value) < 0)
    {
        plog->WRITE_LOG(LOG_WARNING, "Outer map lookup failed\n");
        goto cleanup;
    }

    inner_fd = bpf_map_get_fd_by_id(outer_value);
    if (inner_fd < 0)
    {
        plog->WRITE_LOG(LOG_WARNING, "bpf_map_get_fd_by_id failed: %s\n", strerror(errno));
        goto cleanup;
    }

    while (bpf_map_get_next_key(inner_fd, &service_key, &service_nextkey) == 0)
    {
        if (bpf_map_lookup_elem(inner_fd, &service_nextkey, &service_value) < 0)
        {
            service_key = service_nextkey;
            continue;
        }

        char inner_addr_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &service_nextkey.service_addr, inner_addr_str, sizeof(inner_addr_str));
        char service_key_str[128];
        snprintf(service_key_str, sizeof(service_key_str), "%s:%d %s",
                 inner_addr_str, ntohs(service_nextkey.service_port),
                 service_nextkey.protocol == 6 ? "TCP" : (service_nextkey.protocol == 17 ? "UDP" : "Other"));

        json_object *service_data = json_object_new_object();
        if (!service_data)
        {
            plog->WRITE_LOG(LOG_ERR, "Failed to allocate service_data\n");
            service_key = service_nextkey;
            continue;
        }

        if (service_value.rx_first_ts)
        {
            rx_first_ts = args->boot_delta + service_value.rx_first_ts;
            convert_ns_to_iso8601(rx_first_ts, rx_ts, sizeof(rx_ts));
            json_object_object_add(service_data, "RX first timestamp", json_object_new_string(rx_ts));
        }
        if (service_value.rx_latest_ts)
        {
            rx_latest_ts = args->boot_delta + service_value.rx_latest_ts;
            convert_ns_to_iso8601(rx_latest_ts, rx_ts_latest, sizeof(rx_ts_latest));
            json_object_object_add(service_data, "RX latest timestamp", json_object_new_string(rx_ts_latest));
        }
        if (service_value.tx_first_ts)
        {
            tx_first_ts = args->boot_delta + service_value.tx_first_ts;
            convert_ns_to_iso8601(tx_first_ts, tx_ts, sizeof(tx_ts));
            json_object_object_add(service_data, "TX first timestamp", json_object_new_string(tx_ts));
        }
        if (service_value.tx_latest_ts)
        {
            tx_latest_ts = args->boot_delta + service_value.tx_latest_ts;
            convert_ns_to_iso8601(tx_latest_ts, tx_ts_latest, sizeof(tx_ts_latest));
            json_object_object_add(service_data, "TX latest timestamp", json_object_new_string(tx_ts_latest));
        }

        json_object_object_add(service_data, "RX bytes", json_object_new_uint64(service_value.rx_bytes));
        json_object_object_add(service_data, "TX bytes", json_object_new_uint64(service_value.tx_bytes));

        json_object_object_add(service_data, "RX packets", json_object_new_int(service_value.rx_packets));
        json_object_object_add(service_data, "TX packets", json_object_new_int(service_value.tx_packets));

        json_object_object_add(service_data, "RX packet loss", json_object_new_int(service_value.rx_tcp_retrans));
        json_object_object_add(service_data, "TX packet loss", json_object_new_int(service_value.tx_tcp_retrans));

        if (service_value.jit_calc.rx_jitter > 0)
        {
            uint64_t jitter_ms = service_value.jit_calc.rx_jitter / 1000000ULL;
            json_object_object_add(service_data, "Jitter (ms)", json_object_new_uint64(jitter_ms));
        }

        if (service_value.rtt_measuring / 1000000ULL < 500 && (service_value.rtt_measuring / 1000000ULL != 0))
        {
            json_object_object_add(service_data, "Round-trip time (ms)", json_object_new_uint64(service_value.rtt_measuring / 1000000ULL));
        }

        if (*service_value.sni)
        {
            json_object_object_add(service_data, "SNI", json_object_new_string(service_value.sni));
        }

        json_object_object_add(services_obj, service_key_str, service_data);
        service_key = service_nextkey;
    }

    pthread_mutex_lock(&file_mutex);
    json_str = json_object_to_json_string_ext(user_obj, JSON_C_TO_STRING_PRETTY);
    if (json_str && fdp)
    {
        fwrite(json_str, sizeof(char), strlen(json_str), fdp);
        fwrite("\n", sizeof(char), 1, fdp);
    }
    pthread_mutex_unlock(&file_mutex);

cleanup:
    json_object_put(user_obj);
    if (inner_fd > 0)
        close(inner_fd);
    return NULL;
}

#define NUM_READERS 1000
int main_stat_dispatcher(int mapid_fd, int outer_fd)
{
    struct ipv6_lpm_key next_key, key = {0};
    struct timespec ts, ts_boot;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    __u64 boot = ts_boot.tv_sec * 1000000000L + ts_boot.tv_nsec;
    __u64 realtime = ts.tv_sec * 1000000000L + ts.tv_nsec;

    pthread_t threads[NUM_READERS];
    struct dispatcher_arg *params[NUM_READERS];
    memset(threads, 0, sizeof(threads));
    memset(params, 0, sizeof(params));
    int j = 0;
    pthread_mutex_init(&file_mutex, NULL);

    fdp = fopen("ud_monitor.json", "w");
    if (!fdp)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to open JSON file\n");
        return -1;
    }

    while (bpf_map_get_next_key(mapid_fd, &key, &next_key) == 0)
    {
        params[j] = (struct dispatcher_arg *)calloc(1, sizeof(struct dispatcher_arg));
        if (!params[j])
        {
            plog->WRITE_LOG(LOG_ERR, "Failed to allocate params[%d]\n", j);
            break;
        }

        params[j]->outer_fd = outer_fd;
        params[j]->boot_delta = realtime - boot;
        params[j]->uIP = next_key;
        bpf_map_lookup_elem(mapid_fd, &next_key, &params[j]->user_info);

        int ret = pthread_create(&threads[j], NULL, main_stater2, params[j]);
        if (ret != 0)
        {
            plog->WRITE_LOG(LOG_ERR, "Failed to create thread %d: %s\n", j, strerror(ret));
            free(params[j]);
            params[j] = NULL;
            break;
        }

        key = next_key;
        j++;

        // Flush if limit reached
        if (j == NUM_READERS)
        {
            for (int k = 0; k < j; ++k)
            {
                if (threads[k])
                {
                    pthread_join(threads[k], NULL);
                }
                if (params[k])
                {
                    free(params[k]);
                    params[k] = NULL;
                }
            }
            memset(threads, 0, sizeof(threads));
            memset(params, 0, sizeof(params));
            j = 0;
        }
    }

    // Final flush for remaining threads
    for (int k = 0; k < j; ++k)
    {
        if (threads[k])
        {
            pthread_join(threads[k], NULL);
        }
        if (params[k])
        {
            free(params[k]);
            params[k] = NULL;
        }
    }

    fclose(fdp);
    fdp = NULL;
    pthread_mutex_destroy(&file_mutex);
    return 0;
}

/* Asks the user for an ipv6 address and looks up data associated to the key */
int test_query(int *outer_fd, int *mapid_fd)
{
    struct in6_addr ipv6addr;
    char str[INET6_ADDRSTRLEN];
    int counter = 0;

    printf("Enter a user IPv6 address: ");
    if (scanf("%45s", str) != 1)
    {
        plog->WRITE_LOG(LOG_WARNING, "Scanf error\n");
        return -1;
    }
    if (inet_pton(AF_INET6, str, &ipv6addr) != 1)
    {
        printf("Invalid address\n");
        return -1;
    }
    struct ipv6_lpm_key ip = {128, ipv6addr};

    // inner key and value
    struct service_meta key = {0}, next_key = {0};
    struct service_info value = {0};

    // outer map value
    unsigned int inner_map_id;
    struct mapid_session ms = {0};
    char service_addr[INET6_ADDRSTRLEN];

    int ret = bpf_map_lookup_elem(*mapid_fd, &ip, &ms);
    if (ret < 0)
    {
        plog->WRITE_LOG(LOG_WARNING, "Mapid element not found\n");
        return -1;
    }
    else
    {
        ret = bpf_map_lookup_elem(*outer_fd, &ms.map_num, &inner_map_id);
        if (ret < 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Outer value not found\n");
            return -1;
        }

        unsigned int inner_fd = bpf_map_get_fd_by_id(inner_map_id);
        if (inner_fd == 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Invalid fd\n");
            return -1;
        }

        printf("Registered services: \n");
        while (1)
        {
            ret = bpf_map_get_next_key(inner_fd, &key, &next_key);
            if (ret < 0)
            {
                break;
            }
            ret = bpf_map_lookup_elem(inner_fd, &next_key, &value);
            if (ret < 0)
            {
                plog->WRITE_LOG(LOG_INFO, "Inner entry not found\n");
                return -1;
            }
            else
            {
                inet_ntop(AF_INET6, &next_key.service_addr, service_addr, sizeof(service_addr));
                printf("\tSERIVCE: addr = %s, protocol = %u, ", service_addr, next_key.protocol);
                printf("port = %d\n", ntons(next_key.service_port));
                printf("\tRX bytes = %llu, RX packets = %d, TX bytes = %llu, TX packets = %d\n\n", value.rx_bytes, value.rx_packets, value.tx_bytes, value.tx_packets);
                counter++;
            }
            key = next_key;
        }
        printf("Found (%d)\n", counter);
        close(inner_fd);
    }
    return 0;
}

/* Loops through every saved user IP and lists all data from the inner maps */
int test_lpmtrie_print(int *mapid_fd, int *outer_fd)
{
    int err; // debug stuff
    int counter = 0;
    // int service_counter = 0;

    struct ipv6_lpm_key key = {0}, next_key = {0};
    struct mapid_session value = {0};
    char addr_str[INET6_ADDRSTRLEN];       // address of user
    char inner_addr_str[INET6_ADDRSTRLEN]; // address of service
    unsigned int outer_value;              // inner map id
    unsigned int inner_fd;                 // inner map fd
    struct service_meta service_key = {0}, service_nextkey = {0};
    struct service_info service_value;
    int double_roaming = 0;

    // timestamping
    struct timespec ts, ts_boot;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_gettime(CLOCK_BOOTTIME, &ts_boot);
    __u64 boot = ts_boot.tv_sec * 1000000000L + ts_boot.tv_nsec;
    __u64 realtime = ts.tv_sec * 1000000000L + ts.tv_nsec;
    __u64 service_first_ts;
    char iso8601_str[64];
    char realtime_str[64];
    __u64 rtsfts = 0;
    convert_ns_to_iso8601(realtime, realtime_str, sizeof(realtime_str));

    while (1)
    {
        err = bpf_map_get_next_key(*mapid_fd, &key, &next_key);
        if (err < 0)
        {
            return -1;
        }

        err = bpf_map_lookup_elem(*mapid_fd, &next_key, &value);
        if (err < 0)
        {
            return -1;
        }

        inet_ntop(AF_INET6, &next_key.data, addr_str, sizeof(addr_str));

        if ((value.flags & 0x0003) == 0x0003)
        {
            double_roaming = 1; // HR and R bits are both set to 1
        }

        // service_counter = 0;

        printf("Addr = %s, Value = %u\n", addr_str, value.map_num);

        key = next_key;

        err = bpf_map_lookup_elem(*outer_fd, &value, &outer_value);
        if (err < 0)
        {
            continue;
        } /* no more entries */

        inner_fd = bpf_map_get_fd_by_id(outer_value);
        if (inner_fd == 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Invalid inner fd\n");
            continue;
        }

        else
        {
            memset(&service_key, 0, sizeof(struct service_meta));
            while (1)
            {
                err = bpf_map_get_next_key(inner_fd, &service_key, &service_nextkey);
                if (err < 0)
                {
                    break;
                }

                err = bpf_map_lookup_elem(inner_fd, &service_nextkey, &service_value);
                if (err < 0)
                {
                    plog->WRITE_LOG(LOG_WARNING, "Inner entry not found\n");
                    break;
                }
                else
                {
                    if (service_value.rx_first_ts == 0)
                    {
                        service_first_ts = service_value.tx_first_ts;
                    }
                    else
                    {
                        service_first_ts = service_value.rx_first_ts;
                    }

                    rtsfts = realtime + service_first_ts - boot;
                    convert_ns_to_iso8601(rtsfts, iso8601_str, sizeof(iso8601_str));

                    inet_ntop(AF_INET6, &service_nextkey.service_addr, inner_addr_str, sizeof(inner_addr_str));

                    if (double_roaming == 1)
                    {
                        service_value.tx_packets = (service_value.tx_packets + 1) / 2;
                        service_value.rx_packets = (service_value.rx_packets + 1) / 2;
                        service_value.tx_bytes = (service_value.tx_bytes + 1) / 2;
                        service_value.rx_bytes = (service_value.rx_bytes + 1) / 2;
                    }

                    printf("\tSERVICE: addr = %s, port = %d, protocol = ", inner_addr_str, ntons(service_nextkey.service_port));
                    if (service_nextkey.protocol == 6)
                    {
                        printf("TCP\n");
                    }
                    else if (service_nextkey.protocol == 17)
                    {
                        printf("UDP\n");
                    }
                    else
                    {
                        printf("%d\n", service_nextkey.protocol);
                    }
                    printf("\tTimestamp: %s, RX bytes = %llu, RX packets = %d, TX bytes = %llu, TX packets = %d\n\n", iso8601_str, service_value.rx_bytes, service_value.rx_packets, service_value.tx_bytes, service_value.tx_packets);
                    // service_counter += 1;
                }
                service_key = service_nextkey;
            }
            close(inner_fd);
        }
    }
    return 0;
}

int get_nodes(int node_fd, char* addr_db, unsigned short port)
{
    sga_dbconn dbconn(plog);
    if (!dbconn.db_connect(addr_db, port, "sga", "sga", "sga", NULL)) {
        plog->WRITE_LOG(LOG_ERR, "Failed to connect to database\n");
        return -1;
    }

    if (!dbconn.save_nodes_to_bpf(node_fd)) {
        plog->WRITE_LOG(LOG_ERR, "Failed to load nodes into eBPF map\n");
    }

    dbconn.db_disconnect();
    return 0;
}

void *test_inner(void *params)
{
    struct inner_pthread *par = (struct inner_pthread *)params;
    int outer_fd = par->omap_fd;
    unsigned int start = par->start;
    unsigned int end = par->end;
    int ret = 0;
    int inner_fd;
    int local_loaded = 0;
    // LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
    for (unsigned int i = start; i < end; i++)
    {
        inner_fd = bpf_map_create(
            BPF_MAP_TYPE_HASH,
            "inner_map_struct",
            sizeof(struct service_meta),
            sizeof(struct service_info),
            MAX_SERVICES,
            0);

        if (inner_fd < 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Inner map bpf_map_create failed\n");
            if (local_loaded > 0)
                inner_maps_loaded += local_loaded;
            return NULL;
        }
        ret = bpf_map_update_elem(outer_fd, &i, &inner_fd, BPF_ANY);
        if (ret < 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Outer map bpf_map_update_elem failed\n");
            close(inner_fd);
            if (local_loaded > 0)
                inner_maps_loaded += local_loaded;
            return NULL;
        }
        close(inner_fd);
        local_loaded++;
    }
    if (local_loaded > 0)
        inner_maps_loaded += local_loaded;
    plog->WRITE_LOG(LOG_INFO, "test_inner thread loaded %d inner maps (range %u..%u)\n", local_loaded, start, end);
    return NULL;
}

/* Sets mapid map's first element to address=0 and value=1 */
void init_srcip_map(int *mapid_fd)
{
    plog->WRITE_LOG(LOG_INFO, "Initializing mapid first element...\n");
    struct in6_addr first_addr = {0};
    struct ipv6_lpm_key first_elem = {128, first_addr};
    struct mapid_session map_size = {1, 0, 0}; // map size = 1, flags = 0, first_ts = 0
    int ret = bpf_map_update_elem(*mapid_fd, &first_elem, &map_size, BPF_ANY);
    if (ret < 0) {
        plog->WRITE_LOG(LOG_WARNING, "Mapid first element update fail\n");
        return;
    }
}

/* Clear all users from the program */
int clear_users(int *outer_fd, int *mapid_fd, int *rev_fd)
{
    struct ipv6_lpm_key key = {0}, next_key = {0};
    struct mapid_session value;
    int err;
    uint32_t inner_maps_wiped = 0;
    uint32_t mapid_entries_deleted = 0;

    // wipe inner maps and collect keys to delete
    while (bpf_map_get_next_key(*mapid_fd, &key, &next_key) == 0) {
        err = bpf_map_lookup_elem(*mapid_fd, &next_key, &value);
        if (err < 0) {
            plog->WRITE_LOG(LOG_WARNING, "lookup failed for key (prefixlen=%u)\n", next_key.prefixlen);
            key = next_key;
            continue;
        }
        wipe_inner_map(*outer_fd, value.map_num);
        inner_maps_wiped++;
        
        // delete the mapid entry using the actual LPM key
        if (bpf_map_delete_elem(*mapid_fd, &next_key) < 0) {
            if (errno != ENOENT) {
                plog->WRITE_LOG(LOG_WARNING, "Failed to delete mapid entry (prefixlen=%u), errno=%d\n", next_key.prefixlen, errno);
            }
        } else {
            mapid_entries_deleted++;
        }
        key = next_key;
    }
    plog->WRITE_LOG(LOG_INFO, "Replaced %u inner maps with null map, deleted %u mapid entries\n", inner_maps_wiped, mapid_entries_deleted);

    if (rev_fd) {
        for (__u32 idx = 0; idx < MAX_USERS; ++idx) {
            user_reverse_lookup zero = {};
            if (bpf_map_update_elem(*rev_fd, &idx, &zero, BPF_ANY) < 0) {
                plog->WRITE_LOG(LOG_WARNING, "Failed to clear rev_lookup index %u, errno=%d\n", idx, errno);
            }
        }
    }
    plog->WRITE_LOG(LOG_INFO, "Finished reverse lookup map  clearing.\n");
    init_srcip_map(mapid_fd);
    return 0;
}

/* Thread (giga)factories seem to be the go to way to create a LOT of maps in a short time
   Because there is nothing more safe and fun than to spawn 1000's of Kernel threads at the same time */
#define NUM_THREADS 20
void populate_inner_factory(int outer_fd, int mapid_fd, int rev_fd) 
{
    struct inner_pthread **params = (struct inner_pthread **)malloc(NUM_THREADS * sizeof(struct inner_pthread *));
    if (!params)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to allocate params array\n");
        return;
    }
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++)
    {
        params[i] = (struct inner_pthread *)malloc(sizeof(struct inner_pthread));
        if (!params[i]) {
            plog->WRITE_LOG(LOG_ERR, "Failed to allocate params[%d]\n", i);
            for (int k = 0; k < i; k++) {
                free(params[k]);
            }
            free(params);
            return;
        }
        params[i]->omap_fd = outer_fd;
        params[i]->start = i * 1000;
        params[i]->end = (i + 1) * 1000;

        int ret = pthread_create(&threads[i], NULL, test_inner, (void *)params[i]);
        if (ret != 0) {
            plog->WRITE_LOG(LOG_ERR, "pthread_create failed for thread %d: %s\n", i, strerror(ret));
            for (int k = 0; k < i; k++) {
                pthread_join(threads[k], NULL);
                free(params[k]);
            }
            free(params);
            return;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
        free(params[i]);
    }
    free(params);

    // log total successfully loaded inner maps + reset counter for next run
    plog->WRITE_LOG(LOG_INFO, "Total inner maps loaded into outer_map: %d\n", inner_maps_loaded.load());
    inner_maps_loaded.store(0);

    clear_users(&outer_fd, &mapid_fd, &rev_fd);
}

void bcd_to_str(const uint8_t *bcd, int bcd_len, char *imsi_str)
{
    int imsi_index = 0;
    for (int i = 0; i < bcd_len; i++)
    {
        // Extract two digits from each byte
        uint8_t high_digit = (bcd[i] & 0x0F);     // Low nibble
        uint8_t low_digit = (bcd[i] >> 4) & 0x0F; // High nibble

        // Convert to characters and append to the IMSI string
        if (high_digit <= 9)
        {
            imsi_str[imsi_index++] = '0' + high_digit;
        }

        if (low_digit <= 9 && i != bcd_len - 1)
        { // Avoid the last nibble if it's padding
            imsi_str[imsi_index++] = '0' + low_digit;
        }
    }
    imsi_str[imsi_index] = '\0'; // Null-terminate the string
}

void report_gtpc(int gtpc_fd)
{
    struct ipv6_lpm_key key = {0};
    struct ipv6_lpm_key nextkey = {0};
    key.prefixlen = 128;
    unsigned long long imsi = 0;
    char user_ip[INET6_ADDRSTRLEN];
    char imsi_str[16];
    int err = 0;
    unsigned int i = 0;
    for (i = 0; i < (3 * MAX_USERS); i++)
    {
        err = bpf_map_get_next_key(gtpc_fd, &key, &nextkey);
        if (err < 0)
        {
            break;
        }

        err = bpf_map_lookup_elem(gtpc_fd, &nextkey, &imsi);
        if (err < 0)
        {
            plog->WRITE_LOG(LOG_WARNING, "Key not found: %d\n", err);
            break;
        }
        inet_ntop(AF_INET6, &nextkey.data, user_ip, sizeof(user_ip));
        bcd_to_str((uint8_t *)&imsi, 8, imsi_str);
        printf("\tIMSI: %s, IP: %s\n", imsi_str, user_ip);
        key = nextkey;
    }
    printf("Number of IMSI connected IP's: %d\n", i);
}

/* Prints out debug statistics from debug map */
int report_debug(int *debug_fd)
{
    int ret = 0;
    unsigned int numbers[32]; // counters

    // Retrieve all counter values from debug map
    for (int i = 0; i < 31; i++) {
        ret = bpf_map_lookup_elem(*debug_fd, &i, &numbers[i]);
        if (ret < 0) { 
            plog->WRITE_LOG(LOG_ERR, "DEBUG MAP ERROR\n"); 
            return -1; 
        }
    }

    // General statistics
    printf("=== GENERAL STATISTICS ===\n");
    printf("Ingress sum:           %u\n", numbers[5]);
    printf("Fatal errors sum:      %u\n", numbers[0]);
    printf("Bad packets:           %u\n", numbers[1]);
    printf("Don't care:            %u\n", numbers[2]);
    printf("GTP-U in:              %u\n", numbers[3]);
    printf("GTP-U out:             %u\n", numbers[4]);

    // GTP-C statistics
    printf("\n=== GTP-C STATISTICS ===\n");
    printf("GTP-C counter:         %u\n", numbers[11]);
    printf("GTP-C requests:        %u\n", numbers[12]);
    printf("GTP-C responses:       %u\n", numbers[13]);
    printf("GTP-C assembly success:%u\n", numbers[14]);

    // Fatal errors
    printf("\n=== FATAL ERRORS ===\n");
    printf("Pull data fail:        %u\n", numbers[6]);
    printf("IP decode fail:        %u\n", numbers[7]);
    printf("Mapid lookup fail:     %u\n", numbers[8]);
    printf("Inner UDP update fail: %u\n", numbers[9]);
    printf("Inner TCP update fail: %u\n", numbers[10]);
    printf("Tailcall error:        %u\n", numbers[24]);
    printf("Outer map error:       %u\n", numbers[25]);
    printf("New service error:     %u\n", numbers[26]);

    // TLS/SNI statistics
    printf("\n=== TLS/SNI STATISTICS ===\n");
    printf("Handshake:             %u\n", numbers[15]);
    printf("Client hello:          %u\n", numbers[16]);
    printf("SNI errors:            %u\n", numbers[17]);

    // Other statistics
    printf("\n=== OTHER STATISTICS ===\n");
    printf("DNS capture:           %u\n", numbers[18]);
    printf("SGA dump filter:       %u\n", numbers[19]);
    printf("Wired connection:      %u\n", numbers[20]);
    printf("Next mapid:            %u\n", numbers[21]);

    // Pointer management
    printf("\n=== READ/WRITE POINTER ===\n");
    printf("Free pointer -1 error: %u\n", numbers[22]);
    printf("Lookup free success:   %u\n", numbers[23]);

    return 0;
}

/* Set all values in debug counter map to 0 */
int reset_debug(int *debug_fd)
{
    plog->WRITE_LOG(LOG_INFO, "Resetting debug counters to 0...\n");
    unsigned int value = ZERO;
    int ret = 0;

    for (int i = 0; i < 31; i++) {
        ret = bpf_map_update_elem(*debug_fd, &i, &value, BPF_EXIST);
        if (ret < 0) { plog->WRITE_LOG(LOG_ERR, "DEBUG MAP ERROR\n"); return -1; }
    }
    return 0;
}

/* enables/disables kernel processing pipeline with swapping ENABLE_KERNEL value to 0 or 1) */
int enable_kernel(int *debug_fd)
{
    int ret = 0;
    unsigned int kenable_index = ENABLE_KERNEL;
    unsigned int value;
    unsigned int new_value;

    ret = bpf_map_lookup_elem(*debug_fd, &kenable_index, &value);
    if (ret < 0) { plog->WRITE_LOG(LOG_ERR, "(DIS/EN)ABLE KERNEL ERROR\n"); return -1; }

    if (value == 0)
    {
        plog->WRITE_LOG(LOG_INFO, "Enabling kernel...\n");
        new_value = 1;
        ret = bpf_map_update_elem(*debug_fd, &kenable_index, &new_value, BPF_EXIST);
        if (ret < 0) { plog->WRITE_LOG(LOG_ERR, "ENABLE KERNEL FAIL\n"); return -1; }
    }
    else if (value == 1) {
        plog->WRITE_LOG(LOG_INFO, "Disabling kernel...\n");
        new_value = 0;
        ret = bpf_map_update_elem(*debug_fd, &kenable_index, &new_value, BPF_EXIST);
        if (ret < 0) { plog->WRITE_LOG(LOG_ERR, "DISABLE KERNEL FAIL\n"); return -1; }
    }
    else { plog->WRITE_LOG(LOG_ERR, "(DIS/EN)ABLE KERNEL VALUE NOT 1 OR 0\n"); return -1; }
    return 0;
}

// Use bpf_obj_get to get map file descriptor from pinned path
int get_map_fd(const char *map_path)
{
    int fd = bpf_obj_get(map_path);
    if (fd < 0)
    {
        plog->WRITE_LOG(LOG_ERR, "Failed to get map fd for %s: %s\n", map_path, strerror(errno));
    }
    return fd;
}

int main(int argc, char **argv)
{
    /* Starting concurrent tctap thread */
    std::thread thr_tctap([&]()
                          { tctap_main(argc, argv, exiting); });

    plog = new SGA_Logger(argv[0], LOG_SYS, false);

    /* Set up libbpf logging callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Vars for main cycle handling */
    int gc_started = 0;
    int ans;
    int ret = 0;
    int test_mode_on = 0;
    int cntsec = 0;
    bool use_wire_monitor = false;
    char* addr_db = "10.0.0.185";
   	unsigned short db_port = 3306;

    if (argc < 2) {        
		printf("Usage: %s <interface> <options>\n", argv[0]);
        printf(" -w : Enable wire monitor mode\n");
        printf(" -t : Enable test mode (interactive), otherwise program runs by itself\n");
		printf(" -d <database_ip:port> : SQL DB for filters/statistics\n");
		printf(" -b <Buffer_size> : Monitor buffer size in MB\n");
		printf(" -m [0,1]: Set/unset debug mode\n");
        delete(plog);
        return 1;
    }

    const char *iface = argv[1];
    if (iface == NULL || iface[0] == '\0') {
        plog->WRITE_LOG(LOG_ERR, "Invalid interface name\n");
        delete (plog);
        return -1;
    }

    // check for flags
    for (int i = 0; i < argc; i++) {
        if (argc >= 3 && strcmp(argv[i], "-w") == 0) {
            use_wire_monitor = true;
            plog->WRITE_LOG(LOG_INFO, "Wire monitor mode enabled\n");
        }
        else if ((argc >= 3) && (strcmp(argv[i], "-t") == 0)) {
            test_mode_on = 1;
            plog->WRITE_LOG(LOG_INFO, "Starting program in test mode\n");
        }
        else if ((argc >= 3) && (strcmp(argv[i], "-d") == 0)){
            addr_db = argv[i + 1];
            db_port = cget_addrnport(addr_db);
            plog->WRITE_LOG(LOG_INFO, "Database address set to %s\n", addr_db);
        }
    }

    if (tc_loader(iface, use_wire_monitor) != 0) {
        plog->WRITE_LOG(LOG_ERR, "TC interface load error\n");
        delete (plog);
        return -1;
    }

    /* File descriptors for maps exit if failed to get one */
    int mapid_fd = get_map_fd("/sys/fs/bpf/mapid");
    int freelist_fd = get_map_fd("/sys/fs/bpf/freelist_map");
    int outer_fd = get_map_fd("/sys/fs/bpf/outer_map");
    int node_fd = get_map_fd("/sys/fs/bpf/nodes");
    int debug_fd = get_map_fd("/sys/fs/bpf/reporter");
    int gtpc_fd = get_map_fd("/sys/fs/bpf/ip_imsi");
    int rev_fd = get_map_fd("/sys/fs/bpf/rev_lookup");
    if (mapid_fd < 0 || freelist_fd < 0 || outer_fd < 0 || node_fd < 0 || debug_fd < 0 || gtpc_fd < 0 || rev_fd < 0) { delete (plog); return -1; }

    init_freepointers(freelist_fd);
    init_srcip_map(&mapid_fd);
    get_nodes(node_fd, addr_db, db_port);

    if (test_mode_on == 0) { // auto mode
        plog->WRITE_LOG(LOG_INFO, "Starting program in auto mode\n");
        plog->WRITE_LOG(LOG_INFO, "Populating inner maps...\n");
        populate_inner_factory(outer_fd, mapid_fd, rev_fd);
        plog->WRITE_LOG(LOG_INFO, "Finished populating maps...\n");
        /* Ensure garbage collector is running before enabling kernel processing */
        if (gc_started == 0) {
            plog->WRITE_LOG(LOG_INFO, "Starting garbage collector...\n");
            start_mapid_gc(rev_fd, mapid_fd, outer_fd, freelist_fd);
            gc_started = 1;
        }
        else {
            printf("Garbage collector already started\n");
        }

        unsigned int kenable_index = ENABLE_KERNEL;
        unsigned int value;
        ret = bpf_map_lookup_elem(debug_fd, &kenable_index, &value);
        if (ret < 0) {
            plog->WRITE_LOG(LOG_ERR, "(DIS/EN)ABLE KERNEL ERROR\n");
            delete (plog);
            exiting.store(true);
            return -1;
        }
        if (value != 1) {
            if (gc_started) {
                enable_kernel(&debug_fd);
            } else {
                plog->WRITE_LOG(LOG_WARNING, "Not enabling kernel: garbage collector not running\n");
            }
        }
        time_t last_report = time(NULL);
        while (!exiting.load()) {
            sleep(1);
            time_t now = time(NULL);
            if (difftime(now, last_report) >= 60) { // print stats every minute
                plog->WRITE_LOG(LOG_INFO, "=== Automatic debug report ===\n");
                report_debug(&debug_fd);
                last_report = now;
            }
        }
    }
    else { // debug mode
        while (!exiting.load()) {
            if (ctrlc) { break; }

            printf("\n0) Exit\n1) Print saved user ip addresses\n2) Search for a user ip\n3) Print debug stats\n4) Reset debug stats\n5) Enable/disable kernel module\n6) Print GTPC stats\n7) Load inner maps\n8) Save user data to json (Ultra)\n9) Start garbage collector\nChoice: ");
            fflush(stdout);

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);

            int ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, NULL);
            if (ret < 0) {
                if (errno == EINTR) {
                    break;
                }
                printf("Select\n");
                break;
            }

            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                if (scanf("%d", &ans) != 1) {
                    printf("Invalid input\n");
                    while (getchar() != '\n')
                        ; // stdin flush
                    continue;
                }

                switch (ans) {
                case 0:
                    exiting.store(true);
                    break;
                case 1:
                    ret = test_lpmtrie_print(&mapid_fd, &outer_fd);
                    break;
                case 2:
                    ret = test_query(&outer_fd, &mapid_fd);
                    break;
                case 3:
                    ret = report_debug(&debug_fd);
                    break;
                case 4:
                    ret = reset_debug(&debug_fd);
                    break;
                case 5:
                    if (gc_started) {
                        ret = enable_kernel(&debug_fd);
                    } else {
                        printf("Cannot enable/disable kernel: garbage collector not running\n");
                    }
                    break;
                case 6:
                    report_gtpc(gtpc_fd);
                    break;
                case 7:
                    populate_inner_factory(outer_fd, mapid_fd, rev_fd);
                    break;
                case 8:
                    main_stat_dispatcher(mapid_fd, outer_fd);
                    break;
                case 9:
                    if (gc_started == 0) {
                        start_mapid_gc(rev_fd, mapid_fd, outer_fd, freelist_fd);
                        gc_started = 1;
                    }
                    else {
                        printf("Garbage collector already started\n");
                    }
                    break;
                default:
                    printf("Select from the menu\n");
                    break;
                }
            }
            cntsec++;
            sleep(1);
        }
    }

    /* Cleaning up at end of program */
    stop_mapid_gc();
    if (mapid_fd >= 0) { close(mapid_fd); }
    if (outer_fd >= 0) { close(outer_fd); }
    if (freelist_fd >= 0) { close(freelist_fd); }
    if (rev_fd >= 0) { close(rev_fd); }
    if (node_fd >= 0) { close(node_fd); }
    if (debug_fd >= 0) { close(debug_fd); }
    if (gtpc_fd >= 0) { close(gtpc_fd); }
    delete (plog);
    thr_tctap.join();
    return 0;
}