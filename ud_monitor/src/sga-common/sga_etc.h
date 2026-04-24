#pragma once

#include "sga_dbconn.h"
#include "packet_stream.h"

#define MAX_LINE_LENGTH 256

char tscomp(timespec *a, timespec *b);
void tssub(timespec *a, unsigned long long diff);
void tsadd(timespec *a, unsigned long long diff);

unsigned short get_addrnport(std::string &addr, std::string &mon_ip);
unsigned short cget_addrnport(char *addr);

bool reset_ebpfstats(tydb_config *pcfg, int fd_data);
bool get_ebpfstats(tydb_config *pcfg, int fd_data);
bool reset_ebpfplimit(tydb_config *pcfg, int fd_data);

char *get_hostname();
void get_ifaces(PACKET_stream *pstream);
bool get_hostid(char *iface, std::string &data);
int get_xdpmode(char mode);
int set_if_promiscuous_mode(char *ifname, bool enable);
void log_phy_stats(const char* interface_name, int debug_mode, int init);
void log_uptime(int init);
int set_memory_limit(size_t max_memory_bytes);
