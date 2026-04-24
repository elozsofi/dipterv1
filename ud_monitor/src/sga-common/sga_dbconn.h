#pragma once

#include <mutex>
#include "sga_sqldb.h"
#include "../sga_taps.h"

static const char *FILTER_TABLES[2] = {"Alias_IPs", "Alias_Rules"};

struct sga_xdp;

typedef struct tydb_config
{
//	std::atomic<bool> brestart;
	char flag_addr : 1; // addr changed
	char flag_linkid : 1; // linkid changed
	char flag_res : 6; // reserved	
	std::mutex muti;
	unsigned int ts_db_changed;
	std::string host_id; // MAC address...
	std::string mon_addr; // Monitor IP address:port
	std::string group; // Group name for rules
//	unsigned int linkid; // Link Id
	unsigned long long pck_limit;
	char stream_type;
	sga_xdp *pxdp; // XDP link
} tydb_config;

class sga_dbconn
{
public:
	sga_dbconn(SGA_Logger *_plog) { plog = _plog; adb.setlogger(_plog); cftable_lastchanged = 0; *(char *)&db_config = 0; }
	~sga_dbconn() {}

	bool db_connect(const char *address, const unsigned short port, const char *dbname, const char *dbuser, const char *dbpass, const char *dbopts);
	bool db_disconnect();
	bool db_setup();

	bool save_nodes_to_bpf(int node_fd);
	bool load_ipsubnet(bool breload);
	bool list_ipsubnet();

	bool getconfig_by_hostid();
	void setconfig_hostid(unsigned long long hostid) { db_config.host_id = hostid; }
	tydb_config *getdb_config() { return &db_config; }

protected:
 	SQLDB adb;

private:
	bool delete_subnets();
	bool delete_arules();

	int fd_ip4, fd_ip6, fd_arules;
	unsigned int cftable_lastchanged;
	SGA_Logger *plog;
	tydb_config db_config;

};