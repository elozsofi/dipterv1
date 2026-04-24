#pragma once

#include "sga_taps.h"
#include "sga_dbconn.h"
#include <atomic>

#define VER "v0.5.2"

#define SLEEP_LIST 900 // list every 15 minutes
#define SLEEP_LOAD 60 // check 4 DB changes in every minute
#define USMEM_LIMIT 1024 * 1024 * 1024 // userspace memory allocation limit for tctap

static const char *PROG_FILE = "sga_dump_tc.o";
static const char *PROG_NAME = "sga_dump";
static const char *KERN_BTF_NAME = "kernel.btf";

/*
const char *IP4_TABLE = {"sga_tc_lip4"};
const char *IP6_TABLE = {"sga_tc_lip6"};
const char *RULE_TABLE = {"sga_tc_lrule"};
const char *PERF_MAP = "sga_tc_perf_map";
const char *RING_MAP = "sga_tc_ring_map";
const char *VTAP_DATA = "sga_tc_data";
*/

//void CtrlCHandler(int signum);
static int handle_ring_event(void *private_data, void *data, size_t length);
int sga_sender(tydb_config *pcfg);
int tctap_main(int argc, char** argv, std::atomic<bool>& exiting);