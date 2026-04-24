#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "sga_tctap.hpp"
#include <string>
#include <thread>
#include <signal.h>
#include "sga-common/sga_etc.h"
#include "sga-common/sga_socket.h"
#include "sga-common/sga_dbconn.h"
#include "sga-common/packet_stream.h"
#include <atomic>

using namespace std;

volatile int controlc = 0;

SGA_Logger *sgalogger = NULL; 
static PACKET_stream astream;
static int fd_data = -1;
static struct timespec ts_prev = {0,};

#define SQL_USER "sga"
#define SQL_PASS "sga"
#define SQL_DB "sga"

//#define IPPROTO_GRE 47
#define GREPROTO_ERSPAN1 0xBE88

static unsigned long long tsm64_prev = 0;
static unsigned long long ns64_prev = 0;
static unsigned long long incremental_gain = 1;
static unsigned long long ts_ntp = 0;
static unsigned long long ts_ntp_prev = 0;
static unsigned long long total_sleep_prev = 18446744073709551615ULL;
static char debug_mode = -1;

static int handle_ring_event(void *private_data, void *data, size_t length)
{
	struct xdp_ctx  *ctx = (struct xdp_ctx *)private_data;
	pkt_trace_data *pdata = (pkt_trace_data *)data;
	struct timespec ts, ts_mono, ts_boot;
	unsigned long long tsm64;
	unsigned long long delta_sleep;
	unsigned long long total_sleep;

	if (pdata->meta.cap_len + sizeof(pkt_trace_metadata) > length) // error....
	{
		sgalogger->WRITE_LOG(LOG_ERR, "Error: ring event too short: %d %d\n", length, pdata->meta.cap_len);
		return 0;
	}
	if (pdata->meta.cap_len > MAX_CAPLEN)
	{
		sgalogger->WRITE_LOG(LOG_ERR, "Error: ring event too long: %d %d\n", pdata->meta.cap_len, pdata->meta.pkt_len);
		return 0;
	}

//		offset = Cut_ERSPAN1(e->packet, e->metadata.cap_len);
		clock_gettime(CLOCK_REALTIME, &ts);
		clock_gettime(CLOCK_MONOTONIC, &ts_mono);
		clock_gettime(CLOCK_BOOTTIME, &ts_boot);
		
		total_sleep = 1000000000L + ts_boot.tv_sec*1000000000L + ts_boot.tv_nsec - ts_mono.tv_sec*1000000000L - ts_mono.tv_nsec;
		
		//Correction for interpacket sleep
		if ( 360000000000LL < total_sleep){
			if ((total_sleep > total_sleep_prev) && ((total_sleep - total_sleep_prev) > 100000)){
				delta_sleep = total_sleep - total_sleep_prev;
				if(debug_mode == 1)
					sgalogger->WRITE_LOG(LOG_INFO, "Suspend detected: %llu ns\n",delta_sleep);
			}
			else //For startup
				delta_sleep = 0;
		}
		else
			delta_sleep = 0;

	
		total_sleep_prev = total_sleep;
		
		if  ((ts_mono.tv_sec*1000000000L + ts_mono.tv_nsec) > pdata->meta.ts)
			tsm64 = ts_mono.tv_sec*1000000000L + ts_mono.tv_nsec - pdata->meta.ts;
		else
			tsm64 = 0;
		
		tsm64 = tsm64 + delta_sleep;
		
		// Direction static offset
		if (pdata->meta.dir == 0)
			tsm64 = tsm64 + 400L;

		ts_ntp = ts.tv_sec*1000000000L + ts.tv_nsec;

		if (ts_ntp_prev>ts_ntp)
			sgalogger->WRITE_LOG(LOG_INFO, "NTP back jump detected: %llu to %llu\n", ts_ntp, ts_ntp_prev);

		ts_ntp_prev = ts_ntp;

		if (tsm64 > tsm64_prev)
		{
			if(debug_mode == 1)
		    	sgalogger->WRITE_LOG(LOG_INFO, "Kernel 2 User space diff max: %llu ns\n",tsm64);
		    tsm64_prev = tsm64;
		}

		if ((ns64_prev > pdata->meta.ts) && ((ns64_prev - pdata->meta.ts) > 3000000L))
		{
			if(debug_mode == 1)
		    	sgalogger->WRITE_LOG(LOG_INFO, "Significant Kernel thread syncronization error: %llu ns\n",ns64_prev-pdata->meta.ts);
		}
		ns64_prev = pdata->meta.ts;
					
		if (!tscomp(&ts, &ts_prev))
		{
			ts = ts_prev;
			tsadd(&ts_prev, incremental_gain);
		}
		else
		{
			ts_prev = ts;
		}

		tssub(&ts, tsm64);

		if (pdata->meta.lost)
			ctx->lost_xdp += pdata->meta.lost;

		if (!astream.BUFFER_Write((unsigned char *)&pdata->data[0], &pdata->meta, &ts)) //(ts.tv_sec * 1000000000) + ts.tv_nsec))
		{
			ctx->lost_app++;
		}
		ctx->captured++;

return 0;
}

// no server function
/*bool sga_socket::Srv_Process()
{
	return true;
}*/

int sga_sender(tydb_config *pcfg)
{
	sga_socket asocket(sgalogger, 0);
	unsigned short port;
	char *pbuff = NULL;
	unsigned int size;
	std::string addr;
	unsigned int log_fail = 0;

	port = get_addrnport(pcfg->mon_addr, addr);

	while (!controlc)
	{
		if (pcfg->flag_addr)
		{
			astream.BUFFER_Halt();
			usleep(10000);
			pcfg->muti.lock();
			port = get_addrnport(pcfg->mon_addr, addr);
			pcfg->flag_addr = false;
			pcfg->muti.unlock();
			// upload monitor conn data to XDP
			int fd_data = pcfg->pxdp->open_object(VTAP_DATA);
			if (fd_data >= 0)
			{
				vtap_data adata;
				unsigned int key = DATA_MONITOR;
				adata.addr = inet_addr(addr.c_str());
				adata.port = htons(port);
				pcfg->pxdp->update_object(fd_data, &key, (unsigned long long *)&adata);
			}
			astream.BUFFER_SetType(pcfg->stream_type);
			astream.BUFFER_Open();
			if (pbuff)
			{
				free(pbuff);
				pbuff = NULL;
			}
		}

		if (!asocket.Open(addr.c_str(), "0.0.0.0", port)) // Open error!
		{
			sgalogger->WRITE_LOG(LOG_ERR, "Error on monitor socket open!\n");
			break;
		}
		if (!asocket.Connect())
		{
			sgalogger->WRITE_LOG(LOG_INFO, "Failed connecting to monitor: %s:%d...\n", addr.c_str(), port);
			log_fail = 0;
			asocket.Disconnect();
			usleep(5000000); // 5 sec wait
			continue;
		}
		else
		{
			if (!log_fail)
				sgalogger->WRITE_LOG(LOG_INFO, "Connected to monitor: %s:%d...\n", addr.c_str(), port);
		}

		while ((controlc==0) && asocket.GetState() == STATE_CONNECTED)
		{
			if (pcfg->flag_addr)
			{
				sgalogger->WRITE_LOG(LOG_INFO, "Config Changed: Disconnecting monitor!\n");
				break;
			}

			if (!pbuff)
				pbuff = astream.BUFFER_Read(size);

			if (pbuff)
			{
				if (asocket.Send((const unsigned char *)pbuff, size))
				{
					free(pbuff);
					pbuff = NULL;
					if (log_fail)
					{
						sgalogger->WRITE_LOG(LOG_INFO, "Re-Connected to monitor: %s:%d after %d attempt(s)\n", addr.c_str(), port, log_fail);
						log_fail = 0;
					}
				}
				else
				{
					if (!log_fail)
				    	sgalogger->WRITE_LOG(LOG_INFO, "Monitor socket write failed: %s!\n", strerror(errno));
					else
						usleep(5000000); // 5 sec wait
					log_fail++;
				}
			}
			else
				usleep(1000);
		}
		asocket.Disconnect();
		if (log_fail < 2)
			sgalogger->WRITE_LOG(LOG_INFO, "Disconnected from monitor!\n");
		else if (log_fail && (log_fail % 12) == 0)
		{
			sgalogger->WRITE_LOG(LOG_INFO, "Failed Re-Connection attempt(s): %d\n", log_fail);
		}
	}
	if (pbuff)
		free(pbuff);
	controlc = 1;
	return 0;
}

const char *RING_MAP = "sga_tc_ring_map";
const char *VTAP_DATA = "sga_tc_data";

int tctap_main(int argc, char** argv, std::atomic<bool>& exiting)
{
	controlc = exiting ? 1 : 0;
	int rc;
	char* hostid = "00:11:22:33:44:55";
	char* addr_db = "10.0.0.185";
	int bufsize = 100;
	unsigned int cntsec = 0;
	char promisc = -1;
	std::thread thr_sender;
	tydb_config *pcfg;
	if(set_memory_limit(USMEM_LIMIT) != 0){return 1;} 
	for (int i = 1; i < argc; i++)
	{
		switch (argv[i][1])
		{
		case 'd':
			i++;
			addr_db = argv[i];
			break;

		case 'b':
			i++;
			bufsize = atoi(argv[i]);
			break;

		case 'm':
			i++;
			debug_mode = (argv[i][0]>'0')?1:0;
			break;

		default:
			break;
		}
	}
	if (!hostid || !addr_db) // || !addr_to)
	{
		printf("Usage: %s <options>\n", argv[0]);
		printf(" -d <database_ip:port> : SQL DB for filters/statistics\n");
		printf(" -b <Buffer_size> : Monitor buffer size in MB\n");
		printf(" -m [0,1]: Set/unset debug mode\n");
		return 1;
	}

	// enable ctrl+c handler AFTER connection is establised
	//signal(SIGINT, CtrlCHandler);
	//signal(SIGTERM, CtrlCHandler);
	//signal(SIGPIPE, SIG_IGN);

	sgalogger = new SGA_Logger("./mapinmap", LOG_SYS, false);
	sgalogger->WRITE_LOG(LOG_INFO, "%s %s started.\n", "./mapinmap", VER);

	sga_dbconn adb_conn(sgalogger);

	unsigned short db_port = cget_addrnport(addr_db);

	if (!adb_conn.db_connect(addr_db, db_port, SQL_DB, SQL_USER, SQL_PASS, NULL)) 
	{
		sgalogger->WRITE_LOG(LOG_ERR, "DB connection is needed for startup!\n");
		delete(sgalogger);
		return 1;
	}

	sga_xdp xdp_dump(sgalogger, TC);

	// 1.1 load program settings from DB by MAC-Id
	pcfg = adb_conn.getdb_config();
	pcfg->pxdp = &xdp_dump;

	pcfg->host_id = hostid;
	sgalogger->WRITE_LOG(LOG_INFO, "HostId value: %s\n", pcfg->host_id.c_str());
	pcfg->pck_limit = 50000; // Default value if not specified
	pcfg->stream_type = TYPE_PACKETSTREAM; // if not specified

	if (!adb_conn.db_setup())
	{
		sgalogger->WRITE_LOG(LOG_ERR, "DB setup error!\n");
		delete(sgalogger);
		return 1;
	}

	if (!adb_conn.getconfig_by_hostid())
	{
		sgalogger->WRITE_LOG(LOG_ERR, "Unable to find program config in DB!\n");
		delete(sgalogger);
		return 1;
	}

	// 1.1.a open global data
	fd_data = pcfg->pxdp->open_object(VTAP_DATA);
	if (fd_data < 0)
	{
		sgalogger->WRITE_LOG(LOG_ERR, "Error opening eBPF Data!\n");
		delete(sgalogger);
		return 1;
	}
	sgalogger->WRITE_LOG(LOG_INFO, "eBPF Packet limit is: %d pck/s\n", (unsigned int)pcfg->pck_limit);
	reset_ebpfplimit(pcfg, fd_data);

	// 1.2 load redirection rules

	if (!adb_conn.load_ipsubnet(false))
	{
		sgalogger->WRITE_LOG(LOG_ERR, "Unable to load filter rules from DB!\n");
		delete(sgalogger);	
		return 1;
	}

	sgalogger->WRITE_LOG(LOG_INFO, "Monitor buffer size is: %d MB\n", bufsize);
	bufsize *= 1024*1024;
	// 1.3 init packet_stream
	astream.BUFFER_Setup(get_hostname(), /*pcfg->linkid,*/ pcfg->stream_type, bufsize);
	astream.BUFFER_Open();
	get_ifaces(&astream);

	// 2. start sender thread
	thr_sender = std::thread(sga_sender, pcfg);

	// 3. update redirect table
	int fd_ring = xdp_dump.open_object(RING_MAP);
	xdp_dump.setup_ringbuffer(fd_ring, handle_ring_event);
	reset_ebpfstats(pcfg, fd_data);

	sgalogger->WRITE_LOG(LOG_INFO, "Capture started, press CTRL+C to end...\n");

	while (!exiting)
	{
		cntsec++;
		// 3. list ip redirects by subnet
		if (cntsec == SLEEP_LIST)
		{
			adb_conn.list_ipsubnet();
			get_ebpfstats(pcfg, fd_data);
			cntsec = 0;
		}
		
		if ((cntsec%SLEEP_LOAD) == 0)
		{
			adb_conn.load_ipsubnet(true);
			adb_conn.getconfig_by_hostid();
		}
		sleep(1);
		reset_ebpfplimit(pcfg, fd_data);
	}
	controlc = 1;

	xdp_dump.end_ringbuffer();

	adb_conn.list_ipsubnet();
	get_ebpfstats(pcfg, fd_data);

	adb_conn.db_disconnect();
	astream.BUFFER_Close();
	thr_sender.join();
	delete(sgalogger);
	return 0;
}
