#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "sga_etc.h"

using namespace std;

extern SGA_Logger *plog;

char tscomp(timespec *a, timespec *b) 
{
    if (a->tv_sec == b->tv_sec){
        return (a->tv_nsec > b->tv_nsec)?1:0;
	}
    else{
        return (a->tv_sec > b->tv_sec)?1:0;
	}
}

void tssub(timespec *a, unsigned long long diff)
{
	if (diff > 1000000000L){
		a->tv_sec -= diff/1000000000L;
	}
	a->tv_nsec -= diff%1000000000L;
}

void tsadd(timespec *a, unsigned long long diff)
{
	if (diff > 1000000000L){
		a->tv_sec += diff/1000000000L;
	}
	a->tv_nsec += diff%1000000000L;
}

unsigned short get_addrnport(string &addr, string &mon_ip)
{
	unsigned short port;
	int pos = addr.find(":");

	if (pos != std::string::npos){
		mon_ip = addr.substr(0,pos);
		port = atoi(addr.substr(pos+1).c_str());
	}
	else{
		mon_ip = addr;
		port = 3306;
	}

	return port;
}

unsigned short cget_addrnport(char *addr)
{
	char *pport = addr;
	unsigned short port;

	while (*pport && *pport != ':'){
		pport++;
	}
	if (*pport) {
		*pport = 0;
		port = atoi(pport + 1);
	}
	else {
		port = 3306;
	}
	return port;
}

bool reset_ebpfstats(tydb_config *pcfg, int fd_data)
{
	unsigned long long value = 0;

	unsigned int key = CNTR_PCK_ALL;
	pcfg->pxdp->update_object(fd_data, &key, &value);

	key = CNTR_PCK_EVENT;
	pcfg->pxdp->update_object(fd_data, &key, &value);

	return true;
}

bool get_ebpfstats(tydb_config *pcfg, int fd_data)
{
	unsigned long long value;
	xdp_ctx *pctx = pcfg->pxdp->get_context();

	unsigned int key = CNTR_PCK_ALL;
	pcfg->pxdp->lookup_object(fd_data, &key, &value);
	pctx->ebpf_packets = value;

	key = CNTR_PCK_EVENT;
	pcfg->pxdp->lookup_object(fd_data, &key, &value);
	pctx->ebpf_events = value;

	plog->WRITE_LOG(LOG_INFO, "[Kernelspace Stats] Total packets: %llu Filter match: %llu\n", pctx->ebpf_packets, pctx->ebpf_events);
	plog->WRITE_LOG(LOG_INFO, "[Userspace Stats] Received: %llu Lost in context switch: %llu Lost in monitor transport: %llu\n", pctx->captured, pctx->lost_xdp, pctx->lost_app);

	return true;
}

bool reset_ebpfplimit(tydb_config *pcfg, int fd_data)
{
	unsigned int ppck_limit = DATA_PCKLIMIT;
	return pcfg->pxdp->update_object(fd_data, &ppck_limit, (unsigned long long *)&pcfg->pck_limit);
}	

static char hostname[1024];
char *get_hostname()
{
	hostname[1023] = '\0';
	gethostname(hostname, 1023);
	return hostname;
}

void get_ifaces(PACKET_stream *pstream)
{
    struct if_nameindex *if_nidxs, *intf;
    if_nidxs = if_nameindex();
    if ( if_nidxs != NULL )
    {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
        {
        	pstream->Add_Iface(intf->if_name);
        }
        if_freenameindex(if_nidxs);
    }
}

bool get_hostid(char *iface, std::string &data)
{
	struct ifreq s;
	char tmpbuff[32];
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(s.ifr_name, iface);
	if (ioctl(fd, SIOCGIFHWADDR, &s) == 0) 
	{
		sprintf(tmpbuff, "%02x:%02x:%02x:%02x:%02x:%02x", 
		(unsigned char)s.ifr_hwaddr.sa_data[0], 
		(unsigned char)s.ifr_hwaddr.sa_data[1], 
		(unsigned char)s.ifr_hwaddr.sa_data[2], 
		(unsigned char)s.ifr_hwaddr.sa_data[3], 
		(unsigned char)s.ifr_hwaddr.sa_data[4], 
		(unsigned char)s.ifr_hwaddr.sa_data[5]);
		data = tmpbuff;
		close(fd);
		return true;
	}
	close(fd);	
	return false;
}

int get_xdpmode(char mode)
{
    switch(mode)
		{
		case 'n': // native
			return 1;
		break;
		case 's': // skb
		default:
			return 2;
		break;
		case 'h': // hw
			return 3;
		break;
		}
}

int set_if_promiscuous_mode(char *ifname, bool enable)
{
	int          fd;
	int          rc = 0;
	struct ifreq ifr;

	if (ifname == NULL)
		return -EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) 
	{
		plog->WRITE_LOG(LOG_ERR, "Failed getting promiscuous mode: %s\n", strerror(errno));
		rc = -errno;
		goto exit;
	}
	
	if (((ifr.ifr_flags & IFF_PROMISC) && enable) || (!(ifr.ifr_flags & IFF_PROMISC) && !enable)) 
	{
		plog->WRITE_LOG(LOG_INFO, "Promiscuous mode already %s!\n", enable ? "on" : "off");
		goto exit;
	}

	if (enable)
		ifr.ifr_flags |= IFF_PROMISC;
	else
		ifr.ifr_flags &= ~IFF_PROMISC;

	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) 
	{
		plog->WRITE_LOG(LOG_ERR, "Failed setting promiscuous mode %s: %s\n", enable ? "on" : "off", strerror(errno));
		rc = -errno;
		goto exit;
	}
	plog->WRITE_LOG(LOG_INFO, "Setting promiscous mode %s\n", enable ? "on" : "off");

exit:
	close(fd);
	return rc;
}

void log_phy_stats(const char* interface_name, int debug_mode, int init) {
    static unsigned long long phy_errors[10];
    char errors_path[4][MAX_LINE_LENGTH];
    FILE* statistics_file;
    char line[MAX_LINE_LENGTH];
    snprintf(errors_path[0], MAX_LINE_LENGTH*sizeof(char), "/sys/class/net/%s/statistics/rx_crc_errors", interface_name);
    snprintf(errors_path[1], MAX_LINE_LENGTH*sizeof(char), "/sys/class/net/%s/statistics/rx_frame_errors", interface_name);
    snprintf(errors_path[2], MAX_LINE_LENGTH*sizeof(char), "/sys/class/net/%s/statistics/rx_length_errors", interface_name);
    snprintf(errors_path[3], MAX_LINE_LENGTH*sizeof(char), "/sys/class/net/%s/statistics/rx_missed_errors", interface_name);

    unsigned int i;
    for(i=0;i<4;i++){
        statistics_file = fopen(errors_path[i], "r");

        if (statistics_file == NULL) {
            plog->WRITE_LOG(LOG_ERR, "Error opening sys/net file");
            return;
        }
        // Read the value from the statistics file
        if (fgets(line, sizeof(line), statistics_file) != NULL) {
            line[strcspn(line, "\n")] = '\0';
            phy_errors[i*2+init] = strtol(line, NULL, 10);
        } else {
            plog->WRITE_LOG(LOG_ERR, "Failed to read from sys/net API\n");
	    fclose(statistics_file);
            return;
        }

        // Close the file
        fclose(statistics_file);
    }
    if(init == 0){
        if(debug_mode == 0)
            plog->WRITE_LOG(LOG_INFO, "Total phy errors: %lld\n", (phy_errors[0] + phy_errors[2] + phy_errors[4] + phy_errors[6] - phy_errors[1] - phy_errors[3] - phy_errors[5] - phy_errors[7]));
        else
            plog->WRITE_LOG(LOG_INFO, "rx_crc_errors: %lld, rx_frame_errors: %lld, rx_length_errors: %lld, rx_missed_errors: %lld\n", (phy_errors[0]-phy_errors[1]), (phy_errors[2]-phy_errors[3]), (phy_errors[4]-phy_errors[5]), (phy_errors[6]-phy_errors[7]));
    }
    return;
}

void log_uptime(int init) {
	struct sysinfo info;
	static unsigned long long starttime = 0;
	unsigned long long uptime = 0;
    if (sysinfo(&info) != 0) {
        plog->WRITE_LOG(LOG_ERR, "Could not access sysinfo API");
        return;
    }
	if(init == 1){
    	starttime = info.uptime;
		return;
	}
	else
		uptime = info.uptime;
    
	uptime = uptime - starttime;
    
	unsigned int days = uptime / 86400;
    unsigned int hours = (uptime % 86400) / 3600;
    unsigned int minutes = (uptime % 3600) / 60;

    plog->WRITE_LOG(LOG_INFO, "Uptime: %ud,%uh,%um\n", days, hours, minutes);
    return;
}

int set_memory_limit(size_t max_memory_bytes){
    struct rlimit rl;
    rl.rlim_cur = max_memory_bytes;
    rl.rlim_max = max_memory_bytes;
    if (setrlimit(RLIMIT_AS, &rl) != 0) {
        plog->WRITE_LOG(LOG_ERR, "Userspace memory limit could not be set\n");
        return -1;
    }
    return 0;
}