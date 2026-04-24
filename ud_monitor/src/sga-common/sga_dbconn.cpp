#include "sga_dbconn.h"
#include <string>
#include <net/if.h>
#include <arpa/inet.h>
#include <mutex>
#include <fstream>

using namespace std;

bool sga_dbconn::db_connect(const char *address, const unsigned short port, const char *dbname, const char *dbuser, const char *dbpass, const char *dbopts)
{
	return adb.open(address, port, dbname, dbuser, dbpass, dbopts);
}
bool sga_dbconn::db_disconnect()
{
	return adb.close();
}

bool sga_dbconn::db_setup()
{
	db_config.ts_db_changed = 0;
	return true; 	
}

bool sga_dbconn::getconfig_by_hostid()
{
	string temps;

	temps = "SELECT Changed,Monitor,PacketLimit,StreamType,`Group` FROM Config WHERE Hostid=\"" + db_config.host_id + "\"";

	int res = adb.query(temps.c_str());
	if (res < 0) return false;
	if (res == 0) // not matched
	{
		adb.freerows();
		return false;
	}

	if (!adb.getnextrow()) 
	{
		adb.freerows();		
		return false;
	}

	db_config.muti.lock();
	for (int i=0;i<6;i++)
	{
		char *value = adb.getvalue(i);
		switch (i)
		{
			case 0:
			{
				unsigned int ts_cfg = atoi(value);
				if (ts_cfg != db_config.ts_db_changed) // changed!
				{
					db_config.ts_db_changed = ts_cfg;
				}
				else
				{
					db_config.muti.unlock();
					adb.freerows();
					return false;
				}
			}
			break;

			case 1:
				db_config.mon_addr = value;
				db_config.flag_addr = true;
			break;
/*			case 2:
				db_config.linkid = *(unsigned int *)value;
				db_config.flag_linkid = true;				
			break;*/
			case 2:
				db_config.pck_limit = atoi(value);
			break;
			case 3:
				db_config.stream_type = atoi(value);
				db_config.flag_addr = true;				
			break;
			case 4:
				db_config.group = value;
			break;
		}
	}
	plog->WRITE_LOG(LOG_INFO, "DB: Configuration (re)loaded for: %s, from: %s\n", db_config.host_id.c_str(), plog->GetDate_toStr(db_config.ts_db_changed));
	db_config.muti.unlock();
	adb.freerows();

return true;
}

bool sga_dbconn::delete_subnets()
{
	db_config.pxdp->clear_object(fd_ip4);
	db_config.pxdp->clear_object(fd_ip6);

	return true;
}

bool sga_dbconn::delete_arules()
{
	db_config.pxdp->clear_object(fd_arules);

	return true;
}

const char *IP4_TABLE = {"sga_tc_lip4"};
const char *IP6_TABLE = {"sga_tc_lip6"};
const char *RULE_TABLE = {"sga_tc_lrule"};

#include <map>
#include <vector>
#include <bpf/libbpf.h>
#include "../common.h"

bool sga_dbconn::save_nodes_to_bpf(int node_fd) {
    struct {
        std::string type;
        std::string query;
        int node_value;
    } queries[] = {
        { "UPF", "SELECT IP, Prefix FROM Alias_IPs WHERE AliasID LIKE '%UPF%'", 4 },
        { "eNodeB", "SELECT IP, Prefix FROM Alias_IPs WHERE AliasID LIKE '%eNodeB%'", 1 },
        { "gNodeB", "SELECT IP, Prefix FROM Alias_IPs WHERE AliasID LIKE '%gNodeB%'", 2 },
        { "MME gn", "SELECT IP, Prefix FROM Alias_IPs WHERE AliasID LIKE '%MME gn%'", 7 }
    };

    for (const auto& q : queries) {
        int res = adb.query(q.query.c_str());
        if (res < 0) {
            plog->WRITE_LOG(LOG_ERR, "Failed to query nodes for %s\n", q.type.c_str());
            continue;
        }

        while (adb.getnextrow()) {
            std::string ip_str = adb.getvalue(0);
            unsigned int prefixlen = atoi(adb.getvalue(1));

            struct in_addr ip_addr;
            if (inet_pton(AF_INET, ip_str.c_str(), &ip_addr) != 1) {
                plog->WRITE_LOG(LOG_ERR, "Skipping non-IPv4 address: %s\n", ip_str.c_str());
                continue;
            }

            unsigned int ip_hex = ip_addr.s_addr;
            ipv4_lpm_key ip_key = {prefixlen, ip_hex};

            int ret = bpf_map_update_elem(node_fd, &ip_key, &q.node_value, BPF_ANY);
            if (ret != 0) {
                plog->WRITE_LOG(LOG_ERR, "Failed to update BPF map for %s, IP: %s\n", q.type.c_str(), ip_str.c_str());
            }
        }
        adb.freerows();
    }

    plog->WRITE_LOG(LOG_INFO, "Successfully updated eBPF map with nodes\n");
    return true;
}

bool sga_dbconn::load_ipsubnet(bool breload)
{
	struct CIDR4 afilter4;
	struct CIDR6 afilter6;
	struct AID arule;
	struct AID_wcntr brule;
	unsigned long *plen;
	unsigned int ip_cnt;
	unsigned int num_fields;
	unsigned int num_all, num_group;
	string temps;
	unsigned int temp;
	unsigned int type;

		if (!breload)
		{
			fd_ip4 = db_config.pxdp->open_object(IP4_TABLE);

			fd_ip6 = db_config.pxdp->open_object(IP6_TABLE);

			fd_arules = db_config.pxdp->open_object(RULE_TABLE);

			if (fd_ip4 < 0 || fd_ip6 < 0 || fd_arules < 0)
			{
				plog->WRITE_LOG(LOG_ERR, "DB: Error opening BPF objects!\n");
				return false;
			}
		}

		temps = "SELECT Value FROM capture_control WHERE Name=\"Filters_Changed\"";

		int res = adb.query(temps.c_str());
		if (res < 0) return false;
		if (res == 0) // not matched
		{
			adb.freerows();
			return true;
		}

		plen = adb.getnextrow();
		if (plen)
		{
			unsigned int cftable_changed = atoi(adb.getvalue(0));
			adb.freerows();
			if (cftable_changed == cftable_lastchanged) 
				return true;
			cftable_lastchanged = cftable_changed;
			plog->WRITE_LOG(LOG_INFO, "DB: Loading filters from: %s\n", plog->GetDate_toStr(cftable_lastchanged));
		}
		else
		{
			adb.freerows();
			return false;
		}

	// 1. Fill Alias IP rules
		temps = "SELECT Id,Type,IP,Prefix,Port FROM " + string(FILTER_TABLES[0]);

		ip_cnt = adb.query(temps.c_str());

		if (ip_cnt < 0) return false;

		delete_subnets();

		num_fields = adb.getfields();

		for (int j=0;j<ip_cnt;j++)
		{
			plen = adb.getnextrow();
			if (!plen) break;
			for (int i=0;i<num_fields;i++)
			{
				switch (i)
				{
					case 0: // Index = Alias Id!
						brule.val1 = atoi(adb.getvalue(i));
						brule.val2 = 0;
						brule.cntr = 0;
					break;

					case 1: // IP-Type (0=IPv4, 1=IPv6)
						type = atoi(adb.getvalue(i));
					break;

					case 2: // IP
						if (!type)
							inet_pton(AF_INET, (const char *)adb.getvalue(i), &afilter4.ip);
						else
							inet_pton(AF_INET6, (const char *)adb.getvalue(i), &afilter6.ip);
					break;

					case 3: // IPpfx
						temp = atoi(adb.getvalue(i));
						if (!temp)
						{
							if (!type)
								afilter4.cidr = 32 + 16;
							else
								afilter6.cidr = 128 + 16;
						}
						else
						{
							if (!type)
								afilter4.cidr = temp + 16;
							else
								afilter6.cidr = temp + 16;
						}
					break;

					case 4: // PORT
						if (!type)
							afilter4.port = ntohs(atoi(adb.getvalue(i)));
						else
							afilter6.port = ntohs(atoi(adb.getvalue(i)));
					break;

					default:
					break;
				}
			}
			if (!type)
			{
				db_config.pxdp->update_object(fd_ip4, (void *)&afilter4, (void *)&brule);
			}
			else
			{
				db_config.pxdp->update_object(fd_ip6, (void *)&afilter6, (void *)&brule);
			}

		}
		adb.freerows();

	// 2. Fill Alias lookup rules
	/*
		SELECT a1.Id as 'SrcID',a2.Id as 'DstID', r.LinkID 
		FROM Alias_Rules r
		JOIN Alias_IPs a1 on a1.AliasID = r.Src_AliasID
		JOIN Alias_IPs a2 on a2.AliasID = r.Dst_AliasID;
	*/
		temps = "SELECT a1.Id, a2.Id, r.LinkID, r.Group = \"All\", r.Src_AliasID, r.Dst_AliasID FROM " + 
		string(FILTER_TABLES[1]) + " r LEFT JOIN " +  string(FILTER_TABLES[0]) + 
		" a1 on a1.AliasID = r.Src_AliasID LEFT JOIN " + string(FILTER_TABLES[0]) + 
		" a2 on a2.AliasID = r.Dst_AliasID WHERE r.Group=\"All\"";

		if (db_config.group.length())
			temps += " OR r.Group=\"" + db_config.group + "\"";

		ip_cnt = adb.query(temps.c_str());

		if (ip_cnt < 0) return false;

		delete_arules();

		num_fields = adb.getfields();
		num_all = num_group = 0;

		for (int j=0;j<ip_cnt;j++)
		{
			plen = adb.getnextrow();
			if (!plen) break;
			bool bnExists = false;
			if (!adb.getvalue(0))
			{
				plog->WRITE_LOG(LOG_ERR, "DB: Src Alias ID does not exist: %s in %d\n", adb.getvalue(4), j);
				bnExists = true;
			}
			if (!adb.getvalue(1))
			{
				plog->WRITE_LOG(LOG_ERR, "DB: Dst Alias ID does not exist: %s in %d\n", adb.getvalue(5), j);
				bnExists = true;
			}
			if (bnExists) continue;
			for (int i=0;i<num_fields;i++)
			{
				switch (i)
				{
					case 0: // SrcId
						arule.val1 = atoi(adb.getvalue(i));
					break;
					case 1: // DstId
						arule.val2 = atoi(adb.getvalue(i));
					break;
					case 2: // LinkId
						brule.val1 = *(unsigned int *)adb.getvalue(i);
						brule.val2 = 0;
						brule.cntr = 0;
					break;

					case 3: // 1 = All group
						if (atoi(adb.getvalue(i)) == 1)
							num_all++;
						else
							num_group++;
					break;
					default: // 4,5
					break;
				}
			}
			db_config.pxdp->update_object(fd_arules, (void *)&arule, (void *)&brule);
		}
		plog->WRITE_LOG(LOG_INFO, "DB: Rules loaded from All: %d, Group: %d\n", num_all, num_group);
		adb.freerows();

	return true;
}

bool sga_dbconn::list_ipsubnet()
{
struct AID arule;
struct AID_wcntr brule;
struct AID *prule = NULL;

//	if (fd_arules < 0)
//		return false;

	time_t tnow = time(NULL);

	std::string atemps = "INSERT INTO Stats VALUES (NULL,";

	while (db_config.pxdp->walk_object(fd_arules, prule, &arule))
	{
		db_config.pxdp->lookup_object(fd_arules, &arule, (void *)&brule);
		if (brule.cntr)
		{
			std::string temps = atemps;
			temps += std::to_string(tnow) + ",\"" + db_config.host_id + "\",";
			temps += "(SELECT AliasID FROM " + string(FILTER_TABLES[0]) + " WHERE Id=" + std::to_string(arule.val1) + 
			"),(SELECT AliasID FROM " + string(FILTER_TABLES[0]) + " WHERE Id=" + std::to_string(arule.val2) + ")," + std::to_string(brule.cntr) + ")";

//			plog->WRITE_LOG(LOG_INFO, "Q: %s\n", temps.c_str());
			if (adb.query(temps.c_str()) < 0)
				return false;
			adb.freerows();
		}
		prule = &arule;
	}

return true;
}
