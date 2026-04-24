#include <thread>
#include "../logger-common.h"

#define MAX_PCKSIZE 65536

typedef enum tyensock_mode
{
	TYPE_SRV,
	TYPE_CLI
} tyensock_mode;

typedef enum tyensock_state
{
	STATE_FAILED,
	STATE_CREATED,
	STATE_IDLE,
	STATE_CONNECTED
} tyensock_state;


typedef struct tycli_info
{
	unsigned int srv_addr;
	unsigned int cli_addr;
	unsigned short port;
	tyensock_mode mode;
	tyensock_state state;
	int socket;
} tycli_info;

typedef struct tysrv_info
{
	int socket;
	unsigned short port;
	tyensock_state state;
	std::thread st;
} tysrv_info;

class sga_socket
{
public:
	sga_socket(SGA_Logger *_plog, unsigned int _rec_waitms);
	~sga_socket();

	bool Open(const char *srv_addr, const char *cli_addr, unsigned short port);
	bool Open(const char *srv_addr, unsigned short port);
	bool Listen();
	bool Connect();
	bool Disconnect();
	bool Disconnect_srv();
	bool Nodelay(int socket, bool bset);
	bool KeepAlive(int socket, bool bset);

	bool Send(const unsigned char *pbuff, int size);
	bool Receive(unsigned char *pbuff, int &size);

	tyensock_state GetState() {return cli_info.state;}

	void Exit_Server() { Disconnect(); Disconnect_srv(); }

	bool Accept();
	virtual bool Srv_Process();
private:
	SGA_Logger *plog;
	unsigned int rec_waitms;
	tycli_info cli_info;
	tysrv_info srv_info;
	
};
