#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <poll.h>
#include "sga_socket.h"
#include <fcntl.h>

sga_socket::sga_socket(SGA_Logger *_plog, unsigned int _rec_waitms)
{
	cli_info.state = STATE_FAILED; 
	srv_info.state = STATE_FAILED; 
	plog = _plog; 
	rec_waitms = _rec_waitms;
}

sga_socket::~sga_socket() {
	
}

bool sga_socket::Nodelay(int socket, bool bset)
{
	int flag = bset?1:0;
	int result = setsockopt(socket,	IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	if (result < 0)
		return false;
	return true;
}

bool sga_socket::KeepAlive(int socket, bool bset)
{
	int flag = bset?1:0;
	int result = setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, (char *)&flag, sizeof(int));
	if (result < 0)
		return false;
	flag = 10;
	result = setsockopt(socket, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&flag, sizeof(int));
	if (result < 0)
		return false;
	flag = 2;
	result = setsockopt(socket, IPPROTO_TCP, TCP_KEEPCNT, (char *)&flag, sizeof(int));
	if (result < 0)
		return false;
	flag = 3;
	result = setsockopt(socket, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&flag, sizeof(int));
	if (result < 0)
		return false;

	return true;
}

// Client socket
bool sga_socket::Open(const char *srv_addr, const char *cli_addr, unsigned short port)
{
	int fd;
	if (!cli_addr)
	{
		cli_info.mode = TYPE_SRV;
	}
	else
	{
		cli_info.cli_addr = inet_addr(cli_addr);
		cli_info.mode = TYPE_CLI;
	}
	cli_info.srv_addr = inet_addr(srv_addr);
	cli_info.port = srv_info.port = htons(port);

	cli_info.socket = srv_info.socket = -1;

	// socket create and validation
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
	{
//		plogger->WRITE_LOG("(%d) Socket creation failed...\n", id);
		cli_info.state = STATE_FAILED;
		return false;
	}
	if (cli_info.mode == TYPE_SRV)
		srv_info.socket = fd;
	else
	{
		cli_info.socket = fd;
//		Nodelay(cli_info.socket, true);
		KeepAlive(cli_info.socket, true);
	}
	cli_info.state = STATE_CREATED;
	return true;
}
// Server socket
bool sga_socket::Open(const char *srv_addr, unsigned short port)
{
	return Open(srv_addr, NULL, port);
}

bool sga_socket::Connect()
{
	struct sockaddr_in servaddr;

	memset(&servaddr, 0, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = cli_info.srv_addr;
	servaddr.sin_port = cli_info.port;

	int synRetries = 2; // Send a total of 3 SYN packets => Timeout ~7s
	setsockopt(cli_info.socket, IPPROTO_TCP, TCP_SYNCNT, &synRetries, sizeof(synRetries));

	// connect the client socket to server socket
	if (connect(cli_info.socket, (const sockaddr *)&servaddr, sizeof(servaddr)) != 0)
	{
		//	    plogger->WRITE_LOG("Connection with the server failed: %d\n", bgpc.socket);
		cli_info.state = STATE_IDLE;
		return false;
	}
	cli_info.state = STATE_CONNECTED;
	return true;

}

bool sga_socket::Accept()
{
	struct sockaddr_in cli;
	socklen_t len = sizeof(cli);
	int socket;
	// Accept the data packet from client and verification
	while (srv_info.state != STATE_FAILED)
	{
		socket = accept(srv_info.socket, (sockaddr *)&cli, &len);
		if (socket == -1)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				usleep(10000);
				continue;
			}
			else
				break;
		}
		else
		plog->WRITE_LOG(LOG_INFO, "Server acccepted the client...\n");
		cli_info.state = STATE_CONNECTED;
		cli_info.socket = socket;

//		Nodelay(cli_info.socket, true);

		// Function for chatting between client and server
		Srv_Process();
		Disconnect();
		cli_info.state = STATE_IDLE;
	}
	plog->WRITE_LOG(LOG_INFO, "Accept ended\n");

	return true;
}

bool sga_socket::Listen()
{
	struct sockaddr_in servaddr;
	const int enable = 1;

	if (setsockopt(srv_info.socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
//		printf("setsockopt(SO_REUSEADDR) failed");
		Disconnect_srv();
		return false;
	}

	memset(&servaddr, 0, sizeof(servaddr));

	// assign IP, PORT
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = srv_info.port;

	// Binding newly created socket to given IP and verification
	if ((bind(srv_info.socket, (const sockaddr *)&servaddr, sizeof(servaddr))) != 0)
	{
//		printf("socket bind failed...\n");
		Disconnect_srv();
		return false;
	}
//	else
//		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(srv_info.socket, 5)) != 0)
	{
//		printf("Listen failed...\n");
		Disconnect_srv();
		return false;
	}
//	else
//		printf("BGP/Flowspec server %s listening..\n", VERSION);
	fcntl(srv_info.socket, F_SETFL, O_NONBLOCK);

	srv_info.state = STATE_CREATED;
	srv_info.st = std::thread(&sga_socket::Accept, this);
/*
	Disconnect();
	close(connfd);*/
	return true;
}

bool sga_socket::Srv_Process()
{
	return true;
}

bool sga_socket::Disconnect()
{
	if (cli_info.socket > 0)
	{
		close(cli_info.socket);
		cli_info.socket = -1;
		cli_info.state = STATE_FAILED;
		return true;
	}
	return false;
}

bool sga_socket::Disconnect_srv()
{
	if (srv_info.socket > 0)
	{
		srv_info.state = STATE_FAILED;
		srv_info.st.join();
		close(srv_info.socket);
		srv_info.socket = -1;
		return true;
	}
	return false;
}

bool sga_socket::Send(const unsigned char *pbuff, int size)
{
	if (write(cli_info.socket, pbuff, size) < 0)
	{
		Disconnect();
		return false;
	}
	return true;
}

bool sga_socket::Receive(unsigned char *pbuff, int &size)
{
	int ret;
	struct pollfd fds = { 0, };

	size = 0;

	if (cli_info.socket == -1) return false;

	fds.fd = cli_info.socket;
	fds.events = POLLIN;

	ret = poll(&fds, 1, rec_waitms);

	if (ret <= 0 || !(fds.revents & POLLIN)) return true;

	ret = read(cli_info.socket, pbuff, MAX_PCKSIZE);

	if (ret <= 0) // read error
	{
		Disconnect();
		return false;
	}
	size = ret;
	return true;
}