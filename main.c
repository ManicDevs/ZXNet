#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include "xhdrs/includes.h"
#include "xhdrs/net.h"
#include "xhdrs/packet.h"
#include "xhdrs/sha256.h"
#include "xhdrs/utils.h"

time_t proc_startup;
sig_atomic_t exiting = 0;

uint32_t table_key = 0xdeadbeef; // util_strxor; For packets only?

pthread_t epollEventThread[MAXTHREADS];

static int epollFD = -1;
static int listenFD = -1;
static char uniq_id[32] = "";

static void init_exit(void)
{
	int i;
	
	for(i = 0; i < MAXTHREADS; i++)
		pthread_join(epollEventThread[i], NULL);
	
	util_msgc("Info", "Process ran for %ld second(s).", 
		(time(NULL) - proc_startup));
	util_msgc("Info", "Exiting: now");
}

static void sigexit(int signo)
{
	exiting = 1;
	init_exit();
}

static void init_signals(void)
{
	struct sigaction sa;
	sigset_t ss;
	
	// Implement sigexit on Ctrl+C
	sigemptyset(&ss);
	sa.sa_handler = sigexit;
	sa.sa_mask = ss;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, 0);
	
	// Ignore broken pipes from Kernel
	sigemptyset(&ss);
	sa.sa_handler = SIG_IGN;
	sa.sa_mask = ss;
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, 0);
	
	util_msgc("Info", "Initiated Signals!");
}

static void init_uniq_id(void)
{
	int fd, rc, offset;
	char tmp_uniqid[21], final_uniqid[41];
	
	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
	{
		util_msgc("Error", "open(urandom)");
		init_exit();
		_exit(EXIT_FAILURE);
	}
	
	rc = read(fd, tmp_uniqid, 20);
	if(rc < 0)
	{
		util_msgc("Error", "read(urandom)");
		init_exit();
		_exit(EXIT_FAILURE);
	}
		
	close(fd);
	
	for(offset = 0; offset < 20; offset++)
	{
		sprintf((final_uniqid + (2 * offset)), 
			"%02x", tmp_uniqid[offset] & 0xff);
	}
	
	sprintf(uniq_id, "%s", final_uniqid);
	util_msgc("Info", "Your Machine ID is %s", uniq_id);
	
    {
        unsigned seed;
        read(fd, &seed, sizeof(seed));
        srandom(seed);
    }
}

void *epollEventLoop(void *_)
{
	int n, i, err;
	ssize_t buflen;
	char pktbuf[512];
	
	struct Packet pkt;
	struct epoll_event event;
	struct epoll_event *events;
	
	events = calloc(MAXFDS, sizeof event);
	while(!exiting)
	{		
		n = epoll_wait(epollFD, events, MAXFDS, 0);
		for(i = 0; i < n; i++)
		{
			if((events[i].events & EPOLLERR) || 
				(events[i].events & EPOLLHUP) || 
				(!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].ipaddr = 0;
				clients[events[i].data.fd].connected = 0;
				close(events[i].data.fd);
				continue;
			}
			else if(listenFD == events[i].data.fd)
			{
				while(!exiting)
				{
					int /*ipIdx,*/ infd = -1;//, dupe = 0;
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
					
					struct sockaddr in_addr;
					socklen_t in_len = sizeof(in_addr);
					
					infd = accept(listenFD, &in_addr, &in_len);
					if(infd < 0)
					{
						if((errno == EAGAIN) || (errno == EWOULDBLOCK))
							break;
						else
						{
							util_msgc("Error", "Failed on Accept!");
							break;
						}
					}
					
					err = getnameinfo(&in_addr, in_len, 
						hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
						NI_NUMERICHOST | NI_NUMERICSERV);
					
					if(err != 0)
					{
						close(infd);
						break;
					}
					
					net_fdsend(infd, PING, "");
					
					memset(pktbuf, 0, sizeof(pktbuf));
					buflen = read(infd, pktbuf, sizeof(pktbuf));
					
					if(buflen != sizeof(struct Packet))
					{
						close(infd);
						break;
					}
					
					err = net_set_nonblocking(infd);
					if(err < 0)
					{
						close(infd);
						break;
					}
					
					memset(&event, 0, sizeof(event));
					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					
					err = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if(err < 0)
					{
						close(infd);
						break;
					}
					
					util_msgc("Info", "Adding "
						"(host=%s, fd#%d)", hbuf, infd);
					
					clients[infd].ipaddr = ((struct sockaddr_in*)&in_addr)->
						sin_addr.s_addr;
					clients[infd].connected = 1;
					
					//net_fdsend(infd, PING, "");
				} // While
				continue;
			}
			else
			{
				int done = 0, thefd = events[i].data.fd;
				
				struct in_addr ip4;
				struct Client *client = &(clients[thefd]);
				
				client->connected = 1;
				while(!exiting)
				{
					//memset(pktbuf, 0, sizeof(pktbuf));
					
					while(memset(pktbuf, 0, sizeof(pktbuf)) && 
						(buflen = recv(thefd, pktbuf, sizeof(pktbuf), 0)))
					{
						if(exiting)
							break;
						
						if(buflen != sizeof(struct Packet))
							break;
						
						memcpy(&pkt, pktbuf, buflen);
						
						util_strxor(pkt.msg.payload, pkt.msg.payload, 
							pkt.msg.length);
						
						ip4.s_addr = client->ipaddr;
						
						// Packet received
						util_msgc("Info", "Received a %s (host=%s, fd#%d)", 
							util_type2str(pkt.type), inet_ntoa(ip4), thefd);
						
						switch(pkt.type)
						{
							case PONG:
								util_msgc("Info", "Pong from fd#%d", thefd);
							break;
							
							case MESSAGE:
								util_msgc("Info", "Message from fd#%d", thefd);
								util_msgc("Message", "Payload: %s", pkt.msg.payload);
							break;
						} // Switch
					} // While
					
					if(buflen == -1)
					{
						if(errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
				} // While
				
				if(done)
				{
					client->ipaddr = 0;
					client->connected = 0;
					close(thefd);
				}
			} // If/Else if/Else
		} // For
		sleep(1);
	} // While
	
	free(events);
	
	return 0;
}
 
int main(int argc, char *argv[])
{
	int err, i;
	
	struct epoll_event event;
	
	proc_startup = time(NULL);
	
	init_signals();
	
	if(argc != 2)
	{
		util_msgc("Info", "Usage: %s [port]", argv[0]);
		init_exit();
		return EXIT_FAILURE;
	}
	
	if(atoi(argv[1]) < 1 || atoi(argv[1]) > 65535)
	{
		util_msgc("Error", "Failed to set out of bounds port number!");
		util_msgc("Error", "~ Port number must be between 1 to 65535");
		init_exit();
		return EXIT_FAILURE;
	}
	
	init_uniq_id();
	
	listenFD = net_bind(argv[1], IPPROTO_TCP);
	if(listenFD < 0)
	{
		util_msgc("Error", "Failed on Net_bind!");
		init_exit();
		return EXIT_FAILURE;
	}
	
	err = net_set_nonblocking(listenFD);
	if(err < 0)
	{
		util_msgc("Error", "Failed on Net_set_nonblocking!");
		init_exit();
		return EXIT_FAILURE;
	}
	
	err = listen(listenFD, SOMAXCONN);
	if(err < 0)
	{
		util_msgc("Error", "Failed on Listen!");
		init_exit();
		return EXIT_FAILURE;
	}
	
	epollFD = epoll_create1(0);
	if(epollFD < 0)
	{
		util_msgc("Error", "Failed on Epoll_create1!");
		init_exit();
		return EXIT_FAILURE;
	}
	
	memset(&event, 0, sizeof(event));
	event.data.fd = listenFD;
	event.events = EPOLLIN | EPOLLET;
	
	err = epoll_ctl(epollFD, EPOLL_CTL_ADD, listenFD, &event);
	if(err < 0)
	{
		util_msgc("Error", "Failed on Epoll_ctl!");
		init_exit();
		return EXIT_FAILURE;
	}
	
	for(i = 0; i < MAXTHREADS; i++)
		pthread_create(&epollEventThread[i], NULL, &epollEventLoop, NULL);
	
	while(!exiting)
	{
		net_fdbroadcast(listenFD, PING, "");
		util_sleep(10);
	}
	
	close(listenFD);
	
	return EXIT_SUCCESS;
}
