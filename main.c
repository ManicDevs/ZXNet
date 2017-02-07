#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netdb.h>
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

static volatile int epollFD = -1;
static volatile int listenFD = -1;
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
	
	sigemptyset(&ss);
	
	sa.sa_handler = sigexit;
	sa.sa_mask = ss;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, 0);
	
	signal(SIGPIPE, SIG_IGN); // Ignore broken pipes from Kernel
	
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
					if(infd == -1)
					{
						if((errno == EAGAIN) || (errno == EWOULDBLOCK))
							break;
						else
						{
							perror("accept");
							break;
						}
					}
					
					err = getnameinfo(&in_addr, in_len, 
						hbuf, sizeof(hbuf), sbuf, sizeof(sbuf), 
						NI_NUMERICHOST | NI_NUMERICSERV);
					
					if(err == 0)
						util_msgc("Info", "Accepted client on fd#%d | "
							"(host=%s, port=%s)", infd, hbuf, sbuf);
					
					clients[infd].ipaddr = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;
					
					err = net_set_nonblocking(infd);
					if(err == -1)
					{
						close(infd);
						break;
					}
					
					memset(&event, 0, sizeof(event));
					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					
					err = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if(err == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}
					
					clients[infd].sockfd = infd;
					clients[infd].connected = 1;
					
					util_msgc("Info", "Pinging new client on fd#%d", infd);
					net_fdsend(infd, PING, "");
				} // While
				continue;
			}
			else
			{
				int done = 0, thefd = events[i].data.fd;
				
				struct Client *client = &(clients[thefd]);
				
				client->connected = 1;
				while(!exiting)
				{
					ssize_t buflen;
					char pktbuf[512];
					
					struct Packet pkt;
					
					memset(pktbuf, 0, sizeof(pktbuf));
					
					while(memset(pktbuf, 0, sizeof(pktbuf)) && 
						(buflen = recv(thefd, pktbuf, sizeof(pktbuf), 0)))
					{
						if(exiting)
							break;
						
						if(buflen != sizeof(struct Packet))
						{
							//done = 1;
							break;
						}
						
						memcpy(&pkt, pktbuf, buflen);
						
						// Packet received
						util_msgc("Info", "We've received a %s", 
							util_type2str(pkt.type));
						
						switch(pkt.type)
						{
							case PONG:
								util_msgc("Info", "Pong from fd#%d", thefd);
							break;
							
							case ERROR:
								util_msgc("Info", "Error from fd#%d", thefd);
								net_fdsend(thefd, ERROR, "ACK");
							break;
						}
					}
					
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
		net_fdbroadcast(-1, PING, "");
		util_sleep(30);
	}
	
	close(listenFD);
	
	return EXIT_SUCCESS;
}
