#ifndef INCLUDES_H
#define INCLUDES_H

#include <signal.h>
#include <stdint.h>

#define MAXFDS 100000
#define MAXTHREADS 10

struct Client {
	int sockfd;
	int connected;
	uint32_t ipaddr;
} client_t;

struct Client clients[MAXFDS];

#define DEBUG 1

#endif /* packet_h */
