#ifndef INCLUDES_H
#define INCLUDES_H

#include <signal.h>
#include <stdint.h>

#define DEBUG 1

#define MAXFDS 100000
#define MAXTHREADS 10

#define STDIN   0
#define STDOUT  1
#define STDERR  2

#define FALSE   0
#define TRUE    1
typedef char BOOL;

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

struct Client
{
	int connected;
	ipv4_t ipaddr;
	char version[32];
} client_t;

struct Client clients[MAXFDS];

#endif /* packet_h */
