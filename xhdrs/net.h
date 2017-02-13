#ifndef NET_H
#define NET_H

int net_fdsend(int sockfd, int type, char *buffer);

int net_fdbroadcast(int sockfd, int type, char *buffer);

int net_set_nonblocking(int sockfd);

int net_bind(const char *addr, const char *portno, int protocol);

int net_connect(const char *addr, const char *portno, int protocol);

#endif /* net_h */
