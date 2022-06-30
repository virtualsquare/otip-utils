#ifndef OTIP_RPROXY_H
#define OTIP_RPROXY_H
#include <netinet/in.h>

struct ioth;
struct usagecount;
struct proxy_item {
  in_port_t extport;
  struct sockaddr_in6 intsockaddr;
};

struct connarg {
	struct ioth *extstack;
	struct ioth *intstack;
	struct usagecount *extstack_usage;
	struct proxy_item *item;
	union {
		int size;
		int fd;
	};
};

extern int conf_otip_period;
extern int conf_otip_lifetime;
extern int conf_otip_preactive;
extern int conf_tcp_listen_backlog;
extern int conf_tcp_timeout;
extern int conf_udp_timeout;

void extstack_usageup(struct connarg *connarg);
void extstack_usagedown(struct connarg *connarg);
void proxytcp(struct connarg *connarg);
void proxyudp(struct connarg *connarg);
#endif
