/*
 *   proxyudp.c: tcp/udp reverse proxy for otip: udp module
 *
 *   Copyright 2022 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 * otip_rproxy is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <ioth.h>
#include <utils.h>
#include <otip_rproxy.h>

#define UDPBUFSIZE (64 * 1024)
#define NEVENTS 5

#define CMSG_PKTINFO_SIZE CMSG_SPACE(sizeof(struct in6_pktinfo))

struct udpconn {
	int fd;
	int i;
	time_t expire;
	struct udpconn *next;
	struct sockaddr_in6 sender;
	size_t ctllen;
	uint8_t ctlbuf[];
};

static int on = 1;

static void *udplisten(void * arg) {
	struct connarg *args = arg;
	struct sockaddr_in6 extsock = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_any,
	};
	int usagecount = 0;
	time_t now = time(NULL);
	time_t last = now;
	time_t expire = now + conf_otip_lifetime;
	int epfd = epoll_create(1);
	int fd[args->size];
	struct udpconn *fdconn[args->size];
	for (int i = 0; i < args->size; i++) {
		fd[i] = ioth_msocket(args->extstack, AF_INET6, SOCK_DGRAM, 0);
		extsock.sin6_port = htons(args->item[i].extport);
		if (ioth_bind(fd[i], (struct sockaddr *)&extsock, sizeof(extsock)) < 0)
			printlog(LOG_ERR, "bind error udp port %d", args->item[i].extport);
		if (ioth_setsockopt(fd[i], IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
			printlog(LOG_ERR, "setsockopt error udp port %d", args->item[i].extport);
		epoll_ctl(epfd, EPOLL_CTL_ADD, fd[i],
				&(struct epoll_event) {.events = EPOLLIN, .data.ptr = &fd[i]});
		fdconn[i] = NULL;
		usagecount++;
	}
	while (usagecount > 0) {
		struct epoll_event events[NEVENTS];
		int nevents = epoll_wait(epfd, events, NEVENTS, 1000);
		now = time(NULL);
		for (int k = 0; k < nevents; k++) {
			struct epoll_event *event = &events[k];
			int *extfd = event->data.ptr;
			if (extfd >= fd && extfd < (fd + args->size)) {
				//packet from ext to int
				int i = extfd - fd;
				struct sockaddr_in6 sender;
				uint8_t buf[UDPBUFSIZE];
				uint8_t ctlbuf[CMSG_PKTINFO_SIZE];
				struct msghdr hdr = {
					.msg_name = &sender,
					.msg_namelen = sizeof(struct sockaddr_in6),
					.msg_iov = & (struct iovec) {.iov_base = buf, .iov_len = UDPBUFSIZE},
					.msg_iovlen = 1,
					.msg_control = ctlbuf,
					.msg_controllen = sizeof(ctlbuf)
				};
				int n = recvmsg(fd[i], &hdr, 0);
				if (n > 0) {
					struct udpconn *conn;
					for (conn = fdconn[i]; conn != NULL; conn = conn->next) {
						if (conn->sender.sin6_port == sender.sin6_port &&
								memcmp(&conn->sender.sin6_addr, &sender.sin6_addr, sizeof(struct in6_addr)) == 0 &&
								hdr.msg_controllen == conn->ctllen &&
								memcmp(conn->ctlbuf, ctlbuf, conn->ctllen) == 0) {
							break;
						}
					}
					if (conn == NULL && now <= expire) {
						conn = malloc(sizeof(*conn) + hdr.msg_controllen);
						if (conn != NULL) {
							conn->fd = ioth_msocket(args->intstack, AF_INET6, SOCK_DGRAM, 0);
							ioth_connect(conn->fd, (struct sockaddr *) &args->item[i].intsockaddr, sizeof(struct sockaddr_in6));
							int retval = epoll_ctl(epfd, EPOLL_CTL_ADD, conn->fd,
									&(struct epoll_event) {.events = EPOLLIN, .data.ptr = conn});
							if (retval < 0) {
								ioth_close(conn->fd);
								free(conn);
							} else {
								conn->i = i;
								conn->sender = sender;
								conn->next = fdconn[i];
								conn->ctllen = hdr.msg_controllen;
								memcpy(conn->ctlbuf, ctlbuf, conn->ctllen);
								fdconn[i] = conn;
							}
						}
					}
					if (conn != NULL) {
						send(conn->fd, buf, n, 0);
						conn->expire = now + conf_udp_timeout;
					}
				}
			} else {
				//packet fron int to ext
				struct udpconn *conn = event->data.ptr;
				uint8_t buf[UDPBUFSIZE];
				ssize_t n = recv(conn->fd, buf, UDPBUFSIZE, 0);
				struct msghdr hdr = {
					.msg_name = &conn->sender,
					.msg_namelen = sizeof(struct sockaddr_in6),
					.msg_iov = & (struct iovec) {.iov_base = buf, .iov_len = n},
					.msg_iovlen = 1,
					.msg_control = conn->ctlbuf,
					.msg_controllen = conn->ctllen
				};
				sendmsg(fd[conn->i], &hdr, 0);
				conn->expire = now + conf_udp_timeout;
			}
		}
		if (now > last) {
			//printf("cleanudp\n");
			for (int i = 0; i < args->size; i++) {
				for (struct udpconn **scan = &fdconn[i]; *scan != NULL; ) {
					struct udpconn *conn = *scan;
					if (now > conn->expire) {
						ioth_close(conn->fd);
						epoll_ctl(epfd, conn->fd, EPOLL_CTL_DEL, NULL);
						*scan = conn->next;
						free(conn);
					} else
						scan = &(conn->next);
				}
				if (now > expire && fdconn[i] == NULL) {
					epoll_ctl(epfd, fd[i], EPOLL_CTL_DEL, NULL);
					ioth_close(fd[i]);
					usagecount--;
				}
			}
			last = now;
		}
	}
	extstack_usagedown(args);
	free(args);
	return NULL;
}

void proxyudp(struct connarg *connarg) {
	struct connarg *udpconn = malloc(sizeof(struct connarg));
	*udpconn = *connarg;
	pthread_t p;
	extstack_usageup(udpconn);
	if (pthread_create(&p, NULL, udplisten, (void *) udpconn) < 0)
		extstack_usagedown(udpconn);
	return;
}
