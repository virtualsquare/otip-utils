/*
 *   proxytcp.c: tcp/udp reverse proxy for otip: tcp module
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
#include <poll.h>
#include <time.h>
#include <pthread.h>

#include <ioth.h>
#include <utils.h>
#include <otip_rproxy.h>

#define TCPBUFSIZE (128 * 1024)

/* tcpconn manages a tcp connection. there is a tcpconn thread for each active TCP connection */
static void *tcpconn(void *arg) {
	struct connarg *args = arg;
	int infd = ioth_msocket(args->intstack, AF_INET6, SOCK_STREAM, 0);
	if (ioth_connect(infd, (struct sockaddr *)&args->item->intsockaddr, sizeof(struct sockaddr_in6)) >= 0) {
		struct pollfd pfd[] = {{args->fd, POLLIN, 0}, {infd, POLLIN, 0}};
    uint8_t buf[TCPBUFSIZE];
    for (;;) {
			int pout = poll(pfd, 2, conf_tcp_timeout * 1000);
      if (pout <= 0) break;
      if (pfd[0].revents & POLLIN) {
        ssize_t n = ioth_recv(args->fd, buf, TCPBUFSIZE, 0);
        if (n <= 0) break;
        ioth_send(infd, buf, n, 0);
      }
      if (pfd[1].revents & POLLIN) {
        ssize_t n = ioth_recv(infd, buf, TCPBUFSIZE, 0);
        if (n <= 0) break;
        ioth_send(args->fd, buf, n, 0);
      }
		}
	}
	ioth_close(infd);
	ioth_close(args->fd);
	extstack_usagedown(args);
	free(args);
	return NULL;
}

/* listen thread. It waits for TCP connects on all the proxy ports */
static void *tcplisten(void * arg) {
	struct connarg *args = arg;
	struct sockaddr_in6 extsock = {
		.sin6_family = AF_INET6,
		.sin6_addr = in6addr_any,
	};
	struct pollfd pfd[args->size];
	for (int i = 0; i < args->size; i++) {
		pfd[i].fd = ioth_msocket(args->extstack, AF_INET6, SOCK_STREAM, 0);
		extsock.sin6_port = htons(args->item[i].extport);
		if (ioth_bind(pfd[i].fd, (struct sockaddr *)&extsock, sizeof(extsock)) < 0)
			printlog(LOG_ERR, "bind error tcp port %d", args->item[i].extport);
		if (ioth_listen(pfd[i].fd, conf_tcp_listen_backlog) < 0)
			printlog(LOG_ERR, "listen error tcp port %d", args->item[i].extport);
		pfd[i].events = POLLIN;
		pfd[i].revents = 0;
	}
	int timeout = (conf_otip_lifetime + 1) * 1000;
	time_t expire = time(NULL) + conf_otip_lifetime;
	for (;;) {
		int pout = poll(pfd, args->size, timeout);
		if (pout <= 0) break;
		for (int i = 0; i < args->size; i++) {
			if (pfd[i].revents & POLLIN) {
				int afd = ioth_accept(pfd[i].fd, NULL, 0);
				struct connarg *tcpconnargs = malloc(sizeof(struct connarg));
				if (tcpconnargs) {
					*tcpconnargs = *args;
					tcpconnargs->item = &args->item[i];
					tcpconnargs->fd = afd;
					pthread_t p;
					extstack_usageup(args);
					if (pthread_create(&p, NULL, tcpconn, (void *) tcpconnargs) < 0)
						extstack_usagedown(args);
				}
			}
		}
		timeout = (expire - time(NULL) + 1) * 1000;
	}
	for (int i = 0; i < args->size; i++)
		ioth_close(pfd[i].fd);
	extstack_usagedown(args);
	free(args);
	return NULL;
}

void proxytcp(struct connarg *connarg) {
	struct connarg *tcpconn = malloc(sizeof(struct connarg));
	*tcpconn = *connarg;
	pthread_t p;
	extstack_usageup(tcpconn);
	if (pthread_create(&p, NULL, tcplisten, (void *) tcpconn) < 0)
		extstack_usagedown(tcpconn);
	return;
}
