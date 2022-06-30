/*
 * utils.c: util functions used by ioth_rproxy program
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
 */

#include <utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

static int logok=0;
static char *progname;

void startlog(char *prog, int use_syslog) {
	progname = prog;
	if (use_syslog) {
		openlog(progname, LOG_PID, 0);
		printlog(LOG_INFO, "%s started", progname);
		logok=1;
	}
}

void printlog(int priority, const char *format, ...)
{
	va_list arg;

	va_start (arg, format);

	if (logok)
		vsyslog(priority, format, arg);
	else {
		fprintf(stderr, "%s: ", progname);
		vfprintf(stderr, format, arg);
		fprintf(stderr, "\n");
	}
	va_end (arg);
}

void save_pidfile(char *pidfile, char *cwd)
{
	char pidfile_path[PATH_MAX];

	if(pidfile[0] != '/')
		snprintf(pidfile_path, PATH_MAX, "%s/%s", cwd, pidfile);
	else
		snprintf(pidfile_path, PATH_MAX, "%s", pidfile);

	int fd = open(pidfile_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	FILE *f;

	if(fd == -1) {
		printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
		exit(1);
	}

	if((f = fdopen(fd, "w")) == NULL) {
		printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));
		exit(1);
	}

	if(fprintf(f, "%ld\n", (long int)getpid()) <= 0) {
		printlog(LOG_ERR, "Error in writing pidfile");
		exit(1);
	}

	fclose(f);
}

void packetdump(FILE *f, void *arg,ssize_t len) {
	unsigned char *buf=arg;
	ssize_t lines=(len+15)>>4;
	ssize_t line;
	for (line=0; line<lines; line++) {
		ssize_t i;
		for (i=0; i<16; i++) {
			int n=line<<4 | i;
			if (n<len)
				fprintf(f, "%02x ",buf[n]);
			else
				fprintf(f, "   ");
		}
		fprintf(f, " | ");
		for (i=0; i<16; i++) {
			int n=line<<4 | i;
			if (n<len)
				fprintf(f, "%c", isprint(buf[n])?buf[n]:'.');
		}
		fprintf(f, "\n");
	}
}

void printin6addr(FILE *f, void *addr) {
	char addrbuf[INET6_ADDRSTRLEN];
	fprintf(f, "%s", inet_ntop(AF_INET6, addr, addrbuf, INET6_ADDRSTRLEN));
}
