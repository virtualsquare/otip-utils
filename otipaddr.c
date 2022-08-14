/*
 *   otipaddr.c: print the current otip address
 *
 *   Copyright 2022 Renzo Davoli - Virtual Square Team
 *   University of Bologna - Italy
 *
 * otipaddr is free software; you can redistribute it and/or
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ioth.h>
#include <iothconf.h>
#include <iothdns.h>
#include <iothaddr.h>

#ifndef _GNU_SOURCE
static inline char *strchrnul(const char *s, int c) {
  while (*s && *s != c)
    s++;
  return (char *) s;
}
#endif

/* Main and command line args management */
void usage(char *progname, int isaddr)
{
  fprintf(stderr,"Usage: %s OPTIONS name %s\n"
      "\tOPTIONS:\n"
      "\t--base|--baseaddr|-b <IPv6 base address or base addr domain name>\n"
      "\t--dns|-D <dnsaddr>\n"
      "\t--dnsstack|-s <ioth_stack_conf>\n"
			"%s"
      "\t--help|-h\n",
			progname,
			isaddr ? "" : "password",
			isaddr ? "" : "\t--period|-T <otip_period>\n"
      );
  exit(1);
}

static char *short_options = "hdvf:p:e:i:n:b:P:u:T:D:";
static struct option long_options[] = {
  {"help", 0, 0, 'h'},
  {"base", 1, 0, 'b'},
  {"baseaddr", 1, 0, 'b'},
  {"dnsstack", 1, 0, 's'},
  {"dns", 1, 0, 'D'},
  {"period", 1, 0, 'T'},
  {0,0,0,0}
};

static char *arg_tags = "bsDT";
static union {
  struct {
    char *baseaddr;
    char *dnsstack;
    char *dns;
    char *period;
  };
  char *argv[sizeof(arg_tags)];
} args;

static inline int argindex(char tag) {
  return strchrnul(arg_tags, tag) - arg_tags;
}

int main(int argc, char *argv[]) {
	char *progname = basename(argv[0]);
	int isaddr = (strcmp(progname, "hashaddr") == 0);
	int option_index;
	char *name = NULL;
	char *passwd = NULL;
	struct in6_addr baseaddr;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case -1:
			case '?':
			case 'h': usage(progname, isaddr); break;
			default: {
								 int index = argindex(c);
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
							 break;
		}
	}
	if (isaddr ? argc != optind + 1 : argc != optind + 2)
		usage(progname, isaddr);
	name = argv[optind];
	if (argc > optind + 1)
		passwd = argv[optind + 1];
	if (args.baseaddr != NULL && strchr(args.baseaddr, ':') != NULL) {
		// numeric baseaddr
		if (inet_pton(AF_INET6, args.baseaddr, &baseaddr) != 1) {
			fprintf(stderr, "invalid base address: %s\n", args.baseaddr);
			exit(1);
		}
	} else {
		struct ioth *dnsstack = ioth_newstackc(args.dnsstack);
		struct iothdns *iothdns = iothdns_init_strcfg(dnsstack, args.dns);
		if (args.baseaddr == NULL) {
			char *name2base = strchr(name, '.');
			if (name2base == NULL) {
				fprintf(stderr, "missing domain name: %s\n", name);
				exit(1);
			}
			args.baseaddr = name2base + 1;
		}
		if (iothdns_lookup_aaaa(iothdns, args.baseaddr,  &baseaddr, 1) != 1) {
				fprintf(stderr, "domain name base address not found: %s\n", args.baseaddr);
				exit(1);
		}
	}
	uint32_t otiptime = 0;
	int otip_period = 32;
	if (args.period) otip_period = strtol(args.period, NULL, 0);
	if (passwd != NULL) otiptime = iothaddr_otiptime(otip_period, 0);
	iothaddr_hash(&baseaddr, name, passwd, otiptime);
	char abuf[INET6_ADDRSTRLEN];
	printf("%s\n", inet_ntop(AF_INET6, &baseaddr, abuf, INET6_ADDRSTRLEN));
	return 0;
}
