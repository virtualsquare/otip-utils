/*
 *   otip_rproxy.c: tcp/udp reverse proxy for otip
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
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <errno.h>

#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <strcase.h>
#include <stropt.h>
#include <iothconf.h>
#include <iothdns.h>
#include <iothaddr.h>
#include <otip_rproxy.h>
#include <utils.h>

static int verbose;
static char *cwd;
static pid_t mypid;
int conf_otip_period = 32;
int conf_otip_preactive = 8;
static int conf_otip_postactive = 8;
int conf_otip_lifetime;
int conf_tcp_listen_backlog = 5;
int conf_tcp_timeout = 120;
int conf_udp_timeout = 8;

#ifndef _GNU_SOURCE
static inline char *strchrnul(const char *s, int c) {
	while (*s && *s != c)
		s++;
	return (char *) s;
}
#endif

static void terminate(int signum) {
	pid_t pid = getpid();
	if (pid == mypid) {
		printlog(LOG_INFO, "(%d) leaving on signal %d", pid, signum);
	}
	exit(0);
}

static void setsignals(void) {
	struct sigaction action = {
		.sa_handler = terminate
	};
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
}

/* Main and command line args management */
void usage(char *progname)
{
	fprintf(stderr,"Usage: %s OPTIONS\n"
			"\tOPTIONS:\n"
			"\t--rcfile|-f <conffile>\n"
			"\t--daemon|-d\n"
			"\t--pidfile|-p <pidfile>\n"
			"\t--extstack|-e <ioth_extstack_conf>\n"
			"\t--intstack|-i <ioth_stack_conf>\n"
			"\t--name|-n <fully qualified name>\n"
			"\t--base|--baseaddr|-b <base address>\n"
			"\t--passwd|-P <password>\n"
			"\t--dns|-D <dnsaddr>\n"
			"\t--udp|-u <extport>,<intaddr>,<intport>\n"
			"\t--tcp|-t <extport>,<intaddr>,<intport>\n"
			"\t--verbose|-v\n"
			"\t--help|-h\n"
			"\n"
			"\t<ioth_extstack_conf> iothconf like syntax\n"
			"\tsupported tags: stack, vnl, iface\n",
			progname);
	exit(1);
}

static char *short_options = "hdvf:p:e:i:n:b:P:u:t:D:";
static struct option long_options[] = {
	{"help", 0, 0, 'h'},
	{"daemon", 0, 0, 'd'},
	{"verbose", 0, 0, 'v'},
	{"rcfile", 1, 0, 'f'},
	{"pidfile", 1, 0, 'p'},
	{"extstack", 1, 0, 'e'},
	{"intstack", 1, 0, 'i'},
	{"name", 1, 0, 'n'},
	{"base", 1, 0, 'b'},
	{"baseaddr", 1, 0, 'b'},
	{"passwd", 1, 0, 'P'},
	{"udp", 1, 0, 'u'},
	{"tcp", 1, 0, 't'},
	{"dns", 1, 0, 'D'},
	{"otip_period", 1, 0, '\200'},
	{"otip_postactive", 1, 0, '\201'},
	{"otip_preactive", 1, 0, '\202'},
	{"tcp_listen_backlog", 1, 0, '\210'},
	{"tcp_timeout", 1, 0, '\211'},
	{"udp_timeout", 1, 0, '\212'},
	{0,0,0,0}
};

static char *arg_tags = "dvpeinbPD\200\201\202\210\211\212";
static union {
	struct {
		char *daemon;
		char *verbose;
		char *pidfile;
		char *extstack;
		char *intstack;
		char *name;
		char *baseaddr;
		char *passwd;
		char *dns;
		char *otip_period;
		char *otip_preactive;
		char *otip_postactive;
		char *tcp_listen_backlog;
		char *tcp_timeout;
		char *udp_timeout;
	};
	char *argv[sizeof(arg_tags)];
} args;

static inline int argindex(char tag) {
	return strchrnul(arg_tags, tag) - arg_tags;
}

/* parse_rc_file: parse rc file */
typedef int extraparse(char *optname, char *value, void *arg);
int parse_rc_file(char *path, struct option *options, extraparse xp, void *xparg) {
	int retvalue = 0;
	FILE *f = fopen(path, "r");
	if (f == NULL) return -1;
	char *line = NULL;
	size_t len;
	for (int lineno = 1; getline(&line, &len, f) > 0; lineno++) { //foreach line
		char *scan = line;
		while (*scan && strchr("\t ", *scan)) scan++; //ship heading spaces
		if (strchr("#\n", *scan)) continue; // comments and empty lines
		int len = strlen(scan);
		char optname[len], value[len];
		// parse the line
		*value = 0;
		/* optname <- the first alphanumeric field (%[a-zA-Z0-9])
			 value <- the remaining of the line not including \n (%[^\n])
			 and discard the \n (%*c) */
		if (sscanf (line, "%[a-zA-Z0-9_] %[^\n]%*c", optname, value) > 0) {
			struct option *optscan;
			for (optscan = options; optscan->name; optscan++) // search tag
				if (strcmp(optscan->name, optname) == 0)
					break;
			int index; // index of short opt tag in arg_tags
			if (optscan->name == NULL ||
					arg_tags[index = strchrnul(arg_tags, optscan->val) - arg_tags] == '\0') {
				if (xp == NULL || xp(optname, value, xparg) < 0) {
					fprintf(stderr,"%s (line %d): parameter error %s: %s\n", path, lineno, optname, value);
					errno = EINVAL, retvalue |= -1;
				}
			} else if (args.argv[index] == NULL) // overwrite only if NULL
				args.argv[index] = *value ? strdup(value) : "";
		} else {
			fprintf(stderr,"%s (line %d): syntax error\n", path, lineno);
			errno = EINVAL, retvalue |= -1;
		}
	}
	fclose(f);
	if (line) free(line);
	return retvalue;
}

/* temporary storage for proxy items.
 * this structure is used during option parsing
 * intaddr can be a fully qualified host name, so it needs DNS access to compute
 * the actual address */
struct proxyarg {
	int type;
	in_port_t extport;
	char *intaddr_str;
	in_port_t intport;
};

static int addproxy(int type, char *value, FILE *f) {
	struct proxyarg arg = {.type = type, .intaddr_str = NULL};
	char intaddr_str[strlen(value) + 1];
	int n = sscanf(value, "%hu,%[^,],%hu\n", &arg.extport, intaddr_str, &arg.intport);
	if (n == 3 && arg.extport > 0 && arg.intport > 0) {
		arg.intaddr_str = strdup(intaddr_str);
		if (fwrite(&arg, sizeof(arg), 1, f) == 1)
			return 0;
	}
	return -1;
}

int proxyarg(char *optname, char *value, void *arg) {
	FILE *f = arg;
	if (strcmp(optname, "udp") == 0) {
		return addproxy('u', value, f);
	}
	if (strcmp(optname, "tcp") == 0) {
		return addproxy('t', value, f);
	}
	return -1;
}

/* convert struct proxyarg entries to struct proxy_item entries
 * and split tcp to udp requests */
struct proxy_item *proxyarg2proxy(int type, struct iothdns *intdns, struct proxyarg *arg, int *len) {
	int count = 0;
	for (int i = 0; arg[i].type != 0; i++)
		if (arg[i].type == type)
			count++;
	if (len)
		*len = count;
	struct proxy_item *proxy = calloc(count + 1, sizeof(*proxy));
	if (proxy) {
		int err = 0;
		for (int i = 0; arg->type != 0; arg++) {
			if (arg->type == type) {
				proxy[i].extport = arg->extport;
				proxy[i].intsockaddr.sin6_family = AF_INET6;
				proxy[i].intsockaddr.sin6_port = htons(arg->intport);
				if (iothdns_lookup_aaaa_compat(intdns, arg->intaddr_str,
							& proxy[i].intsockaddr.sin6_addr, 1) < 1) {
					fprintf(stderr, "Error configuring proxy %s\n", arg->intaddr_str);
					err = 1;
				}
				i++;
			}
		}
		if (err) {
			free(proxy);
			proxy = NULL;
		}
	}
	return proxy;
}

/* extstack definition uses a syntax similar to iothconf.
 * stack, vnl and iface have the same meaning as in iothconf */
struct extargs {
	char *stack;
	char *vnl;
	char *iface;
};

struct extargs *parse_extargs(char *input) {
	static struct extargs eargs;
	int tagc = stropt(input, NULL, NULL, NULL);
	if(tagc > 0) {
		char buf[strlen(input)+1];
		char *tags[tagc];
		char *args[tagc];
		stropt(input, tags, args, buf);
		for (int i=0; i < tagc - 1; i++) {
			switch(strcase(tags[i])) {
				case STRCASE(s,t,a,c,k): eargs.stack = strdup(args[i]); break;
				case STRCASE(v,n,l): eargs.vnl = strdup(args[i]); break;
				case STRCASE(i,f,a,c,e): eargs.iface = strdup(args[i]); break;
				default: fprintf(stderr, "extstack: unknown tag %s\n", tags[i]);
					return NULL;
			}
		}
		return &eargs;
	} else
		return NULL;
}

/* count the threads currently using the extstack.
 * close the stack when usagecount is 0 */
struct usagecount {
	_Atomic int count;
};

void extstack_usageup(struct connarg *conn) {
	struct usagecount *usage = conn->extstack_usage;
	if (verbose) printlog(LOG_INFO, "extstack_usageup %p", conn->extstack);
	usage->count++;
}

void extstack_usagedown(struct connarg *conn) {
	struct usagecount *usage = conn->extstack_usage;
	if (verbose) printlog(LOG_INFO, "extstack_usagedown %p", conn->extstack);
	int newcount = --usage->count;
	if (newcount == 0) {
		if (verbose) printlog(LOG_INFO, "close stack %p", conn->extstack);
		ioth_delstack(conn->extstack);
		free(usage);
	}
}

/* MAIN program */
int main(int argc, char *argv[])
{
	char *progname = basename(argv[0]);
	char *rcfile = NULL;
	int option_index;
	/* memory file for proxy items (struct proxyarg) */
	char *proxbuf = NULL;
	size_t proxlen = 0;
	FILE *prox = open_memstream(&proxbuf, &proxlen);
	/* parse command line options */
	int err = 0;
	while(1) {
		int c;
		if ((c = getopt_long (argc, argv, short_options,
						long_options, &option_index)) < 0)
			break;
		switch (c) {
			case 'f':
				rcfile = optarg;
				break;
			case -1:
			case '?':
			case 'h': usage(progname); break;
			case 'u': if (proxyarg("udp", optarg, prox) < 0)
									fprintf(stderr, "error in proxy udp config %s\n", optarg), err = 1;
								break;
			case 't': if (proxyarg("tcp", optarg, prox) < 0)
                  fprintf(stderr, "error in proxy tcp config %s\n", optarg), err = 1;
								break;
			default: {
								 int index = argindex(c);
								 if (args.argv[index] == NULL)
									 args.argv[index] = optarg ? optarg : "";
							 }
								break;
		}
	}
	if (argc == 1 || optind != argc || err)
		usage(progname);

	if (rcfile) {
		if (parse_rc_file(rcfile, long_options, proxyarg, prox) < 0) {
			fprintf(stderr, "configfile %s: %s\n", rcfile, strerror(errno));
			exit(1);
		}
	}

	fwrite(& (struct proxyarg) {.type = 0}, sizeof(struct proxyarg), 1, prox);
	fclose(prox);

	if (args.verbose) verbose = 1;

	if (args.extstack == NULL) {
		fprintf(stderr, "Error external stack configuration is required\n");
    exit(1);
  }

	struct extargs *extargs = parse_extargs(args.extstack);
	if (extargs == NULL) {
		fprintf(stderr, "Error configuring external stack %s\n", args.extstack);
    exit(1);
  }
	if (extargs->iface == NULL)
		extargs->iface = "vde0";

	struct ioth *intstack = ioth_newstackc(args.intstack);
	if (intstack == NULL) {
		fprintf(stderr, "Error configuring internal stack %s\n", args.intstack);
		exit(1);
	}

	struct iothdns *intdns = iothdns_init_strcfg(intstack, args.dns); // XXX
	if (intstack == NULL) {
		fprintf(stderr, "Error configuring internal dns %s\n", args.dns ? args.dns : "default");
		exit(1);
	}

	if (args.baseaddr == NULL) {
		fprintf(stderr, "Error: otip baseaddr is required\n");
		exit(1);
	}

	struct in6_addr baseaddr[1];
	if (iothdns_lookup_aaaa_compat(intdns, args.baseaddr, baseaddr, 1) < 1) {
		fprintf(stderr, "Error configuring baseaddr %s\n", args.baseaddr);
		exit(1);
	}

	/* set up the procy item tables for proxytcp and proxyudp */
	struct proxy_item *proxytcptab, *proxyudptab;
	int proxytcptablen, proxyudptablen;
	proxytcptab = proxyarg2proxy('t', intdns, (struct proxyarg *) proxbuf, &proxytcptablen);
	proxyudptab = proxyarg2proxy('u', intdns, (struct proxyarg *) proxbuf, &proxyudptablen);
	free(proxbuf);

	/* proxyarg2proxy returns NULL in case of error */
	if (proxytcptab == NULL || proxyudptab == NULL)
		exit(1);

	startlog(progname, args.daemon != NULL);
	mypid = getpid();
	setsignals();
	/* saves current path in cwd, because otherwise with daemon() we
	 * forget it */
	if((cwd = getcwd(NULL, 0)) == NULL) {
		printlog(LOG_ERR, "getcwd: %s", strerror(errno));
		exit(1);
	}
	if (args.daemon && daemon(0, 0)) {
		printlog(LOG_ERR,"daemon: %s", strerror(errno));
		exit(1);
	}

	/* once here, we're sure we're the true process which will continue as a
	 * server: save PID file if needed */
	if(args.pidfile) save_pidfile(args.pidfile, cwd);

	if (args.otip_period) conf_otip_period = strtol(args.otip_period, NULL, 0);
	if (args.otip_preactive) conf_otip_preactive = strtol(args.otip_preactive, NULL, 0);
	if (args.otip_postactive) conf_otip_postactive = strtol(args.otip_postactive, NULL, 0);
	conf_otip_lifetime = conf_otip_period + conf_otip_preactive + conf_otip_postactive;
	if (args.tcp_listen_backlog) conf_tcp_listen_backlog = strtol(args.tcp_listen_backlog, NULL, 0);
	if (args.tcp_timeout) conf_tcp_timeout = strtol(args.tcp_timeout, NULL, 0);
	if (args.udp_timeout) conf_udp_timeout = strtol(args.udp_timeout, NULL, 0);

	/* MAIN loop. Create new stacks when required */
	uint32_t last_otiptime = 0;
  for(;;) {
    uint32_t otiptime = iothaddr_otiptime(conf_otip_period, conf_otip_preactive);
    if (otiptime != last_otiptime) {
			/* time to change stack */
      last_otiptime = otiptime;
			if (verbose) printlog(LOG_INFO, "NEW stack %u", otiptime);
			struct connarg connarg;
			connarg.extstack = ioth_newstack(extargs->stack, extargs->vnl);
			if (connarg.extstack != NULL) {
				connarg.intstack = intstack;
				connarg.extstack_usage = calloc(1, sizeof(struct usagecount));
				if (connarg.extstack_usage != NULL) {
					extstack_usageup(&connarg);
					int iface = ioth_if_nametoindex(connarg.extstack, extargs->iface);
					struct in6_addr extaddr = baseaddr[0];
					iothaddr_hash(&extaddr, args.name, args.passwd, otiptime);
					if (verbose) {
						char ipasciibuf[INET6_ADDRSTRLEN];
						printlog(LOG_INFO, "new stack addr %s %s", args.name,
								inet_ntop(AF_INET6, &extaddr, ipasciibuf, sizeof(ipasciibuf)));
					}
					/* if these configuration instructions fail, simply the stack won't work */
					ioth_ipaddr_add(connarg.extstack, AF_INET6, &extaddr, 64, iface);
					ioth_linksetupdown(connarg.extstack, iface, 1);
					ioth_linksetupdown(connarg.extstack, 1, 1);
					connarg.item = proxytcptab;
					connarg.size = proxytcptablen;
					proxytcp(&connarg);
					connarg.item = proxyudptab;
					connarg.size = proxyudptablen;
					proxyudp(&connarg);
					extstack_usagedown(&connarg);
				}
			}
		}
		sleep(1);
	}
}
