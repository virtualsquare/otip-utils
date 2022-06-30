#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <syslog.h>

void startlog(char *prog, int use_syslog);
void printlog(int priority, const char *format, ...);
void save_pidfile(char *pidfile, char *cwd);

void packetdump(FILE *f, void *arg,ssize_t len);
void printin6addr(FILE *f, void *addr);

#endif
