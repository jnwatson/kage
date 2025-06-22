#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

#include <linux/kage_syscall.h>

struct kage;

struct kage_host_call {
	const char *name;
	unsigned long guard_func;
	unsigned long stub;
};

struct kage_host_call *find_host_call(const char *name);

typedef unsigned long guard_t(struct kage *kage, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5);

extern guard_t *syscall_to_guard[KAGE_SYSCALL_COUNT];

#endif /* _KAGE_GUARDS_H */
