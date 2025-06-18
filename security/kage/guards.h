#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

#include <linux/kage_syscall.h>

struct kage;

typedef unsigned long guard_t(struct kage *kage, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5);

extern guard_t *syscall_to_guard[KAGE_SYSCALL_COUNT];

#endif /* _KAGE_GUARDS_H */
