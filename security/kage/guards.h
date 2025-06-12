#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

struct kage;

typedef unsigned long guard_t(struct kage *kage, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5);

#define GUARD_NUM_SYSCALLS 20
extern guard_t *syscall_to_guard[GUARD_NUM_SYSCALLS];

#endif /* _KAGE_GUARDS_H */
