#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

#include <linux/kage_syscall.h>

struct kage;

struct kage_g2h_call {
	const char *name;
	unsigned long guard_func; // usually == *guard_sig or guard_sig_precall
	unsigned long guard_func2; // only for variadic
	unsigned long stub; // == lfi_syscall_entry2
	unsigned long host_func; // The actual kernel function

        const char *sig; // from sigs.h
};

struct kage_g2h_call *create_g2h_call(const char *name, 
					unsigned long target_func);

typedef unsigned long guard_t(struct kage *kage, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5);

#endif /* _KAGE_GUARDS_H */
