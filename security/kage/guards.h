#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

#include "funcsig.h"

struct kage;

struct kage_g2h_call {
	const char *name;
	unsigned long guard_func; // usually == *guard_sig or guard_sig_precall
	unsigned long guard_func2; // only used for variadic
	unsigned long stub; // == lfi_syscall_entry FIXME change to g2hentry
	unsigned long host_func; // The actual kernel function
	struct kage_argspec *spec; // 0 terminated array
};

extern struct kage_g2h_call g2h_call_overrides[];

struct kage_g2h_call *kage_guard_create_g2h_call(const char *name,
						 unsigned long target_func);
void kage_guard_destroy_g2h_call(struct kage_g2h_call *call);
unsigned long kage_guard_resolve_gvars(struct kage *kage, const char *name);
void kage_guards_init(void);

#endif /* _KAGE_GUARDS_H */
