#ifndef _KAGE_GUARDS_H
#define _KAGE_GUARDS_H

struct kage;

struct kage_g2h_call {
	const char *name;
	unsigned long guard_func; // usually == *guard_sig or guard_sig_precall
	unsigned long guard_func2; // only used for variadic
	unsigned long stub; // == lfi_syscall_entry
	unsigned long host_func; // The actual kernel function
        const char *sig; // from sigs.h
};

struct kage_g2h_call *kage_guard_create_g2h_call(const char *name, 
					unsigned long target_func);
unsigned long kage_guard_resolve_gvars(struct kage *kage, const char *name);

#endif /* _KAGE_GUARDS_H */
