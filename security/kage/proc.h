#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/types.h>

typedef struct kage_regs {
	uint64_t x[31];
	uint64_t sp;
	uint64_t _pad;
} kage_regs;

struct kage_proc;

struct kage;
struct kage_proc {
	void *kstackp;
	void *sstackp;
	struct kage *kage;
	// void* tp;
	kage_regs regs;
};

void lfi_proc_init(struct kage_proc *proc, struct kage *kage, uintptr_t entry,
		   uintptr_t sp, uintptr_t ssp);

uint64_t lfi_proc_start(struct kage_proc *proc);

void lfi_proc_free(struct kage_proc *proc);


uint64_t lfi_proc_invoke(struct kage_proc *proc, void *fn, void *ret,
                         uint64_t p0, uint64_t p1, uint64_t p2,
                         uint64_t p3, uint64_t p4, uint64_t p5);

#endif /* _KAGE_PROC_H */
