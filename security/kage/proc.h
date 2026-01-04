#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/kage_asm.h>
#include <linux/types.h>

#ifndef __ASSEMBLY__

struct kage;

/* The guest's saved context */
typedef struct {
	uint64_t x[31];
	uint64_t sp;
} kage_regs;

struct kage_proc {
	unsigned long kstackp;
	unsigned long sstackp;
	struct kage *kage;
	kage_regs regs;
};

void lfi_proc_init(struct kage_proc *proc, struct kage *kage, 
		   unsigned long entry, unsigned long sp, unsigned long ssp);

unsigned long lfi_proc_invoke(struct kage_proc *proc, void *fn,
			      void *exit_addr, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5);

#endif /* __ASSEMBLY__ */

#endif /* _KAGE_PROC_H */
