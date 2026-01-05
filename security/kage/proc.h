#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/kage_asm.h>
#include <linux/types.h>

#ifndef __ASSEMBLY__

struct kage;

/* The guest's saved context */
struct kage_regs {
	unsigned long x[31];
	unsigned long sp;
};

struct kage_proc {
	unsigned long kstackp; // host's saved stack
	unsigned long sstackp; // host's saved SCS
	struct kage *kage;
	struct kage_regs regs; // guest's saved registers
};

void lfi_proc_init(struct kage_proc *proc, struct kage *kage, 
		   unsigned long entry, unsigned long sp, unsigned long ssp);

unsigned long lfi_proc_invoke(struct kage_proc *proc, unsigned long fn,
			      unsigned long p0, unsigned long p1, 
                              unsigned long p2, unsigned long p3, 
                              unsigned long p4, unsigned long p5);

#endif /* __ASSEMBLY__ */

#endif /* _KAGE_PROC_H */
