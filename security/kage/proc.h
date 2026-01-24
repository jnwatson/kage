#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/kage_asm.h>
#include <linux/types.h>

#ifndef __ASSEMBLY__

struct kage;

/* The guest's saved context */
struct kage_regs {
	unsigned long sp;  // guest's stack pointer
	unsigned long lr;  // guest's LR (x30)
	unsigned long ssp; // guest's SCS pointer (x18)
	unsigned long fp;  // guest's frame pointer (x29)
};

struct kage_proc_args {
	unsigned long x[8];
};

struct kage_proc {
	unsigned long kstackp; // host's stack
	unsigned long sstackp; // host's SCS
	struct kage *kage;
	unsigned long caller; // PC of host call (for debugging)
	unsigned long entry; // initial guest entry point
	struct kage_regs regs; // guest's saved registers
};

void lfi_proc_init(struct kage_proc *proc, struct kage *kage,
		   unsigned long pc, unsigned long lr, unsigned long sp,
		   unsigned long ssp, unsigned long caller);

unsigned long lfi_proc_invoke(struct kage_proc *proc,
			      unsigned long p0, unsigned long p1, 
                              unsigned long p2, unsigned long p3, 
                              unsigned long p4, unsigned long p5);

#endif /* __ASSEMBLY__ */

#endif /* _KAGE_PROC_H */
