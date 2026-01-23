// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>

#include <linux/kage.h>
#include "proc.h"

#include "arm64.h"

extern unsigned long lfi_asm_invoke(struct kage_proc *proc, unsigned long entry,
				    unsigned long p0, unsigned long p1,
				    unsigned long p2, unsigned long p3,
				    unsigned long p4, unsigned long p5);

unsigned long procaddr(unsigned long base, unsigned long addr)
{
	return base | ((uint32_t)addr);
}

static void proc_validate(struct kage_proc *proc)
{
	unsigned long *r;
	int n = 0;

	wr_regs_base(&proc->regs, proc->kage->base);

	while ((r = regs_addr(&proc->regs, n++)))
		*r = procaddr(proc->kage->base, *r);
}

void lfi_proc_init(struct kage_proc *proc, struct kage *kage, unsigned long lr,
		   unsigned long sp, unsigned long ssp)
{
	proc->kage = kage;

        // Store proc past the top of the stack in RO memory to the guest
	*((unsigned long*)sp) = (unsigned long)proc;

	regs_init(&proc->regs, lr, sp, ssp);

	proc_validate(proc);
}

unsigned long lfi_proc_invoke(struct kage_proc *proc, unsigned long fn,
			      unsigned long p0, unsigned long p1,
                              unsigned long p2, unsigned long p3,
                              unsigned long p4, unsigned long p5) {
	pr_info("lfi_proc_invoke: starting guest function at 0x%lx\n", fn);

	return lfi_asm_invoke(proc, fn, p0, p1, p2, p3, p4, p5);
}
