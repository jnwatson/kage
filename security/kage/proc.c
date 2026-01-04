// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>

#include <linux/kage.h>
#include "proc.h"

#include "arm64.h"

extern uint64_t lfi_asm_invoke(struct kage_proc *proc, void *fn,
			       unsigned long *kstackp, unsigned long *sstackp) 
	asm("lfi_asm_invoke");

unsigned long procaddr(unsigned long base, unsigned long addr)
{
	return base | ((uint32_t)addr);
}

static void proc_validate(struct kage_proc *proc)
{
	uint64_t *r;
	int n = 0;

	wr_regs_base(&proc->regs, proc->kage->base);

	while ((r = regs_addr(&proc->regs, n++)))
		*r = procaddr(proc->kage->base, *r);
}

void lfi_proc_init(struct kage_proc *proc, struct kage *kage, unsigned long entry,
		   unsigned long sp, unsigned long ssp)
{
	proc->kage = kage;

        // Store proc past the top of the stack in RO memory
	*((unsigned long*)sp) = (unsigned long)proc;

	regs_init(&proc->regs, entry, sp, ssp);

	proc_validate(proc);
}

unsigned long lfi_proc_invoke(struct kage_proc *proc, void *fn,
			      void *exit_addr, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5) {
	*lfi_regs_arg(&proc->regs, 0) = p0;
	*lfi_regs_arg(&proc->regs, 1) = p1;
	*lfi_regs_arg(&proc->regs, 2) = p2;
	*lfi_regs_arg(&proc->regs, 3) = p3;
	*lfi_regs_arg(&proc->regs, 4) = p4;
	*lfi_regs_arg(&proc->regs, 5) = p5;
	proc->regs.x[30] = (unsigned long)exit_addr;
	return lfi_asm_invoke(proc, fn, &proc->kstackp, &proc->sstackp);
}
