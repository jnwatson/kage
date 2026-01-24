// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>

#include <linux/kage.h>
#include "proc.h"
#include "runtime.h"

void lfi_proc_init(struct kage_proc *proc, struct kage *kage,
		   unsigned long pc, unsigned long lr, unsigned long sp,
		   unsigned long ssp, unsigned long caller)
{
	proc->kage = kage;
	proc->regs.sp = sp;
	proc->regs.ssp = ssp;
	proc->entry = pc;
	proc->regs.lr = lr;
	proc->caller = caller;

	// FIXME: assert entryaddr in guest and exitaddr not in guest

        /* Store proc past the top of the stack in RO memory to the guest
	 * The GET_PROC macro in runtime.S retrieves this */
	*((unsigned long*)sp) = (unsigned long)proc;
}

unsigned long lfi_proc_invoke(struct kage_proc *proc,
			      unsigned long p0, unsigned long p1,
                              unsigned long p2, unsigned long p3,
                              unsigned long p4, unsigned long p5) {
	pr_info("lfi_proc_invoke: starting guest function at 0x%lx\n",
		proc->entry);

	return lfi_asm_invoke(proc, p0, p1, p2, p3, p4, p5);
}
