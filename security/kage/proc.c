// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>

#include <linux/kage.h>
#include "proc.h"

#include "arm64.h"

extern uint64_t lfi_asm_invoke(struct LFIProc *proc, void *fn,
			       void **kstackp) asm("lfi_asm_invoke");

unsigned long procaddr(unsigned long base, unsigned long addr)
{
	return base | ((uint32_t)addr);
}

static void proc_validate(struct LFIProc *proc)
{
	uint64_t *r;
	int n = 0;

	wr_regs_base(&proc->regs, proc->kage->base);

	while ((r = regs_addr(&proc->regs, n++)))
		*r = procaddr(proc->kage->base, *r);
}

void lfi_proc_init(struct LFIProc *proc, struct kage *kage, uintptr_t entry,
		   uintptr_t sp, uint32_t idx)
{
	proc->kage = kage;

	sp -= 4;
	*((uint32_t *)(sp + kage->base)) = idx;
	sp -= 12;

	regs_init(&proc->regs, entry, sp);

	proc_validate(proc);
}

uint64_t lfi_proc_invoke(struct LFIProc *proc, void *fn, void *ret, 
                         uint64_t p0, uint64_t p1, uint64_t p2, 
                         uint64_t p3, uint64_t p4, uint64_t p5)
{
	*lfi_regs_sysarg(&proc->regs, 0) = p0;
	*lfi_regs_sysarg(&proc->regs, 1) = p1;
	*lfi_regs_sysarg(&proc->regs, 2) = p2;
	*lfi_regs_sysarg(&proc->regs, 3) = p3;
	*lfi_regs_sysarg(&proc->regs, 4) = p4;
	*lfi_regs_sysarg(&proc->regs, 5) = p5;
	proc->regs.x30 = (uintptr_t)ret;
	return lfi_asm_invoke(proc, fn, &proc->kstackp);
}

void lfi_syscall_handler(struct LFIProc *proc) asm("lfi_syscall_handler");

void lfi_syscall_handler(struct LFIProc *proc)
{
	uint64_t sysno = *lfi_regs_sysno(&proc->regs);
	uint64_t a0 = *lfi_regs_sysarg(&proc->regs, 0);
	uint64_t a1 = *lfi_regs_sysarg(&proc->regs, 1);
	uint64_t a2 = *lfi_regs_sysarg(&proc->regs, 2);
	uint64_t a3 = *lfi_regs_sysarg(&proc->regs, 3);
	uint64_t a4 = *lfi_regs_sysarg(&proc->regs, 4);
	uint64_t a5 = *lfi_regs_sysarg(&proc->regs, 5);
	uint64_t ret =
		proc->kage->syshandler(proc->kage, sysno, a0, a1, a2, a3, a4, a5);

	*lfi_regs_sysret(&proc->regs) = ret;
}
