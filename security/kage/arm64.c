// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>
#include <linux/bug.h>

#include "proc.h"

unsigned long *lfi_regs_arg(struct kage_regs *regs, int arg)
{
	BUG_ON(arg>=8);
	return &regs->x[arg];
}

void wr_regs_base(struct kage_regs *regs, uint64_t val)
{
	regs->x[27] = val;
}
// These are the registers that must be limited to the guest's range
unsigned long *regs_addr(struct kage_regs *regs, int n)
{
	switch (n) {
	case 0:
		return &regs->x[28];
	case 1:
		return &regs->sp;
	case 2:
		return &regs->x[30];
	case 3:
		return &regs->x[18];
	}
	return NULL;
}

void regs_init(struct kage_regs *regs, unsigned long lr, unsigned long sp, unsigned long ssp)
{
	regs->x[18] = ssp;
	regs->x[30] = lr;
	regs->sp = sp;
}
