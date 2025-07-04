// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/types.h>
#include <linux/bug.h>

#include "proc.h"

uint64_t *lfi_regs_arg(LFIRegs *regs, int arg)
{
	BUG_ON(arg>=8);
	return &regs->x[arg];
}

void wr_regs_base(LFIRegs *regs, uint64_t val)
{
	regs->x[27] = val;
}

uint64_t *regs_addr(LFIRegs *regs, int n)
{
	switch (n) {
	case 0:
		return &regs->x[28];
	case 1:
		return &regs->sp;
	case 2:
		return &regs->x[30];
	}
	return NULL;
}

void regs_init(LFIRegs *regs, uint64_t entry, uint64_t sp)
{
	regs->x[30] = entry;
	regs->sp = sp;
}

