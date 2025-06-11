// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#ifndef _KAGE_ARM64_H
#define _KAGE_ARM64_H

#include <linux/types.h>
#include <linux/bug.h>
#include "proc.h"

static void wr_regs_base(LFIRegs *regs, uint64_t val)
{
	regs->x21 = val;
}

static uint64_t *regs_addr(LFIRegs *regs, int n)
{
	switch (n) {
	case 0:
		return &regs->x18;
	case 1:
		return &regs->sp;
	case 2:
		return &regs->x30;
	}
	return NULL;
}

static void regs_init(LFIRegs *regs, uint64_t entry, uint64_t sp)
{
	regs->x30 = entry;
	regs->sp = sp;
}

#endif /* _KAGE_ARM64_H */
