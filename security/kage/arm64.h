// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#ifndef _KAGE_ARM64_H
#define _KAGE_ARM64_H

#include "proc.h"

void wr_regs_base(struct kage_regs *regs, unsigned long val);
unsigned long *regs_addr(struct kage_regs *regs, int n);
void regs_init(struct kage_regs *regs, unsigned long entry, unsigned long sp, unsigned long ssp);
unsigned long *lfi_regs_arg(struct kage_regs *regs, int arg);

#endif /* _KAGE_ARM64_H */
