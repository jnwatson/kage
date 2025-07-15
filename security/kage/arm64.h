// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#ifndef _KAGE_ARM64_H
#define _KAGE_ARM64_H

#include "proc.h"

void wr_regs_base(kage_regs *regs, uint64_t val);
uint64_t *regs_addr(kage_regs *regs, int n);
void regs_init(kage_regs *regs, uint64_t entry, uint64_t sp, uint64_t ssp);
uint64_t *lfi_regs_arg(kage_regs *regs, int arg);

#endif /* _KAGE_ARM64_H */
