// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#ifndef _KAGE_ARM64_H
#define _KAGE_ARM64_H

#include "proc.h"

void wr_regs_base(LFIRegs *regs, uint64_t val);
uint64_t *regs_addr(LFIRegs *regs, int n);
void regs_init(LFIRegs *regs, uint64_t entry, uint64_t sp);
uint64_t *lfi_regs_arg(LFIRegs *regs, int arg);

#endif /* _KAGE_ARM64_H */
