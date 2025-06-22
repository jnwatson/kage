#ifndef KAGE_ASM_H_
#define KAGE_ASM_H_

#include <asm/page-def.h>

/* This file includes simple constants appropriate to share among assembly
 * and C files */

/* == offsetof(struct LFIProc, regs) */
#define KAGE_LFIPROC_KAGE_OFFS 8
#define KAGE_LFIPROC_REGS_OFFS 16

/* == offsetof(struct LFISys, procs) */
#define KAGE_LFISYS_PROCS_OFFS 2048

/* log2(guest stack) */
#define KAGE_GUEST_STACK_ORDER 13
#define KAGE_GUEST_STACK_SIZE (1 << KAGE_GUEST_STACK_ORDER)

// Max number of different external functions a guest can call
#define MAX_HOST_CALLS 512

// Size of lfi_trampoline text
#define KAGE_TRAMP_SIZE (4 * 4)

#define KAGE_ALIGN(x, mask)(((x) + (mask) - 1) & ~(mask - 1))

// Size of the each of the two trampoline regions
#define KAGE_TRAMP_REGION_SIZE \
	KAGE_ALIGN(MAX_HOST_CALLS * KAGE_TRAMP_SIZE, PAGE_SIZE)
#endif
