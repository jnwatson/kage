#ifndef KAGE_ASM_H_
#define KAGE_ASM_H_

#include <asm/page-def.h>

/* This file includes simple constants appropriate to share among assembly
 * and C files */

#define MODULE_NAME "kage"

/* == offsetof(struct LFIProc, regs) */
#define KAGE_LFIPROC_KAGE_OFFS 8
#define KAGE_LFIPROC_REGS_OFFS 16
#define KAGE_G2H_CALL_GUARD_FUNC_OFFS 8
#define KAGE_G2H_CALL_TARGET_FUNC_OFFS 24
/* == offsetof(struct LFISys, procs) */
#define KAGE_LFISYS_PROCS_OFFS 2048

/* log2(guest stack) */
#define KAGE_GUEST_STACK_ORDER 13
#define KAGE_GUEST_STACK_SIZE (1 << KAGE_GUEST_STACK_ORDER)

#define KAGE_MAX_STACK_ARGS_SIZE 256


// Max number of different external functions a guest can call
#define KAGE_MAX_G2H_CALLS 512

// Max number of different callback a guest can register in host calls
#define KAGE_MAX_H2G_CALLS 256

// Size of lfi_g2h_trampoline text; 4 instructions of size 4
#define KAGE_G2H_TRAMP_SIZE (4 * 4)
#define KAGE_H2G_TRAMP_SIZE (4 * 4)

#define KAGE_ALIGN(x, mask)(((x) + (mask) - 1) & ~(mask - 1))

// Size of the each of the two guest-to-host trampoline regions
#define KAGE_G2H_TRAMP_REGION_SIZE \
	KAGE_ALIGN(KAGE_MAX_H2G_CALLS * KAGE_G2H_TRAMP_SIZE, PAGE_SIZE)
#define KAGE_H2G_TRAMP_REGION_SIZE \
	KAGE_ALIGN(KAGE_MAX_G2H_CALLS * KAGE_H2G_TRAMP_SIZE, PAGE_SIZE)
#endif
