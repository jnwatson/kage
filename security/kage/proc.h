#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/types.h>

typedef struct LFIRegs {
	uint64_t x0;
	uint64_t x1;
	uint64_t x2;
	uint64_t x3;
	uint64_t x4;
	uint64_t x5;
	uint64_t x6;
	uint64_t x7;
	uint64_t x8;
	uint64_t x9;
	uint64_t x10;
	uint64_t x11;
	uint64_t x12;
	uint64_t x13;
	uint64_t x14;
	uint64_t x15;
	uint64_t x16;
	uint64_t x17;
	uint64_t x18;
	uint64_t x19;
	uint64_t x20;
	uint64_t x21;
	uint64_t x22;
	uint64_t x23;
	uint64_t x24;
	uint64_t x25;
	uint64_t x26;
	uint64_t x27;
	uint64_t x28;
	uint64_t x29;
	uint64_t x30;
	uint64_t sp;
	uint64_t _pad;
} LFIRegs;

struct LFIProc;

typedef struct LFISys {
	uintptr_t rtcalls[256];
	struct LFIProc *(*procs)[]; /* == &kage->procs */
} LFISys;

struct kage;
struct LFIProc {
	void *kstackp; // This must be first as lfi_ret depends on it
	struct kage *kage;
	// void* tp;
	LFIRegs regs;
};

// Entry and sp are relative to sandbox base
void lfi_proc_init(struct LFIProc *proc, struct kage *kage, uintptr_t entry,
		   uintptr_t sp, uint32_t idx);

uint64_t lfi_proc_start(struct LFIProc *proc);

void lfi_proc_free(struct LFIProc *proc);

// lfi_regs_sysno returns the register used for the system call number.
uint64_t *lfi_regs_sysno(LFIRegs *regs);

// lfi_regs_sysarg returns the nth system call argument (0-5).
uint64_t *lfi_regs_sysarg(LFIRegs *regs, int n);

// lfi_regs_sysret returns the register used for system call return values.
uint64_t *lfi_regs_sysret(LFIRegs *regs);

uint64_t lfi_proc_invoke(struct LFIProc *proc, void *fn, void *ret,
                         uint64_t p0, uint64_t p1, uint64_t p2,
                         uint64_t p3, uint64_t p4, uint64_t p5);

#endif /* _KAGE_PROC_H */
