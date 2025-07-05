#ifndef _KAGE_PROC_H
#define _KAGE_PROC_H

#include <linux/types.h>

typedef struct LFIRegs {
	uint64_t x[31];
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
	void *kstackp;
	void *sstackp;
	struct kage *kage;
	// void* tp;
	LFIRegs regs;
};

void lfi_proc_init(struct LFIProc *proc, struct kage *kage, uintptr_t entry,
		   uintptr_t sp, uintptr_t ssp, uint32_t idx);

uint64_t lfi_proc_start(struct LFIProc *proc);

void lfi_proc_free(struct LFIProc *proc);


uint64_t lfi_proc_invoke(struct LFIProc *proc, void *fn, void *ret,
                         uint64_t p0, uint64_t p1, uint64_t p2,
                         uint64_t p3, uint64_t p4, uint64_t p5);

#endif /* _KAGE_PROC_H */
