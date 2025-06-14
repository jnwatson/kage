/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KAGE_H
#define _LINUX_KAGE_H

#include <linux/types.h>
#include <linux/module.h>
#include "../../../../kdriver1/kage_syscall.h"


// Assume 8k stack
#define KAGE_SANDBOX_STACK_ORDER 13
#define KAGE_SANDBOX_STACK_SIZE (1 << KAGE_SANDBOX_STACK_ORDER)
#define KAGE_GUEST_SIZE (4UL * 1024 * 1024 * 1024)

#define KAGE_MAX_PROCS 8

struct LFIProc;
struct LFISys;

typedef uint64_t (*SysHandler)(struct kage *kage, uint64_t sysno, uint64_t,
			       uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t);

#include <linux/assoc_array.h>

struct kage {
	struct page **pages; // ==NULL if kage unused
	unsigned long base;
	unsigned long *alloc_bitmap;
	unsigned long next_open_offs;
	struct LFIProc *procs[KAGE_MAX_PROCS];
	int open_proc_idx;
	// User-provided runtime call handler.
	SysHandler syshandler;

	// Pointer to the base of the sandbox
	struct LFISys *sys;

	// Where the instruction sequence to exit from sandbox lives (inside the
	// sandbox)
	unsigned long kage_exit_addr;

	struct assoc_array closures;
};

void *kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type, gfp_t flags);
void kage_memory_free_all(struct kage *kage);
void kage_memory_free(struct kage *kage, void *vaddr);
struct kage *kage_create(void);
void kage_free(struct kage *kage);

// Calls a modules's init function from within the sandbox and returns the
// value returned from fn
int kage_call_init(struct kage *kage, initcall_t fn);

// Calls any function in the sandbox and returns the result
uint64_t kage_call(struct kage *kage, void * fn,
              uint64_t p0, uint64_t p1, uint64_t p2,
              uint64_t p3, uint64_t p4, uint64_t p5);

#endif /* _LINUX_KAGE_H */
