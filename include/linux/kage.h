/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KAGE_H
#define _LINUX_KAGE_H

#include <linux/types.h>
#include <linux/module.h>
#include <linux/assoc_array.h>
#include <linux/kage_syscall.h>
#include <linux/kage_asm.h>


// Assume 8k stack
#define KAGE_GUEST_SIZE (4UL * 1024 * 1024 * 1024)

#define KAGE_MAX_PROCS 8

struct LFIProc;
struct LFISys;

typedef uint64_t (*SysHandler)(struct kage *kage, uint64_t sysno, uint64_t,
			       uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t);

#include <linux/kage_objdescriptor.h>

/*
 * While object descriptors reserve 16 bits for the index, we limit the
 * actual number of objects to a smaller value to avoid excessive memory
 * allocation.
 */
#define KAGE_MAX_OBJ_INDEX 511

struct kage_objstorage {
	void __rcu *objs[KAGE_MAX_OBJ_INDEX + 1];
	spinlock_t lock;
	unsigned int next_slot;
};

struct kage {
	struct page **pages; // ==NULL if kage unused
        const char *modname;
	unsigned long base;
	unsigned long *alloc_bitmap;
	unsigned long next_open_memory_offs;
	struct LFIProc *procs[KAGE_MAX_PROCS];
	int open_proc_idx;
	// User-provided runtime call handler.
	SysHandler syshandler;

	// Pointer to the base of the sandbox
	struct LFISys *sys;

	// Where the instruction sequence to exit from sandbox lives (inside the
	// sandbox)
	unsigned long exit_addr;
	void * tramp_text;
	void * tramp_data;

	struct assoc_array closures;
	struct kage_objstorage *objstorage;
	u8 owner_id;
	unsigned int num_host_calls;
	struct kage_host_call *host_calls[MAX_HOST_CALLS];
};

void *kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type, gfp_t flags);
void kage_memory_free_all(struct kage *kage);
void kage_memory_free(struct kage *kage, void *vaddr);
struct kage *kage_create(const char *modname);
void kage_free(struct kage *kage);
void kage_post_relocation(struct kage *kage, 
			   const Elf_Shdr *sechdrs,
                           unsigned int shnum,
                           const Elf_Sym *symtab,
                           unsigned int num_syms,
                           const char *strtab);

// Calls a modules's init function from within the sandbox and returns the
// value returned from fn
int kage_call_init(struct kage *kage, initcall_t fn);

// Calls any function in the sandbox and returns the result
uint64_t kage_call(struct kage *kage, void * fn,
              uint64_t p0, uint64_t p1, uint64_t p2,
              uint64_t p3, uint64_t p4, uint64_t p5);

unsigned long kage_symbol_value(struct kage *, const char *name);

#endif /* _LINUX_KAGE_H */
