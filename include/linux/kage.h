/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KAGE_H
#define _LINUX_KAGE_H

#include <linux/types.h>
#include <linux/module.h>
#include <linux/assoc_array.h>
#include <linux/kage_syscall.h>
#include <linux/kage_asm.h>
#include <linux/kage_objdescriptor.h>


#define KAGE_GUEST_SIZE (4UL * 1024 * 1024 * 1024)

#define KAGE_MAX_PROCS 8

/*
 * While object descriptors reserve 16 bits for the index, we limit the
 * actual number of objects to a smaller value to avoid excessive memory
 * allocation.
 */
#define KAGE_MAX_OBJ_INDEX 511
struct LFIProc; // FIXME: < prepend with kage
struct LFISys; // prepend with kage
struct kage;

typedef uint64_t (*SysHandler)(struct kage *kage, uint64_t sysno, uint64_t,
			       uint64_t, uint64_t, uint64_t, uint64_t,
			       uint64_t);


struct kage_objstorage {
	void __rcu *objs[KAGE_MAX_OBJ_INDEX + 1];
	spinlock_t lock;
	unsigned int next_slot;
};
struct kage_h2g_tramp_data_entry {
	struct kage *kage;
	u64 guest_func; // callback into guest
};

struct kage {
	
        const char *modname;
	spinlock_t lock;

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

	// Trampolines from guest to host and vice versa
	unsigned int num_g2h_calls;
	void * g2h_tramp_text;
	void * g2h_tramp_data;

	unsigned int num_h2g_calls; // h->g calls
	void * h2g_tramp_text;
	struct kage_h2g_tramp_data_entry * h2g_tramp_data;

	struct assoc_array closures;
	struct kage_objstorage *objstorage;
	u8 owner_id;
	struct kage_g2h_call *g2h_calls[KAGE_MAX_G2H_CALLS];
};

void *kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type, gfp_t flags);
void kage_memory_free_all(struct kage *kage);
void kage_memory_free(struct kage *kage, void *vaddr);
struct kage *kage_create(const char *modname);
void kage_destroy(struct kage *kage);
int kage_post_relocation(struct kage *kage, 
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

unsigned long kage_symbol_value(struct kage *, const char *name, 
				unsigned long target_func);

#endif /* _LINUX_KAGE_H */
