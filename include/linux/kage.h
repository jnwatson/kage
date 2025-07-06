/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_KAGE_H
#define _LINUX_KAGE_H

#include <linux/types.h>
#include <linux/module.h>
#include <linux/assoc_array.h>
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
#define KAGE_GVAR_SPACE_SIZE PAGE_SIZE
#define KAGE_MAX_GVARS 16
struct LFIProc; // FIXME: < prepend with kage
struct LFISys; // prepend with kage
struct kage;

struct kage_objstorage {
	void __rcu *objs[KAGE_MAX_OBJ_INDEX + 1];
	spinlock_t lock;
	unsigned int next_slot;
};

// The literal pool entry for a single host-to-guest trampoline
struct kage_h2g_tramp_data_entry {
	struct kage *kage;
	u64 guest_func; // callback into guest
};

// A guest imported variable
struct kage_gvar {
	const char *name;
	unsigned long (*resolver)(struct kage *kage);
	unsigned long addr;
};

struct kage {
        const char *modname;
	spinlock_t lock;

	// Lowest address of guest address space
	unsigned long base;

        // Bitmap of allocated pages in guest
	unsigned long *alloc_bitmap;

        // The next available location in the guest
	unsigned long next_open_memory_offs;

        // Run contexts
	struct LFIProc *procs[KAGE_MAX_PROCS];

	int open_proc_idx;

	struct LFISys *sys;

	// Where the instruction sequence to exit from guest lives (inside the
	// guest)
	unsigned long exit_addr;

	// Trampolines from guest to host and vice versa
	unsigned int num_g2h_calls;
	struct kage_g2h_call *g2h_calls[KAGE_MAX_G2H_CALLS];

	// Guest's imported global variables; only used at load time
	unsigned int num_gvars;
	struct kage_gvar gvars[KAGE_MAX_GVARS];

	void * gvar_space;
	void * gvar_space_open;

	void * g2h_tramp_text;
	void * g2h_tramp_data;

	unsigned int num_h2g_calls;
	void * h2g_tramp_text;
	struct kage_h2g_tramp_data_entry * h2g_tramp_data;

	struct assoc_array closures;

        /* Stores mapping of opaque references to addresses of struct 
         * pointers */
	struct kage_objstorage *objstorage;
	u8 owner_id; // Used in objstorage to constrain access to objects
};

void *kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type, gfp_t flags);
void kage_memory_free(struct kage *kage, void *vaddr);
void kage_memory_free_all(struct kage *kage);
struct kage *kage_create(const char *modname);
void kage_destroy(struct kage *kage);
int kage_post_relocation(struct kage *kage, 
			const Elf_Shdr *sechdrs,
                        unsigned int shnum,
                        const Elf_Sym *symtab,
                        unsigned int num_syms,
                        const char *strtab);

// Calls a function in the guest and returns the result
unsigned long kage_call(struct kage *kage, void * fn, unsigned long p0, 
                   unsigned long p1, unsigned long p2, unsigned long p3, 
                   unsigned long p4, unsigned long p5);

unsigned long kage_symbol_value(struct kage *, const char *name, 
				unsigned long target_func);

#endif /* _LINUX_KAGE_H */
