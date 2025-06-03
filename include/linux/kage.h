#pragma once

#include <linux/types.h>
#include <linux/module.h>

// Assume 8k stack
#define KAGE_SANDBOX_STACK_ORDER 13
#define KAGE_SANDBOX_STACK_SIZE (1<<KAGE_SANDBOX_STACK_ORDER)

#define KAGE_MAX_PROCS 8

struct LFIProc;
struct LFISys;

typedef uint64_t (*SysHandler)(uint64_t sysno, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

struct kage{
    struct page **pages; // ==NULL if kage unused
    unsigned long start_vaddr;
    unsigned long *alloc_bitmap;
    unsigned long next_open_offs;
    struct LFIProc *procs[KAGE_MAX_PROCS];
    int open_proc_idx;
    // User-provided runtime call handler.
    SysHandler syshandler;

    // Pointer to the base of the sandbox
    struct LFISys* sys;
};

void * kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type);
void kage_memory_free_all(struct kage *kage);
void kage_memory_free(struct kage *kage, void *vaddr);
struct kage *kage_create(void);
void kage_free(struct kage * kage);

// Calls a modules's init function from within the sandbox and returns the
// value returned from fn
int kage_call_init(struct kage *kage, initcall_t fn);

