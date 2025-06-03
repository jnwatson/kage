#include <linux/types.h>

#include <linux/kage.h>
#include "proc.h"

#include "arm64.h"


extern uint64_t lfi_proc_entry(struct LFIProc* proc, void** kstackp) asm ("lfi_proc_entry");
extern uint64_t lfi_asm_invoke(struct LFIProc* proc, void* fn, void** kstackp) asm ("lfi_asm_invoke");
extern void lfi_asm_proc_exit(void* kstackp, uint64_t code) asm ("lfi_asm_proc_exit");
extern void lfi_syscall_entry(void) asm ("lfi_syscall_entry");
extern void lfi_ret(void) asm ("lfi_ret");

static uintptr_t
procaddr(uintptr_t base, uintptr_t addr)
{
    return base | ((uint32_t) addr);
}

static void
proc_validate(struct LFIProc* proc)
{
    uint64_t* r;

    // base
    wr_regs_base(&proc->regs, proc->base);

    // address registers
    int n = 0;
    while ((r = regs_addr(&proc->regs, n++)))
        *r = procaddr(proc->base, *r);

    // sys register (if used for this arch)
    if ((r = regs_sys(&proc->regs)))
        *r = (uintptr_t) proc->kage->sys;
}

void
lfi_proc_init(struct LFIProc* proc, struct kage * kage, uintptr_t entry, uintptr_t sp, uint32_t idx)
{
    proc->kage = kage;
    sp -= 4;
    *((uint32_t *)sp) = idx;
    sp -= 12;  // to maintain ABI 16-byte stack frame alignment
    regs_init(&proc->regs, entry, sp);

    proc_validate(proc);
}


uint64_t
lfi_proc_invoke(struct LFIProc* proc, void* fn, void* ret)
{
    // TODO: set return point to retfn in a cross-architecture way
#if defined(__aarch64__) || defined(_M_ARM64)
    proc->regs.x30 = (uintptr_t) ret;
#elif defined(__x86_64__) || defined(_M_X64)
    proc->regs.rsp -= 8;
    *((void**) proc->regs.rsp) = ret;
#endif
    return lfi_asm_invoke(proc, fn, &proc->kstackp);
}
#if 0
static void
syssetup(LFISys* table, struct LFIProc* proc)
{
    table->rtcalls[0] = (uintptr_t) &lfi_syscall_entry;
    table->rtcalls[1] = (uintptr_t) &lfi_ret;
    table->base = proc->base;
    table->proc = proc;
}
#endif

// This function will be called from assembly.
void lfi_syscall_handler(struct LFIProc* proc) asm ("lfi_syscall_handler");

void
lfi_syscall_handler(struct LFIProc* proc)
{
    uint64_t sysno = *lfi_regs_sysno(&proc->regs);

    uint64_t a0 = *lfi_regs_sysarg(&proc->regs, 0);
    uint64_t a1 = *lfi_regs_sysarg(&proc->regs, 1);
    uint64_t a2 = *lfi_regs_sysarg(&proc->regs, 2);
    uint64_t a3 = *lfi_regs_sysarg(&proc->regs, 3);
    uint64_t a4 = *lfi_regs_sysarg(&proc->regs, 4);
    uint64_t a5 = *lfi_regs_sysarg(&proc->regs, 5);

    uint64_t ret = proc->kage->syshandler(sysno, a0, a1, a2, a3, a4, a5);

    *lfi_regs_sysret(&proc->regs) = ret;
}

