#include <linux/kage_asm.h>
.text

// Places the pointer to the active kage_proc in x27.
.macro GET_PROC
/* Precondition: syspage (base of guest domain) in x27 */
/* Postcondition: kage_proc * in x27 */

    /* Add (stack size - 1) to SP to guarantee we are in the next block (except
       if we're already at the top of the stack) */
    add   x16, sp, KAGE_GUEST_STACK_SIZE
    sub   x16, x16, 1
    // Clear the lower 13 bits to get the base address of the *next* 8KiB block
    and   x16, x16, ~(KAGE_GUEST_STACK_SIZE-1)
    // Load proc from the first bytes past the stack (in "proc data")
    ldr   x27, [x16]
.endm

// save caller-saved registers, assuming sandbox syspage is x27
.macro SAVE_PARTIAL_REGS
	GET_PROC
	stp x0, x1,   [x27, KAGE_PROC_REG_X_OFFS(0)]
	stp x2, x3,   [x27, KAGE_PROC_REG_X_OFFS(2)]
	stp x4, x5,   [x27, KAGE_PROC_REG_X_OFFS(4)]
	stp x6, x7,   [x27, KAGE_PROC_REG_X_OFFS(6)]
	stp x8, x9,   [x27, KAGE_PROC_REG_X_OFFS(8)]
	stp x10, x11, [x27, KAGE_PROC_REG_X_OFFS(10)]
	stp x12, x13, [x27, KAGE_PROC_REG_X_OFFS(12)]
	stp x14, x15, [x27, KAGE_PROC_REG_X_OFFS(14)]
	stp x16, x17, [x27, KAGE_PROC_REG_X_OFFS(16)]
	str x18,      [x27, KAGE_PROC_REG_X_OFFS(18)]
	mov x16, sp
	stp x30, x16,  [x27, KAGE_PROC_REG_X_OFFS(30)]
.endm

/* This trampoline is executed in the guest to return from a function called by
 * the host. */
.p2align 4
.globl do_ret
do_ret:
        mov x26, x30
	ldr x30, . + (KAGE_G2H_TRAMP_REGION_SIZE - 4)
        blr x30
.p2align 4
.globl do_ret_end
do_ret_end:

/* This code is called from guest to return back to the host when called
 * by lfi_asm_invoke */
.p2align 4
.globl lfi_ret
lfi_ret:
	GET_PROC
	// restore kernel stack from kage_proc.kstackp
	ldr x22, [x27, #KAGE_PROC_KSTACKP_OFFS]
	mov sp, x22
#ifdef CONFIG_SHADOW_CALL_STACK
	ldr x18, [x27, #KAGE_PROC_SSTACKP_OFFS]
#endif
	// restore callee-saved registers
	ldp x29, x30, [sp], 16
	ldp x27, x28, [sp], 16
	ldp x25, x26, [sp], 16
	ldp x23, x24, [sp], 16
	ldp x21, x22, [sp], 16
	ldp x19, x20, [sp], 16
	ret

	brk #0

/* This is used for the host to call into the guest from a new run context */
// lfi_asm_invoke(Proc* p, void* fn, unsigned long p0-p5)
.globl lfi_asm_invoke
lfi_asm_invoke:
	// x0 -> proc
	// x1 -> guest entry point
	// x2-x7 -> parameters to guest function

	// save callee-saved registers to stack
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	stp x29, x30, [sp, #-16]!

	// save kstack to proc->kstackp
	mov x16, sp
	str x16, [x0, #KAGE_PROC_KSTACKP_OFFS]

#ifdef CONFIG_SHADOW_CALL_STACK
	// save host shadow stack to proc->sstackp
	str x18, [x0, #KAGE_PROC_SSTACKP_OFFS]
	// set guest shadow stack
	ldr x18, [x0, #KAGE_PROC_REG_X_OFFS(18)]
#endif
	// set guest base
	ldr x27, [x0, #KAGE_PROC_REG_X_OFFS(27)]

	// set guest LR (return address)
	ldr x30, [x0, #KAGE_PROC_REG_X_OFFS(30)]

	// set guest stack
	ldr x16, [x0, #KAGE_PROC_REG_SP_OFFS]
	mov sp, x16


	mov x16, x1

	// Shift guest function parameters left 2 spots
	mov x0, x2
	mov x1, x3
	mov x2, x4
	mov x3, x5
	mov x4, x6
	mov x5, x7

	br x16
	brk #0

// Restore only caller-saved registers.
.globl lfi_restore_partial_regs
lfi_restore_partial_regs:
	ldp x2, x3,   [x0, KAGE_PROC_REG_X_OFFS(2)]
	ldp x4, x5,   [x0, KAGE_PROC_REG_X_OFFS(4)]
	ldp x6, x7,   [x0, KAGE_PROC_REG_X_OFFS(6)]
	ldp x8, x9,   [x0, KAGE_PROC_REG_X_OFFS(8)]
	ldp x10, x11, [x0, KAGE_PROC_REG_X_OFFS(10)]
	ldp x12, x13, [x0, KAGE_PROC_REG_X_OFFS(12)]
	ldp x14, x15, [x0, KAGE_PROC_REG_X_OFFS(14)]
	ldp x16, x17, [x0, KAGE_PROC_REG_X_OFFS(16)]
	ldr x18,      [x0, KAGE_PROC_REG_X_OFFS(18)]
	ldr x27,      [x0, KAGE_PROC_REG_X_OFFS(27)]
	ldp x30, x1,  [x0, KAGE_PROC_REG_X_OFFS(30)]
	mov sp, x1
	ldp x0, x1,   [x0, KAGE_PROC_REG_X_OFFS(0)]
	add x30, x27, w30, uxtw
	ret

/* The trampoline code region and the trampoline data region (aka literal pool)
 * are the same size.  This code will be duplicated in the code section as many
 * times as there are different guest kernel calls */

/* This code is repeated in the g2h text region.  Host calls in the
 * guest resolve to an instance of this */
.p2align 4
.globl lfi_g2h_trampoline
lfi_g2h_trampoline:
	 ldr     x17, . + (KAGE_G2H_TRAMP_REGION_SIZE)
	 ldr     x16, . + (KAGE_G2H_TRAMP_REGION_SIZE) + 4
	 br      x16
	 brk     #0

.globl lfi_g2h_trampoline_end
lfi_g2h_trampoline_end:

/* This code is repeated in h2g text region */
.p2align 4
.globl lfi_h2g_trampoline
lfi_h2g_trampoline:
	 ldr     x17, . + (KAGE_H2G_TRAMP_REGION_SIZE)
	 ldr     x16, . + (KAGE_H2G_TRAMP_REGION_SIZE) + 4
/* This instruction gets patched to branch to lfi_setup_kage_call */
	 brk     #0
	 brk     #0

.globl lfi_h2g_trampoline_end
lfi_h2g_trampoline_end:


// Used by the kernel to call callbacks registered by the guest
.p2align 7
.globl lfi_setup_kage_call
lfi_setup_kage_call:
	// Shift two registers to the right for kage * and fn params
	mov x7, x5
	mov x6, x4
	mov x5, x3
	mov x4, x2
	mov x3, x1
	mov x2, x0
	mov x1, x16
	mov x0, x17
	ldr x16, . + (KAGE_H2G_TRAMP_REGION_SIZE) - 32
	br x16
.p2align 4
.globl lfi_setup_kage_call_end
lfi_setup_kage_call_end:

/* Precondition: x17 == struct kage_g2h_call *. */
/* This code is jumped to from lfi_g2h_trampoline */
.globl lfi_g2h_entry
lfi_g2h_entry:
	SAVE_PARTIAL_REGS
	// struct kage_proc *proc == x27 now
	// sp = proc->kstackp
	ldr x16, [x27, KAGE_PROC_KSTACKP_OFFS]
	mov sp, x16

#ifdef CONFIG_SHADOW_CALL_STACK
	// x18 (shadow stack) = proc->sstackp
	ldr x18, [x27, KAGE_PROC_SSTACKP_OFFS]
#endif

	mov x0, x27 // 1st arg: proc ptr
	mov x1, x17 // 2nd arg: kage_g2h_call ptr
	ldr x17, [x17, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x17 // Call guard function
	// proc->regs[0] = return value from guard func
	str x0, [x27, KAGE_PROC_REG_X_OFFS(0)]
	mov x0, x27 // x0 = proc
	b  lfi_restore_partial_regs // head back to guest
	brk #0

/* Precondition: x17 == struct kage_g2h_call *. */
/* This code is jumped to from lfi_g2h_trampoline.  This entry is appropriate
 * for calling to manually coded guards that want (kage, p0, ...) parameters
 */
.globl lfi_g2h_entry_override
lfi_g2h_entry_override:
	// Save sp, shadow sp, FR, LR
	GET_PROC
	// struct kage_proc *proc == x27 now
#ifdef CONFIG_SHADOW_CALL_STACK
	str x18,      [x27, KAGE_PROC_REG_X_OFFS(18)]
#endif
	str x29,      [x27, KAGE_PROC_REG_X_OFFS(29)]
	mov x16, sp
	stp x30, x16,  [x27, KAGE_PROC_REG_X_OFFS(30)]

	// sp = proc->kstackp
	ldr x16, [x27, KAGE_PROC_KSTACKP_OFFS]
	mov sp, x16

#ifdef CONFIG_SHADOW_CALL_STACK
	// x18 (shadow stack) = proc->sstackp
	ldr x18, [x27, KAGE_PROC_SSTACKP_OFFS]
#endif

	/* Shift the argument registers to the right so proc,
	 * kage_g2h_call params are first */
	mov x7, x5
	mov x6, x4
	mov x5, x3
	mov x4, x2
	mov x3, x1
	mov x2, x0
	mov x1, x17 // Move kage_g2h_call * into second argument
	mov x0, x27 // Move kage_proc * into first argument
	ldr x17, [x17, KAGE_G2H_CALL_GUARD_FUNC_OFFS]

	blr x17 // Call guard function
	// proc->regs[0] = return value from guard func
	mov x17, x27 // kage_proc * into x0

	// Restore regs
#ifdef CONFIG_SHADOW_CALL_STACK
	ldr x18,      [x17, KAGE_PROC_REG_X_OFFS(18)]
#endif
	ldr x27,      [x17, KAGE_PROC_REG_X_OFFS(27)]
	ldr x29,      [x17, KAGE_PROC_REG_X_OFFS(29)]
	ldp x30, x16, [x17, KAGE_PROC_REG_X_OFFS(30)]
	mov sp, x16
	add x30, x27, w30, uxtw
	ret

	brk #0

/* Precondition: x17 == struct kage_g2h_call *. */
.globl lfi_g2h_entry_variadic
lfi_g2h_entry_variadic:
	// Save sp, shadow sp, FR, LR
	GET_PROC
	// struct kage_proc *proc == x27 now

	stp x0, x1,   [x27, KAGE_PROC_REG_X_OFFS(0)]
	stp x2, x3,   [x27, KAGE_PROC_REG_X_OFFS(2)]
	stp x4, x5,   [x27, KAGE_PROC_REG_X_OFFS(4)]
	stp x6, x7,   [x27, KAGE_PROC_REG_X_OFFS(6)]
#ifdef CONFIG_SHADOW_CALL_STACK
	str x18,      [x27, KAGE_PROC_REG_X_OFFS(18)]
#endif
	str x29,      [x27, KAGE_PROC_REG_X_OFFS(29)]
	mov x16, sp
	stp x30, x16,  [x27, KAGE_PROC_REG_X_OFFS(30)]

	str x19,      [x27, KAGE_PROC_REG_X_OFFS(19)]
	str x20,      [x27, KAGE_PROC_REG_X_OFFS(20)]
	str x22,      [x27, KAGE_PROC_REG_X_OFFS(22)]

	mov x1, sp

	mov x22, x17  // preserve kage_g2h_call

	// Copy Guest Stack Arguments to Host Stack

	// Get the host kernel stack pointer (offset 0 from kage_proc*)
	ldr x19, [x27]

	// Calculate the top of the guest's current stack
	add x20, x1, #KAGE_GUEST_STACK_SIZE
	and x20, x20, #~(KAGE_GUEST_STACK_SIZE-1)

	// Calculate the total space used on the guest stack
	sub   x20, x20, x1

	// Determine the number of bytes to copy (min(used, 256))
	mov   x15, #KAGE_MAX_STACK_ARGS_SIZE
	cmp   x20, x15
	csel  x20, x20, x15, lo


	// Make space on the host stack
	sub   x19, x19, x20

	mov   x0, x19   // dest: new (host) sp
	mov   x1, sp    // src: current (guest) sp
        mov   x2, x20   // size
	bl    memcpy

	// Switch to the host stack and shadow stack
	mov   sp, x0    // memcpy returns dest in x0
#ifdef CONFIG_SHADOW_CALL_STACK
	ldr   x18, [x27, #KAGE_PROC_SSTACKP_OFFS]
#endif

	// Call guard func 1 (guard_sig_precall)
	mov x0, x27   // kage_proc* is 1st parameter
	mov x1, x22   // kage_g2h_call* is 2nd parameter
	ldr x15, [x22, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x15
	cmp x0, #0
	b.ne return // don't call host function if guard fails

	// Call the host function
	ldp x0, x1, [x27, KAGE_PROC_REG_X_OFFS(0)]
	ldp x2, x3, [x27, KAGE_PROC_REG_X_OFFS(2)]
	ldp x4, x5, [x27, KAGE_PROC_REG_X_OFFS(4)]
	ldp x6, x7, [x27, KAGE_PROC_REG_X_OFFS(6)]
	ldr x15, [x22, KAGE_G2H_CALL_HOST_FUNC_OFFS]
	blr x15

	// Call guard func 2 (guard_sig_postcall)
	mov x2, x0
	mov x0, x27
	mov x1, x22
	ldr x15, [x22, #KAGE_G2H_CALL_GUARD_FUNC2_OFFS]
	bl guard_sig_postcall

	// rv preserved in x0

	return:

	// Cleanup
	add sp, sp, x20  // Restore the stack
	mov x17,    x27  // x17 = kage_proc*

	// Restore regs
	ldr x19,      [x17, KAGE_PROC_REG_X_OFFS(19)]
	ldr x20,      [x17, KAGE_PROC_REG_X_OFFS(20)]
	ldr x22,      [x17, KAGE_PROC_REG_X_OFFS(22)]
#ifdef CONFIG_SHADOW_CALL_STACK
	ldr x18,      [x17, KAGE_PROC_REG_X_OFFS(18)]
#endif
	ldr x27,      [x17, KAGE_PROC_REG_X_OFFS(27)]
	ldr x29,      [x17, KAGE_PROC_REG_X_OFFS(29)]
	ldp x30, x16, [x17, KAGE_PROC_REG_X_OFFS(30)]
	mov sp, x16
	add x30, x27, w30, uxtw
	ret

	brk #0

/* This trampoline is used during module loading for alternatives patching.
 * It is mapped into guest but only called by the host.  It is destroyed
 * before the guest starts executing. */
.p2align 4
.globl load_tramp
load_tramp:
	ldr x16, 1f
	br  x16
1:	.quad 0
.p2align 4
.globl load_tramp_end
load_tramp_end:

