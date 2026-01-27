#include <linux/kage_asm.h>

.text

// Places the pointer to the active kage_proc in x27.
.macro GET_PROC
/* Precondition: x27 == guest base
   Postcondition: x27 == proc* */

    /* Add (stack size - 1) to SP to guarantee we are in the next block (except
       if we're already at the top of the stack) */
    add   x16, sp, KAGE_GUEST_STACK_SIZE
    sub   x16, x16, 1
    // Clear the lower 13 bits to get the base address of the *next* 8KiB block
    and   x16, x16, ~(KAGE_GUEST_STACK_SIZE-1)
    // Load proc from the first bytes past the stack (in "proc data")
    ldr   x27, [x16]
.endm

// save sp, shadow sp, FR, LR
// Precondition: x27 == guest base
.macro SAVE_PARTIAL_REGS
	GET_PROC
	// x27 == struct kage_proc *proc
	mov x16, sp
	stp x16, x30, [x27, KAGE_PROC_REG_X_OFFS(0)]
#ifdef CONFIG_SHADOW_CALL_STACK
	stp x18, x29, [x27, KAGE_PROC_REG_X_OFFS(2)]
#else
	str x29,      [x27, KAGE_PROC_REG_X_OFFS(3)]
#endif
.endm

// Restore registers saved by SAVE_PARTIAL_REGS + x27 and return to guest
// Precondition: x17 == proc*
.globl lfi_restore_partial_regs
lfi_restore_partial_regs:
#ifdef CONFIG_SHADOW_CALL_STACK
	ldp x18, x29, [x17, KAGE_PROC_REG_X_OFFS(2)] // ssp and FR
#else
	ldr x29,      [x17, KAGE_PROC_REG_X_OFFS(3)] // FP
#endif
	ldp x16, x30, [x17, #KAGE_PROC_REG_X_OFFS(0)] // SP and LR
	mov sp, x16

	// x27 = proc->kage->base
	ldr x16,  [x17, #KAGE_PROC_KAGE_OFFS]
	ldr x27,  [x16, #KAGE_BASE_OFFS]

	add x30, x27, w30, uxtw
	ret


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
// lfi_asm_invoke(Proc* p, unsigned long p0-p5)
.globl lfi_asm_invoke
lfi_asm_invoke:
	// x0 -> proc
	// x1-x6 -> parameters to guest function

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
	ldr x18, [x0, #KAGE_PROC_REG_X_OFFS(2)]
#endif
	// set guest base x27 = proc->kage->base
	ldr x16, [x0, #KAGE_PROC_KAGE_OFFS]
	ldr x27, [x16, #KAGE_BASE_OFFS]

	// Clear FP
	mov x29, 0

	// set guest stack, LR
	ldp x16, x30, [x0, #KAGE_PROC_REG_X_OFFS(0)]
	mov sp, x16

	ldr x16, [x0, #KAGE_PROC_ENTRY_OFFS]

	// Shift guest function parameters left 1 spot
	mov x0, x1
	mov x1, x2
	mov x2, x3
	mov x3, x4
	mov x4, x5
	mov x5, x6

	br x16
	brk #0

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
	sub sp, sp, #KAGE_PROC_ARGS_SIZE
	stp x0, x1,   [sp, #0]
	stp x2, x3,   [sp, #16]
	stp x4, x5,   [sp, #32]
	stp x6, x7,   [sp, #48]

	mov x0, x27 // 1st arg: proc *
	mov x1, x17 // 2nd arg: kage_g2h_call *
	mov x2, sp  // 3rd arg: kage_proc_args *
	ldr x17, [x17, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x17 // Call guard function

	mov x17, x27  // x17 = kage_proc*

	// not strictly necessary since proc->kstackp is intact
	// add sp, sp, #KAGE_PROC_ARGS_SIZE

	b lfi_restore_partial_regs

/* Precondition: x17 == struct kage_g2h_call *. */
/* This code is jumped to from lfi_g2h_trampoline.  This entry is appropriate
 * for calling to manually coded guards that want (kage, p0, ...) parameters
 *
 * Note: clobbers x16
 */
.globl lfi_g2h_entry_override
lfi_g2h_entry_override:
	SAVE_PARTIAL_REGS

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

	b lfi_restore_partial_regs

.globl lfi_g2h_entry_variadic
lfi_g2h_entry_variadic:
/* Precondition: x17 == struct kage_g2h_call *. */
	SAVE_PARTIAL_REGS

	// Get the host kernel stack pointer (offset from kage_proc*)
	ldr x16, [x27, KAGE_PROC_KSTACKP_OFFS]

	// Allocate space for an args struct plus 2 temp vars
	sub x9, x16, #KAGE_PROC_ARGS_SIZE + 16

	stp x0, x1,   [x9, 0]
	stp x2, x3,   [x9, #16]
	stp x4, x5,   [x9, #32]
	stp x6, x7,   [x9, #48]
	stp x20, x21, [x9, #64]
	str x22,      [x9, #80]

	mov x22, x9 // x22 == *kage_proc_args

	mov x1, sp

	mov x21, x17  // preserve kage_g2h_call into callee-saved

	// Copy Guest Stack Arguments to Host Stack

	// Calculate the top of the guest's current stack
	add x20, x1, #KAGE_GUEST_STACK_SIZE
	and x20, x20, #~(KAGE_GUEST_STACK_SIZE-1)

	// Calculate the total space used on the guest stack
	sub  x20, x20, x1

	// Determine the number of bytes to copy (min(used, 256))
	mov  x15, #KAGE_MAX_STACK_ARGS_SIZE
	cmp  x20, x15
	csel x20, x20, x15, lo

	// Make space on the host stack
	sub   x16, x22, x20

	mov   x0, x16   // dest: new (host) sp
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
	mov x1, x21   // kage_g2h_call* is 2nd parameter
	mov x2, x22   // kage_proc_args* is 3rd parameter
	ldr x15, [x21, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x15
	cmp x0, #0
	b.ne return // don't call host function if guard fails

	// Call the host function.  Note that precall might have modified args
	ldp x0, x1, [x22, #0]
	ldp x2, x3, [x22, #16]
	ldp x4, x5, [x22, #32]
	ldp x6, x7, [x22, #48]
	ldr x15, [x21, KAGE_G2H_CALL_HOST_FUNC_OFFS]
	blr x15

	// Call guard func 2 (guard_sig_postcall)
	mov x2, x0
	mov x0, x27
	mov x1, x21
	ldr x15, [x21, #KAGE_G2H_CALL_GUARD_FUNC2_OFFS]
	bl guard_sig_postcall
	// rv preserved in x0

	return:

	// Not necessary since proc->kstackp is intact
	// add sp, sp, x20  // Restore the stack
	// add sp, sp, #KAGE_PROC_ARGS_SIZE + 16

	// Restore regs
	mov x17, x27  // x17 = kage_proc*
	mov x9, x22

	ldp x20, x21, [x9, #64]
	ldr x22,      [x9, #80]
	b lfi_restore_partial_regs

.globl lfi_g2h_entry_override_variadic
lfi_g2h_entry_override_variadic:
/* Precondition: x17 == struct kage_g2h_call *. */
	SAVE_PARTIAL_REGS // sets x27=proc, clobbers x16

	// 1. Save guest registers immediately to the host kernel stack
	ldr x16, [x27, KAGE_PROC_KSTACKP_OFFS]
	sub x16, x16, #96 // space for x0-x7 (64) + x19-x22 (32)
	stp x0, x1,   [x16, #0]
	stp x2, x3,   [x16, #16]
	stp x4, x5,   [x16, #32]
	stp x6, x7,   [x16, #48]
	stp x19, x20, [x16, #64]
	stp x21, x22, [x16, #80]

	mov x22, x16 // x22 = base of register save area
	mov x21, x17 // x21 = call pointer
	
	// 2. Calculate guest stack usage
	mov x1, sp    // guest sp
	add x20, x1, #KAGE_GUEST_STACK_SIZE
	and x20, x20, #~(KAGE_GUEST_STACK_SIZE-1)
	sub x20, x20, x1
	mov x15, #KAGE_MAX_STACK_ARGS_SIZE
	cmp x20, x15
	csel x20, x20, x15, lo

	// 3. Allocate host stack for [x6, x7] and [stack args]
	// Space needed: x20 (args) + 16 (x6,x7), 16-byte aligned
	add x19, x20, #16
	add x19, x19, #15
	and x19, x19, #~15
	sub sp, x22, x19

	// 4. Copy Guest Stack Arguments
	mov x0, sp
	add x0, x0, #16 // dest (leave room for x6/x7 shadow)
	// x1 is still guest sp
	mov x2, x20
	bl memcpy

	// 5. Copy guest x6, x7 to the host stack shadow area
	ldp x6, x7, [x22, #48]
	stp x6, x7, [sp]

#ifdef CONFIG_SHADOW_CALL_STACK
	ldr x18, [x27, #KAGE_PROC_SSTACKP_OFFS]
#endif

	// 6. Call the override guard
	// guard(proc, call, g_x0, g_x1, g_x2, g_x3, g_x4, g_x5, ...)
	ldp x2, x3, [x22, #0]
	ldp x4, x5, [x22, #16]
	ldp x6, x7, [x22, #32]
	mov x1, x21 // call
	mov x0, x27 // proc
	ldr x15, [x21, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x15

	// 7. Restore and return
	mov x17, x27
	ldp x19, x20, [x22, #64]
	ldp x21, x22, [x22, #80]
	b lfi_restore_partial_regs

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

