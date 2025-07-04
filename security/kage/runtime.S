#include <linux/kage_asm.h>
.text

// All this code runs in the host, not the sandbox

// Places the pointer to the active LFIProc in x27.
.macro GET_PROC

/* Precondition: syspage (base of guest domain) in x27
   Find the base of the stack (highest address) and load index into kage->procs
   The stack is 8KiB (0x2000) aligned. We find the top of the 8KiB block
   that SP is in, and then load the 32-bit word from the very top. */
   /* Add the stack size-1 to SP to guarantee we are in the next block (except
      if we're already at the top of the stack */
    add   x16, sp, KAGE_GUEST_STACK_SIZE
    sub   x16, x16, 1
    // Clear the lower 13 bits to get the base address of the *next* 8KiB block
    and   x16, x16, ~(KAGE_GUEST_STACK_SIZE-1)
    // Load the 32-bit index from the last 4 bytes of the current stack block.
    ldr   w16, [x16, #-4] 
    // w16 now holds the index; the upper 32 bits of x16 are zeroed.
    // Check if the index is out of bounds (>= 8).
    cmp   w16, #8
    b.ge  1f

    ldr   x27, [x27, KAGE_LFISYS_PROCS_OFFS]          // Load LFISys->procs

    // Load LFISys->procs[i] into x27
    ldr   x27, [x27, x16, LSL #3]
    b     2f

1:
    /* FIXME: this is attacker controlled, but bounds checked by the other
     * side.  Can attacker do bad things by hijacking another thread context?
     * Solution: allocate an extra page when the stack is allocated, and then
     * mark it RO
     */
	b 1b
 
2:  // done
.endm

// save caller-saved registers, assuming sandbox syspage is x27
.macro SAVE_PARTIAL_REGS
	GET_PROC
	stp x0, x1,   [x27, KAGE_LFIPROC_REG_X_OFFS(0)]
	stp x2, x3,   [x27, KAGE_LFIPROC_REG_X_OFFS(2)]
	stp x4, x5,   [x27, KAGE_LFIPROC_REG_X_OFFS(4)]
	stp x6, x7,   [x27, KAGE_LFIPROC_REG_X_OFFS(6)]
	stp x8, x9,   [x27, KAGE_LFIPROC_REG_X_OFFS(8)]
	stp x10, x11, [x27, KAGE_LFIPROC_REG_X_OFFS(10)]
	stp x12, x13, [x27, KAGE_LFIPROC_REG_X_OFFS(12)]
	stp x14, x15, [x27, KAGE_LFIPROC_REG_X_OFFS(14)]
	stp x16, x17, [x27, KAGE_LFIPROC_REG_X_OFFS(16)]
	str x18,      [x27, KAGE_LFIPROC_REG_X_OFFS(18)]
	mov x1, sp
	stp x30, x1,  [x27, KAGE_LFIPROC_REG_X_OFFS(30)]
.endm

.macro RESTORE_INVOKE_REGS
	ldp x2, x3,   [x0, KAGE_LFIPROC_REG_X_OFFS(2)]
	ldp x4, x5,   [x0, KAGE_LFIPROC_REG_X_OFFS(4)]
	ldp x6, x7,   [x0, KAGE_LFIPROC_REG_X_OFFS(6)]
	ldp x8, x9,   [x0, KAGE_LFIPROC_REG_X_OFFS(8)]
	ldp x10, x11, [x0, KAGE_LFIPROC_REG_X_OFFS(10)]
	ldp x12, x13, [x0, KAGE_LFIPROC_REG_X_OFFS(12)]
	ldp x14, x15, [x0, KAGE_LFIPROC_REG_X_OFFS(14)]
	ldp x16, x17, [x0, KAGE_LFIPROC_REG_X_OFFS(16)]
	ldr x18,      [x0, KAGE_LFIPROC_REG_X_OFFS(18)]
	ldr x27,      [x0, KAGE_LFIPROC_REG_X_OFFS(27)]
	ldp x30, x1,  [x0, KAGE_LFIPROC_REG_X_OFFS(30)]
	mov sp, x1
	ldp x0, x1,   [x0, KAGE_LFIPROC_REG_X_OFFS(0)]
.endm

/* This code is called from guest to return back to the host when called
 * by lfi_asm_invoke, as well as when the guest calls into the host */
.p2align 4
.globl lfi_ret
lfi_ret:
	GET_PROC
	// restore kernel stack from LFIProc.kstackp
	ldr x22, [x27, #KAGE_LFIPROC_KSTACKP_OFFS]
	mov sp, x22
	// restore callee-saved registers
	ldp x29, x30, [sp], 16
	ldp x27, x28, [sp], 16
	ldp x25, x26, [sp], 16
	ldp x23, x24, [sp], 16
	ldp x21, x22, [sp], 16
	ldp x19, x20, [sp], 16
	ldr x18,      [sp], 16
	mov x15, 0
	ret

/* This is used for the host to call into the guest from a new run context */
// lfi_asm_invoke(Proc* p, void* fn, void** kstackp)
.globl lfi_asm_invoke
lfi_asm_invoke:
	// save callee-saved registers to stack
	str x18, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	// save stack to kstackp
	mov x22, x1
	mov x3, sp
	str x3, [x2] //*3rd param = $sp
	RESTORE_INVOKE_REGS
	br x22
	brk #0

// Restore only caller-saved registers.
.globl lfi_restore_partial_regs
lfi_restore_partial_regs:
	ldp x2, x3,   [x0, KAGE_LFIPROC_REG_X_OFFS(2)]
	ldp x4, x5,   [x0, KAGE_LFIPROC_REG_X_OFFS(4)]
	ldp x6, x7,   [x0, KAGE_LFIPROC_REG_X_OFFS(6)]
	ldp x8, x9,   [x0, KAGE_LFIPROC_REG_X_OFFS(8)]
	ldp x10, x11, [x0, KAGE_LFIPROC_REG_X_OFFS(10)]
	ldp x12, x13, [x0, KAGE_LFIPROC_REG_X_OFFS(12)]
	ldp x14, x15, [x0, KAGE_LFIPROC_REG_X_OFFS(14)]
	ldp x16, x17, [x0, KAGE_LFIPROC_REG_X_OFFS(16)]
	ldr x18,      [x0, KAGE_LFIPROC_REG_X_OFFS(18)]
	ldr x27,      [x0, KAGE_LFIPROC_REG_X_OFFS(27)]
	ldp x30, x1,  [x0, KAGE_LFIPROC_REG_X_OFFS(30)]
	mov sp, x1
	ldp x0, x1,   [x0, KAGE_LFIPROC_REG_X_OFFS(0)]
	add x30, x27, w30, uxtw
	ret

// lfi_restore_regs(Proc* p)
// Restores registers from the given Proc struct.
// This function does not return.
.p2align 4
.globl lfi_restore_regs
lfi_restore_regs:
	ldp x2, x3,   [x0, KAGE_LFIPROC_REG_X_OFFS(2)]
	ldp x4, x5,   [x0, KAGE_LFIPROC_REG_X_OFFS(4)]
	ldp x6, x7,   [x0, KAGE_LFIPROC_REG_X_OFFS(6)]
	ldp x8, x9,   [x0, KAGE_LFIPROC_REG_X_OFFS(8)]
	ldp x10, x11, [x0, KAGE_LFIPROC_REG_X_OFFS(10)]
	ldp x12, x13, [x0, KAGE_LFIPROC_REG_X_OFFS(12)]
	ldp x14, x15, [x0, KAGE_LFIPROC_REG_X_OFFS(14)]
	ldp x16, x17, [x0, KAGE_LFIPROC_REG_X_OFFS(16)]
	ldp x18, x19, [x0, KAGE_LFIPROC_REG_X_OFFS(18)]
	ldp x20, x21, [x0, KAGE_LFIPROC_REG_X_OFFS(20)]
	ldp x22, x23, [x0, KAGE_LFIPROC_REG_X_OFFS(22)]
	ldp x24, x25, [x0, KAGE_LFIPROC_REG_X_OFFS(24)]
	ldp x26, x27, [x0, KAGE_LFIPROC_REG_X_OFFS(26)]
	ldp x28, x29, [x0, KAGE_LFIPROC_REG_X_OFFS(28)]
	ldp x30, x1,  [x0, KAGE_LFIPROC_REG_X_OFFS(30)]
	mov sp, x1
	ldp x0, x1,   [x0, KAGE_LFIPROC_REG_X_OFFS(0)]
	add x30, x27, w30, uxtw
	ret
	brk #0

/* The trampoline code region and the trampoline data region (aka literal pool)
 * are the same size, separated by an empty page.  This code will be duplicated
 * in the code section as many times as there are different guest kernel calls
 * */

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
	 ldr     x17, . + (KAGE_G2H_TRAMP_REGION_SIZE)
	 ldr     x16, . + (KAGE_G2H_TRAMP_REGION_SIZE) + 4
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
	ldr x16, . + (KAGE_G2H_TRAMP_REGION_SIZE) - 32
	br x16
.globl lfi_setup_kage_call_end
lfi_setup_kage_call_end:

/* Precondition: x17 == struct kage_g2h_call *. */
/* This code is jumped to from lfi_g2h_trampoline */
.globl lfi_syscall_entry2
lfi_syscall_entry2:
	SAVE_PARTIAL_REGS
	// struct LFIProc *proc == x27 now
	// sp = proc->kstackp
	ldr x16, [x27, KAGE_LFIPROC_KSTACKP_OFFS]
	mov sp, x16
	mov x0, x27 // 1st arg: proc ptr
	mov x1, x17 // 2nd arg: kage_g2h_call ptr
	ldr x17, [x17, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x17 // Call guard function
	// proc->regs[0] = return value from guard func
	str x0, [x27, KAGE_LFIPROC_REG_X_OFFS(0)]
	mov x0, x27 // x0 = proc
	b  lfi_restore_partial_regs // head back to guest
	brk #0

/* Precondition: x17 == struct kage_host_call *. */
/* This code is jumped to from lfi_g2h_trampoline.  This entry is appropriate for
 * calling to manually coded guards that want (kage, p0, ...) parameters
 */
.globl lfi_syscall_entry_override
lfi_syscall_entry_override:
	SAVE_PARTIAL_REGS
	// struct LFIProc *proc == x27 now

	// sp = proc->kstackp
	ldr x16, [x27, KAGE_LFIPROC_KSTACKP_OFFS]
	mov sp, x16

	/* Shift the argument registers to the right so kage param is first */
	mov x7, x6
	mov x6, x5
	mov x5, x4
	mov x4, x3
	mov x3, x2
	mov x2, x1
	mov x1, x0
	mov x0, x27 // Move LFIProc * into first argument
	ldr x17, [x17, KAGE_G2H_CALL_GUARD_FUNC_OFFS]

	blr x17 // Call guard function
	// proc->regs[0] = return value from guard func
	str x0, [x27, KAGE_LFIPROC_REGS_OFFS+16*0]
	mov x0, x27 // LFIProc * into x0
	b  lfi_restore_partial_regs
	brk #0

/* Precondition: x17 == struct kage_g2h_call *. */
.globl lfi_syscall_entry_variadic
lfi_syscall_entry_variadic:
	SAVE_PARTIAL_REGS
	// FIXME: would be slightly more optimal to group two of these, e.g.
	// x20 -> x23
	str x19,      [x27, KAGE_LFIPROC_REG_X_OFFS(19)]
	str x20,      [x27, KAGE_LFIPROC_REG_X_OFFS(20)]
	str x22,      [x27, KAGE_LFIPROC_REG_X_OFFS(22)]
	// x27 now contains LFIProc*
	// x1 still contains guest sp

	// Copy Guest Stack Arguments to Host Stack

	// Get the host kernel stack pointer (offset 0 from LFIProc*)
	ldr   x19, [x27]

	// Calculate the top of the guest's current stack
	add   x20, x1, #KAGE_GUEST_STACK_SIZE
	and   x20, x20, #~(KAGE_GUEST_STACK_SIZE-1)

	// Calculate the total space used on the guest stack
	sub   x20, x20, x1

	// Determine the number of bytes to copy (min(used, 256))
	mov   x15, #KAGE_MAX_STACK_ARGS_SIZE
	cmp   x20, x15
	csel  x20, x20, x15, lo
	
	mov x22, x17  // preserve kage_g2h_call

	// Make space on the host stack
	sub   x19, x19, x20

	mov   x0, x19   // dest: new (host) sp
	mov   x1, sp    // src: current (guest) sp
        mov   x2, x20   // size
	bl    memcpy

	// Switch to the host stack 
	mov   sp, x0    // memcpy returns dest in x0

	// Call guard func 1 (guard_sig_precall)
	mov x0, x27   // LFIProc* is 1st parameter
	mov x1, x22   // kage_g2h_call* is 2nd parameter
	ldr x15, [x22, KAGE_G2H_CALL_GUARD_FUNC_OFFS]
	blr x15
	cmp x0, #0
	b.ne 0f   // don't call host function if guard fails

	// Call the host function
	ldp x0, x1,   [x27, KAGE_LFIPROC_REG_X_OFFS(0)]
	ldp x2, x3,   [x27, KAGE_LFIPROC_REG_X_OFFS(2)]
	ldp x4, x5,   [x27, KAGE_LFIPROC_REG_X_OFFS(4)]
	ldp x6, x7,   [x27, KAGE_LFIPROC_REG_X_OFFS(6)]
	ldr x15, [x22, KAGE_G2H_CALL_HOST_FUNC_OFFS]
	blr x15

	// Call guard func 2 (guard_sig_postcall)
	mov x2, x0
	mov x0, x27
	mov x1, x22
	ldr x15, [x22, #KAGE_G2H_CALL_GUARD_FUNC2_OFFS]
	bl guard_sig_postcall

	0: 
	str x0, [x27, KAGE_LFIPROC_REG_X_OFFS(0)] // Save return value

	// Copy arguments back to guest stack
	ldr   x0, [x27, KAGE_LFIPROC_REG_X_OFFS(31)] // dest: original guest sp
	mov   x1, sp    // src: current (host) sp
        mov   x2, x20   // size
	bl    memcpy

	// Cleanup
	add sp, sp, x20  // Restore the stack
	mov x0, x27 // LFIProc* into x0 for the return path
	ldr x19,      [x0, KAGE_LFIPROC_REG_X_OFFS(19)]
	ldr x20,      [x0, KAGE_LFIPROC_REG_X_OFFS(20)]
	ldr x22,      [x0, KAGE_LFIPROC_REG_X_OFFS(22)]
	b  lfi_restore_partial_regs
	brk #0



