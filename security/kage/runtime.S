#define N_RTCALLS 256
#define PROC_REGS 16

#define STACK_ORDER 13
.text

// All this code does not run in the sandbox

// Places the pointer to the active LFIProc in x21.
.macro GET_PROC

// Assumes syspage (base of sandbox) in x21
// FIXME: remove magic numbers
// Find the base of the stack (highest address) and load index into kage->procs
//    The stack is 8KiB (0x2000) aligned. We find the top of the 8KiB block
//    that SP is in, and then load the 32-bit word from the very top.
    add   x22, sp, #0x2000                // Add the stack size to SP to guarantee we are in the next block
    and   x22, x22, #~0x1FFF              // Clear the lower 13 bits to get the base address of the *next* 8KiB block
    ldr   w22, [x22, #-4]                 // Load the 32-bit index from the last 4 bytes of the current stack block.
                                          // w22 now holds the index; the upper 32 bits of x22 are zeroed.
// Check if the index is out of bounds (>= 8).
    cmp   w22, #8
    b.ge  1f

    ldr   x21, [x21, #2048]                      // Load LFISys->procs

// Load LFISys->procs[i] into x21
    ldr   x21, [x21, x22, LSL #3]
    b     2f

1:
    mov   x21, #0  // FIXME: this is attacker controlled
    brk #0
2:  // done
.endm

// save caller-saved registers, assuming sandbox syspage is x21
.macro SAVE_PARTIAL_REGS
	GET_PROC
	stp x0, x1,   [x21, PROC_REGS+16*0]
	stp x2, x3,   [x21, PROC_REGS+16*1]
	stp x4, x5,   [x21, PROC_REGS+16*2]
	stp x6, x7,   [x21, PROC_REGS+16*3]
	stp x8, x9,   [x21, PROC_REGS+16*4]
	stp x10, x11, [x21, PROC_REGS+16*5]
	stp x12, x13, [x21, PROC_REGS+16*6]
	stp x14, x15, [x21, PROC_REGS+16*7]
	stp x16, x17, [x21, PROC_REGS+16*8]
	str x18,      [x21, PROC_REGS+16*9]
	mov x1, sp
	stp x30, x1,  [x21, PROC_REGS+16*15]
	mrs x0, nzcv
	mrs x1, fpsr
	stp x0, x1, [x21, PROC_REGS+8*34]
.endm

.macro RESTORE_INVOKE_REGS
	ldp x2, x3,   [x0, PROC_REGS+16*1]
	ldp x4, x5,   [x0, PROC_REGS+16*2]
	ldp x6, x7,   [x0, PROC_REGS+16*3]
	ldp x8, x9,   [x0, PROC_REGS+16*4]
	ldp x10, x11, [x0, PROC_REGS+16*5]
	ldp x12, x13, [x0, PROC_REGS+16*6]
	ldp x14, x15, [x0, PROC_REGS+16*7]
	ldp x16, x17, [x0, PROC_REGS+16*8]
	ldr x18,      [x0, PROC_REGS+16*9]
	ldr x21,      [x0, PROC_REGS+16*10+8]
	ldp x30, x1,  [x0, PROC_REGS+16*15]
	mov sp, x1
	ldp x0, x1,   [x0, PROC_REGS+16*0]
.endm

// Accelerated return for library sandboxes.
// called from sandbox
.p2align 4
.globl lfi_ret
lfi_ret:
	GET_PROC
	// restore kernel stack from LFIProc.kstackp
	ldr x22, [x21]
	mov sp, x22
	// restore callee-saved registers
	ldp x29, x30, [sp], 16
	ldp x27, x28, [sp], 16
	ldp x25, x26, [sp], 16
	ldp x23, x24, [sp], 16
	ldp x21, x22, [sp], 16
	ldp x19, x20, [sp], 16
	ldp x18, x18, [sp], 16
	ret

// lfi_asm_invoke(Proc* p, void* fn, void** kstackp)
.p2align 4
.globl lfi_asm_invoke
lfi_asm_invoke:
	// save callee-saved registers to stack
	stp x18, x18, [sp, #-16]!
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	// save stack to kstackp
	mov x22, x1
	mov x3, sp
	str x3, [x2]
	RESTORE_INVOKE_REGS
	br x22
	brk #0

// lfi_proc_entry(LFIProc* p, void** kstackp)
.p2align 4
.globl lfi_proc_entry
lfi_proc_entry:
	// save callee-saved registers to stack
	stp x19, x20, [sp, #-16]!
	stp x21, x22, [sp, #-16]!
	stp x23, x24, [sp, #-16]!
	stp x25, x26, [sp, #-16]!
	stp x27, x28, [sp, #-16]!
	stp x29, x30, [sp, #-16]!
	// save stack to kstackp
	mov x2, sp
	str x2, [x1]
	b lfi_restore_regs
	brk #0

// lfi_asm_proc_exit(uintptr kstackp)
.p2align 4
.globl lfi_asm_proc_exit
lfi_asm_proc_exit:
	mov sp, x0
	mov x0, x1
	ldp x29, x30, [sp], 16
	ldp x27, x28, [sp], 16
	ldp x25, x26, [sp], 16
	ldp x23, x24, [sp], 16
	ldp x21, x22, [sp], 16
	ldp x19, x20, [sp], 16
	ret

.p2align 4
.globl lfi_syscall_entry
lfi_syscall_entry:
	SAVE_PARTIAL_REGS
	// x21 now contains Proc*
	ldr x1, [x21]         // load stack
	mov sp, x1
	str x21, [sp, #-16]!
	mov x0, x21
	bl lfi_syscall_handler
	ldr x0, [sp], 16
	b  lfi_restore_partial_regs
	brk #0

.p2align 4
.globl lfi_yield_entry
lfi_yield_entry:
	brk #0

// Restore only caller-saved registers.
.p2align 4
.globl lfi_restore_partial_regs
lfi_restore_partial_regs:
	ldp x1, x2, [x0, PROC_REGS+8*34]
	ldp x2, x3,   [x0, PROC_REGS+16*1]
	ldp x4, x5,   [x0, PROC_REGS+16*2]
	ldp x6, x7,   [x0, PROC_REGS+16*3]
	ldp x8, x9,   [x0, PROC_REGS+16*4]
	ldp x10, x11, [x0, PROC_REGS+16*5]
	ldp x12, x13, [x0, PROC_REGS+16*6]
	ldp x14, x15, [x0, PROC_REGS+16*7]
	ldp x16, x17, [x0, PROC_REGS+16*8]
	ldr x18,      [x0, PROC_REGS+16*9]
	ldr x21,      [x0, PROC_REGS+16*10+8]
	ldp x30, x1,  [x0, PROC_REGS+16*15]
	mov sp, x1
	ldp x0, x1,   [x0, PROC_REGS+16*0]
	add x30, x21, w30, uxtw
	ret

// lfi_restore_regs(Proc* p)
// Restores registers from the given Proc struct.
// This function does not return.
.p2align 4
.globl lfi_restore_regs
lfi_restore_regs:
	ldp x1, x2, [x0, PROC_REGS+8*34]
	ldp x2, x3,   [x0, PROC_REGS+16*1]
	ldp x4, x5,   [x0, PROC_REGS+16*2]
	ldp x6, x7,   [x0, PROC_REGS+16*3]
	ldp x8, x9,   [x0, PROC_REGS+16*4]
	ldp x10, x11, [x0, PROC_REGS+16*5]
	ldp x12, x13, [x0, PROC_REGS+16*6]
	ldp x14, x15, [x0, PROC_REGS+16*7]
	ldp x16, x17, [x0, PROC_REGS+16*8]
	ldp x18, x19, [x0, PROC_REGS+16*9]
	ldp x20, x21, [x0, PROC_REGS+16*10]
	ldp x22, x23, [x0, PROC_REGS+16*11]
	ldp x24, x25, [x0, PROC_REGS+16*12]
	ldp x26, x27, [x0, PROC_REGS+16*13]
	ldp x28, x29, [x0, PROC_REGS+16*14]
	ldp x30, x1,  [x0, PROC_REGS+16*15]
	mov sp, x1
	ldp x0, x1,   [x0, PROC_REGS+16*0]
	add x30, x21, w30, uxtw
	ret

#ifndef __APPLE__
.section .note.GNU-stack,"",@progbits
#endif
