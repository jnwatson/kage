#ifndef _KAGE_RUNTIME_H_
#define _KAGE_RUNTIME_H_

extern void lfi_g2h_entry(void);
extern void lfi_g2h_entry_override(void);
extern void lfi_g2h_entry_variadic(void);
extern void lfi_g2h_entry_variadic_end(void);
extern void lfi_ret(void);
extern void lfi_g2h_trampoline_end(void);
extern void lfi_g2h_trampoline(void);
extern void lfi_h2g_trampoline_end(void);
extern void lfi_h2g_trampoline(void);
extern void lfi_setup_kage_call(void);
extern void lfi_setup_kage_call_end(void);
extern void do_ret(void);
extern void do_ret_end(void);
extern void load_tramp(void);
extern void load_tramp_end(void);

struct kage_proc;
extern unsigned long lfi_asm_invoke(struct kage_proc *proc,
				    unsigned long p0, unsigned long p1,
				    unsigned long p2, unsigned long p3,
				    unsigned long p4, unsigned long p5);

#endif
