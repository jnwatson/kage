#ifndef _KAGE_RUNTIME_H_
#define _KAGE_RUNTIME_H_

extern void lfi_syscall_entry(void);
extern void lfi_syscall_entry_override(void);
extern void lfi_syscall_entry_variadic(void);
extern void lfi_ret(void);
extern void lfi_g2h_trampoline_end(void);
extern void lfi_g2h_trampoline(void);
extern void lfi_h2g_trampoline_end(void);
extern void lfi_h2g_trampoline(void);
extern void lfi_setup_kage_call(void);
extern void lfi_setup_kage_call_end(void);

#endif
