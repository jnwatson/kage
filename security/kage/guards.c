// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */
#include "linux/kage_asm.h"
#include <linux/assoc_array.h>
#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/dynamic_debug.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/kage.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/stdarg.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/genalloc.h>
#include <linux/klist.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/fortify-string.h>
#ifdef CONFIG_GOOGLE_LOGBUFFER
#include <linux/logbuffer.h>
#endif
#include <linux/mutex.h>
#include <linux/nvmem-provider.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/pm_wakeup.h>
#include <linux/power_supply.h>
#include <linux/regmap.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/usb/tcpm.h>
#ifdef CONFIG_CHARGER_MAX77759
#include <linux/usb/max77759_export.h>
#endif

#include <linux/kage_syscall.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "objdesc.h"
#include "sigs.h"

// DEBUG
#pragma clang optimize off

static unsigned long guard_kmalloc_trace(struct LFIProc *proc, 
					 struct kmem_cache *s, gfp_t flags, 
					 size_t size)
{
	return (unsigned long)kage_memory_alloc(proc->kage, size, MOD_DATA, flags);
}

/* Parses and returns a positive integer while advancing the pointer.
 * Postcondition: *str points to the last character of number */
static u32 eat_num(const char **str) {
	u32 objidx = 0;
	bool valid = false;
	const char *s = *str;
	while (1) {
		s++;
		if (s[0] < '0' || s[0] > '9')
			break;
		objidx = objidx * 10 + s[0] - '0';
		valid = true;
	}
	if (valid)
		*str = s - 1;
	return objidx;
}

/* Resides in h2g_tramp_data; corresponding trampoline precedes this by 
 * KAGE_H2G_TRAMP_REGION_SIZE bytes */
struct h2g_tramp_data_entry {
	struct kage *kage;
	u64 guest_func; // callback into guest
};
static_assert(sizeof(struct h2g_tramp_data_entry)==KAGE_H2G_TRAMP_SIZE);

// Returns the next slot in the literal pool
// Note that the kage->lock should be held when calling
static struct kage_h2g_tramp_data_entry * alloc_h2g_entry(struct kage * kage) {
	struct kage_h2g_tramp_data_entry * ret;
	if (kage->num_h2g_calls >= KAGE_MAX_H2G_CALLS)
		return NULL;

	ret = &kage->h2g_tramp_data[kage->num_h2g_calls++];

	return ret;
}

static unsigned long get_key_chunk(const void * index_key, int level)
{
	return ((unsigned long)index_key >>
		(level * ASSOC_ARRAY_KEY_CHUNK_SIZE)) &
	       (ASSOC_ARRAY_KEY_CHUNK_SIZE - 1);
}

static unsigned long get_h2g_key_chunk(const void *object, int level)
{
	struct kage_h2g_tramp_data_entry * entry = 
		  (struct kage_h2g_tramp_data_entry *)object;

	// indexing on the guest_func pointer
	const unsigned long index_key = entry->guest_func;

	return get_key_chunk((void *)index_key, level);
}

static const struct assoc_array_ops kage_h2g_closure_ops = {
	.get_key_chunk = get_key_chunk,
	.get_object_key_chunk = get_h2g_key_chunk,
};

/* Returns a closure over the guest function, capturing kage and the function
 * address.  The returned new function, when called, calls kage_call with the
 * first two arguments being kage and func.
 *
 * The associate array (aka dict) stores entry pointers indexed by the original
 * function, so if the guest uses the same callback twice (or just uses it in a
 * loop), it only allocates one closure.  The entry pointer is exactly
 * KAGE_H2G_TRAMP_REGION_SIZE ahead of the actual call site, since the entry is
 * the part of the literal pool that the call site uses.  The call site is
 * pointing to an instance of lfi_h2g_trampoline.
 * */
static void *get_closure_over(struct kage *kage, unsigned long func)
{
	unsigned long irq_flags;
	struct assoc_array_edit *edit;
	void *rv;
	struct kage_h2g_tramp_data_entry * entry;
	if ((func - kage->base) >= KAGE_GUEST_SIZE) {
		return ERR_PTR(-EINVAL);
	}

	spin_lock_irqsave(&kage->lock, irq_flags);
	entry = assoc_array_find(&kage->closures, &kage_h2g_closure_ops,
				   (void *)func);
	if (entry)
		goto finish;

	entry = alloc_h2g_entry(kage);
	if (!entry) {
		rv = ERR_PTR(-ENOMEM);
		goto on_err;
	}

	entry->kage = kage;
	entry->guest_func = func;

	edit = assoc_array_insert(&kage->closures, &kage_h2g_closure_ops,
				  (void *)func, entry);
	if (IS_ERR(edit)) {
		rv = edit;
		goto on_err;
	}
	assoc_array_apply_edit(edit);
finish:
	rv = (void *)((u64)entry - KAGE_H2G_TRAMP_REGION_SIZE);
        pr_info("closure_over created at 0x%lx for guest func 0x%lx",
                (unsigned long)rv, func);
on_err:
	spin_unlock_irqrestore(&kage->lock, irq_flags);
	return rv;
}

struct rv_sig {
	bool rv_is_ptr;
	bool rv_is_obj;
	u32 rv_obj_type;
};

// Called from lfi_syscall_variadic
/* Guards and calls a host call using just its signature */
int guard_sig_precall(struct LFIProc *proc, struct kage_g2h_call *host_call)
{
	const char *sig = host_call->sig;
	LFIRegs *regs = &proc->regs;
	int regnum = -1;
	u32 objidx;
	u64 val = 0;
	while(sig[0]) {
		if (regnum >= 0)
			val = ((u64 *)regs)[regnum];
		switch (sig[0]){
		case 'I': // integer/enum/const
			eat_num(&sig);
			break;
		case 'V': //void
			if (regnum >= 0) {
				pr_err(MODULE_NAME ": encountered void "
				       "argument in signature for %s\n", 
				       host_call->name);

			}
			break;
		case 'P':// pointer
			if (regnum < 0)
				break;
			// Intentional unsigned wrap here
			if (val && (val - proc->kage->base) >= KAGE_GUEST_SIZE) {
				pr_err(MODULE_NAME ": invalid argument %d "
				       "value of 0x%llx in call to %s\n",
				       regnum + 1, val, host_call->name);
				return -1;
			}
			break;
		case 'F':// function pointer
			if (regnum < 0) {
				pr_err(MODULE_NAME ": %s: unsupported call to "
				       "kernel function returning pointer to "
				       "function\n", host_call->name);
				return -1;
			}
			eat_num(&sig);
			void * closure = get_closure_over(proc->kage, val);
			if (IS_ERR(closure))
				return PTR_ERR(closure);
			((u64 *)regs)[regnum] = (unsigned long)closure;
			break;

		case 'S': // struct
			pr_err(MODULE_NAME ": call to function %s taking "
			       "struct not supported\n", host_call->name);
			return -1;
		case 'U': // union
			pr_err(MODULE_NAME ": call to function %s taking "
			       "union not supported\n", host_call->name);
			return -1;
		case 'A': // variadic
			break;
		case 'B':// oBject/struct
			objidx = eat_num(&sig);
			if (!objidx) {
				pr_err(MODULE_NAME ": missing num arg in "
				       "signature %s\n", host_call->sig);
				return -1;
			}
			if (regnum < 0)
				break;
			if (!val) // NULLs are always safe
				break;
			// Check to see if a guest local pointer
			if ((val - proc->kage->base) < KAGE_GUEST_SIZE)
				break;
			void * obj = kage_obj_get(proc->kage, val, objidx);
			if (!obj) {
				pr_err(MODULE_NAME ": invalid struct ptr in "
				       "arg %d in call to %s\n", 
				       regnum + 1, host_call->name);
			}
			((u64 *)(&proc->regs))[regnum] = (unsigned long)obj;
			break;
		default:
			pr_err(MODULE_NAME ": invalid char in signature '%c' "
			       "for %s\n", sig[0], host_call->name);
			return -1;
		}
		sig++;
		regnum++;
	} // while sig
	return 0;
}

u64 guard_sig_postcall(struct LFIProc *proc, struct kage_g2h_call *host_call, u64 rv) {
	const char *sig = host_call->sig;
	switch (sig[0]) {
	case 'I':
	case 'V':
		break;

	case 'P':
		if (IS_ERR_OR_NULL((void *)rv))
			return rv;
		if ((rv - proc->kage->base) >= KAGE_GUEST_SIZE) {
			pr_err(MODULE_NAME ": out-of-guest pointer return "
			       "value of %llx returned in call to%s\n", rv, 
			       host_call->name);
			return -1;
		}
		break;
	case 'B':
		if (IS_ERR_OR_NULL((void *)rv))
			return rv;
		u32 objidx = eat_num(&sig);
		void *obj = kage_obj_get(proc->kage, rv, objidx);
		if (!obj) {
			u64 desc = kage_objstorage_alloc(proc->kage, true,
							objidx, (void *)rv);
			if (!desc) {
				return -1;
			}
			return desc;
		}
		break;
	default:
		pr_err(MODULE_NAME ": invalid char in signature '%c' "
		       "for %s\n", sig[0], host_call->name);
		return -1;
	}

	return rv;
}

// Called from lfi_syscall_entry2
/* Guards and calls a host call using just its signature */
u64 guard_sig(struct LFIProc *proc, struct kage_g2h_call *host_call) {
	LFIRegs *regs = &proc->regs;
	if (guard_sig_precall(proc, host_call)) {
		return -EINVAL;
	}
	u64 (*host_func)(u64 p0, u64 p1, u64 p2, u64 p3, u64 p4, u64 p5) = 
			(void *)host_call->host_func;
	
	u64 rv = host_func(regs->x0, regs->x1, regs->x2, regs->x3, regs->x4, 
			   regs->x5);
	return guard_sig_postcall(proc, host_call, rv);
}

#define NAME_TO_GUARD_ENTRY(s) {\
		#s, \
		(unsigned long)guard_ ## s, 0, \
		(unsigned long)lfi_syscall_entry_override, \
		0, NULL}

/* Guards for which the default guard_sig won't work (probably because
 * it is a kmalloc variant)
 * NOTE: this array must be sorted by name (so bsearch works) */
struct kage_g2h_call guard_overrides[] = {
	NAME_TO_GUARD_ENTRY(kmalloc_trace),
};


static const char * find_sig(const char *func) {
	// FIXME: use bsearch
	unsigned int i;
	for (i=0; i<ARRAY_SIZE(funcsigs); i++) {
		if (0 == strcmp(func, funcsigs[i].func)) {
			return funcsigs[i].sig;
		}
	}
	return NULL;
}

struct kage_g2h_call *find_override(const char *name)
{
	// FIXME: use bsearch
	unsigned int i;
	for (i=0; i<ARRAY_SIZE(guard_overrides); i++) {
		struct kage_g2h_call *call = &guard_overrides[i];
		if (0 == strcmp(name, call->name)) {
			return call;
		}
	}
	return NULL;
}

struct kage_g2h_call *create_g2h_call(const char *name, 
					unsigned long target_func)
{
	struct kage_g2h_call *call = kmalloc(sizeof(*call), GFP_KERNEL);
	if (!call)
		return ERR_PTR(-ENOMEM);

	struct kage_g2h_call *over_call = find_override(name);
	if (over_call) {
		*call = *over_call;
		call->host_func = target_func;
		return call;
	}
	call->sig = find_sig(name);
	if (!call->sig)
		return ERR_PTR(-ENOKEY);

	if (call->sig[strlen(call->sig)-1] == 'A') {
		call->guard_func = (unsigned long)guard_sig_precall;
		call->guard_func2 = (unsigned long)guard_sig_postcall;
		call->stub = (unsigned long)lfi_syscall_entry_variadic;
	}
	else
	{
		call->guard_func = (unsigned long)guard_sig;
		call->guard_func2 = 0;
		call->stub = (unsigned long)lfi_syscall_entry2;
	}
	call->name = name;
	call->host_func = target_func;
	if (!call->sig) {
		pr_err(MODULE_NAME ": no function signature found for %s\n", name);
		return ERR_PTR(-EINVAL);
	}
	return call;
}


