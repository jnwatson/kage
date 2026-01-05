// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */
#include <linux/assoc_array.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/slab.h>

#include <linux/kage.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "arm64.h"
#include "funcsig.h"

// DEBUG
#pragma clang optimize off

static unsigned long guard_kmalloc_trace(struct kage_proc *proc,
					 struct kmem_cache *s, gfp_t flags,
					 size_t size)
{
	return (unsigned long)kage_memory_alloc(proc->kage, size, MOD_DATA,
						flags);
}

/* Resides in h2g_tramp_data; corresponding trampoline precedes this by
 * KAGE_H2G_TRAMP_REGION_SIZE bytes */
struct h2g_tramp_data_entry {
	struct kage *kage;
	u64 guest_func; // callback into guest
};
static_assert(sizeof(struct h2g_tramp_data_entry) == KAGE_H2G_TRAMP_SIZE);

// Returns the next slot in the literal pool
// Note that the kage->lock should be held when calling
static struct kage_h2g_tramp_data_entry *alloc_h2g_entry(struct kage *kage)
{
	struct kage_h2g_tramp_data_entry *ret;

	if (kage->num_h2g_calls >= KAGE_MAX_H2G_CALLS)
		return NULL;

	ret = &kage->h2g_tramp_data[kage->num_h2g_calls++];

	return ret;
}

static unsigned long get_key_chunk(const void *index_key, int level)
{
	return ((unsigned long)index_key >>
		(level * ASSOC_ARRAY_KEY_CHUNK_SIZE)) &
	       (ASSOC_ARRAY_KEY_CHUNK_SIZE - 1);
}

static unsigned long get_h2g_key_chunk(const void *object, int level)
{
	struct kage_h2g_tramp_data_entry *entry =
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
 * The associative array (aka dict) stores entry pointers indexed by the original
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
	void *tramp;
	struct kage_h2g_tramp_data_entry *entry;

	if ((func - kage->base) >= KAGE_GUEST_SIZE) {
		return ERR_PTR(-EINVAL);
	}

	spin_lock_irqsave(&kage->lock, irq_flags);
	tramp = assoc_array_find(&kage->closures, &kage_h2g_closure_ops,
				 (void *)func);
	if (tramp)
		goto finish;

	entry = alloc_h2g_entry(kage);
	if (!entry) {
		tramp = ERR_PTR(-ENOMEM);
		goto on_err;
	}

	entry->kage = kage;
	entry->guest_func = func;

	// Each trampoline is exactly region size away from its literal pool
	tramp = (void *)((u64)entry - KAGE_H2G_TRAMP_REGION_SIZE);

	edit = assoc_array_insert(&kage->closures, &kage_h2g_closure_ops,
				  (void *)func, tramp);
	if (IS_ERR(edit)) {
		tramp = edit;
		goto on_err;
	}
	assoc_array_apply_edit(edit);
finish:
	pr_info("closure_over created at 0x%px for guest func 0x%lx", tramp,
		func);
on_err:
	spin_unlock_irqrestore(&kage->lock, irq_flags);
	return tramp;
}

/* Guards and calls a host call using its argument specification. */
int guard_sig_precall(struct kage_proc *proc, struct kage_g2h_call *host_call)
{
	struct kage_argspec *spec = host_call->spec;
	struct kage_regs *regs = &proc->regs;
	int regnum = 0;
	u64 val;

	// Skip the return value
	spec++;

	while (spec->kind != KAGE_ARG_END) {
		val = *lfi_regs_arg(regs, regnum);
		switch (spec->kind) {
		case KAGE_ARG_INT:
		case KAGE_ARG_VOID:
			break;
		case KAGE_ARG_PTR:
			// Intentional unsigned wrap here
			if (val &&
			    (val - proc->kage->base) >= KAGE_GUEST_SIZE) {
				pr_err(MODULE_NAME
				       ": invalid ptr argument %d value of "
                                       "0x%llx in call to %s\n",
				       regnum + 1, val, host_call->name);
				return -1;
			}
			break;
		case KAGE_ARG_FUNC_PTR: {
			void *closure = get_closure_over(proc->kage, val);
			if (IS_ERR(closure))
				return PTR_ERR(closure);

			((u64 *)regs)[regnum] = (unsigned long)closure;
			break;
		}
		case KAGE_ARG_PSTRUCT:
			if (!val) // NULLs are always safe
				break;
			// Check to see if a guest local pointer
			if ((val - proc->kage->base) < KAGE_GUEST_SIZE)
				break;
			void *obj = kage_obj_get(proc->kage, val,
						 spec->spec.obj_type_id);
			if (!obj) {
				pr_err(MODULE_NAME
				       ": invalid struct ptr in arg %d in call to %s\n",
				       regnum + 1, host_call->name);
			}
			((u64 *)(&proc->regs))[regnum] = (unsigned long)obj;
			break;
		case KAGE_ARG_VARIADIC:
			goto end_loop;
		case KAGE_ARG_END: // solely to eliminate unhandled case warning
			unreachable();
		}
		spec++;
		regnum++;
	}
end_loop:
	return 0;
}

u64 guard_sig_postcall(struct kage_proc *proc, struct kage_g2h_call *host_call,
		       u64 rv)
{
	struct kage_argspec *spec = host_call->spec;

	switch (spec->kind) {
	case KAGE_ARG_INT:
	case KAGE_ARG_VOID:
		break;
	case KAGE_ARG_PTR:
		if (IS_ERR_OR_NULL((void *)rv))
			return rv;
		if ((rv - proc->kage->base) >= KAGE_GUEST_SIZE) {
			pr_err(MODULE_NAME
			       ": out-of-guest pointer return value of %llx returned in call to%s\n",
			       rv, host_call->name);
			return -1;
		}
		break;
	case KAGE_ARG_PSTRUCT:
		if (IS_ERR_OR_NULL((void *)rv))
			return rv;
		void *obj =
			kage_obj_get(proc->kage, rv, spec->spec.obj_type_id);

		if (!obj) {
			u64 desc = kage_objstorage_alloc(proc->kage, true,
							 spec->spec.obj_type_id,
							 (void *)rv);
			if (!desc) {
				return -1;
			}
			return desc;
		}
		break;
	default:
		pr_err(MODULE_NAME
		       ": invalid return kind %d in signature for %s\n",
		       spec->kind, host_call->name);
		return -1;
	}

	return rv;
}

// Called from lfi_syscall_entry
/* Guards and calls a host call using just its signature */
u64 guard_sig(struct kage_proc *proc, struct kage_g2h_call *host_call)
{
	struct kage_regs *regs = &proc->regs;
	u64 rv;
	u64 (*host_func)(u64 p0, u64 p1, u64 p2, u64 p3, u64 p4, u64 p5);

	if (guard_sig_precall(proc, host_call)) {
		return -EINVAL;
	}
	host_func = (void *)host_call->host_func;

	rv = host_func(regs->x[0], regs->x[1], regs->x[2], regs->x[3],
		       regs->x[4], regs->x[5]);
	return guard_sig_postcall(proc, host_call, rv);
}

#define NAME_TO_GUARD_ENTRY(s) \
	{ .name = #s, \
	  .guard_func = (unsigned long)guard_##s, \
	  .guard_func2 = 0, \
	  .stub = 0, \
	  .spec = NULL }

/* Guards for which the default guard_sig won't work (probably because
 * it is a kmalloc variant)
 * NOTE: this array should be sorted by name (so bsearch works) */
struct kage_g2h_call g2h_call_overrides[] = {
	NAME_TO_GUARD_ENTRY(kmalloc_trace),
};

void kage_guards_init(void) {
	g2h_call_overrides[0].stub = (unsigned long)lfi_syscall_entry_override;
}
static struct kage_g2h_call *find_g2h_call_override(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(g2h_call_overrides); i++) {
		struct kage_g2h_call *call = &g2h_call_overrides[i];

		if (0 == strcmp(name, call->name))
			return call;
	}
	return NULL;
}

struct kage_g2h_call *kage_guard_create_g2h_call(const char *name,
						 unsigned long target_func)
{
	struct kage_g2h_call *call = kmalloc(sizeof(*call), GFP_KERNEL);
	if (!call)
		return ERR_PTR(-ENOMEM);

	struct kage_g2h_call *over_call = find_g2h_call_override(name);

	if (over_call) {
		*call = *over_call;
		call->host_func = target_func;
		return call;
	}

	call->spec = kage_get_funcspec(name);
	if (!call->spec) {
		kfree(call);
		return ERR_PTR(-ENOKEY);
	}

	// Check if the last argument is variadic
	struct kage_argspec *last_arg = call->spec;
	while (last_arg->kind != KAGE_ARG_END)
		last_arg++;
	last_arg--; // Go back to the last real argument

	if (last_arg->kind == KAGE_ARG_VARIADIC) {
		call->guard_func = (unsigned long)guard_sig_precall;
		call->guard_func2 = (unsigned long)guard_sig_postcall;
		call->stub = (unsigned long)lfi_syscall_entry_variadic;
	} else {
		call->guard_func = (unsigned long)guard_sig;
		call->guard_func2 = 0;
		call->stub = (unsigned long)lfi_syscall_entry;
	}
	call->name = name;
	call->host_func = target_func;
	return call;
}

static unsigned long gvar_space_alloc(struct kage *kage, size_t size)
{
	unsigned long start = (unsigned long)kage->gvar_space_open;
	unsigned long end =
		(unsigned long)kage->gvar_space + KAGE_GVAR_SPACE_SIZE;
	unsigned long pos = ALIGN(start, 16);

	if (pos + size > end) {
		pr_err(MODULE_NAME ": ran out of gvar space\n");
		return 0;
	}
	kage->gvar_space_open = (void *)(pos + size);
	return pos;
}

static unsigned long kmalloc_caches_resolve(struct kage *kage)
{
	// Seems to work fine with everything just 0 initialized
	return gvar_space_alloc(kage, sizeof(kmalloc_caches));
}

struct kage_gvar gvar_overrides[] = { { "kmalloc_caches",
					kmalloc_caches_resolve, 0 } };

static struct kage_gvar *find_gvar_override(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(gvar_overrides); i++) {
		struct kage_gvar *gvar = &gvar_overrides[i];

		if (0 == strcmp(name, gvar->name))
			return gvar;
	}
	return NULL;
}

unsigned long kage_guard_resolve_gvars(struct kage *kage, const char *name)
{
	unsigned int i;

	for (i = 0; i < kage->num_gvars; i++) {
		if (name == kage->gvars[i].name)
			return kage->gvars[i].addr;
	}
	struct kage_gvar *gvar_override = find_gvar_override(name);

	if (!gvar_override)
		return 0;
	if (kage->num_gvars >= KAGE_MAX_GVARS) {
		pr_err("Exceeded max imported variables by guest\n");
		return 0;
	}
	struct kage_gvar *gvar = &kage->gvars[kage->num_gvars];

	*gvar = *gvar_override;
	gvar->addr = gvar->resolver(kage);
	if (!gvar->addr) {
		pr_err(MODULE_NAME ": Resolver failed for imported symbol %s\n",
		       name);
		return 0;
	}
	kage->num_gvars++;
	return gvar->addr;
}

void kage_guard_destroy_g2h_call(struct kage_g2h_call *call)
{
	if (!call)
		return;
	kfree(call->spec);
	kfree(call);
}
