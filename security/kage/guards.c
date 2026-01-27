// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and guard host function calls
 * made by the guests */
#include <linux/assoc_array.h>
#include <linux/err.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/device.h>
#ifdef CONFIG_KUNIT
#include <kunit/test.h>
#include <kunit/assert.h>
#endif

#include <linux/kage.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "funcsig.h"

struct res_t{
	struct kage *kage;
	void * mem;
};

static int in_guest(const struct kage_proc *proc, const void *ptr)
{
	return ((unsigned long)ptr - proc->kage->base) < KAGE_GUEST_SIZE;
}

static void devm_free(void *vres)
{
	struct res_t *res = vres;
	kage_memory_free(res->kage, res->mem);
	kfree(vres);
}

static void guard_kfree(struct kage_proc *proc,
			struct kage_g2h_call * call,
			const void *object)
{
	if (!in_guest(proc, object)) {
		pr_err(MODULE_NAME ": Invalid pointer %px passed to kfree\n",
		       object);
		return;
	}
	kage_memory_free(proc->kage, object);
}

#ifdef CONFIG_KUNIT
static void guard___kunit_do_failed_assertion(struct kage_proc *proc,
			       struct kage_g2h_call * call,
			       struct kunit *otest,
			       const struct kunit_loc *oloc,
			       enum kunit_assert_type otype,
			       const struct kunit_assert *oassert,
			       assert_format_t oassert_format,
			       const char *ofmt, ...)
{
	assert_format_t assert_format;
	va_list args;
	struct va_format message;
	char const *fn = "__kunit_do_failed_assertion";

	assert_format = kage_unwrap_g2h_tramp(proc->kage, (unsigned long)oassert_format);
        if (!assert_format) {
		pr_err("kage: invalid param 5 in %s\n", fn);
		return;
        }

	// FIXME: otest should be in objstorage
	if (in_guest(proc, otest)) {
		pr_err("kage: invalid param 1 in %s\n", fn);
		return;
	}

	if (!ofmt) {
		__kunit_do_failed_assertion(otest, oloc, otype, oassert,
					    assert_format, NULL);
		return;
	}

	va_start(args, ofmt);
	guard_printf(proc->kage, ofmt, args);

	message.fmt = ofmt;
	message.va = &args;
	__kunit_do_failed_assertion(otest, oloc, otype, oassert,
				    assert_format,
				    "%pV", &message);

	va_end(args);
}
#endif

static int guard_sprintf(struct kage_proc *proc,
			 struct kage_g2h_call *call,
			 char *buf, const char *fmt, ...)
{
	va_list args;
	int rv;

	if (buf && !in_guest(proc, buf))
		return -1;
	if (fmt && !in_guest(proc, fmt))
		return -1;

	va_start(args, fmt);
	guard_printf(proc->kage, fmt, args);
	rv = vsprintf(buf, fmt, args);
	va_end(args);

	return rv;
}

static void *guard_devm_kmalloc(struct kage_proc *proc,
				struct kage_g2h_call * call, unsigned long odev,
				size_t size, gfp_t gfp)
{
	BUG_ON((call->spec[1].kind) != KAGE_ARG_PSTRUCT);
	u16 dev_type_id = call->spec[1].spec.obj_type_id;

	if (unlikely(!size))
		return ZERO_SIZE_PTR; // FIXME

	struct device * dev = kage_obj_get(proc->kage, odev, dev_type_id);
	if (!dev) {
		pr_err(MODULE_NAME
		       ": invalid dev ptr in arg 0 in call to devm_kalloc\n");
	}

	void * resmem = kmalloc(sizeof(struct res_t), GFP_KERNEL);
	if (unlikely(!resmem))
		return NULL;
	void *mem = kage_memory_alloc(proc->kage, size, MOD_DATA, gfp);
	if (unlikely(!mem)) {
		kfree(resmem);
		return NULL;
	}
	struct res_t * res = resmem;
	res->kage = proc->kage;
	res->mem = mem;

	int rv = devm_add_action(dev, devm_free, res);
	if (unlikely(rv)) {
		kfree(resmem);
		kage_memory_free(proc->kage, mem);
		return NULL;
	}
	return mem;
}
// FIXME: need corresponding realloc, free

static unsigned long guard_kmalloc_trace(struct kage_proc *proc,
					 struct kage_g2h_call *call,
					 struct kmem_cache *s, gfp_t flags,
					 size_t size)
{
	return (unsigned long)kage_memory_alloc(proc->kage, size, MOD_DATA,
						flags);
}

/* Guards and calls a host call using its argument specification. */
static int guard_sig_precall(struct kage_proc *proc,
			     struct kage_g2h_call *host_call,
			     struct kage_proc_args *args)
{
	struct kage_argspec *spec = host_call->spec;
	int regnum = 0;
	unsigned long val;

	// Skip the return value
	spec++;

	while (spec->kind != KAGE_ARG_END) {
		val = args->x[regnum];
		switch (spec->kind) {
		case KAGE_ARG_INT:
		case KAGE_ARG_VOID:
			break;
		case KAGE_ARG_PTR:
			if (val && !in_guest(proc, (void *)val)) {
				pr_err(MODULE_NAME
				       ": invalid ptr argument %d value of "
                                       "0x%lx in call to %s\n",
				       regnum + 1, val, host_call->name);
				return -1;
			}
			break;
		case KAGE_ARG_FUNC_PTR: {
			void *closure = kage_get_closure_over(proc->kage, val);
			if (IS_ERR(closure))
				return PTR_ERR(closure);
			pr_info("closure_over created at 0x%px for guest func "
				"0x%lx (%s)", closure, val, host_call->name);

			args->x[regnum] = (unsigned long)closure;
			break;
		}
		case KAGE_ARG_PSTRUCT:
			if (!val) // NULLs are always safe
				break;
			// Bail if a guest local pointer
			if (in_guest(proc, (void *)val))
				break;
			void *obj = kage_obj_get(proc->kage, val,
						 spec->spec.obj_type_id);
			if (!obj) {
				pr_err(MODULE_NAME
				       ": invalid struct ptr in arg %d in call "
				       "to %s\n", regnum + 1, host_call->name);
				return -1;
			}
			args->x[regnum] = (unsigned long)obj;
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

unsigned long guard_sig_postcall(struct kage_proc *proc,
				 struct kage_g2h_call *host_call,
			         unsigned long rv)
{
	struct kage_argspec *spec = host_call->spec;

	switch (spec->kind) {
	case KAGE_ARG_INT:
	case KAGE_ARG_VOID:
		break;
	case KAGE_ARG_PTR:
		if (IS_ERR_OR_NULL((void *)rv))
			return rv;
		if (!in_guest(proc, (void *)rv)) {
			pr_err(MODULE_NAME
			       ": out-of-guest pointer return value of %lx "
			       "returned in call to %s\n",
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

// Called from lfi_g2h_entry
/* Guards and calls a host call using just its signature */
unsigned long guard_sig(struct kage_proc *proc, struct kage_g2h_call *host_call,
			struct kage_proc_args *args)
{
	unsigned long rv;
	unsigned long (*host_func)(unsigned long p0, unsigned long p1,
				   unsigned long p2, unsigned long p3,
				   unsigned long p4, unsigned long p5);

	if (guard_sig_precall(proc, host_call, args)) {
		return -EINVAL;
	}
	host_func = (void *)host_call->host_func;

	rv = host_func(args->x[0], args->x[1], args->x[2], args->x[3],
		       args->x[4], args->x[5]);
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
 * NOTE: this array must be sorted by name (so bsearch works) */
struct kage_g2h_call g2h_call_overrides[] = {
	NAME_TO_GUARD_ENTRY(devm_kmalloc),
	NAME_TO_GUARD_ENTRY(kmalloc_trace),
	NAME_TO_GUARD_ENTRY(kfree),
	NAME_TO_GUARD_ENTRY(sprintf),
#ifdef CONFIG_KUNIT
	NAME_TO_GUARD_ENTRY(__kunit_do_failed_assertion)
#endif
};

void kage_guards_init(void) {
}

static struct kage_g2h_call *find_g2h_call_override(const char *name)
{
	unsigned int i;
	// FIXME: bsearch
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

	if (over_call) {
		if (last_arg->kind == KAGE_ARG_VARIADIC) {
			call->stub = (unsigned long)lfi_g2h_entry_override_variadic;
		} else {
			call->stub = (unsigned long)lfi_g2h_entry_override;
		}
		return call;
	}

	if (last_arg->kind == KAGE_ARG_VARIADIC) {
		call->guard_func = (unsigned long)guard_sig_precall;
		call->guard_func2 = (unsigned long)guard_sig_postcall;
		call->stub = (unsigned long)lfi_g2h_entry_variadic;
	} else {
		call->guard_func = (unsigned long)guard_sig;
		call->guard_func2 = 0;
		call->stub = (unsigned long)lfi_g2h_entry;
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
