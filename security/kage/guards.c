// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/assoc_array.h>
#include <linux/kage.h>

#include "proc.h"
#include "guards.h"

/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */

// FIXME: add an identifier to prevent closure type confusion
struct kage_tasklet_closure {
	void (*func)(unsigned long);
        struct kage * kage;
	unsigned long data;
	struct list_head list;
};

static void kage_tasklet_callback(unsigned long data)
{
	struct kage_tasklet_closure *closure =
		(struct kage_tasklet_closure *)data;
	kage_call(closure->kage, closure->func, closure->data, 0, 0, 0, 0, 0);
}

static unsigned long
get_key_chunk(const void *index_key, int level)
{
	return ((unsigned long)index_key >> (level * ASSOC_ARRAY_KEY_CHUNK_SIZE)) &
		(ASSOC_ARRAY_KEY_CHUNK_SIZE - 1);
}

static unsigned long
get_object_key_chunk(const void *object, int level)
{
	const struct kage_tasklet_closure *closure = object;

	return get_key_chunk(closure->func, level);
}

static const struct assoc_array_ops kage_tasklet_closure_ops = {
	.get_key_chunk = get_key_chunk,
	.get_object_key_chunk = get_object_key_chunk,
};

static unsigned long guard_tasklet_init(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct tasklet_struct *t = (struct tasklet_struct *)p0;
	void (*func)(unsigned long) = (void (*)(unsigned long))p1;
	unsigned long data = p2;
	struct kage_tasklet_closure *closure;
	struct assoc_array_edit *edit;

	closure = assoc_array_find(&kage->closures, &kage_tasklet_closure_ops,
				   (void *)func);
	if (closure)
		goto finish;
                

	closure = kzalloc(sizeof(*closure), GFP_KERNEL);
	if (!closure)
		return -ENOMEM;

	closure->func = func;
        closure->kage = kage;
	closure->data = data;

	edit = assoc_array_insert(&kage->closures, &kage_tasklet_closure_ops,
				  (void *)func, closure);
	if (IS_ERR(edit)) {
		kfree(closure);
		return PTR_ERR(edit);
	}

	assoc_array_apply_edit(edit);

      finish:
	tasklet_init(t, kage_tasklet_callback, (unsigned long)closure);

	return 0;
}

static unsigned long guard__printk(struct kage *kage, unsigned long p0,
			    unsigned long p1, unsigned long p2,
			    unsigned long p3, unsigned long p4,
			    unsigned long p5)
{
	char *fmt = (char *)p0;
	va_list *pargs = (va_list *)p1;
	int rv = 0;

	pr_info("before vprintk\n");
	rv = vprintk(fmt, *pargs);
	pr_info("after vprintk\n");
	return rv;
}

static unsigned long guard_kmalloc_generic(struct kage *kage, unsigned long p0,
			      unsigned long p1, unsigned long p2,
			      unsigned long p3, unsigned long p4,
			      unsigned long p5)
{
	size_t size = (size_t)p0;
	gfp_t flags = (gfp_t)p1;

	return (unsigned long)kage_memory_alloc(kage, size, MOD_DATA, 
                                                flags);
}

guard_t *syscall_to_guard[] = {
	[KAGE_PRINTK] = guard__printk,
	[KAGE_TASKLET_INIT] = guard_tasklet_init,
	[KAGE_KMALLOC_LARGE] = guard_kmalloc_generic,
	[KAGE_KMALLOC_TRACE] = guard_kmalloc_generic,
	[KAGE___KMALLOC] = guard_kmalloc_generic,
};
