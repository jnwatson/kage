// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */
#include <linux/printk.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/assoc_array.h>
#include <linux/cdev.h>
#include <linux/kage.h>
#include <linux/fs.h>

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

struct kage_fops_closure {
	struct kage *kage;
	const struct file_operations *guest_fops;
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

static loff_t kage_fops_llseek(struct file *file, loff_t offset, int whence)
{
	struct kage_fops_closure *closure =
		(struct kage_fops_closure *)file->f_op->owner;

	return kage_call(closure->kage, (void *)closure->guest_fops->llseek,
			 (unsigned long)file, offset, whence, 0, 0, 0);
}

static ssize_t kage_fops_read(struct file *file, char __user *buf, size_t size,
			      loff_t *offset)
{
	struct kage_fops_closure *closure =
		(struct kage_fops_closure *)file->f_op->owner;

	return kage_call(closure->kage, (void *)closure->guest_fops->read,
			 (unsigned long)file, (unsigned long)buf, size,
			 (unsigned long)offset, 0, 0);
}

static ssize_t kage_fops_write(struct file *file, const char __user *buf,
			       size_t size, loff_t *offset)
{
	struct kage_fops_closure *closure =
		(struct kage_fops_closure *)file->f_op->owner;

	return kage_call(closure->kage, (void *)closure->guest_fops->write,
			 (unsigned long)file, (unsigned long)buf, size,
			 (unsigned long)offset, 0, 0);
}

static int kage_fops_open(struct inode *inode, struct file *file)
{
	struct kage_fops_closure *closure =
		(struct kage_fops_closure *)file->f_op->owner;

	return kage_call(closure->kage, (void *)closure->guest_fops->open,
			 (unsigned long)inode, (unsigned long)file, 0, 0, 0, 0);
}

static int kage_fops_release(struct inode *inode, struct file *file)
{
	struct kage_fops_closure *closure =
		(struct kage_fops_closure *)file->f_op->owner;

	return kage_call(closure->kage, (void *)closure->guest_fops->release,
			 (unsigned long)inode, (unsigned long)file, 0, 0, 0, 0);
}

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

        if (p1 < kage->base || p1 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
        }

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

        if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
        }
        if (p1 < kage->base || p1 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
        }

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

static unsigned long guard_alloc_chrdev_region(struct kage *kage, unsigned long p0,
					 unsigned long p1, unsigned long p2,
					 unsigned long p3, unsigned long p4,
					 unsigned long p5)
{
	dev_t *dev = (dev_t *)p0;
	unsigned baseminor = (unsigned)p1;
	unsigned count = (unsigned)p2;
	const char *name = (const char *)p3;

	if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
	}
	if (p3 < kage->base || p3 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
	}

	return alloc_chrdev_region(dev, baseminor, count, name);
}

static unsigned long guard_alt_cb_patch_nops(struct kage *kage, unsigned long p0,
					 unsigned long p1, unsigned long p2,
					 unsigned long p3, unsigned long p4,
					 unsigned long p5)
{
	alt_cb_patch_nops((struct alt_instr *)p0, (__le32 *)p1, (__le32 *)p2, p3);
	return 0;
}

static unsigned long guard_cdev_add(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct cdev *p = (struct cdev *)p0;
	dev_t dev = (dev_t)p1;
	unsigned count = (unsigned)p2;

	if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
	}

	return cdev_add(p, dev, count);
}

static unsigned long guard_cdev_del(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct cdev *cdev = (struct cdev *)p0;
	struct file_operations *host_fops;
	struct kage_fops_closure *closure;

	if ((unsigned long)cdev < kage->base || (unsigned long)cdev > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	host_fops = (struct file_operations *)cdev->ops;
	if (host_fops) {
		closure = (struct kage_fops_closure *)host_fops->owner;
		kfree(closure);
		kfree(host_fops);
	}

	cdev_del(cdev);
	return 0;
}

static unsigned long guard_cdev_init(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct cdev *cdev = (struct cdev *)p0;
	const struct file_operations *guest_fops =
		(const struct file_operations *)p1;
	struct kage_fops_closure *closure;
	struct file_operations *host_fops;

	if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	closure = kzalloc(sizeof(*closure), GFP_KERNEL);
	if (!closure)
		return -ENOMEM;

	closure->kage = kage;
	closure->guest_fops = guest_fops;

	host_fops = kzalloc(sizeof(*host_fops), GFP_KERNEL);
	if (!host_fops) {
		kfree(closure);
		return -ENOMEM;
	}

	if (guest_fops->llseek)
		host_fops->llseek = kage_fops_llseek;
	if (guest_fops->read)
		host_fops->read = kage_fops_read;
	if (guest_fops->write)
		host_fops->write = kage_fops_write;
	if (guest_fops->open)
		host_fops->open = kage_fops_open;
	if (guest_fops->release)
		host_fops->release = kage_fops_release;

	host_fops->owner = (struct module *)closure;

	cdev_init(cdev, host_fops);
	return 0;
}

static unsigned long guard_filp_open(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	const char *filename = (const char *)p0;
	int flags = (int)p1;
	umode_t mode = (umode_t)p2;

	if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)filp_open(filename, flags, mode);
}

static unsigned long guard_filp_close(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct file *filp = (struct file *)p0;
	fl_owner_t id = (fl_owner_t)p1;

	return filp_close(filp, id);
}

static unsigned long guard_device_create(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct class *class = (struct class *)p0;
	struct device *parent = (struct device *)p1;
	dev_t devt = (dev_t)p2;
	void *drvdata = (void *)p3;
	const char *fmt = (const char *)p4;

	if (p4 < kage->base || p4 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)device_create(class, parent, devt, drvdata, fmt);
}

static unsigned long guard_device_destroy(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct class *class = (struct class *)p0;
	dev_t devt = (dev_t)p1;

	device_destroy(class, devt);
	return 0;
}

static unsigned long guard_class_create(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	const char *name = (const char *)p0;

	if (p0 < kage->base || p0 > kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)class_create(name);
}

static unsigned long guard_class_destroy(struct kage *kage, unsigned long p0,
				  unsigned long p1, unsigned long p2,
				  unsigned long p3, unsigned long p4,
				  unsigned long p5)
{
	struct class *cls = (struct class *)p0;

	class_destroy(cls);
	return 0;
}

guard_t *syscall_to_guard[] = {
	[KAGE_PRINTK] = guard__printk,
	[KAGE_TASKLET_INIT] = guard_tasklet_init,
	[KAGE_KMALLOC_LARGE] = guard_kmalloc_generic,
	[KAGE_KMALLOC_TRACE] = guard_kmalloc_generic,
	[KAGE___KMALLOC] = guard_kmalloc_generic,
	[KAGE_ALLOC_CHRDEV_REGION] = guard_alloc_chrdev_region,
	[KAGE_ALT_CB_PATCH_NOPS] = guard_alt_cb_patch_nops,
	[KAGE_CDEV_ADD] = guard_cdev_add,
	[KAGE_CDEV_DEL] = guard_cdev_del,
	[KAGE_CDEV_INIT] = guard_cdev_init,
	[KAGE_FILP_OPEN] = guard_filp_open,
	[KAGE_FILP_CLOSE] = guard_filp_close,
	[KAGE_DEVICE_CREATE] = guard_device_create,
	[KAGE_DEVICE_DESTROY] = guard_device_destroy,
	[KAGE_CLASS_CREATE] = guard_class_create,
	[KAGE_CLASS_DESTROY] = guard_class_destroy,
};