// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */
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

#include "proc.h"
#include "guards.h"
#include "objdesc.h"

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

        if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
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

static unsigned long guard___tasklet_schedule(struct kage *kage, unsigned long p0,
                                    unsigned long p1, unsigned long p2,
                                    unsigned long p3, unsigned long p4,
                                    unsigned long p5)
{
  struct tasklet_struct *t = (struct tasklet_struct *)p0;

  if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
          pr_err("%s: guest pointer argument out of bounds\n", __func__);
          return -1;
  }

  __tasklet_schedule(t);
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_info("kage->base: %lx\n", kage->base);
		pr_info("p0: %lx\n", p0);
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
        }
        if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
        }

	rv = vprintk(fmt, *pargs);
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

static unsigned long guard_kmalloc_trace(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
  gfp_t flags = (gfp_t)p1;
  size_t size = (size_t)p2;

  // We ignore p0 (cache) parameter since we want to use the host's

  return (unsigned long)kmalloc(size, flags);
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n",  __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
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

	if ((unsigned long)cdev < kage->base || (unsigned long)cdev >= kage->base + KAGE_GUEST_SIZE) {
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
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

	if (p4 < kage->base || p4 >= kage->base + KAGE_GUEST_SIZE) {
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

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
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

static unsigned long guard_debugfs_create_dir(struct kage *kage, unsigned long p0,
					  unsigned long p1, unsigned long p2,
					  unsigned long p3, unsigned long p4,
					  unsigned long p5)
{
	const char *name = (const char *)p0;
	struct dentry *parent = (struct dentry *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)debugfs_create_dir(name, parent);
}

static unsigned long guard_debugfs_create_file(struct kage *kage, unsigned long p0,
					   unsigned long p1, unsigned long p2,
					   unsigned long p3, unsigned long p4,
					   unsigned long p5)
{
	const char *name = (const char *)p0;
	umode_t mode = (umode_t)p1;
	struct dentry *parent = (struct dentry *)p2;
	void *data = (void *)p3;
	const struct file_operations *fops = (const struct file_operations *)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)debugfs_create_file(name, mode, parent, data, fops);
}

static unsigned long guard_debugfs_remove(struct kage *kage, unsigned long p0,
					  unsigned long p1, unsigned long p2,
					  unsigned long p3, unsigned long p4,
					  unsigned long p5)
{
	struct dentry *dentry = (struct dentry *)p0;

	debugfs_remove(dentry);
	return 0;
}

static unsigned long guard_delayed_work_timer_fn(struct kage *kage, unsigned long p0,
					     unsigned long p1, unsigned long p2,
					     unsigned long p3, unsigned long p4,
					     unsigned long p5)
{
	struct timer_list *t = (struct timer_list *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	delayed_work_timer_fn(t);
	return 0;
}

static unsigned long guard_dev_driver_string(struct kage *kage, unsigned long p0,
					 unsigned long p1, unsigned long p2,
					 unsigned long p3, unsigned long p4,
					 unsigned long p5)
{
	const struct device *dev = (const struct device *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)dev_driver_string(dev);
}

static unsigned long guard__dev_err(struct kage *kage, unsigned long p0,
				    unsigned long p1, unsigned long p2,
				    unsigned long p3, unsigned long p4,
				    unsigned long p5)
{
	const struct device *dev = (const struct device *)p0;
	const char *fmt = (const char *)p1;
	va_list *pargs = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	_dev_err(dev, fmt, *pargs);
	return 0;
}

static unsigned long guard__dev_info(struct kage *kage, unsigned long p0,
				     unsigned long p1, unsigned long p2,
				     unsigned long p3, unsigned long p4,
				     unsigned long p5)
{
	const struct device *dev = (const struct device *)p0;
	const char *fmt = (const char *)p1;
	va_list *pargs = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	_dev_info(dev, fmt, *pargs);
	return 0;
}

static unsigned long guard_devm_kmalloc(struct kage *kage, unsigned long p0,
					unsigned long p1, unsigned long p2,
					unsigned long p3, unsigned long p4,
					unsigned long p5)
{
	struct device *dev = (struct device *)p0;
	size_t size = (size_t)p1;
	gfp_t gfp = (gfp_t)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)devm_kmalloc(dev, size, gfp);
}

static unsigned long guard_dev_printk_emit(struct kage *kage, unsigned long p0,
					   unsigned long p1, unsigned long p2,
					   unsigned long p3, unsigned long p4,
					   unsigned long p5)
{
	int level = (int)p0;
	const struct device *dev = (const struct device *)p1;
	const char *fmt = (const char *)p2;
	va_list *pargs = (va_list *)p3;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return dev_printk_emit(level, dev, fmt, *pargs);
}

static unsigned long guard__dev_warn(struct kage *kage, unsigned long p0,
				     unsigned long p1, unsigned long p2,
				     unsigned long p3, unsigned long p4,
				     unsigned long p5)
{
	const struct device *dev = (const struct device *)p0;
	const char *fmt = (const char *)p1;
	va_list *pargs = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	_dev_warn(dev, fmt, *pargs);
	return 0;
}

static unsigned long guard_down_interruptible(struct kage *kage, unsigned long p0,
					      unsigned long p1, unsigned long p2,
					      unsigned long p3, unsigned long p4,
					      unsigned long p5)
{
	struct semaphore *sem = (struct semaphore *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return down_interruptible(sem);
}

#include <linux/dynamic_debug.h>

static unsigned long guard___dynamic_dev_dbg(struct kage *kage, unsigned long p0,
                                       unsigned long p1, unsigned long p2,
                                       unsigned long p3, unsigned long p4,
                                       unsigned long p5)
{
#if defined(CONFIG_DYNAMIC_DEBUG) || \
	(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))
	struct _ddebug *descriptor = (struct _ddebug *)p0;
	const struct device *dev = (const struct device *)p1;
	const char *fmt = (const char *)p2;
	va_list *va_args = (va_list *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	struct va_format vaf = {fmt, va_args};

	__dynamic_dev_dbg(descriptor, dev, "%pV", &vaf);
	return 0;
#else
	return -1;
#endif
}

static unsigned long guard_fortify_panic(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *name = (const char *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	fortify_panic(name);
	return 0;
}

static unsigned long guard_generic_file_llseek(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	loff_t offset = (loff_t)p1;
	int whence = (int)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return generic_file_llseek(file, offset, whence);
}

static unsigned long guard_gen_pool_add_owner(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct gen_pool *pool = (struct gen_pool *)p0;
	phys_addr_t addr = (phys_addr_t)p1;
	size_t size = (size_t)p2;
	void *owner = (void *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return gen_pool_add_owner(pool, 0, addr, size, -1, owner);
}

static unsigned long guard_gen_pool_alloc_algo_owner(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct gen_pool *pool = (struct gen_pool *)p0;
	size_t size = (size_t)p1;
	genpool_algo_t algo = (genpool_algo_t)p2;
	void *data = (void *)p3;
	void *owner = (void *)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return gen_pool_alloc_algo_owner(pool, size, algo, data, owner);
}

static unsigned long guard_gen_pool_create(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	int min_alloc_order = (int)p0;
	int nid = (int)p1;

	return (unsigned long)gen_pool_create(min_alloc_order, nid);
}

static unsigned long guard_gen_pool_destroy(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct gen_pool *pool = (struct gen_pool *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	gen_pool_destroy(pool);
	return 0;
}

static unsigned long guard_init_timer_key(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct timer_list *timer = (struct timer_list *)p0;
	const char *name = (const char *)p1;
	struct lock_class_key *key = (struct lock_class_key *)p2;
	unsigned int flags = (unsigned int)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	init_timer_key(timer, NULL, flags, name, key);
	return 0;
}

static unsigned long guard_kfree(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const void *x = (const void *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	kfree(x);
	return 0;
}

static unsigned long guard_klist_add_head(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist_node *n = (struct klist_node *)p0;
	struct klist *k = (struct klist *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_add_head(n, k);
	return 0;
}

static unsigned long guard_klist_add_tail(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist_node *n = (struct klist_node *)p0;
	struct klist *k = (struct klist *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_add_tail(n, k);
	return 0;
}

static unsigned long guard_klist_init(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist *k = (struct klist *)p0;
	void (*get)(struct klist_node *) = (void (*)(struct klist_node *))p1;
	void (*put)(struct klist_node *) = (void (*)(struct klist_node *))p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_init(k, get, put);
	return 0;
}

static unsigned long guard_klist_iter_exit(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist_iter *i = (struct klist_iter *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_iter_exit(i);
	return 0;
}

static unsigned long guard_klist_iter_init(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist *k = (struct klist *)p0;
	struct klist_iter *i = (struct klist_iter *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_iter_init(k, i);
	return 0;
}

static unsigned long guard_klist_next(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist_iter *i = (struct klist_iter *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)klist_next(i);
}

static unsigned long guard_klist_remove(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct klist_node *n = (struct klist_node *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	klist_remove(n);
	return 0;
}

static unsigned long guard_kstrdup(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *s = (const char *)p0;
	gfp_t gfp = (gfp_t)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)kstrdup(s, gfp);
}

static unsigned long guard_kstrtoint(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *s = (const char *)p0;
	unsigned int base = (unsigned int)p1;
	int *res = (int *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return kstrtoint(s, base, res);
}

static unsigned long guard_ktime_get_real_seconds(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	return ktime_get_real_seconds();
}

static unsigned long guard_ktime_get_with_offset(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	enum tk_offsets offs = (enum tk_offsets)p0;

	return (unsigned long)ktime_get_with_offset(offs);
}

static unsigned long guard_list_add_valid_or_report(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct list_head *new = (struct list_head *)p0;
	struct list_head *prev = (struct list_head *)p1;
	struct list_head *next = (struct list_head *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return __list_add_valid_or_report(new, prev, next);
}

static unsigned long guard_list_del_entry_valid_or_report(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct list_head *entry = (struct list_head *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return __list_del_entry_valid_or_report(entry);
}

#ifdef CONFIG_GOOGLE_LOGBUFFER
static unsigned long guard_logbuffer_log(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	int level = (int)p0;
	const char *msg = (const char *)p1;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	logbuffer_log(level, msg);
	return 0;
}

static unsigned long guard_logbuffer_vlog(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	int level = (int)p0;
	const char *fmt = (const char *)p1;
	va_list *args = (va_list *)p2;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	logbuffer_vlog(level, fmt, *args);
	return 0;
	return -EOPNOTSUPP;
}
#endif

static unsigned long guard_memcpy(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	void *dest = (void *)p0;
	const void *src = (const void *)p1;
	size_t count = (size_t)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	memcpy(dest, src, count);
	return 0;
}

static unsigned long guard_memset(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	void *s = (void *)p0;
	int c = (int)p1;
	size_t count = (size_t)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	memset(s, c, count);
	return 0;
}

static unsigned long guard_msleep(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	unsigned int msecs = (unsigned int)p0;

	msleep(msecs);
	return 0;
}

static unsigned long guard_mutex_init(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct mutex *lock = (struct mutex *)p0;
	const char *name = (const char *)p1;
	struct lock_class_key *key = (struct lock_class_key *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	__mutex_init(lock, name, key);
	return 0;
}

static unsigned long guard_mutex_lock(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct mutex *lock = (struct mutex *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	mutex_lock(lock);
	return 0;
}

static unsigned long guard_mutex_unlock(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct mutex *lock = (struct mutex *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	mutex_unlock(lock);
	return 0;
}

static unsigned long guard_nvmem_device_put(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
#ifdef CONFIG_NVMEM
	struct nvmem_device *nvmem = (struct nvmem_device *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	nvmem_device_put(nvmem);
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

static unsigned long guard_nvmem_device_read(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
#ifdef CONFIG_NVMEM
	struct nvmem_device *nvmem = (struct nvmem_device *)p0;
	unsigned int offset = (unsigned int)p1;
	size_t bytes = (size_t)p2;
	void *buf = (void *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return nvmem_device_read(nvmem, offset, bytes, buf);
#else
	return -EOPNOTSUPP;
#endif
}

static unsigned long guard_nvmem_device_write(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
#ifdef CONFIG_NVMEM
	struct nvmem_device *nvmem = (struct nvmem_device *)p0;
	unsigned int offset = (unsigned int)p1;
	size_t bytes = (size_t)p2;
	void *buf = (void *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return nvmem_device_write(nvmem, offset, bytes, buf);
#else
	return -EOPNOTSUPP;
#endif
}

static unsigned long guard_of_find_node_by_name(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct device_node *from = (struct device_node *)p0;
	const char *name = (const char *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_find_node_by_name(from, name);
}

static unsigned long guard_of_find_node_by_phandle(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	phandle handle = (phandle)p0;

	return (unsigned long)of_find_node_by_phandle(handle);
}

static unsigned long guard_of_find_property(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *name = (const char *)p1;
	int *lenp = (int *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_find_property(np, name, lenp);
}

static unsigned long guard_of_get_child_by_name(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *node = (const struct device_node *)p0;
	const char *name = (const char *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_get_child_by_name(node, name);
}

static unsigned long guard_of_get_next_child(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *node = (const struct device_node *)p0;
	struct device_node *prev = (struct device_node *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_get_next_child(node, prev);
}

static unsigned long guard_of_get_property(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *name = (const char *)p1;
	int *lenp = (int *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_get_property(np, name, lenp);
}

static unsigned long guard_of_nvmem_device_get(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
#ifdef CONFIG_NVMEM
	struct device_node *np = (struct device_node *)p0;
	const char *name = (const char *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)of_nvmem_device_get(np, name);
#else
	return -EOPNOTSUPP;
#endif
}

static unsigned long guard_of_property_count_elems_of_size(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *propname = (const char *)p1;
	int elem_size = (int)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return of_property_count_elems_of_size(np, propname, elem_size);
}

static unsigned long guard_of_property_read_string(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *propname = (const char *)p1;
	const char **out_string = (const char **)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return of_property_read_string(np, propname, out_string);
}

static unsigned long guard_of_property_read_string_helper(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct device_node *np = (struct device_node *)p0;
	const char *propname = (const char *)p1;
	const char **out_string = (const char **)p2;
	size_t sz = (size_t)p3;
        int index = (int)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return of_property_read_string_helper(np, propname, out_string, sz, index);
}

static unsigned long guard_of_property_read_variable_u16_array(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *propname = (const char *)p1;
	u16 *out_values = (u16 *)p2;
	size_t sz_min = (size_t)p3;
	size_t sz_max = (size_t)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return of_property_read_variable_u16_array(np, propname, out_values, sz_min, sz_max);
}

static unsigned long guard_of_property_read_variable_u32_array(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const struct device_node *np = (const struct device_node *)p0;
	const char *propname = (const char *)p1;
	u32 *out_values = (u32 *)p2;
	size_t sz_min = (size_t)p3;
	size_t sz_max = (size_t)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return of_property_read_variable_u32_array(np, propname, out_values, sz_min, sz_max);
}

static unsigned long guard_pm_relax(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct wakeup_source *ws = (struct wakeup_source *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	__pm_relax(ws);
	return 0;
}

static unsigned long guard_pm_stay_awake(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct wakeup_source *ws = (struct wakeup_source *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	__pm_stay_awake(ws);
	return 0;
}

static unsigned long guard_power_supply_get_by_phandle_array(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct device_node *np = (struct device_node *)p0;
	const char *property = (const char *)p1;
	struct power_supply **psy = (struct power_supply **)p2;
	ssize_t size = (ssize_t)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)power_supply_get_by_phandle_array(np, property, psy, size);
}

static unsigned long guard_power_supply_get_drvdata(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct power_supply *psy = (struct power_supply *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)power_supply_get_drvdata(psy);
}

static unsigned long guard_power_supply_get_property(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct power_supply *psy = (struct power_supply *)p0;
	enum power_supply_property psp = (enum power_supply_property)p1;
	union power_supply_propval *val = (union power_supply_propval *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return power_supply_get_property(psy, psp, val);
}

static unsigned long guard_power_supply_put(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct power_supply *psy = (struct power_supply *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	power_supply_put(psy);
	return 0;
}

static unsigned long guard_power_supply_set_property(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct power_supply *psy = (struct power_supply *)p0;
	enum power_supply_property psp = (enum power_supply_property)p1;
	const union power_supply_propval *val = (const union power_supply_propval *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return power_supply_set_property(psy, psp, val);
}

static unsigned long guard_queue_delayed_work_on(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	int cpu = (int)p0;
	struct workqueue_struct *wq;
	struct delayed_work *dwork = (struct delayed_work *)p2;
	unsigned long delay = (unsigned long)p3;

	if (is_kage_objdescriptor(p1)) {
		wq = kage_obj_get(kage, p1, KAGE_ODTYPE_WORKQUEUE);
		if (!wq) {
			pr_err("%s: invalid object descriptor\n", __func__);
			return 0;
		}
	}
	else {

		if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
			pr_err("%s: guest pointer argument out of bounds\n", __func__);
			return 0;
		}
		wq = (struct workqueue_struct *)p1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return 0;
	}

	return queue_delayed_work_on(cpu, wq, dwork, delay);
}

static unsigned long guard__raw_spin_lock_irqsave(struct kage *kage, unsigned long p0,
					      unsigned long p1, unsigned long p2,
					      unsigned long p3, unsigned long p4,
					      unsigned long p5)
{
	raw_spinlock_t *lock = (raw_spinlock_t *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	_raw_spin_lock_irqsave(lock);
	return 0;
}

static unsigned long guard__raw_spin_unlock_irqrestore(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	raw_spinlock_t *lock = (raw_spinlock_t *)p0;
	unsigned long flags = (unsigned long)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	_raw_spin_unlock_irqrestore(lock, flags);
	return 0;
}

static unsigned long guard_regmap_read(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct regmap *map = (struct regmap *)p0;
	unsigned int reg = (unsigned int)p1;
	unsigned int *val = (unsigned int *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return regmap_read(map, reg, val);
}

static unsigned long guard_regmap_write(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct regmap *map = (struct regmap *)p0;
	unsigned int reg = (unsigned int)p1;
	unsigned int val = (unsigned int)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return regmap_write(map, reg, val);
}

static unsigned long guard_scnprintf(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	char *buf = (char *)p0;
	size_t size = (size_t)p1;
	const char *fmt = (const char *)p2;
	va_list *args = (va_list *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return scnprintf(buf, size, fmt, *args);
}

static unsigned long guard_seq_lseek(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	loff_t offset = (loff_t)p1;
	int whence = (int)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return seq_lseek(file, offset, whence);
}

static unsigned long guard_seq_open(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	const struct seq_operations *op = (const struct seq_operations *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return seq_open(file, op);
}

static unsigned long guard_seq_printf(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct seq_file *m = (struct seq_file *)p0;
	const char *fmt = (const char *)p1;
	va_list *args = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	seq_printf(m, fmt, *args);
	return 0;
}

static unsigned long guard_seq_read(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	char __user *buf = (char __user *)p1;
	size_t size = (size_t)p2;
	loff_t *ppos = (loff_t *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return seq_read(file, buf, size, ppos);
}

static unsigned long guard_seq_release(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct inode *inode = (struct inode *)p0;
	struct file *file = (struct file *)p1;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return seq_release(inode, file);
}

static unsigned long guard_simple_attr_open(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct inode *inode = (struct inode *)p0;
	struct file *file = (struct file *)p1;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return simple_attr_open(inode, file, NULL, NULL, NULL);
}

static unsigned long guard_simple_attr_read(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	char __user *buf = (char __user *)p1;
	size_t size = (size_t)p2;
	loff_t *ppos = (loff_t *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return simple_attr_read(file, buf, size, ppos);
}

static unsigned long guard_simple_attr_release(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return 0;
}

static unsigned long guard_simple_open(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct inode *inode = (struct inode *)p0;
	struct file *file = (struct file *)p1;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return simple_open(inode, file);
}

static unsigned long guard_simple_read_from_buffer(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	void __user *to = (void __user *)p0;
	size_t count = (size_t)p1;
	loff_t *ppos = (loff_t *)p2;
	const void *from = (const void *)p3;
	size_t available = (size_t)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return simple_read_from_buffer(to, count, ppos, from, available);
}

static unsigned long guard_simple_write_to_buffer(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	void *to = (void *)p0;
	size_t available = (size_t)p1;
	loff_t *ppos = (loff_t *)p2;
	const void __user *from = (const void __user *)p3;
	size_t count = (size_t)p4;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return simple_write_to_buffer(to, available, ppos, from, count);
}

static unsigned long guard_single_open(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct file *file = (struct file *)p0;
	int (*show)(struct seq_file *, void *) = (int (*)(struct seq_file *, void *))p1;
	void *data = (void *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return single_open(file, show, data);
}

static unsigned long guard_single_release(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct inode *inode = (struct inode *)p0;
	struct file *file = (struct file *)p1;

	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return single_release(inode, file);
}

static unsigned long guard_sscanf(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *buf = (const char *)p0;
	const char *fmt = (const char *)p1;
	va_list *args = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return sscanf(buf, fmt, *args);
}

static unsigned long guard_stack_chk_fail(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	__stack_chk_fail();
	return 0;
}

static unsigned long guard_strlen(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *s = (const char *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return strlen(s);
}

static unsigned long guard_strncmp(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *cs = (const char *)p0;
	const char *ct = (const char *)p1;
	size_t count = (size_t)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return strncmp(cs, ct, count);
}

static unsigned long guard_strnlen(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *s = (const char *)p0;
	size_t count = (size_t)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return strnlen(s, count);
}

static unsigned long guard_strscpy(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	char *dest = (char *)p0;
	const char *src = (const char *)p1;
	size_t count = (size_t)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return strscpy(dest, src, count);
}

static unsigned long guard_strsep(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	char **s = (char **)p0;
	const char *ct = (const char *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)strsep(s, ct);
}

static unsigned long guard_sysfs_emit_at(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	char *buf = (char *)p0;
	int at = (int)p1;
	const char *fmt = (const char *)p2;
	va_list *args = (va_list *)p3;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	sysfs_emit_at(buf, at, fmt, *args);
	return 0;
}

static unsigned long guard_system_wq(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	return (unsigned long)system_wq;
}

#ifdef CONFIG_CHARGER_MAX77759
static unsigned long guard_tcpm_get_partner_src_caps(struct kage *kage, unsigned long p0,
						     unsigned long p1, unsigned long p2,
						     unsigned long p3, unsigned long p4,
						     unsigned long p5)
{
	struct tcpm_port *port = (struct tcpm_port *)p0;
	u32 *src_caps = (u32 *)p1;
	int *cnt = (int *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return tcpm_get_partner_src_caps(port, src_caps, cnt);
}

static unsigned long guard_tcpm_put_partner_src_caps(struct kage *kage, unsigned long p0,
						     unsigned long p1, unsigned long p2,
						     unsigned long p3, unsigned long p4,
						     unsigned long p5)
{
	struct tcpm_port *port = (struct tcpm_port *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	tcpm_put_partner_src_caps(port);
	return 0;
}
#endif

static unsigned long guard_unregister_chrdev_region(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	dev_t from = (dev_t)p0;
	unsigned count = (unsigned)p1;

	unregister_chrdev_region(from, count);
	return 0;
}

static unsigned long guard_up(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct semaphore *sem = (struct semaphore *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	up(sem);
	return 0;
}

static unsigned long guard_vprintk(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	const char *fmt = (const char *)p0;
	va_list *args = (va_list *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return vprintk(fmt, *args);
}

static unsigned long guard_wakeup_source_register(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	struct device *dev = (struct device *)p0;
	const char *name = (const char *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	return (unsigned long)wakeup_source_register(dev, name);
}

static unsigned long guard_wakeup_source_unregister(struct kage *kage, unsigned long p0,
						  unsigned long p1, unsigned long p2,
						  unsigned long p3, unsigned long p4,
						  unsigned long p5)
{
	struct wakeup_source *ws = (struct wakeup_source *)p0;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	wakeup_source_unregister(ws);
	return 0;
}

static unsigned long guard___warn_printk(struct kage *kage, unsigned long p0,
					 unsigned long p1, unsigned long p2,
					 unsigned long p3, unsigned long p4,
					 unsigned long p5)
{
	const char *fmt = (const char *)p0;
	va_list *pargs = (va_list *)p1;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}

	__warn_printk(fmt, *pargs);
	return 0;
}

static unsigned long guard___dynamic_pr_dbg(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
#if defined(CONFIG_DYNAMIC_DEBUG) || \
	(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))
	struct _ddebug *descriptor = (struct _ddebug *)p0;
	const char *fmt = (const char *)p1;
	va_list *va_args = (va_list *)p2;

	if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		pr_err("%s: guest pointer argument out of bounds\n", __func__);
		return -1;
	}
	struct va_format vaf = {fmt, va_args};

	__dynamic_pr_debug(descriptor, "%pV", &vaf);
	return 0;
#else
	return -1;
#endif
}

static unsigned long guard_simple_attr_write(struct kage *kage, unsigned long p0,
                                      unsigned long p1, unsigned long p2,
                                      unsigned long p3, unsigned long p4,
                                      unsigned long p5)
{
	 struct file *file = (struct file *)p0;
	 const char __user *buf = (const char __user *)p1;
	 size_t size = (size_t)p2;
	 loff_t *ppos = (loff_t *)p3;

	 if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
		 pr_err("%s: guest pointer argument out of bounds\n", __func__);
		 return -1;
	 }
	 if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
		 pr_err("%s: guest pointer argument out of bounds\n", __func__);
		 return -1;
	 }
	 if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
		 pr_err("%s: guest pointer argument out of bounds\n", __func__);
		 return -1;
	 }

	 return simple_attr_write(file, buf, size, ppos);
}

static unsigned long guard_sysfs_emit(struct kage *kage, unsigned long p0,
                               unsigned long p1, unsigned long p2,
                               unsigned long p3, unsigned long p4,
                               unsigned long p5)
{
 char *buf = (char *)p0;
 const char *fmt = (const char *)p1;
 va_list *args = (va_list *)p2;

 if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }
 if (p1 < kage->base || p1 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }
 if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }

 return sysfs_emit(buf, fmt, *args);
}

static unsigned long guard_vsnprintf(struct kage *kage, unsigned long p0,
                              unsigned long p1, unsigned long p2,
                              unsigned long p3, unsigned long p4,
                              unsigned long p5)
{
 char *buf = (char *)p0;
 size_t size = (size_t)p1;
 const char *fmt = (const char *)p2;
 va_list *args = (va_list *)p3;

 if (p0 < kage->base || p0 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }
 if (p2 < kage->base || p2 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }
 if (p3 < kage->base || p3 >= kage->base + KAGE_GUEST_SIZE) {
         pr_err("%s: guest pointer argument out of bounds\n", __func__);
         return -1;
 }

 return vsnprintf(buf, size, fmt, *args);
}


guard_t *syscall_to_guard[KAGE_SYSCALL_COUNT] = {
	[KAGE_TASKLET_INIT] = guard_tasklet_init,
        [KAGE___TASKLET_SCHEDULE] = guard___tasklet_schedule,
	[KAGE_PRINTK] = guard__printk,
	[KAGE_KMALLOC_GENERIC] = guard_kmalloc_generic,
        [KAGE_KMALLOC_TRACE] = guard_kmalloc_trace,
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
	[KAGE_DEBUGFS_CREATE_DIR] = guard_debugfs_create_dir,
	[KAGE_DEBUGFS_CREATE_FILE] = guard_debugfs_create_file,
	[KAGE_DEBUGFS_REMOVE] = guard_debugfs_remove,
	[KAGE_DELAYED_WORK_TIMER_FN] = guard_delayed_work_timer_fn,
	[KAGE_DEV_DRIVER_STRING] = guard_dev_driver_string,
	[KAGE__DEV_ERR] = guard__dev_err,
	[KAGE__DEV_INFO] = guard__dev_info,
	[KAGE_DEVM_KMALLOC] = guard_devm_kmalloc,
	[KAGE_DEV_PRINTK_EMIT] = guard_dev_printk_emit,
	[KAGE__DEV_WARN] = guard__dev_warn,
	[KAGE_DOWN_INTERRUPTIBLE] = guard_down_interruptible,
	[KAGE___DYNAMIC_DEV_DBG] = guard___dynamic_dev_dbg,
	[KAGE_FORTIFY_PANIC] = guard_fortify_panic,
	[KAGE_GENERIC_FILE_LLSEEK] = guard_generic_file_llseek,
	[KAGE_GEN_POOL_ADD_OWNER] = guard_gen_pool_add_owner,
	[KAGE_GEN_POOL_ALLOC_ALGO_OWNER] = guard_gen_pool_alloc_algo_owner,
	[KAGE_GEN_POOL_CREATE] = guard_gen_pool_create,
	[KAGE_GEN_POOL_DESTROY] = guard_gen_pool_destroy,
	[KAGE_INIT_TIMER_KEY] = guard_init_timer_key,
	[KAGE_KFREE] = guard_kfree,
	[KAGE_KLIST_ADD_HEAD] = guard_klist_add_head,
	[KAGE_KLIST_ADD_TAIL] = guard_klist_add_tail,
	[KAGE_KLIST_INIT] = guard_klist_init,
	[KAGE_KLIST_ITER_EXIT] = guard_klist_iter_exit,
	[KAGE_KLIST_ITER_INIT] = guard_klist_iter_init,
	[KAGE_KLIST_NEXT] = guard_klist_next,
	[KAGE_KLIST_REMOVE] = guard_klist_remove,
	[KAGE_KSTRDUP] = guard_kstrdup,
	[KAGE_KSTRTOINT] = guard_kstrtoint,
	[KAGE_KTIME_GET_REAL_SECONDS] = guard_ktime_get_real_seconds,
	[KAGE_KTIME_GET_WITH_OFFSET] = guard_ktime_get_with_offset,
	[KAGE_LIST_ADD_VALID_OR_REPORT] = guard_list_add_valid_or_report,
	[KAGE_LIST_DEL_ENTRY_VALID_OR_REPORT] = guard_list_del_entry_valid_or_report,
#ifdef CONFIG_GOOGLE_LOGBUFFER
	[KAGE_LOGBUFFER_LOG] = guard_logbuffer_log,
	[KAGE_LOGBUFFER_VLOG] = guard_logbuffer_vlog,
#endif
	[KAGE_MEMCPY] = guard_memcpy,
	[KAGE_MEMSET] = guard_memset,
	[KAGE_MSLEEP] = guard_msleep,
	[KAGE_MUTEX_INIT] = guard_mutex_init,
	[KAGE_MUTEX_LOCK] = guard_mutex_lock,
	[KAGE_MUTEX_UNLOCK] = guard_mutex_unlock,
	[KAGE_NVMEM_DEVICE_PUT] = guard_nvmem_device_put,
	[KAGE_NVMEM_DEVICE_READ] = guard_nvmem_device_read,
	[KAGE_NVMEM_DEVICE_WRITE] = guard_nvmem_device_write,
	[KAGE_OF_FIND_NODE_BY_NAME] = guard_of_find_node_by_name,
	[KAGE_OF_FIND_NODE_BY_PHANDLE] = guard_of_find_node_by_phandle,
	[KAGE_OF_FIND_PROPERTY] = guard_of_find_property,
	[KAGE_OF_GET_CHILD_BY_NAME] = guard_of_get_child_by_name,
	[KAGE_OF_GET_NEXT_CHILD] = guard_of_get_next_child,
	[KAGE_OF_GET_PROPERTY] = guard_of_get_property,
	[KAGE_OF_NVMEM_DEVICE_GET] = guard_of_nvmem_device_get,
	[KAGE_OF_PROPERTY_COUNT_ELEMS_OF_SIZE] = guard_of_property_count_elems_of_size,
	[KAGE_OF_PROPERTY_READ_STRING] = guard_of_property_read_string,
	[KAGE_OF_PROPERTY_READ_STRING_HELPER] = guard_of_property_read_string_helper,
	[KAGE_OF_PROPERTY_READ_VARIABLE_U16_ARRAY] = guard_of_property_read_variable_u16_array,
	[KAGE_OF_PROPERTY_READ_VARIABLE_U32_ARRAY] = guard_of_property_read_variable_u32_array,
	[KAGE_PM_RELAX] = guard_pm_relax,
	[KAGE_PM_STAY_AWAKE] = guard_pm_stay_awake,
	[KAGE_POWER_SUPPLY_GET_BY_PHANDLE_ARRAY] = guard_power_supply_get_by_phandle_array,
	[KAGE_POWER_SUPPLY_GET_DRVDATA] = guard_power_supply_get_drvdata,
	[KAGE_POWER_SUPPLY_GET_PROPERTY] = guard_power_supply_get_property,
	[KAGE_POWER_SUPPLY_PUT] = guard_power_supply_put,
	[KAGE_POWER_SUPPLY_SET_PROPERTY] = guard_power_supply_set_property,
	[KAGE_QUEUE_DELAYED_WORK_ON] = guard_queue_delayed_work_on,
	[KAGE__RAW_SPIN_LOCK_IRQSAVE] = guard__raw_spin_lock_irqsave,
	[KAGE__RAW_SPIN_UNLOCK_IRQRESTORE] = guard__raw_spin_unlock_irqrestore,
	[KAGE_REGMAP_READ] = guard_regmap_read,
	[KAGE_REGMAP_WRITE] = guard_regmap_write,
	[KAGE_SCNPRINTF] = guard_scnprintf,
	[KAGE_SEQ_LSEEK] = guard_seq_lseek,
	[KAGE_SEQ_OPEN] = guard_seq_open,
	[KAGE_SEQ_PRINTF] = guard_seq_printf,
	[KAGE_SEQ_READ] = guard_seq_read,
	[KAGE_SEQ_RELEASE] = guard_seq_release,
	[KAGE_SIMPLE_ATTR_OPEN] = guard_simple_attr_open,
	[KAGE_SIMPLE_ATTR_READ] = guard_simple_attr_read,
	[KAGE_SIMPLE_ATTR_RELEASE] = guard_simple_attr_release,
	[KAGE_SIMPLE_ATTR_WRITE] = guard_simple_attr_write,
	[KAGE_SIMPLE_OPEN] = guard_simple_open,
	[KAGE_SIMPLE_READ_FROM_BUFFER] = guard_simple_read_from_buffer,
	[KAGE_STRNLEN] = guard_strnlen,
	[KAGE_SYSFS_EMIT] = guard_sysfs_emit,
	[KAGE_UP] = guard_up,
	[KAGE_VSNPRINTF] = guard_vsnprintf,
	[KAGE_SIMPLE_WRITE_TO_BUFFER] = guard_simple_write_to_buffer,
	[KAGE_SINGLE_OPEN] = guard_single_open,
	[KAGE_SINGLE_RELEASE] = guard_single_release,
	[KAGE_SSCANF] = guard_sscanf,
	[KAGE_STACK_CHK_FAIL] = guard_stack_chk_fail,
	[KAGE_STRLEN] = guard_strlen,
	[KAGE_STRNCMP] = guard_strncmp,
	[KAGE_STRSCPY] = guard_strscpy,
	[KAGE_STRSEP] = guard_strsep,
	[KAGE_SYSFS_EMIT_AT] = guard_sysfs_emit_at,
	[KAGE_SYSTEM_WQ] = guard_system_wq,
	[KAGE_UNREGISTER_CHRDEV_REGION] = guard_unregister_chrdev_region,
	[KAGE_VPRINTK] = guard_vprintk,
	[KAGE_WAKEUP_SOURCE_REGISTER] = guard_wakeup_source_register,
	[KAGE_WAKEUP_SOURCE_UNREGISTER] = guard_wakeup_source_unregister,
	[KAGE___DYNAMIC_PR_DBG] = guard___dynamic_pr_dbg,
#ifdef CONFIG_CHARGER_MAX77759
	[KAGE_TCPM_GET_PARTNER_SRC_CAPS] = guard_tcpm_get_partner_src_caps,
	[KAGE_TCPM_PUT_PARTNER_SRC_CAPS] = guard_tcpm_put_partner_src_caps,
#endif
	[KAGE___WARN_PRINTK] = guard___warn_printk,
};
