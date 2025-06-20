// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kage.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pgtable.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "objdesc.h"

#define MODULE_NAME "kage"
#define VM_AREA_SIZE (64UL * 1024 * 1024 * 1024)
#define MAX_GUESTS (VM_AREA_SIZE / KAGE_GUEST_SIZE - 1)

// To reduce PTE fragmentation, prefer PMD-sized allocations.
// FIXME: This won't be appropriate for PAGE_SIZE > 4KiB, nor call stacks
int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
			     pgprot_t prot, struct page **pages,
			     unsigned int page_shift);

struct vm_struct *vm_area;
spinlock_t lock;

static struct kage kages[MAX_GUESTS];

// Returns true if compatible with LFI Spec 2.5 dense mode.
bool is_valid_vaddr(struct kage const *kage, unsigned long addr,
		    enum mod_mem_type type)
{
	unsigned long offset = addr - kage->base;

	if (addr < kage->base)
		return false;
	if (offset < PAGE_SIZE + 80UL * 1024 ||
	    offset > KAGE_GUEST_SIZE - 80UL * 1024)
		return false;
	if (offset > KAGE_GUEST_SIZE - 128UL * 1024 && mod_mem_type_is_text(type))
		return false;
	return true;
}

static void *kage_memory_alloc_explicit(struct kage *kage, unsigned long start,
					unsigned long end,
					enum mod_mem_type type, bool do_lock, gfp_t flags)
{
	unsigned long size = end - start;
	if (size > KAGE_GUEST_SIZE)
		return ERR_PTR(-ENOMEM);

	unsigned int nr_pages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	unsigned long start_offset = start - kage->base;
	unsigned long irq_flags;
	int i, err;
	void *ret = NULL;
	struct page **tmp_pages;


	/* Track pages allocated to undo the allocation on failure */
	tmp_pages = kmalloc_array(nr_pages, sizeof(*tmp_pages), GFP_KERNEL);
	if (!tmp_pages)
		return ERR_PTR(-ENOMEM);

	// FIXME: we need a more fine-grained lock
	if (do_lock)
		spin_lock_irqsave(&lock, irq_flags);

	for (i = 0; i < nr_pages; i++) {
		tmp_pages[i] = alloc_page(flags);
		if (!tmp_pages[i]) {
			ret = ERR_PTR(-ENOMEM);
			goto free_pages;
		}
		kage->pages[(start_offset >> PAGE_SHIFT) + i] =
			tmp_pages[i];
		set_bit((start_offset >> PAGE_SHIFT) + i,
			kage->alloc_bitmap);
	}

	pgprot_t prot = PAGE_KERNEL;
#if 0
	if (mod_mem_type_is_text(type))
		prot = PAGE_KERNEL_EXEC;
#endif

	/* Map pages into VM area */
	err = vmap_pages_range_noflush(start, end, prot, tmp_pages,
				       PAGE_SHIFT);
	flush_cache_vmap(start, end);
	if (err)
		goto free_pages;

	ret = (void *)start;
	goto cleanup;

free_pages:
	for (i--; i >= 0; i--) {
		clear_bit((start_offset >> PAGE_SHIFT) + i,
			  kage->alloc_bitmap);
		__free_page(tmp_pages[i]);
	}
cleanup:
	if (do_lock)
		spin_unlock_irqrestore(&lock, irq_flags);
	kfree(tmp_pages);
	return ret;
}

/*
 * Allocates memory in the guest's address range
 */
void *kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type, gfp_t flags)
{
	pr_info("kage_memory_alloc: type=%d\n", type);
	unsigned long start = ALIGN(kage->base + kage->next_open_offs,
				    1 << PAGE_SHIFT);
	unsigned long end = ALIGN(start + size, 1 << PAGE_SHIFT);
	void *ret = NULL;
	unsigned long irq_flags;

	size = end - start;

	if (!is_valid_vaddr(kage, start, type) ||
	    !is_valid_vaddr(kage, end, type)) {
		pr_err("%s: cannot allocate size %zu\n", MODULE_NAME, size);
		return ERR_PTR(-ENOMEM);
	}

	spin_lock_irqsave(&lock, irq_flags);
	ret = kage_memory_alloc_explicit(kage, start, end, type, false, flags);
	if (IS_ERR(ret))
		goto cleanup;
	kage->next_open_offs = end - kage->base;
cleanup:
	spin_unlock_irqrestore(&lock, irq_flags);
	return ret;
}
EXPORT_SYMBOL(kage_memory_alloc);

static void kage_free_closures(struct kage *kage)
{
	assoc_array_destroy(&kage->closures, NULL);
}

static int kage_init(struct kage *kage)
{
	unsigned long nr_pages = VM_AREA_SIZE >> PAGE_SHIFT;
	int i, err;
	static u8 next_owner_id = 0;

	if (next_owner_id == KAGE_OWNER_GLOBAL)
		return -ENOSPC;

	kage->pages = vzalloc(nr_pages * sizeof(*kage->pages));
	kage->alloc_bitmap = bitmap_zalloc(nr_pages, GFP_KERNEL);
	kage->next_open_offs = PAGE_SIZE + 80UL * 1024;
	BUG_ON(!is_valid_vaddr(kage, kage->base + kage->next_open_offs,
			       MOD_TEXT));
	if (!kage->pages || !kage->alloc_bitmap) {
		vfree(kage->pages);
		kage->pages = 0;
		bitmap_free(kage->alloc_bitmap);
		return -ENOMEM;
	}

	err = kage_objstorage_init(&kage->objstorage);
	if (err) {
		vfree(kage->pages);
		kage->pages = 0;
		bitmap_free(kage->alloc_bitmap);
		return err;
	}

	kage->owner_id = next_owner_id++;

	for (i = 0; i < ARRAY_SIZE(kage->procs); i++)
		kage->procs[i] = NULL;
	kage->open_proc_idx = 0;
	assoc_array_init(&kage->closures);
	return 0;
}

void kage_memory_free(struct kage *kage, void *vaddr)
{
//FIXME
#if 0
	unsigned long vaddr_offset = vaddr - kage->base;
	unsigned long end = vaddr + size;
	unsigned int first_page = vaddr_offset >> DOMAIN_PAGE_SHIFT;
	unsigned int nr_pages = size >> DOMAIN_PAGE_SHIFT;
	unsigned long flags;
	int i;

	if (vaddr_offset >= KAGE_GUEST_SIZE || end > kage->base + KAGE_GUEST_SIZE) {
		WARN_ON(1);
		return;
	}

	spin_lock_irqsave(&lock, flags);

	for (i = 0; i < nr_pages; i++) {
		if (!test_bit(first_page + i, kage->alloc_bitmap)) {
			spin_unlock_irqrestore(&lock, flags);
			WARN_ON(1);
		}
	}

	vunmap_range(vaddr, end);

	spin_unlock_irqrestore(&lock, flags);
	return 0;
#endif
}
EXPORT_SYMBOL(kage_memory_free);

void kage_memory_free_all(struct kage *kage)
{
	unsigned long flags;
	unsigned int nr_pages = KAGE_GUEST_SIZE >> PAGE_SHIFT;
	int i;

	vunmap_range(kage->base, kage->base + KAGE_GUEST_SIZE);
	spin_lock_irqsave(&lock, flags);
	for_each_set_bit(i, kage->alloc_bitmap, nr_pages)
		__free_page(kage->pages[i]);

	bitmap_zero(kage->alloc_bitmap, nr_pages);
	spin_unlock_irqrestore(&lock, flags);
}
EXPORT_SYMBOL(kage_memory_free_all);

static ssize_t debugfs_trigger_write(struct file *debug_file_node,
				     const char __user *user_buf, size_t count,
				     loff_t *ppos);

static struct dentry *my_debugfs_dir;
// File operations for our debugfs node
static const struct file_operations debugfs_trigger_fops = {
	.owner = THIS_MODULE,
	.write = debugfs_trigger_write,
	.llseek = no_llseek,
};

static void init_debugfs(void)
{
	my_debugfs_dir = debugfs_create_dir("kage", NULL);
	if (IS_ERR_OR_NULL(my_debugfs_dir)) {
		pr_warn("%s: Failed to create debugfs directory\n",
			MODULE_NAME);
		my_debugfs_dir = NULL;
	} else if (!debugfs_create_file("load", 0220, my_debugfs_dir, NULL,
					&debugfs_trigger_fops)) {
		pr_warn("%s: Failed to create debugfs file 'load'\n",
			MODULE_NAME);
		debugfs_remove_recursive(my_debugfs_dir);
		my_debugfs_dir = NULL;
	} else {
		pr_info("%s: Created debugfs entry at /sys/kernel/debug/kage/load\n",
			MODULE_NAME);
	}
}

// Set the start addrs of the kage
static void init_kages(void)
{
	unsigned long addr = ALIGN((unsigned long)vm_area->addr, KAGE_GUEST_SIZE);
	int i;

	for (i = 0; i < MAX_GUESTS; i++)
		kages[i].base = addr;

	addr += KAGE_GUEST_SIZE;
	BUG_ON(addr > ((unsigned long)vm_area->addr + vm_area->size));
}


static struct kage_objstorage *kage_global_objstorage;

int kage_objstorage_init(struct kage_objstorage **storage_ptr)
{
	*storage_ptr = kzalloc(sizeof(struct kage_objstorage), GFP_KERNEL);
	if (!*storage_ptr)
		return -ENOMEM;
	spin_lock_init(&(*storage_ptr)->lock);
	(*storage_ptr)->next_slot = 0;
	return 0;
}

void kage_objstorage_free(struct kage_objstorage *storage)
{
	kfree(storage);
}

void *kage_obj_get(struct kage *kage, u64 descriptor,
		   enum kage_objdescriptor_type type)
{
	u8 owner = kage_unpack_objdescriptor_owner(descriptor);
	u16 objindex = kage_unpack_objdescriptor_objindex(descriptor);
	u8 obj_type = kage_unpack_objdescriptor_type(descriptor);
	struct kage_objstorage *storage;

	// Pass-through NULLs; sometimes that's OK
        if (!descriptor)
		return 0;

	if (objindex > KAGE_MAX_OBJ_INDEX)
		return ERR_PTR(-EINVAL);

	if (obj_type != type)
		return ERR_PTR(-EINVAL);

	if (owner == KAGE_OWNER_GLOBAL)
		storage = kage_global_objstorage;
	else
		storage = kage->objstorage;

	return rcu_dereference(storage->objs[objindex]);
}

void kage_obj_set(struct kage *kage, u64 descriptor, void *obj)
{
	u8 owner = kage_unpack_objdescriptor_owner(descriptor);
	u16 objindex = kage_unpack_objdescriptor_objindex(descriptor);
	struct kage_objstorage *storage;

	BUG_ON(objindex > KAGE_MAX_OBJ_INDEX);

	if (owner == KAGE_OWNER_GLOBAL)
		storage = kage_global_objstorage;
	else
		storage = kage->objstorage;

	rcu_assign_pointer(storage->objs[objindex], obj);
}

void kage_obj_delete(struct kage *kage, u64 descriptor)
{
	kage_obj_set(kage, descriptor, NULL);
}

u64 kage_objstorage_alloc(struct kage *kage, bool is_global,
			  enum kage_objdescriptor_type type,
			  void * obj)
{
	struct kage_objstorage *storage;
	unsigned long flags;
	unsigned int i;
	u8 owner;

	if (is_global) {
		storage = kage_global_objstorage;
		owner = KAGE_OWNER_GLOBAL;
	} else {
		storage = kage->objstorage;
		owner = kage->owner_id;
	}

	spin_lock_irqsave(&storage->lock, flags);

	for (i = 0; i <= KAGE_MAX_OBJ_INDEX; i++) {
		unsigned int slot = (storage->next_slot + i) % (KAGE_MAX_OBJ_INDEX + 1);

		if (!rcu_dereference_protected(storage->objs[slot],
					       lockdep_is_held(&storage->lock))) {
			storage->next_slot = slot + 1;
			spin_unlock_irqrestore(&storage->lock, flags);
			u64 desc = kage_pack_objdescriptor(type, owner, slot);
			kage_obj_set(kage, desc, obj);
			return desc;
		}
	}

	spin_unlock_irqrestore(&storage->lock, flags);
	return 0;
}

static int __init kagemodule_init(void)
{
	unsigned long vmalloc_start_addr, vmalloc_end_addr, vmalloc_size_bytes;
	int err;

	/* Initialize context */
	init_debugfs();

	spin_lock_init(&lock);

	err = kage_objstorage_init(&kage_global_objstorage);
	if (err)
		return err;

	/* Allocate VM area */
	vm_area = get_vm_area(VM_AREA_SIZE, VM_ALLOC);
	if (!vm_area)
		return -ENOMEM;

	init_kages();

	vmalloc_start_addr = (unsigned long)VMALLOC_START;
	vmalloc_end_addr = (unsigned long)VMALLOC_END;
	vmalloc_size_bytes = vmalloc_end_addr - vmalloc_start_addr;

	pr_info("kage_vmalloc_info: Vmalloc Area Size:     %lu bytes (%lu MB, %lu GB)\n",
		vmalloc_size_bytes, vmalloc_size_bytes / (1024 * 1024),
		vmalloc_size_bytes / (1024 * 1024 * 1024));

	return 0;
}

// Find and return an unused kage in the kages array
static struct kage *alloc_kage(void)
{
	struct kage *kage = NULL;
	static int nextidx;
	int i = nextidx;
	int last = i ? i - 1 : MAX_GUESTS - 1;

	do {
		if (!kages[i].pages) {
			kage = &kages[i];
			break;
		}
		i = (i + 1) % MAX_GUESTS;
	} while (i != last);

	nextidx = i++ % MAX_GUESTS;

	return kage;
}

static uint64_t kage_syshandler(struct kage *kage, uint64_t sysno, uint64_t p0,
				uint64_t p1, uint64_t p2, uint64_t p3,
				uint64_t p4, uint64_t p5)
{
	guard_t *f;

	pr_info("%s syshandler %llu %llx %llx %llx %llx %llx %llx\n",
		MODULE_NAME, sysno, p0, p1, p2, p3, p4, p5);
	if (sysno >= KAGE_SYSCALL_COUNT) {
		pr_warn("%s invalid system call number %lld\n", MODULE_NAME,
			sysno);
		return -1;
	}

	f = syscall_to_guard[sysno];
	if (!f) {
		pr_warn("%s invalid system call number %lld\n", MODULE_NAME,
			sysno);
		return -1;
	}
	return f(kage, p0, p1, p2, p3, p4, p5);
}

/* Setup the syspage at the lowest address of the guest range */
static int setup_lfisys(struct kage *kage)
{
	unsigned long lfisys_end = ALIGN((kage->base + sizeof(struct LFISys)),
					 PAGE_SIZE);
	void *sysmem = kage_memory_alloc_explicit(kage, kage->base, lfisys_end,
						  MOD_DATA, true, GFP_KERNEL);

	if (IS_ERR(sysmem))
		return PTR_ERR(sysmem);

	kage->sys = (struct LFISys *)kage->base;
	kage->sys->rtcalls[0] = (uintptr_t)&lfi_syscall_entry;
	kage->sys->rtcalls[3] = (uintptr_t)&lfi_ret;
	kage->sys->procs = &kage->procs;
	return 0;
}

static unsigned long find_symbol_address(const struct kage * kage,
					 const Elf_Shdr *sechdrs,
                                         unsigned int shnum,
                                         const Elf_Sym *symtab,
                                         unsigned int num_syms,
                                         const char *strtab,
                                         const char *target_symbol_name)
{
  unsigned int i;
  const Elf_Sym *s;
  const char *name;
  const char *modname = kage->modname;

  /* Basic validation of the data passed from the loader. */
  if (!sechdrs || !symtab || !strtab) {
          pr_warn("kage: Invalid ELF data provided for module '%s'\n", modname);
          return 0;
  }

  /* Iterate through all symbols in the module's symbol table. */
  for (i = 0; i < num_syms; i++) {
          s = &symtab[i];
          name = strtab + s->st_name;

          if (strcmp(name, target_symbol_name) == 0) {
                  /*
                   * Found the symbol by name. The symbol's section index
                   * (st_shndx) tells us which section it belongs to.
                   */
                  if (s->st_shndx >= shnum || s->st_shndx == SHN_UNDEF) {
                          pr_warn("kage: Symbol '%s' in module '%s' has an invalid section index %u\n",
                                  target_symbol_name, modname, s->st_shndx);
                          return 0;
                  }

                  /*
                   * The final address is the base address where the section was
                   * loaded (sechdrs[s->st_shndx].sh_addr) plus the symbol's
                   * offset within that section (s->st_value).
                   *
                   * This relies on the caller having already run the layout
                   * logic that populates sh_addr with the final VMA.
                   */
                  return sechdrs[s->st_shndx].sh_addr + s->st_value;
          }
  }

  pr_warn("kage: Symbol '%s' not found in module '%s'\n",
          target_symbol_name, modname);
  return 0;
}

void kage_post_move(struct kage *kage, 
			   const Elf_Shdr *sechdrs,
                           unsigned int shnum,
                           const Elf_Sym *symtab,
                           unsigned int num_syms,
                           const char *strtab)
{
	unsigned long do_ret = find_symbol_address(kage, sechdrs, shnum, symtab, num_syms, strtab, "do_ret");
	pr_info("do_ret addr=0x%lx\n", do_ret);
	kage->exit_addr = do_ret;
	unsigned long do_ret2 = find_symbol_address(kage, sechdrs, shnum, symtab, num_syms, strtab, "do_ret2");
	pr_info("do_ret2 addr=0x%lx\n", do_ret2);
}


struct kage *kage_create(const char *modname)
{
	struct kage *kage;
	int err;
	unsigned long irq_flags;
	bool in_cs = false;

	// There's a remote chance that two calls can come in simultaneously, so
	// serialize with a lock
	spin_lock_irqsave(&lock, irq_flags);
	in_cs = true;
	kage = alloc_kage();
	if (!kage) {
		err = ENOMEM;
		goto on_err;
	}

	err = kage_init(kage);
	if (err)
		goto on_err;

	kage->syshandler = kage_syshandler;

	spin_unlock_irqrestore(&lock, irq_flags);
	in_cs = false;

	err = setup_lfisys(kage);
	if (err) 
		goto on_err;

	return kage;
on_err:
	if (in_cs)
		spin_unlock_irqrestore(&lock, irq_flags);
	kage_free(kage);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(kage_create);

static struct LFIProc *alloc_lfiproc(struct kage *kage, int *idx)
{
	int start_idx = kage->open_proc_idx;
	struct LFIProc *lfiproc;

	while (kage->procs[kage->open_proc_idx]) {
		kage->open_proc_idx =
			(kage->open_proc_idx + 1) % ARRAY_SIZE(kage->procs);
		if (start_idx == kage->open_proc_idx)
			return NULL;
	}
	lfiproc = kmalloc(sizeof(*lfiproc), GFP_KERNEL);
	if (!lfiproc)
		return NULL;

	*idx = kage->open_proc_idx;
	kage->procs[kage->open_proc_idx] = lfiproc;
	kage->open_proc_idx =
		(kage->open_proc_idx + 1) % ARRAY_SIZE(kage->procs);
	return lfiproc;
}

// Call a module init function
int kage_call_init(struct kage *kage, initcall_t fn) {
	return kage_call(kage, fn, 0, 0, 0, 0, 0, 0);
}

// Invoke a function call into the sandbox
uint64_t kage_call(struct kage *kage, void * fn,
              uint64_t p0, uint64_t p1, uint64_t p2, 
              uint64_t p3, uint64_t p4, uint64_t p5)
{
	// FIXME: check fn in sandbox range
	void *sb_stack = kage_memory_alloc(kage, 1 << KAGE_SANDBOX_STACK_ORDER,
					   MOD_DATA, GFP_KERNEL);
	uint64_t rv;
	int lfi_idx;
	struct LFIProc *lfiproc = alloc_lfiproc(kage, &lfi_idx);
	if (!lfiproc) {
		pr_err(MODULE_NAME " kage_call: Failure to allocate LFI context\n");
		return -1;
	}
	unsigned long rel_stack_base =
		(uintptr_t)sb_stack + KAGE_SANDBOX_STACK_SIZE - kage->base;

	lfi_proc_init(lfiproc, kage, (int64_t)fn - kage->base, rel_stack_base,
		      lfi_idx);
	rv = lfi_proc_invoke(lfiproc, fn, (void *)(kage->exit_addr), 
			     p0, p1, p2, p3, p4, p5);
	pr_info("%s finished\n", __func__);
    // FIXME: free lfiproc
	return rv;
}

static ssize_t debugfs_trigger_write(struct file *debug_file_node,
				     const char __user *user_buf, size_t count,
				     loff_t *ppos)
{
	char *path_buf;
	struct file *target_file_ptr;
	size_t slen;

	if (*ppos != 0) {
		pr_warn("%s: Partial write to debugfs not supported\n",
			MODULE_NAME);
		return -EINVAL;
	}
	if (count >= PAGE_SIZE) {
		pr_warn("%s: Path too long for debugfs\n", MODULE_NAME);
		return -EINVAL;
	}

	pr_info("%s: count=%zu\n", MODULE_NAME, count);
	path_buf = strndup_user(user_buf, PAGE_SIZE);
	if (IS_ERR(path_buf)) {
		pr_warn("%s: Failed to copy path from user: err=%ld\n",
			MODULE_NAME, PTR_ERR(path_buf));
		return PTR_ERR(path_buf);
	}

	slen = strlen(path_buf);
	if (!slen) {
		pr_warn("%s: Empty path\n", MODULE_NAME);
		kfree(path_buf);
		return -EINVAL;
	}

	if (path_buf[slen - 1] == '\n')
		path_buf[slen - 1] = '\0';

	target_file_ptr = filp_open(path_buf, O_RDONLY, 0);
	if (IS_ERR(target_file_ptr)) {
		pr_warn("%s: Failed to open file '%s': %ld\n", MODULE_NAME,
			path_buf, PTR_ERR(target_file_ptr));
		kfree(path_buf);
		return PTR_ERR(target_file_ptr);
	}

	filp_close(target_file_ptr, NULL);
	kfree(path_buf);

	return count;
}

void kage_free(struct kage *kage)
{
	pr_info("%s %s\n", MODULE_NAME, __func__);
	kage_free_closures(kage);
	kage_memory_free_all(kage);
	kage_objstorage_free(kage->objstorage);
	bitmap_free(kage->alloc_bitmap);
	vfree(kage->pages);
	kage->pages = NULL;
}
EXPORT_SYMBOL(kage_free);

static void __exit kagemodule_exit(void)
{
	int i;

	pr_info(MODULE_NAME ": Exiting\n");
	for (i = 0; i < MAX_GUESTS; i++) {
		struct kage *kage = &kages[i];

		if (kage->pages)
			kage_free(kage);
	}
	kage_objstorage_free(kage_global_objstorage);
	vfree(vm_area);
}

module_init(kagemodule_init);
module_exit(kagemodule_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nic Watson");
MODULE_DESCRIPTION("Kage: A Kernel Module Sandbox");
