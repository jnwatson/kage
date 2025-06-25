// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include "linux/gfp_types.h"
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
#include <asm-generic/vmlinux.lds.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "objdesc.h"

static_assert(offsetof(struct LFIProc, kage) == KAGE_LFIPROC_KAGE_OFFS, 
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFIProc, regs) == KAGE_LFIPROC_REGS_OFFS, 
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFISys, procs) == KAGE_LFISYS_PROCS_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct kage_g2h_call, guard_func) == 
			KAGE_G2H_CALL_GUARD_FUNC_OFFS,
	      "Inconsistency among guards.h and kage_asm.h");

#define VM_AREA_SIZE (64UL * 1024 * 1024 * 1024)
#define MAX_GUESTS (VM_AREA_SIZE / KAGE_GUEST_SIZE - 1)

// FIXME: avoid alloc inside of spinlock

static int kage_objstorage_init(struct kage_objstorage **storage_ptr);

int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
			     pgprot_t prot, struct page **pages,
			     unsigned int page_shift);

struct vm_struct *vm_area;
unsigned long vm_area_start;
unsigned long vm_area_end;

static struct kage *kages[MAX_GUESTS];
static spinlock_t module_lock;

// Returns true if compatible with LFI Spec 2.5 dense mode.
bool is_valid_vaddr(struct kage const *kage, unsigned long addr,
		    enum mod_mem_type type)
{
	unsigned long offset = addr - kage->base;

	if (addr < kage->base)
		return false;
	if (offset < PAGE_SIZE + 80UL * 1024 ||
	    offset >= KAGE_GUEST_SIZE - 80UL * 1024)
		return false;
	if (offset >= KAGE_GUEST_SIZE - 128UL * 1024 && mod_mem_type_is_text(type))
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
	if (!tmp_pages) {
		pr_err(MODULE_NAME ": kmalloc_array failed\n");
		return 0;
	}

	if (do_lock)
		spin_lock_irqsave(&kage->lock, irq_flags);

	for (i = 0; i < nr_pages; i++) {
		tmp_pages[i] = alloc_page(flags);
		if (!tmp_pages[i]) {
			ret = ERR_PTR(-ENOMEM);
			goto free_pages;
		}
		set_bit((start_offset >> PAGE_SHIFT) + i,
			kage->alloc_bitmap);
	}

	pgprot_t prot = PAGE_KERNEL;

	/* Map pages into VM area */
	err = vmap_pages_range_noflush(start, end, prot, tmp_pages,
				       PAGE_SHIFT);
	if (err) {
		pr_err(MODULE_NAME 
		       ": vmap_pages_range_noflush failed with %pe\n", 
		       ERR_PTR(err));
		ret = NULL;
		goto free_pages;
	}

	if (end - kage->base > kage->next_open_memory_offs)
		kage->next_open_memory_offs = end - kage->base;
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
		spin_unlock_irqrestore(&kage->lock, irq_flags);
	kfree(tmp_pages);
	return ret;
}
/*
 * Allocates memory in the guest's address range.
 * FIXME:  type parameter not used
 */
static void *kage_memory_alloc_aligned(struct kage *kage, size_t size, enum
				       mod_mem_type type, gfp_t flags, size_t
				       alignment)
{
	unsigned long irq_flags;
	void * ret;

	spin_lock_irqsave(&kage->lock, irq_flags);
	unsigned long start = ALIGN(kage->base + kage->next_open_memory_offs,
				    alignment);
	unsigned long end = ALIGN(start + size, alignment);
	size = end - start;

	if (!is_valid_vaddr(kage, start, type) ||
	    !is_valid_vaddr(kage, end, type)) {
		pr_err("%s: cannot allocate size %zu\n", MODULE_NAME, size);
		ret = ERR_PTR(-ENOMEM);
		goto cleanup;
	}

	ret = kage_memory_alloc_explicit(kage, start, end, type, false, flags);
cleanup:
	spin_unlock_irqrestore(&kage->lock, irq_flags);
	return ret;
}

void * kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type,
		   gfp_t flags)
{
	return kage_memory_alloc_aligned(kage, size, type, flags, PAGE_SIZE);
}

EXPORT_SYMBOL(kage_memory_alloc);

static void kage_free_closures(struct kage *kage)
{
	assoc_array_destroy(&kage->closures, NULL);
}

/* Allocate two chunks twice, one page apart, one for the text, and one for the
 * literal pool */
static int alloc_trampolines(struct kage *kage)
{
	// g2h is allocated in guest space
	kage->g2h_tramp_text = kage->g2h_tramp_data = NULL;
	kage->h2g_tramp_text = kage->h2g_tramp_data = NULL;

	kage->g2h_tramp_text = 
		kage_memory_alloc(kage, 2 * KAGE_G2H_TRAMP_REGION_SIZE, MOD_TEXT, 
				  GFP_KERNEL);
	if (!kage->g2h_tramp_text)
		goto on_err;

	kage->g2h_tramp_data = (void *)((unsigned long)kage->g2h_tramp_text +
			KAGE_G2H_TRAMP_REGION_SIZE);

	// h2g is allocated in host space
	kage->h2g_tramp_text = vzalloc(2 * KAGE_H2G_TRAMP_REGION_SIZE);
	if (!kage->h2g_tramp_text)
		goto on_err;
	kage->h2g_tramp_data = (void *)((unsigned long)kage->h2g_tramp_text +
			KAGE_H2G_TRAMP_REGION_SIZE);

	pr_info("g2h trampoline text=%llx, data=%llx\n", (u64)kage->g2h_tramp_text, 
		(u64)kage->g2h_tramp_data);

	return 0;

on_err:
	kage_memory_free(kage, kage->g2h_tramp_text);
	kage_memory_free(kage, kage->g2h_tramp_data);
	vfree(kage->h2g_tramp_text);
	vfree(kage->h2g_tramp_data);
	return -ENOMEM;
}

struct g2h_tramp_data_entry {
	const struct kage_g2h_call *call;
	u64 trampoline; // points to lfi_syscall_entry2
};

static_assert(sizeof(struct g2h_tramp_data_entry)==KAGE_G2H_TRAMP_SIZE);

// tmp
extern guard_t *syscall_to_guard[KAGE_SYSCALL_COUNT];

static void fill_trampolines(struct kage *kage)
{
	unsigned int i;
	unsigned long tramp_loc = (unsigned long)kage->g2h_tramp_text;
	for (i=0; i<kage->num_g2h_calls; i++) {
		memcpy((void *)tramp_loc, &lfi_g2h_trampoline, KAGE_G2H_TRAMP_SIZE);
		tramp_loc += KAGE_G2H_TRAMP_SIZE;
	}
	size_t left = (unsigned long)kage->g2h_tramp_text + KAGE_G2H_TRAMP_REGION_SIZE - tramp_loc;
	memset((void *)tramp_loc, 0, left);

	struct g2h_tramp_data_entry* entry = kage->g2h_tramp_data;
	for (i=0; i<kage->num_g2h_calls; i++) {
		struct kage_g2h_call * host_call = kage->g2h_calls[i];
		entry[i].call = host_call;
		entry[i].trampoline = host_call->stub;
	}
	left = (unsigned long)kage->g2h_tramp_data + KAGE_G2H_TRAMP_REGION_SIZE - 
			(unsigned long)(&entry[i]);
	memset(&entry[i], 0, left);

	tramp_loc = (unsigned long)kage->h2g_tramp_text;
	for (i=0; i<KAGE_MAX_H2G_CALLS; i++) {
		memcpy((void *)tramp_loc, &lfi_h2g_trampoline, KAGE_H2G_TRAMP_SIZE);
		tramp_loc += KAGE_H2G_TRAMP_SIZE;
	}

}

/* Returns the absolute address in the guest of the trampoline for the target of
 * a guest's call of a function in the kernel or another module */
unsigned long kage_symbol_value(struct kage *kage, const char *name, 
				unsigned long target_func)
{
	unsigned int i;
	for (i=0; i<kage->num_g2h_calls; i++) {
		/* We can compare strings by address here because they point to
		 the same structure */
		if (name == kage->g2h_calls[i]->name)
			return (unsigned long)kage->g2h_tramp_text + 
				i * KAGE_G2H_TRAMP_SIZE;
	}
	if (kage->num_g2h_calls >= ARRAY_SIZE(kage->g2h_calls)) {
		pr_err(MODULE_NAME 
		       ": exceeded max external call sites from guest\n");
		return 0;
	}
	struct kage_g2h_call *host_call = create_g2h_call(name, target_func);
	if (IS_ERR(host_call)) {
		pr_err(MODULE_NAME 
		       ": error %pe creating host call %s\n", host_call, name);
		return 0;
	}
	unsigned long ret = (unsigned long)kage->g2h_tramp_text + 
				kage->num_g2h_calls * KAGE_G2H_TRAMP_SIZE;
	kage->g2h_calls[kage->num_g2h_calls++] = host_call;
	pr_info(MODULE_NAME ": kage_symbol_value %s=%lx\n", name, ret);
	return ret;
}


static int kage_init(struct kage *kage)
{
	unsigned long num_pages = KAGE_GUEST_SIZE >> PAGE_SHIFT;
	int i, err;
	static u8 next_owner_id = 0;

	spin_lock_init(&kage->lock);
	kage->alloc_bitmap = bitmap_zalloc(num_pages, GFP_KERNEL);
	kage->next_open_memory_offs = PAGE_SIZE + 80UL * 1024;
	BUG_ON(!is_valid_vaddr(kage, kage->base + kage->next_open_memory_offs,
			       MOD_TEXT));
	if (!kage->alloc_bitmap) {
		err = -ENOMEM;
		goto objstorage_err;
	}

	err = kage_objstorage_init(&kage->objstorage);
	if (err)
		goto objstorage_err;

	kage->owner_id = next_owner_id++;

	for (i = 0; i < ARRAY_SIZE(kage->procs); i++)
		kage->procs[i] = NULL;
	kage->open_proc_idx = 0;
	assoc_array_init(&kage->closures);
	kage->num_g2h_calls = 0;
	kage->num_h2g_calls = 0;
	err = alloc_trampolines(kage);
	if (err)
		goto tramp_err;
	return 0;
tramp_err:
	kfree(kage->objstorage);
objstorage_err:
	bitmap_free(kage->alloc_bitmap);
	return err;
}

void kage_memory_free(struct kage *kage, void *vaddr)
{
	if (!vaddr)
		return;
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
	unsigned long nr_pages = KAGE_GUEST_SIZE >> PAGE_SHIFT;
	unsigned long i;

	vunmap_range(kage->base, kage->base + KAGE_GUEST_SIZE);
	for_each_set_bit(i, kage->alloc_bitmap, nr_pages) {
		struct page *page;
		unsigned long vaddr = kage->base + (i << PAGE_SHIFT);

		page = vmalloc_to_page((const void *)vaddr);
		if (page) {
			__free_page(page);
		}
	}

	bitmap_zero(kage->alloc_bitmap, nr_pages);
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

static struct kage_objstorage *kage_global_objstorage;

static int kage_objstorage_init(struct kage_objstorage **storage_ptr)
{
	*storage_ptr = kzalloc(sizeof(struct kage_objstorage), GFP_KERNEL);
	if (!*storage_ptr)
		return -ENOMEM;
	spin_lock_init(&(*storage_ptr)->lock);
	(*storage_ptr)->next_slot = 0;
	return 0;
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
	u64 ret = 0;

	if (is_global) {
		storage = kage_global_objstorage;
		owner = KAGE_OWNER_GLOBAL;
	} else {
		storage = kage->objstorage;
		owner = kage->owner_id;
	}

	spin_lock_irqsave(&storage->lock, flags);

	for (i = 0; i <= ARRAY_SIZE(kage->objstorage->objs); i++) {
		unsigned int slot = (storage->next_slot + i) % (KAGE_MAX_OBJ_INDEX + 1);

		if (!rcu_dereference_protected(storage->objs[slot],
					       lockdep_is_held(&storage->lock))) {
			storage->next_slot = slot + 1;
			u64 desc = kage_pack_objdescriptor(type, owner, slot);
			kage_obj_set(kage, desc, obj);
			ret = desc;
			break;
		}
	}
	if (!ret) {
		pr_err(MODULE_NAME ": objstorage exhausted\n");
	}

	spin_unlock_irqrestore(&storage->lock, flags);
	return ret;
}

static int __init kagemodule_init(void)
{
	unsigned long vmalloc_start_addr, vmalloc_end_addr, vmalloc_size_bytes;
	int err;

	/* Initialize context */
	init_debugfs();

	err = kage_objstorage_init(&kage_global_objstorage);
	if (err)
		return err;

	spin_lock_init(&module_lock);

	/* Allocate VM area */
	vm_area = get_vm_area(VM_AREA_SIZE, VM_ALLOC);
	if (!vm_area)
		return -ENOMEM;
	vm_area_start = ALIGN((unsigned long)vm_area->addr, KAGE_GUEST_SIZE);
	vm_area_end = vm_area_start + MAX_GUESTS * KAGE_GUEST_SIZE - 1;

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
	static int nextidx = 1;
	unsigned long irq_flags;
	kage = kzalloc(sizeof(*kage), GFP_KERNEL);
	if (!kage)
		return ERR_PTR(-ENOMEM);

	spin_lock_irqsave(&module_lock, irq_flags);
	kage->owner_id = nextidx++;
	spin_unlock_irqrestore(&module_lock, irq_flags);

	kage->base = (kage->owner_id - 1) * KAGE_GUEST_SIZE + vm_area_start;
	BUG_ON(kage->base + KAGE_GUEST_SIZE > vm_area_end);

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
        // FIXME: remove rtcalls
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

// Mark text RX and data R
static int protect_trampolines(struct kage *kage)
{
	int err;

	struct {
		unsigned long text;
		size_t size;
	} parms[] = {
		{(unsigned long)kage->g2h_tramp_text, 
			KAGE_G2H_TRAMP_REGION_SIZE },
		{(unsigned long)kage->h2g_tramp_text, 
			KAGE_H2G_TRAMP_REGION_SIZE },
	};

	for (int i=0; i<ARRAY_SIZE(parms); i++) {
		err = set_memory_x(parms[i].text, parms[i].size >> PAGE_SHIFT);
		if (err) {
			pr_err(MODULE_NAME ": Failed to set trampoline text "
			       "executable: %pe\n", ERR_PTR(err));
			return err;
		}

		err = set_memory_ro(parms[i].text, parms[i].size >> PAGE_SHIFT);
		if (err) {
			pr_err(MODULE_NAME ": Failed to set trampoline text "
			       "read-only: %pe\n", ERR_PTR(err));
			return err;
		}

		flush_icache_range(parms[i].text, parms[i].text + parms[i].size);
	}

	err = set_memory_ro((unsigned long)kage->g2h_tramp_data,
			    KAGE_G2H_TRAMP_REGION_SIZE >> PAGE_SHIFT);
	if (err) {
		pr_err("kage: Failed to set trampoline data RO: %pe\n",
			ERR_PTR(err));
		return err;
	}
	return 0;
}

int kage_post_relocation(struct kage *kage, 
		    const Elf_Shdr *sechdrs,
                    unsigned int shnum,
                    const Elf_Sym *symtab,
                    unsigned int num_syms,
                    const char *strtab)
{

	// FIXME:  dynamically allocate in guest
	unsigned long do_ret = find_symbol_address(kage, sechdrs, shnum, 
						   symtab, num_syms, strtab, 
						   "do_ret");
	pr_info("do_ret addr=0x%lx\n", do_ret); // DEBUG
	kage->exit_addr = do_ret;

	fill_trampolines(kage);
	int err = protect_trampolines(kage);
	if (err)
		return err;
	return 0;
}

static void do_linktime_assertions(void) 
{
	BUG_ON((unsigned long)&lfi_g2h_trampoline_end - 
	       (unsigned long)&lfi_g2h_trampoline != KAGE_G2H_TRAMP_SIZE);
	BUG_ON((unsigned long)&lfi_h2g_trampoline_end - 
	       (unsigned long)&lfi_h2g_trampoline != KAGE_H2G_TRAMP_SIZE);

}
struct kage *kage_create(const char *modname)
{
	struct kage *kage;
	int err;
	bool in_cs = false;
	do_linktime_assertions();

	kage = alloc_kage();
	if (!kage) {
		err = ENOMEM;
		goto on_err;
	}

	err = kage_init(kage);
	if (err)
		goto on_err;

	kage->syshandler = kage_syshandler;

	in_cs = false;

	err = setup_lfisys(kage);
	if (err) 
		goto on_err;

	return kage;
on_err:
	kage_destroy(kage);
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

// Invoke a function call into the guest
uint64_t kage_call(struct kage *kage, void * fn,
              uint64_t p0, uint64_t p1, uint64_t p2, 
              uint64_t p3, uint64_t p4, uint64_t p5)
{
	// FIXME: check fn in guest range
	void *guest_stack = kage_memory_alloc_aligned(kage,
						      KAGE_GUEST_STACK_SIZE,
						      MOD_DATA, GFP_KERNEL,
						      KAGE_GUEST_STACK_SIZE);
	if (!guest_stack) {
		pr_err(MODULE_NAME " kage_call: Failed to allocate guest stack\n");
		return -1;
	}
	pr_info("guest stack at %px-%px\n", guest_stack, 
		(char *)guest_stack + KAGE_GUEST_STACK_SIZE - 1);
	uint64_t rv;
	int lfi_idx;
	struct LFIProc *lfiproc = alloc_lfiproc(kage, &lfi_idx);
	if (!lfiproc) {
		pr_err(MODULE_NAME " kage_call: Failure to allocate LFI context\n");
		return -1;
	}
	unsigned long rel_stack_base =
		(uintptr_t)guest_stack + KAGE_GUEST_STACK_SIZE - kage->base;

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

void kage_destroy(struct kage *kage)
{
	unsigned int i;
	pr_info("%s %s\n", MODULE_NAME, __func__);
	kage_free_closures(kage);
	kage_memory_free_all(kage);
	kfree(kage->objstorage);
	bitmap_free(kage->alloc_bitmap);
	for (i=0; i < kage->num_g2h_calls; i++) {
		kfree(kage->g2h_calls[i]);
	}
	kages[kage->owner_id - 1] = NULL;
}
EXPORT_SYMBOL(kage_destroy);

static void __exit kagemodule_exit(void)
{
	int i;

	pr_info(MODULE_NAME ": Exiting\n");
	for (i = 0; i < MAX_GUESTS; i++) {
		struct kage *kage = kages[i];

		kage_destroy(kage);
	}
	kfree(kage_global_objstorage);
	vfree(vm_area);
}

module_init(kagemodule_init);
module_exit(kagemodule_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nic Watson");
MODULE_DESCRIPTION("Kage: A Kernel Module Sandbox");
