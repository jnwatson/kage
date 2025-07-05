// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include "linux/err.h"
#include <linux/gfp_types.h>
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
#include <linux/scs.h>
#include <asm-generic/vmlinux.lds.h>

#include "runtime.h"
#include "proc.h"
#include "guards.h"
#include "objdesc.h"

// DEBUG
#pragma clang optimize off

static_assert(offsetof(struct LFIProc, kstackp) == KAGE_LFIPROC_KSTACKP_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFIProc, sstackp) == KAGE_LFIPROC_SSTACKP_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFIProc, kage) == KAGE_LFIPROC_KAGE_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFIProc, regs) == KAGE_LFIPROC_REGS_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct LFISys, procs) == KAGE_LFISYS_PROCS_OFFS,
	      "Inconsistency among proc.h and kage_asm.h");
static_assert(offsetof(struct kage_g2h_call, guard_func) ==
			KAGE_G2H_CALL_GUARD_FUNC_OFFS,
	      "Inconsistency among guards.h and kage_asm.h");
static_assert(offsetof(struct kage_g2h_call, guard_func2) ==
			KAGE_G2H_CALL_GUARD_FUNC2_OFFS,
	      "Inconsistency among guards.h and kage_asm.h");
static_assert(offsetof(struct kage_g2h_call, host_func) ==
			KAGE_G2H_CALL_HOST_FUNC_OFFS,
	      "Inconsistency among guards.h and kage_asm.h");
static_assert(KAGE_GUEST_STACK_ORDER <= THREAD_SIZE_ORDER + PAGE_SHIFT);

// Size of the space reserved for *all* guests
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
// Nic tmp
	flush_cache_vmap(start, end);

	if (err) {
		pr_err(MODULE_NAME
		       ": vmap_pages_range_noflush failed with %pe\n",
		       ERR_PTR(err));
		ret = NULL;
		goto free_pages;
	}

	if (end - kage->base > kage->next_open_memory_offs)
		kage->next_open_memory_offs = end - kage->base + PAGE_SIZE;
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
	//pr_info("kmae 0x%lx - 0x%lx, page=%px\n", start, end, vmalloc_to_page((void *)start));
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

/* Allocate two regions, one in guest, one in host, for trampolines.  Split
 * each of the two regions in half:  one for the text, one for its literal pool
 */
static int alloc_trampolines(struct kage *kage)
{
	// g2h is allocated in guest space
	kage->g2h_tramp_text = kage->g2h_tramp_data = NULL;
	kage->h2g_tramp_text = kage->h2g_tramp_data = NULL;

	kage->g2h_tramp_text =
		kage_memory_alloc(kage, 2 * KAGE_G2H_TRAMP_REGION_SIZE,
				  MOD_TEXT, GFP_KERNEL);
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

	pr_info("g2h trampoline text=0x%px, data=0x%px\n", kage->g2h_tramp_text,
		kage->g2h_tramp_data);
	pr_info("h2g trampoline text=0x%px, data=0x%px\n", kage->h2g_tramp_text,
		kage->h2g_tramp_data);

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
	u64 trampoline; // points to lfi_syscall_entry
};

static_assert(sizeof(struct g2h_tramp_data_entry)==KAGE_G2H_TRAMP_SIZE);


/* Returns a b <offs> instruction, a relative jump of offs bytes */
static u32 make_rel_branch_inst(s32 offs) {
    BUG_ON((offs % 4) != 0);

    const uint32_t b_opcode = 0x05;

    int32_t imm = offs / 4;
    uint32_t imm26 = imm & 0x03FFFFFF;
    return (b_opcode << 26) | imm26;
}

static void fill_trampolines(struct kage *kage)
{
	unsigned int i;
	unsigned long tramp_loc = (unsigned long)kage->g2h_tramp_text;

	// Copy in the G2H trampolines (into guest memory)
	for (i=0; i<kage->num_g2h_calls; i++) {
		memcpy((void *)tramp_loc, &lfi_g2h_trampoline, KAGE_G2H_TRAMP_SIZE);
		tramp_loc += KAGE_G2H_TRAMP_SIZE;
	}

	// Copy in do_ret
	kage->exit_addr = tramp_loc;
	memcpy((void *)tramp_loc, &do_ret, KAGE_DO_RET_SIZE);
	tramp_loc += KAGE_DO_RET_SIZE;

	// Zero the rest
	size_t left = (unsigned long)kage->g2h_tramp_text + KAGE_G2H_TRAMP_REGION_SIZE - tramp_loc;
	memset((void *)tramp_loc, 0, left);

	// Copy in the G2H trampoline literal pool
	struct g2h_tramp_data_entry* entry = kage->g2h_tramp_data;
	for (i=0; i<kage->num_g2h_calls; i++) {
		struct kage_g2h_call * host_call = kage->g2h_calls[i];
		entry[i].call = host_call;
		entry[i].trampoline = host_call->stub;
	}
	left = (unsigned long)kage->g2h_tramp_data + KAGE_G2H_TRAMP_REGION_SIZE
			- (unsigned long)(&entry[i]);
	memset(&entry[i], 0, left);

	/* Copy in the H2G trampolines (in host memory).  The literal pool
	 * gets filled in later dynamically */
	tramp_loc = (unsigned long)kage->h2g_tramp_text;
	for (i=0; i<KAGE_MAX_H2G_CALLS; i++) {
		memcpy((void *)tramp_loc, &lfi_h2g_trampoline, KAGE_H2G_TRAMP_SIZE);
		// Patch in a jump to lfi_setup_kage_call
		u32 branch_offset = (unsigned long)kage->h2g_tramp_text + 
				KAGE_H2G_TRAMP_REGION_SETUP_OFFSET - 
				(tramp_loc + 8);
		((u32 *)tramp_loc)[2] = make_rel_branch_inst(branch_offset);
		tramp_loc += KAGE_H2G_TRAMP_SIZE;
	}

	// Copy in lfi_setup_kage_call at the end
	BUG_ON(tramp_loc - (unsigned long)kage->h2g_tramp_text != 
	       KAGE_H2G_TRAMP_REGION_SETUP_OFFSET);
	memcpy((void *)tramp_loc, &lfi_setup_kage_call, 
	       KAGE_SETUP_KAGE_CALL_SIZE);

	// Fill lfi_setup_kage_call literal pool
	*(unsigned long *)(tramp_loc + KAGE_H2G_TRAMP_REGION_SIZE) = 
			(unsigned long)kage_call;

	BUG_ON(tramp_loc + KAGE_SETUP_KAGE_CALL_SIZE - 
	       (unsigned long)kage->h2g_tramp_text > 
		KAGE_H2G_TRAMP_REGION_SIZE);
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

	spin_lock_init(&kage->lock);
	kage->alloc_bitmap = bitmap_zalloc(num_pages, GFP_KERNEL);
	if (!kage->alloc_bitmap) {
		return -ENOMEM;
	}
	kage->next_open_memory_offs = PAGE_SIZE + 80UL * 1024;
	BUG_ON(!is_valid_vaddr(kage, kage->base + kage->next_open_memory_offs,
			       MOD_TEXT));

	err = kage_objstorage_init(&kage->objstorage);
	if (err)
		goto objstorage_err;

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

       unsigned long vaddr_offset = (unsigned long)vaddr - kage->base;
       unsigned int first_page = vaddr_offset >> PAGE_SHIFT;
       unsigned long nr_pages = KAGE_GUEST_SIZE >> PAGE_SHIFT;
       unsigned long i;

       if (vaddr_offset >= KAGE_GUEST_SIZE) {
               WARN_ON(1);
               return;
       }

       // FIXME:  this is super-fragile.  Need a more robust heap system
       unsigned long size = 0;
       for (i = first_page; i < nr_pages; i++) {
               if (!test_and_clear_bit(i, kage->alloc_bitmap))
                       break;
               size += PAGE_SIZE;
       }

       for (i = first_page; i < first_page + (size >> PAGE_SHIFT); i++) {
               struct page *page = vmalloc_to_page((const void *)(kage->base + (i << PAGE_SHIFT)));
               if (page)
                       __free_page(page);
       }
       vunmap_range((unsigned long)vaddr, (unsigned long)vaddr + size);
       //pr_info("kmfr 0x%lx - 0x%lx\n", (unsigned long)vaddr, (unsigned long)vaddr + size);
}
EXPORT_SYMBOL(kage_memory_free);

void kage_memory_free_all(struct kage *kage)
{
	unsigned long nr_pages = KAGE_GUEST_SIZE >> PAGE_SHIFT;
	unsigned long i;

	//pr_info("kmfa start");
	for_each_set_bit(i, kage->alloc_bitmap, nr_pages) {
		struct page *page;
		unsigned long vaddr = kage->base + (i << PAGE_SHIFT);

		page = vmalloc_to_page((const void *)vaddr);
		if (page) {
			__free_page(page);
			//pr_info("kmfa 0x%lx\n", vaddr);
		}
		//else
		//	pr_info("kmfa !mp 0x%lx\n", vaddr);

	}
	bitmap_zero(kage->alloc_bitmap, nr_pages);
	vunmap_range(kage->base, kage->base + KAGE_GUEST_SIZE);
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

void *kage_obj_get(struct kage *kage, u64 descriptor, u16 type)
{
	u8 owner = kage_unpack_objdescriptor_owner(descriptor);
	u16 objindex = kage_unpack_objdescriptor_objindex(descriptor);
	u16 obj_type = kage_unpack_objdescriptor_type(descriptor);
	struct kage_objstorage *storage;
	//pr_info("%s: try %llx(%x, %4u(=?%4u), %x)\n", __func__, 
	//	descriptor, owner, obj_type, type, objindex);

	// Pass-through NULLs; sometimes that's OK
        if (!descriptor)
		return 0;

	if (!is_kage_objdescriptor(descriptor)) 
		return NULL;

	if (objindex > KAGE_MAX_OBJ_INDEX)
		return NULL;

	if (obj_type != type)
		return NULL;

	if (owner == KAGE_OWNER_GLOBAL)
		storage = kage_global_objstorage;
	else
		storage = kage->objstorage;

	void * rv = rcu_dereference(storage->objs[objindex]);
	pr_info("%s: %llx(%x, %4u, %x) -> 0x%px\n", __func__, 
		descriptor, owner, obj_type, objindex, rv);

	return rv;
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
	u16 obj_type = kage_unpack_objdescriptor_type(descriptor);
	pr_info("%s: %llx(%x, %4u, %x) -> 0x%px\n", __func__, 
		descriptor, owner, obj_type, objindex, obj);
}

void kage_obj_delete(struct kage *kage, u64 descriptor)
{
	kage_obj_set(kage, descriptor, NULL);
}

u64 kage_objstorage_alloc(struct kage *kage, bool is_global,
			  u16 type,
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
			u64 desc = kage_pack_objdescriptor(type, is_global, slot);
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

static void do_linktime_assertions(void)
{
	BUG_ON((unsigned long)&lfi_g2h_trampoline_end -
	       (unsigned long)&lfi_g2h_trampoline != KAGE_G2H_TRAMP_SIZE);
	BUG_ON((unsigned long)&lfi_h2g_trampoline_end -
	       (unsigned long)&lfi_h2g_trampoline != KAGE_H2G_TRAMP_SIZE);
	BUG_ON((unsigned long)&lfi_setup_kage_call_end -
	       (unsigned long)&lfi_setup_kage_call != 
		KAGE_SETUP_KAGE_CALL_SIZE);
	BUG_ON((unsigned long)&do_ret_end - (unsigned long)&do_ret != 
		KAGE_DO_RET_SIZE);
}

static int __init kagemodule_init(void)
{
	unsigned long vmalloc_start_addr, vmalloc_end_addr, vmalloc_size_bytes;
	int err;
	do_linktime_assertions();

	/* Initialize context */
	init_debugfs();

	err = kage_objstorage_init(&kage_global_objstorage);
	if (err)
		return err;

	spin_lock_init(&module_lock);

	// TODO:  if an aligned version of this is exported, we could allocate
	// on demand
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
	int idx = -1;
	unsigned long irq_flags;
	kage = kzalloc(sizeof(*kage), GFP_KERNEL);
	if (!kage)
		return ERR_PTR(-ENOMEM);

	spin_lock_irqsave(&module_lock, irq_flags);
	for (int i = 0; i < ARRAY_SIZE(kages); i++) {
	        if (!kages[i]) {
	                idx = i;
	                break;
	        }
	}
	
	if (idx == -1) {
	        spin_unlock(&module_lock);
	        kfree(kage);
	        return ERR_PTR(-ENOMEM);
	}

	kage->owner_id = idx;
        kages[kage->owner_id] = kage;
	spin_unlock_irqrestore(&module_lock, irq_flags);

	kage->base = (kage->owner_id) * KAGE_GUEST_SIZE + vm_area_start;
	BUG_ON(kage->base + KAGE_GUEST_SIZE > vm_area_end);

	return kage;
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
	kage->sys->rtcalls[3] = (unsigned long)&lfi_ret;
	kage->sys->procs = &kage->procs;
	return 0;
}

// Don't need this right now
#if 0
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
#endif 

static void unprotect_trampolines(struct kage *kage)
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
		err = set_memory_rw(parms[i].text, parms[i].size >> PAGE_SHIFT);
		if (err) {
			pr_err(MODULE_NAME ": Failed to set trampoline text "
			       "read-write: %pe\n", ERR_PTR(err));
		}
	}

	err = set_memory_rw((unsigned long)kage->g2h_tramp_data,
			    KAGE_G2H_TRAMP_REGION_SIZE >> PAGE_SHIFT);
	if (err) {
		pr_err("kage: Failed to set trampoline data read-write: %pe\n",
			ERR_PTR(err));
	}
}

static int set_memory_xonly(unsigned long addr, size_t size)
{
	int err;
	int npages = size >> PAGE_SHIFT;

	err = set_memory_x(addr, npages);
	if (err) {
		pr_err(MODULE_NAME ": Failed to set trampoline text "
		       "executable: %pe\n", ERR_PTR(err));
		return err;
	}

	err = set_memory_ro(addr, npages);
	if (err) {
		pr_err(MODULE_NAME ": Failed to set trampoline text "
		       "read-only: %pe\n", ERR_PTR(err));
		return err;
	}

	flush_icache_range(addr, addr + size);
	return 0;
}

// Mark text RX and data R
static int protect_trampolines(struct kage *kage)
{
	int err;

	err = set_memory_xonly((unsigned long)kage->g2h_tramp_text, 
			       KAGE_G2H_TRAMP_REGION_SIZE);
	if (err)
		return err;

	err = set_memory_xonly((unsigned long)kage->h2g_tramp_text, 
			       KAGE_H2G_TRAMP_REGION_SIZE);
	if (err)
		return err;

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
	fill_trampolines(kage);
	int err = protect_trampolines(kage);
	if (err)
		return err;
	return 0;
}

struct kage *kage_create(const char *modname)
{
	pr_info("%s started\n", __func__);

	struct kage *kage;
	int err;
	bool in_cs = false;

	kage = alloc_kage();
	if (IS_ERR(kage)) {
		return kage;
	}

	err = kage_init(kage);
	if (err)
		goto on_err;

	in_cs = false;

	err = setup_lfisys(kage);
	if (err)
		goto on_err;
	pr_info("%s with base 0x%lx finished\n", __func__, kage->base);
	return kage;
on_err:
	kage_destroy(kage);
	return ERR_PTR(err);
}
EXPORT_SYMBOL(kage_create);

static struct LFIProc *alloc_lfiproc(struct kage *kage, int *ret_idx)
{
	int start_idx = kage->open_proc_idx;
	int idx;
	struct LFIProc *lfiproc;
	unsigned long irq_flags;

	spin_lock_irqsave(&kage->lock, irq_flags);
	while (kage->procs[kage->open_proc_idx]) {
		kage->open_proc_idx =
			(kage->open_proc_idx + 1) % ARRAY_SIZE(kage->procs);
		if (start_idx == kage->open_proc_idx) {
			spin_unlock_irqrestore(&kage->lock, irq_flags);
			return NULL;
		}
	}
	idx = kage->open_proc_idx;
	// Reserve the slot so no one takes it
	kage->procs[idx] = (struct LFIProc *)1;
	spin_unlock_irqrestore(&kage->lock, irq_flags);

	lfiproc = kmalloc(sizeof(*lfiproc), GFP_KERNEL);
	if (!lfiproc) {
		kage->procs[idx] = NULL;
		return NULL;
	}

	*ret_idx = idx;
	kage->procs[idx] = lfiproc;
	kage->open_proc_idx =
		(idx + 1) % ARRAY_SIZE(kage->procs);
	return lfiproc;
}

#ifdef CONFIG_SHADOW_CALL_STACK 
static void * guest_scs_alloc(struct kage *kage)
{
        void * stack= kage_memory_alloc(kage, SCS_SIZE, MOD_DATA, GFP_SCS);
	if (!stack) {
		pr_err(MODULE_NAME " %s: Failed to allocate guest shadow stack\n",
		       __func__);
		return ERR_PTR(-ENOMEM);
	}
        return stack;
}
#else
static void * guest_scs_alloc(struct kage *kage) {
	return NULL;
}
#endif


// Invoke a function call into the guest
unsigned long kage_call(struct kage *kage, void * fn,
              unsigned long p0, unsigned long p1, unsigned long p2,
              unsigned long p3, unsigned long p4, unsigned long p5)
{
	void *guest_stack;
	void *guest_shadow_stack;
	unsigned long rv;
	int lfi_idx;
	struct LFIProc *lfiproc;

	if (((unsigned long)fn - kage->base) >= KAGE_GUEST_SIZE) {
		pr_err(MODULE_NAME " %s: call outside of guest range\n", 
		       __func__);
		return -1;
	}


	guest_stack = kage_memory_alloc_aligned(kage,
						KAGE_GUEST_STACK_SIZE,
						MOD_DATA, GFP_KERNEL,
						THREAD_ALIGN);
	if (!guest_stack) {
		pr_err(MODULE_NAME " %s: Failed to allocate guest stack\n", 
		       __func__);
		return -1;
	}

	guest_shadow_stack = guest_scs_alloc(kage);
	if (IS_ERR(guest_shadow_stack)) {
		kage_memory_free(kage, guest_stack);
		return -1;
	}

	lfiproc = alloc_lfiproc(kage, &lfi_idx);
	pr_info(MODULE_NAME " %s allocated LFIProc slot %d\n", __func__, lfi_idx);
	if (!lfiproc) {
		pr_err(MODULE_NAME " %s: Failure to allocate LFI context\n", 
		       __func__);
		kage_memory_free(kage, guest_shadow_stack);
		kage_memory_free(kage, guest_stack);
		return -1;
	}

	unsigned long guest_stack_base = (unsigned long)guest_stack;
	unsigned long guest_stack_end = 
			guest_stack_base + KAGE_GUEST_STACK_SIZE;
	unsigned long guest_shadow_stack_end = 
			(unsigned long)guest_shadow_stack + SCS_SIZE;

	pr_info("guest stack at %px-%lx\n", guest_stack, guest_stack_end - 1);
	if (guest_shadow_stack) 
		pr_info("guest scs   at %px-%lx\n", guest_shadow_stack, 
			guest_shadow_stack_end - 1);

	// Shadow stacks grow up, so initialize it to the base 
	lfi_proc_init(lfiproc, kage, (unsigned long)fn, guest_stack_end,
		      (unsigned long)guest_shadow_stack, lfi_idx);
	// pr_info("%s id=%d, fn=0x%lx, ret=0x%lx\n", __func__, lfi_idx, 
	// 	(unsigned long)fn, kage->exit_addr);
	rv = lfi_proc_invoke(lfiproc, fn, (void *)(kage->exit_addr),
			     p0, p1, p2, p3, p4, p5);

	pr_info("%s to 0x%lx finished\n", __func__, (unsigned long)fn);
	kage_memory_free(kage, guest_shadow_stack);
	kage_memory_free(kage, guest_stack);
	kfree(lfiproc);
	kage->procs[lfi_idx] = NULL;
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
	int i;

	if (!kage)
		return;

	pr_info(MODULE_NAME ": destroying kage owner_id=%d\n", kage->owner_id);

	for (i = 0; i < kage->num_g2h_calls; i++)
		kfree(kage->g2h_calls[i]);

	for (i = 0; i < ARRAY_SIZE(kage->procs); i++)
		kfree(kage->procs[i]);

	unprotect_trampolines(kage);
	if (kage->alloc_bitmap)
		kage_memory_free_all(kage);

	vfree(kage->h2g_tramp_text);

	kfree(kage->objstorage);

	bitmap_free(kage->alloc_bitmap);

	assoc_array_destroy(&kage->closures, NULL);

	if (kage->owner_id < MAX_GUESTS && kages[kage->owner_id] == kage)
		kages[kage->owner_id] = NULL;

	kfree(kage);
	pr_info(MODULE_NAME ": %s complete\n", __func__);

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
