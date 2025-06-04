#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/hugetlb.h> // For huge page checks
#include <linux/pgtable.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h> // For flush_icache_range
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>   // For page table types and functions (arch-specific)
#include <linux/module.h>

//for debugfs
#include <linux/debugfs.h>
#include <linux/fs.h>       // For filp_open, filp_close
#include <linux/uaccess.h>  // For strndup_user
#include <linux/slab.h>


#include <linux/kage.h>

#include "proc.h"


#pragma clang optimize off

#define MODULE_NAME "kage"
#define VM_AREA_SIZE (64UL * 1024 * 1024 * 1024)
#define DOMAIN_SPAN (4UL * 1024 * 1024 * 1024) // 4GiB
#define MAX_DOMAINS (VM_AREA_SIZE / DOMAIN_SPAN - 1)

extern void lfi_syscall_entry(void) asm ("lfi_syscall_entry");
extern void lfi_ret(void) asm ("lfi_ret");

// To reduce PTE fragmentation, prefer PMD-sized allocations.
// FIXME: This won't be appropriate for PAGE_SIZE > 4KiB, nor call stacks
#define DOMAIN_PAGE_SHIFT PMD_SHIFT // 2MB pages
int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
                             pgprot_t prot, struct page **pages, unsigned int page_shift);

struct vm_struct *vm_area;
spinlock_t lock;

static struct kage kages[MAX_DOMAINS] = {};

// Returns true if compatible with LFI Spec 2.5 dense mode.
bool is_valid_vaddr(struct kage const *kage, unsigned long addr, enum mod_mem_type type) {
    unsigned long offset = addr - kage->base;
    if (addr < kage->base)
            return false;
    if (offset < PAGE_SIZE + 80UL * 1024 || offset > DOMAIN_SPAN - 80UL * 1024)
            return false;
    if (offset > DOMAIN_SPAN - 128UL * 1024 && mod_mem_type_is_text(type))
            return false;
    return true;
}

static void * kage_memory_alloc_explicit(struct kage *kage, unsigned long start, unsigned long end, 
                                         enum mod_mem_type type, bool do_lock) {

    // Keep track of all pages allocated just so we can undo the allocation if
    // we get a failure
    unsigned long size = end - start;
    unsigned int nr_pages = size >> DOMAIN_PAGE_SHIFT;
    unsigned long start_offset = start - kage->base;
    unsigned long irq_flags;
    int i, err;
    void * ret = NULL;

    struct page **tmp_pages = kmalloc_array(nr_pages, sizeof(*tmp_pages), GFP_KERNEL);
    if (!tmp_pages)
        return ERR_PTR(-ENOMEM);

    // FIXME: if we use this function in proxy/guard functions, we need a more
    // fine-grained lock
    if (do_lock)
            spin_lock_irqsave(&lock, irq_flags);

    for (i = 0; i < nr_pages; i++) {
        tmp_pages[i] = alloc_pages(GFP_KERNEL | __GFP_ZERO, DOMAIN_PAGE_SHIFT - PAGE_SHIFT);
        if (!tmp_pages[i]) {
            ret = ERR_PTR(-ENOMEM);
            goto free_pages;
        }
        kage->pages[(start_offset >> DOMAIN_PAGE_SHIFT) + i] = tmp_pages[i];
        set_bit((start_offset >> DOMAIN_PAGE_SHIFT) + i, kage->alloc_bitmap);
    }

    /* Map pages into VM area */
    err = vmap_pages_range_noflush(start, end, PAGE_KERNEL, tmp_pages, DOMAIN_PAGE_SHIFT);
    if (err)
        goto free_pages;

    ret = (void *)start;
    goto cleanup;

free_pages:
    for (i--; i >= 0; i--) {
        clear_bit((start_offset >> DOMAIN_PAGE_SHIFT) + i, kage->alloc_bitmap);
        __free_pages(tmp_pages[i], DOMAIN_PAGE_SHIFT - PAGE_SHIFT);
    }
cleanup:
    if (do_lock)
            spin_unlock_irqrestore(&lock, irq_flags);
    kfree(tmp_pages);
    return ret;
}

void * kage_memory_alloc(struct kage *kage, size_t size, enum mod_mem_type type)
{
    unsigned long start = ALIGN(kage->base + kage->next_open_offs, 1<<DOMAIN_PAGE_SHIFT);
    unsigned long end = ALIGN(start + size, 1<<DOMAIN_PAGE_SHIFT);
    size = end - start;

    if (!is_valid_vaddr(kage, start, type) || !is_valid_vaddr(kage, end, type)) {
            pr_err(MODULE_NAME ": cannot allocate size %zu\n", size);
            return ERR_PTR(-ENOMEM);
    }
    void *ret = NULL;
    unsigned long irq_flags;

    spin_lock_irqsave(&lock, irq_flags);
    ret = kage_memory_alloc_explicit(kage, start, end, type, false);
    if (IS_ERR(ret))
             goto cleanup;
    kage->next_open_offs = end - kage->base;
cleanup:
    spin_unlock_irqrestore(&lock, irq_flags);
    return ret;
}
EXPORT_SYMBOL(kage_memory_alloc);

static int kage_init(struct kage *kage)
{
    /* Allocate tracking structures */
    unsigned long nr_pages = VM_AREA_SIZE >> DOMAIN_PAGE_SHIFT;
    kage->pages = vzalloc(nr_pages * sizeof(*kage->pages));
    kage->alloc_bitmap = bitmap_zalloc(nr_pages, GFP_KERNEL);
    kage->next_open_offs = PAGE_SIZE + 80UL * 1024;
    BUG_ON(!is_valid_vaddr(kage, kage->base + kage->next_open_offs, MOD_TEXT));
    if (!kage->pages || !kage->alloc_bitmap) {
        vfree(kage->pages);
        kage->pages = 0;
        bitmap_free(kage->alloc_bitmap);
        return -ENOMEM;
    }

    for (int i=0; i<ARRAY_SIZE(kage->procs); i++)
              kage->procs[i] = NULL;
    kage->open_proc_idx = 0;
    return 0;
}

#if 0
void kage_free(struct kage *kage, 
              unsigned long vaddr)
{
    unsigned long vaddr_offset = vaddr - kage->base;
    unsigned long end = vaddr + size;
    unsigned int first_page = vaddr_offset >> DOMAIN_PAGE_SHIFT;
    unsigned int nr_pages = size >> DOMAIN_PAGE_SHIFT;
    unsigned long flags;
    int i;

    if (vaddr_offset >= DOMAIN_SPAN || end > kage->base + DOMAIN_SPAN) {
            WARN_ON(1);
            return;
    }

    spin_lock_irqsave(&lock, flags);

    /* Check if all pages in this section are actually allocated */
    for (i = 0; i < nr_pages; i++) {
        if (!test_bit(first_page + i, kage->alloc_bitmap)) {
            spin_unlock_irqrestore(&lock, flags);
            WARN_ON(1); // freeing 
        }
    }

    /* Remove kernel mapping */
    vunmap_range(vaddr, end);

    spin_unlock_irqrestore(&lock, flags);
    return 0;
}
EXPORT_SYMBOL(kage_memory_free);
#endif

void kage_memory_free_all(struct kage *kage)
{
    unsigned long flags;
    unsigned int nr_pages = DOMAIN_SPAN >> DOMAIN_PAGE_SHIFT;
    int i;

    vunmap_range(kage->base, kage->base + DOMAIN_SPAN);
    spin_lock_irqsave(&lock, flags);
    for_each_set_bit(i, kage->alloc_bitmap, nr_pages) {
        __free_pages(kage->pages[i], DOMAIN_PAGE_SHIFT - PAGE_SHIFT);
    }

    bitmap_zero(kage->alloc_bitmap, nr_pages);
    spin_unlock_irqrestore(&lock, flags);
}
EXPORT_SYMBOL(kage_memory_free_all);

static ssize_t debugfs_trigger_write(struct file *debug_file_node,
                                   const char __user *user_buf,
                                   size_t count, loff_t *ppos);

static struct dentry *my_debugfs_dir; // To hold our debugfs directory
// File operations for our debugfs node
static const struct file_operations debugfs_trigger_fops = {
    .owner = THIS_MODULE, // Still good practice, though THIS_MODULE is less critical for built-in
    .write = debugfs_trigger_write,
    // You might want .open and .release if you need to manage state
    // or just .llseek = no_llseek for a simple write-only node
    .llseek = no_llseek,
};


static void init_debugfs(void){

    my_debugfs_dir = debugfs_create_dir("kage", NULL);
    if (IS_ERR_OR_NULL(my_debugfs_dir)) {
        printk(KERN_WARNING MODULE_NAME ": Failed to create debugfs directory\n");
        my_debugfs_dir = NULL; // Ensure it's NULL if error
        // Decide if this is a fatal error for your feature
    } else {
        if (!debugfs_create_file("load", 0220, my_debugfs_dir,
                NULL, /* private_data, can be used to pass context */
            &debugfs_trigger_fops)) { 
              printk(KERN_WARNING MODULE_NAME ": Failed to create debugfs file 'load'\n");
            // Clean up directory if file creation fails and it's critical
            debugfs_remove_recursive(my_debugfs_dir);
            my_debugfs_dir = NULL;
        } else {
            printk(KERN_INFO MODULE_NAME": Created debugfs entry at /sys/kernel/debug/kage/load\n");
        }
    }

}

struct vm_struct *kage_vm_area;
void * vaddr_start;

#if 0
static int allocate_vmem(void) {
  size_t size = 64ULL * 1024 * 1024 * 1024;
  kage_vm_area = get_vm_area(size, VM_MAP); // VM_MAP indicates it's for mapping
  if (!kage_vm_area) {
      pr_err("Failed to get VM area for 0x%zx KiB\n", size / 1024);
      // Handle error
      return -ENOMEM;
  }
  vaddr_start = kage_vm_area->addr;
  pr_info("Reserved VM area: %px - %px (size: %lu GiB)\n",
          vaddr_start, vaddr_start + size - 1, size >> 30);

  // 2. For each section you want to map:
  size_t section_size = 8192; // Must be page-aligned
  unsigned int order = get_order(section_size);

  // Allocate contiguous physical pages
  struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
  if (!page) {
      // Handle error
  }

  return 0;
}
#endif

// Set the start addrs of the kage
static void init_kages(void)
{
    unsigned long addr = ALIGN((unsigned long)vm_area->addr, DOMAIN_SPAN);

    for (int i=0; i < MAX_DOMAINS; i++) {
      kages[i].base = addr;
    }
    addr += DOMAIN_SPAN;
    BUG_ON( addr > ((unsigned long)vm_area->addr + vm_area->size));
}

static int __init kagemodule_init(void)
{
    //unsigned long kernel_addr = (unsigned long)kage_init; // Example kernel address
    init_debugfs();
    printk(KERN_INFO "%s: kage_init\n", MODULE_NAME);

    /* Initialize context */

    spin_lock_init(&lock);

    /* Allocate VM area */
    vm_area = get_vm_area(VM_AREA_SIZE, VM_ALLOC);
    if (!vm_area) {
        return -ENOMEM;
    }

    init_kages();

    void * addr = vmalloc(PAGE_SIZE);
    ((uint8_t *)addr)[0] = 'a';
    unsigned long long kernel_addr = (uintptr_t) addr;
    struct page *page_ptr = vmalloc_to_page((void *)kernel_addr);
    // Convert the struct page* obtained from the correct path to a physical address.
    phys_addr_t phys_addr = page_to_phys(page_ptr);
    printk(KERN_INFO "physical/virtual address of vmalloc page is 0x%llx/0x%llx\n", phys_addr, kernel_addr);

    page_ptr = vmalloc_to_page((void *)kage_init);
    phys_addr = page_to_phys(page_ptr);
    printk(KERN_INFO "physical/virtual address of module page via vmalloc_to_page is 0x%llx/0x%llx\n", phys_addr, (unsigned long long) kage_init);

    page_ptr = virt_to_page((const void *)kage_init);
    phys_addr = page_to_phys(page_ptr);
    printk(KERN_INFO "physical address of module page via virt_to_page is 0x%llx\n", phys_addr);

    page_ptr = vmalloc_to_page((void *)vprintk);
    phys_addr = page_to_phys(page_ptr);
    printk(KERN_INFO "physical/virtual address of kernel page via vmalloc_to_page is 0x%llx/0x%llx\n", phys_addr, (unsigned long long)vprintk);

    page_ptr = virt_to_page((const void *)vprintk);
    phys_addr = page_to_phys(page_ptr);
    printk(KERN_INFO "physical address of kernel page via virt_to_page is 0x%llx\n", phys_addr);

    unsigned long vmalloc_start_addr = (unsigned long)VMALLOC_START;
    unsigned long vmalloc_end_addr = (unsigned long)VMALLOC_END;
    unsigned long vmalloc_size_bytes = vmalloc_end_addr - vmalloc_start_addr;

    pr_info("kage_vmalloc_info: VMALLOC_START Address: 0x%lx\n", vmalloc_start_addr);
    pr_info("kage_vmalloc_info: VMALLOC_END Address:   0x%lx\n", vmalloc_end_addr);
    pr_info("kage_vmalloc_info: Vmalloc Area Size:     %lu bytes (%lu MB, %lu GB)\n",
            vmalloc_size_bytes,
            vmalloc_size_bytes / (1024 * 1024),
            vmalloc_size_bytes / (1024 * 1024 * 1024));

    return 0;
}

// Find and return an unused kage in the kages array
static struct kage * alloc_kage(void)
{
  struct kage * kage = NULL;
  static int nextidx = 0;
  int i = nextidx;
  int last = i ? i-1 : MAX_DOMAINS - 1;

  while (1) {
    if (!kages[i].pages) {
      kage = &kages[i];
      break;
    }
    if (i==last) {
      break;
    }
    i = (i+1) % MAX_DOMAINS;
  }

  nextidx = i++ % MAX_DOMAINS;

  return kage;

}

static uint64_t kage_syshandler(uint64_t sysno, uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4, uint64_t p5) {
  pr_info(MODULE_NAME "syshandler %llu\n", sysno);
  return 0;
}

static void * setup_lfisys(struct kage *kage) {
    // FIXME: way too large an allocation
    unsigned long lfisys_end = ALIGN((kage->base + sizeof(LFISys)), 1<<DOMAIN_PAGE_SHIFT);
    void * sysmem = kage_memory_alloc_explicit(kage, kage->base, lfisys_end, MOD_DATA, true);
    if (IS_ERR(sysmem))
        return sysmem;

    kage->sys = (struct LFISys *) kage->base;
    kage->sys->rtcalls[0] = (uintptr_t) &lfi_syscall_entry;
    kage->sys->procs = &kage->procs;
    //FIXME: mark LFISys as readonly
    return kage->sys;
}

struct kage *kage_create(void) {
    struct kage * kage;
    int err;
    unsigned long irq_flags;

    // There's a remote chance that two calls can come in simultaneously, so
    // serialize with a lock
    spin_lock_irqsave(&lock, irq_flags);
    kage = alloc_kage();
    if (!kage) {
        kage = ERR_PTR(-ENOMEM);
        goto cleanup;
    }

    if ((err = kage_init(kage))) {
        kage = ERR_PTR(err);
        goto cleanup;
    }
    kage->syshandler = kage_syshandler;
cleanup:
    spin_unlock_irqrestore(&lock, irq_flags);
    void * ret = setup_lfisys(kage);
    if (IS_ERR(ret)) {
        kage_free(kage);
        return ret;
    }

    return kage;
}
EXPORT_SYMBOL(kage_create);

static struct LFIProc *alloc_lfiproc(struct kage *kage){
  // FIXME: acquire lock
        int start_idx = kage->open_proc_idx;
        while (kage->procs[kage->open_proc_idx]) {
          kage->open_proc_idx = (kage->open_proc_idx+1) % ARRAY_SIZE(kage->procs);
          if (start_idx == kage->open_proc_idx)
                  return NULL;
        }
        struct LFIProc * lfiproc = (struct LFIProc *)kmalloc(sizeof(*lfiproc), GFP_KERNEL);
        if (!lfiproc)
                  return NULL;

        kage->procs[kage->open_proc_idx] = lfiproc;
        kage->open_proc_idx = (kage->open_proc_idx+1) % ARRAY_SIZE(kage->procs);
        return lfiproc;
}

void do_ret(void) {
        lfi_ret();
}

// Call a module init function
int kage_call_init(struct kage *kage, initcall_t fn) {
        void * sb_stack = kage_memory_alloc(kage, 1 << KAGE_SANDBOX_STACK_ORDER, MOD_DATA);
        struct LFIProc * lfiproc = alloc_lfiproc(kage);
        int lfi_idx = (lfiproc - kage->procs[0]) / sizeof(struct LFIProc);
        unsigned long rel_stack_base = (uintptr_t)sb_stack + KAGE_SANDBOX_STACK_SIZE - kage->base;
        lfi_proc_init(lfiproc, kage, (int64_t)fn - kage->base, rel_stack_base, lfi_idx);
        return lfi_proc_invoke(lfiproc, fn, do_ret);
        //FIXME: free lfiproc
}

void kage_memory_free(struct kage *kage, void *vaddr) {
  // FIXME: free kage->procs
}


static struct dentry *my_debugfs_dir; // To hold our debugfs directory


// The write operation for our debugfs file
static ssize_t debugfs_trigger_write(struct file *debug_file_node,
                                   const char __user *user_buf,
                                   size_t count, loff_t *ppos) {
    struct kage * kage;
    char *path_buf;
    struct file *target_file_ptr;

    // Don't allow partial writes or seeks for this simple example
    if (*ppos != 0) {
        pr_warn(MODULE_NAME ": Partial write to debugfs not supported\n");
        return -EINVAL;
    }
    if (count >= PAGE_SIZE) { // Prevent overly long paths
        pr_warn(MODULE_NAME ": Path too long for debugfs\n");
        return -EINVAL;
    }

    // Get the path from userspace
    printk(KERN_INFO MODULE_NAME ": count=%zu\n", count);
    path_buf = strndup_user(user_buf, PAGE_SIZE);
    if (IS_ERR(path_buf)) {
        pr_warn(MODULE_NAME ": Failed to copy path from user: err=%ld\n", PTR_ERR(path_buf));
        return PTR_ERR(path_buf);
    }

    size_t slen = strlen(path_buf);
    if (!slen){
      pr_warn(MODULE_NAME ": Empty path\n");
      return -EINVAL;
    }

    // Remove trailing newline
    if (path_buf[slen-1] == '\n') {
      path_buf[slen-1] = '\0';
    }

    // Open the file specified by the path
    target_file_ptr = filp_open(path_buf, O_RDONLY, 0);
    if (IS_ERR(target_file_ptr)) {
        pr_warn(MODULE_NAME ": Failed to open file '%s': %ld\n",
                 path_buf, PTR_ERR(target_file_ptr));
        kfree(path_buf);
        return PTR_ERR(target_file_ptr);
    }

    kage = kage_create();
    if (IS_ERR(kage)) {
        pr_warn(MODULE_NAME ": create_kage failed with %ld\n", PTR_ERR(kage));
    }

    // Close the file
    filp_close(target_file_ptr, NULL);
    kfree(path_buf);

    return count; // Tell userspace we consumed 'count' bytes
}

void kage_free(struct kage * kage) {
    pr_info(MODULE_NAME " kage_free\n");
    kage_memory_free_all(kage);
    bitmap_free(kage->alloc_bitmap);
    vfree(kage->pages);
    kage->pages = NULL;
}
EXPORT_SYMBOL(kage_free);

static void __exit kagemodule_exit(void)
{
    printk(KERN_INFO "%s: Exiting\n", MODULE_NAME);
    for (int i=0; i < MAX_DOMAINS; i++) {
        struct kage * kage = &kages[i];
        if (kage->pages)
            kage_free(kage);
    }
    vfree(vm_area);
}

module_init(kagemodule_init);
module_exit(kagemodule_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("PTE walking example using current->mm");
