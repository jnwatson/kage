#include <linux/printk.h>
#include "guards.h"

unsigned long guard__printk(
  unsigned long p0,
  unsigned long p1,
  unsigned long p2,
  unsigned long p3,
  unsigned long p4,
  unsigned long p5) {
        int rv;

        char * fmt = (char *)p0;
        va_list * pargs = (va_list *)p1;
        pr_info("before vprintk\n");
        rv = vprintk(fmt, *pargs);
        pr_info("after vprintk\n");
        return rv;
}

guardT* syscall_to_guard[GUARD_NUM_SYSCALLS] = {
    [1] = guard__printk,
};

