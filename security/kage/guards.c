// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/printk.h>
#include "guards.h"

/*
 * These functions sit outside the LFI sandbox and allow the sandbox to make
 * function calls into the kernel
 */

unsigned long guard__printk(unsigned long p0, unsigned long p1,
			    unsigned long p2, unsigned long p3,
			    unsigned long p4, unsigned long p5)
{
	char *fmt = (char *)p0;
	va_list *pargs = (va_list *)p1;
	int rv = 0;

	pr_info("before vprintk\n");
	rv = vprintk(fmt, *pargs);
	pr_info("after vprintk\n");
	return rv;
}

guard_t *syscall_to_guard[GUARD_NUM_SYSCALLS] = {
	[1] = guard__printk,
};
