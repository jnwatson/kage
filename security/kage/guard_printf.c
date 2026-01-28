// SPDX-License-Identifier: GPL-2.0-only
#include <linux/stdarg.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kage.h>
#include <linux/string.h>

/* ARM64-specific internal va_list structure for in-place modification. */
typedef struct {
	void *__stack;
	void *__gr_top;
	void *__vr_top;
	int __gr_offs;
	int __vr_offs;
} kage_va_list;

/* Returns the address of the next 8-byte argument slot in the va_list.
 * On ARM64, arguments are first consumed from the general-purpose register
 * save area and then from the stack area once registers are exhausted.
 */
static void **get_next_va_slot(kage_va_list *ap)
{
	void **ptr;

	if (ap->__gr_offs < 0) {
		ptr = (void **)(ap->__gr_top + ap->__gr_offs);
		ap->__gr_offs += 8;
	} else {
		ptr = (void **)ap->__stack;
		ap->__stack += 8;
	}
	return ptr;
}

/* Guards a printf-fmt variadic function. Replaces all out-of-guest pointers with NULL. */
void guard_printf(const struct kage *kage, const char *fmt, va_list args)
{
	kage_va_list *ap;
	va_list args_copy;

	if (!fmt)
		return;

	/* On ARM64, va_list is a struct array, so it is passed by reference.
	 * We work on a copy to avoid advancing the original va_list's offsets,
	 * but the copy points to the same register/stack save areas.
	 */
	va_copy(args_copy, args);
	ap = (kage_va_list *)(void *)&args_copy;

	while (*fmt) {
		if (*fmt++ != '%')
			continue;

		if (*fmt == '%') {
			fmt++;
			continue;
		}

		/* 1. Skip flags */
		while (*fmt && strchr("-+ #0", *fmt))
			fmt++;

		/* 2. Handle dynamic or literal width */
		if (*fmt == '*') {
			get_next_va_slot(ap);
			fmt++;
		} else {
			while (isdigit(*fmt))
				fmt++;
		}

		/* 3. Handle dynamic or literal precision */
		if (*fmt == '.') {
			fmt++;
			if (*fmt == '*') {
				get_next_va_slot(ap);
				fmt++;
			} else {
				while (isdigit(*fmt))
					fmt++;
			}
		}

		/* 4. Skip length qualifiers */
		while (*fmt && strchr("hlLzt", *fmt))
			fmt++;

		/* 5. Handle type and sanitize if it's a pointer, string, or %n */
		if (*fmt == 's' || *fmt == 'p' || *fmt == 'n') {
			void **ptr_loc = get_next_va_slot(ap);
			unsigned long val = (unsigned long)*ptr_loc;

			if (val && (val - kage->base) >= KAGE_GUEST_SIZE)
				*ptr_loc = NULL;

			/* Skip pointer extensions (e.g., %pS, %pM) */
			if (*fmt == 'p') {
				fmt++;
				while (isalnum(*fmt))
					fmt++;
			} else {
				fmt++;
			}
		} else if (*fmt && strchr("cdiouxyX", *fmt)) {
			get_next_va_slot(ap);
			fmt++;
		} else if (*fmt) {
			/* Unknown specifier: stop to avoid desyncing the va_list. */
			break;
		}
	}
	va_end(args_copy);
}
