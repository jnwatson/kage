// SPDX-License-Identifier: GPL-2.0-only
#include <linux/stdarg.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kage.h>

/* Based on lib/vsprintf.c */

enum format_type {
	FORMAT_TYPE_NONE,
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF
};

struct printf_spec {
	unsigned int	type:8;
	unsigned int	flags:8;
};

#define LEFT	16	/* left justified */
#define PLUS	32	/* show plus */
#define SPACE	64	/* space if plus */
#define SPECIAL	128	/* 0x */
#define ZEROPAD	256	/* pad with zero, rather than space */
#define SMALL	512	/* use lowercase in hex (must be 32) */
#define SIGN	1024	/* unsigned/signed long */

static int skip_atoi(const char **s)
{
	int i = 0;

	do {
		i = i * 10 + *((*s)++) - '0';
	} while (isdigit(**s));

	return i;
}

static int format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;
	char qualifier;

	if (spec->type == FORMAT_TYPE_WIDTH) {
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	if (spec->type == FORMAT_TYPE_PRECISION) {
		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	spec->type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	if (fmt != start || !*fmt)
		return fmt - start;

	spec->flags = 0;

	while (1) {
		bool found = true;
		++fmt;
		switch (*fmt) {
		case '-': spec->flags |= LEFT;    break;
		case '+': spec->flags |= PLUS;    break;
		case ' ': spec->flags |= SPACE;   break;
		case '#': spec->flags |= SPECIAL; break;
		case '0': spec->flags |= ZEROPAD; break;
		default:  found = false;
		}
		if (!found)
			break;
	}

	if (isdigit(*fmt))
		skip_atoi(&fmt);
	else if (*fmt == '*') {
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	if (*fmt == '.') {
		++fmt;
		if (isdigit(*fmt)) {
			skip_atoi(&fmt);
		} else if (*fmt == '*') {
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	qualifier = 0;
	if (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' ||
	    *fmt == 'z' || *fmt == 't') {
		qualifier = *fmt++;
		if (qualifier == *fmt) {
			if (qualifier == 'l') {
				qualifier = 'L';
				++fmt;
			} else if (qualifier == 'h') {
				qualifier = 'H';
				++fmt;
			}
		}
	}

	switch (*fmt) {
	case 'c':
		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	case 'p':
		spec->type = FORMAT_TYPE_PTR;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	case 'o':
		break;

	case 'x':
		spec->flags |= SMALL;
		fallthrough;

	case 'X':
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;
		break;
	case 'u':
		break;

	default:
		spec->type = FORMAT_TYPE_INVALID;
		return fmt - start;
	}

	if (qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if (qualifier == 'l')
		spec->type = FORMAT_TYPE_ULONG + (spec->flags & SIGN);
	else if (qualifier == 'z')
		spec->type = FORMAT_TYPE_SIZE_T;
	else if (qualifier == 't')
		spec->type = FORMAT_TYPE_PTRDIFF;
	else if (qualifier == 'H')
		spec->type = FORMAT_TYPE_UBYTE + (spec->flags & SIGN);
	else if (qualifier == 'h')
		spec->type = FORMAT_TYPE_USHORT + (spec->flags & SIGN);
	else
		spec->type = FORMAT_TYPE_UINT + (spec->flags & SIGN);

	return ++fmt - start;
}

/* ARM64 specific va_list handling to allow in-place modification */
typedef struct {
	void *__stack;
	void *__gr_top;
	void *__vr_top;
	int __gr_offs;
	int __vr_offs;
} kage_va_list;

static void *get_next_va_ptr(kage_va_list *ap, int size)
{
	void *ptr;

	if (ap->__gr_offs < 0) {
		ptr = ap->__gr_top + ap->__gr_offs;
		ap->__gr_offs += 8;
	} else {
		ap->__stack = (void *)ALIGN((unsigned long)ap->__stack, 8);
		ptr = ap->__stack;
		ap->__stack += ALIGN(size, 8);
	}
	return ptr;
}

static void modify_va_ptr(struct kage *kage, void **ap_ptr)
{
	unsigned long val = (unsigned long)*ap_ptr;

	if (val && (val - kage->base) >= KAGE_GUEST_SIZE) {
		*ap_ptr = NULL;
	}
}

/* Guards a printf-fmt varargs. Replaces all out-of-guest pointers with NULL. */
void guard_printf(struct kage *kage, const char *fmt, va_list args)
{
	struct printf_spec spec = {0};
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
		int read = format_decode(fmt, &spec);
		fmt += read;

		switch (spec.type) {
		case FORMAT_TYPE_NONE:
		case FORMAT_TYPE_PERCENT_CHAR:
			break;

		case FORMAT_TYPE_STR:
		case FORMAT_TYPE_PTR: {
			void **ptr_loc = get_next_va_ptr(ap, 8);
			/* We are modifying the save area shared with the original va_list. */
			modify_va_ptr(kage, ptr_loc);
			if (spec.type == FORMAT_TYPE_PTR) {
				while (isalnum(*fmt))
					fmt++;
			}
			break;
		}

		case FORMAT_TYPE_INVALID:
			goto out;

		default:
			/* All other types consume one 8-byte GPR slot/stack slot on ARM64. */
			get_next_va_ptr(ap, 8);
			break;
		}
	}
out:
	va_end(args_copy);
}