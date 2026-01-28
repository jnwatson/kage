#ifndef _KAGE_FUNCSIG_H
#define _KAGE_FUNCSIG_H

#include <linux/types.h>

enum kage_arg_kind {
	KAGE_ARG_END = 0,
	KAGE_ARG_VOID,
	KAGE_ARG_INT,
	KAGE_ARG_PTR,
	KAGE_ARG_PSTRUCT,
	KAGE_ARG_FUNC_PTR,
	KAGE_ARG_VARIADIC,
};

struct kage_argspec {
	enum kage_arg_kind kind;
	u32 type_id;
	union {
		struct kage_argspec *func_spec;
		u8 int_size;
	} spec;
};

struct kage_argspec *kage_get_funcspec(const char *func_name);
struct kage_argspec *kage_get_funcptr_argspec(struct kage_argspec *spec);
void kage_free_argspec(struct kage_argspec *specs);

#endif /* _KAGE_FUNCSIG_H */
