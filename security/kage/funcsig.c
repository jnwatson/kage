// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include "funcsig.h"

static u32 resolve_type_id(const struct btf *btf, u32 type_id,
			  const struct btf_type **type_out)
{
	const struct btf_type *t = btf_type_by_id(btf, type_id);

	while (btf_type_is_typedef(t) || btf_type_is_volatile(t) ||
	       btf_kind(t) == BTF_KIND_RESTRICT ||
	       btf_kind(t) == BTF_KIND_CONST) {
		type_id = t->type;
		t = btf_type_by_id(btf, type_id);
	}
	if (type_out)
		*type_out = t;
	return type_id;
}

static u32 find_kobject_offset_recursive(const struct btf *btf, u32 type_id)
{
	const struct btf_type *t = btf_type_by_id(btf, type_id);
	const struct btf_member *m;
	u32 i;

	if (!btf_type_is_struct(t))
		return (u32)-1;

	const char *name = btf_name_by_offset(btf, t->name_off);
	if (name && !strcmp(name, "kobject"))
		return 0;

	for (i = 0, m = btf_members(t); i < btf_vlen(t); i++, m++) {
		const struct btf_type *mtype;
		u32 mtype_id = resolve_type_id(btf, m->type, &mtype);
		u32 sub_off = find_kobject_offset_recursive(btf, mtype_id);

		if (sub_off != (u32)-1)
			return (m->offset / 8) + sub_off;
	}
	return (u32)-1;
}

static u16 find_kobject_offset(const struct btf *btf, u32 type_id)
{
	u32 off = find_kobject_offset_recursive(btf, type_id);

	if (off == (u32)-1 || off >= 0xFFFF)
		return 0;

	return (u16)off + 1;
}

/**
 * resolve_type() - Convert a BTF type ID into a kage_argspec.
 * @btf: The BTF blob for the kernel or module.
 * @type_id: The ID of the type to resolve.
 * @spec: Pointer to the kage_argspec to populate.
 *
 * This function resolves a given type ID to its base type and then populates
 * a kage_argspec structure with the relevant information, such as its kind
 * (integer, pointer, etc.) and any associated data (e.g., integer size).
 *
 * Return: True on success, false if the type is unsupported.
 */
static bool resolve_type(const struct btf *btf, __u32 type_id,
			 const char *name, struct kage_argspec *spec);

static struct kage_argspec *get_funcspec_from_proto_btf(const struct btf *btf, u32 proto_id);

static bool resolve_type(const struct btf *btf, __u32 type_id,
			 const char *name, struct kage_argspec *spec)
{
	const struct btf_type *t;
	u32 base_id = resolve_type_id(btf, type_id, &t);

	if (btf_type_is_void(t)) {
		spec->kind = KAGE_ARG_VOID;
		return true;
	}

	spec->type_id = base_id;

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_ENUM:
		spec->kind = KAGE_ARG_INT;
		spec->spec.int_size = t->size;
		break;
	case BTF_KIND_PTR: {
		const struct btf_type *target_t;
		u32 target_id = resolve_type_id(btf, t->type, &target_t);
		u16 target_kind = btf_kind(target_t);

		if (btf_type_is_func_proto(target_t)) {
			spec->kind = KAGE_ARG_FUNC_PTR;
			spec->type_id = target_id;
			spec->spec.func_spec = get_funcspec_from_proto_btf(btf, target_id);
		} else if (target_kind == BTF_KIND_STRUCT) {
			spec->kind = KAGE_ARG_PSTRUCT;
			spec->type_id = target_id;
			spec->kobj_offset = find_kobject_offset(btf, target_id);
		} else if (target_kind == BTF_KIND_UNION) {
			pr_warn("kage: pointers to unions are not supported types\n");
			return false;
		} else {
			spec->kind = KAGE_ARG_PTR;
		}
		break;
	}
	case BTF_KIND_STRUCT:
		pr_warn("kage: passing structs by value is not supported\n");
		return false;
	case BTF_KIND_UNION:
		pr_warn("kage: unions are not supported types\n");
		return false;
	default:
		pr_warn("kage: unsupported BTF kind %u\n", btf_kind(t));
		return false;
	}

	return true;
}

static struct kage_argspec *get_funcspec_from_proto_btf(const struct btf *btf, u32 proto_id)
{
	const struct btf_type *proto_t = btf_type_by_id(btf, proto_id);
	struct kage_argspec *specs = NULL;
	u16 nargs, i;
	bool has_func_ptr = false;

	if (!proto_t || !btf_type_is_func_proto(proto_t))
		return NULL;

	nargs = btf_vlen(proto_t);

	// Space for the return type + func args + end
	specs = kcalloc(nargs + 2, sizeof(*specs), GFP_KERNEL);
	if (!specs)
		return NULL;

	if (!resolve_type(btf, proto_t->type, NULL, &specs[0])) {
		kfree(specs);
		return NULL;
	}

	for (i = 0; i < nargs; i++) {
		const struct btf_param *p = btf_params(proto_t) + i;
		const char *name = btf_name_by_offset(btf, p->name_off);
		struct kage_argspec *spec = &specs[i + 1];

		if (!p->name_off && !p->type && i == nargs - 1) {
			spec->kind = KAGE_ARG_VARIADIC;
		}
		else if (!resolve_type(btf, p->type, name, spec)) {
			pr_warn("kage: unsupported type for argument %d of function signature\n",
				i);
			kfree(specs);
			return NULL;
		}

		if (has_func_ptr && spec->kind == KAGE_ARG_INT &&
		    spec->spec.int_size == sizeof(unsigned long)) {
			spec->kind = KAGE_ARG_PTR;
		}

		if (spec->kind == KAGE_ARG_FUNC_PTR)
			has_func_ptr = true;
	}

	specs[nargs + 1].kind = KAGE_ARG_END;
	return specs;
}

struct kage_argspec *kage_get_funcptr_argspec(struct kage_argspec *spec)
{
	if (spec->kind != KAGE_ARG_FUNC_PTR)
		return NULL;

	return spec->spec.func_spec;
}

/**
 * get_funcspec() - Retrieve the signature of a function using BTF.
 * @func_name: The name of the function to look up.
 *
 * This function queries the kernel's BTF data to find the specified function
 * and dynamically constructs its signature. The signature is returned as an
 * array of kage_argspec structures, with the first element representing the
 * return type and subsequent elements representing the parameters.
 *
 * Return: A kmalloc'd array of kage_argspec structures, terminated by an
 * entry with kind == KAGE_ARG_END. Returns NULL on failure (e.g., function
 * not found, memory allocation error, or unsupported argument type). The
 * caller is responsible for freeing the returned array with kage_free_argspec().
 */
struct kage_argspec *kage_get_funcspec(const char *func_name)
{
	struct btf *btf = NULL;
	s32 func_id;
	const struct btf_type *func_t;

	func_id = bpf_find_btf_id(func_name, BTF_KIND_FUNC, &btf);
	if (func_id < 0) {
		pr_warn("kage: could not find function %s in BTF\n", func_name);
		return NULL;
	}

	func_t = btf_type_by_id(btf, func_id);
	return get_funcspec_from_proto_btf(btf, func_t->type);
}

void kage_free_argspec(struct kage_argspec *specs)
{
	struct kage_argspec *s;

	if (!specs)
		return;

	for (s = specs; s->kind != KAGE_ARG_END; s++) {
		if (s->kind == KAGE_ARG_FUNC_PTR && s->spec.func_spec) {
			kage_free_argspec(s->spec.func_spec);
		}
	}
	kfree(specs);
}
