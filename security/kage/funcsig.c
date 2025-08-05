// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
#include <linux/btf.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include "funcsig.h"

// DEBUG
#pragma clang optimize off

/**
 * resolve_typedef() - Traverse BTF type modifiers and typedefs.
 * @btf: The BTF blob for the kernel or module.
 * @t: The starting BTF type.
 *
 * This function follows the chain of type modifiers (e.g., const, volatile)
 * and typedefs until it reaches the underlying base type.
 *
 * Return: A pointer to the resolved base struct btf_type.
 */
static const struct btf_type *resolve_typedef(const struct btf *btf,
					      const struct btf_type *t)
{
	while (btf_type_is_typedef(t) || btf_type_is_volatile(t) ||
	       btf_kind(t) == BTF_KIND_RESTRICT ||
	       btf_kind(t) == BTF_KIND_CONST)
		t = btf_type_by_id(btf, t->type);
	return t;
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
			 const char *name, struct kage_argspec *spec)
{
	const struct btf_type *t =
		resolve_typedef(btf, btf_type_by_id(btf, type_id));

	if (btf_type_is_void(t)) {
		spec->kind = KAGE_ARG_VOID;
		return true;
	}

	switch (btf_kind(t)) {
	case BTF_KIND_INT:
		spec->kind = KAGE_ARG_INT;
		spec->spec.int_size = t->size;
		break;
	case BTF_KIND_PTR: {
		const struct btf_type *target_t = resolve_typedef(
			btf, btf_type_by_id(btf, t->type));
		u16 target_kind = btf_kind(target_t);

		if (btf_type_is_func_proto(target_t)) {
			spec->kind = KAGE_ARG_FUNC_PTR;
		} else if (target_kind == BTF_KIND_STRUCT) {
			spec->kind = KAGE_ARG_PSTRUCT;
			spec->spec.obj_type_id = target_t->type;
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
 * caller is responsible for freeing the returned array with kfree().
 */
struct kage_argspec *kage_get_funcspec(const char *func_name)
{
	struct btf *btf = NULL;
	s32 func_id;
	const struct btf_type *func_t, *proto_t;
	struct kage_argspec *specs = NULL;
	u16 nargs, i;
	bool has_func_ptr = false;

	func_id = bpf_find_btf_id(func_name, BTF_KIND_FUNC, &btf);
	if (func_id < 0) {
		pr_warn("kage: could not find function %s in BTF\n", func_name);
		return NULL;
	}

	func_t = btf_type_by_id(btf, func_id);
	proto_t = btf_type_by_id(btf, func_t->type);

	if (!btf_type_is_func_proto(proto_t)) {
		pr_err("kage: %s is not a function prototype\n", func_name);
		return NULL;
	}

	nargs = btf_vlen(proto_t);

	// Space for the return type + func args + end
	specs = kcalloc(nargs + 2, sizeof(*specs), GFP_KERNEL);
	if (!specs)
		return NULL;

	if (!resolve_type(btf, proto_t->type, NULL, &specs[0])) {
		pr_warn("kage: unsupported return type for function %s\n",
			func_name);
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
			pr_warn("kage: unsupported type for argument %d of function %s\n",
				i, func_name);
			kfree(specs);
			return NULL;
		}

		// FIXME: could actually check for unsigned long type
                // Treat a size_t-sized int as a ptr if it follows a function
                // pointer
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
