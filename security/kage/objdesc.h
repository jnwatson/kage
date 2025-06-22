/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KAGE_OBJDESC_H
#define __KAGE_OBJDESC_H

#include <linux/kage.h>
#include <linux/kage_objdescriptor.h>

void *kage_obj_get(struct kage *kage, u64 descriptor,
		   enum kage_objdescriptor_type type);
void kage_obj_set(struct kage *kage, u64 descriptor, void *obj);
void kage_obj_delete(struct kage *kage, u64 descriptor);
u64 kage_objstorage_alloc(struct kage *kage, bool is_global,
			  enum kage_objdescriptor_type type, void * obj);

#endif /* __KAGE_OBJDESC_H */
