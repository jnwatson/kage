#ifndef KAGE_OBJDESCRIPTOR_H_
#define KAGE_OBJDESCRIPTOR_H_

#include <linux/types.h>

/*
 * Kage object descriptors encode metadata into a 64-bit value that does not
 * represent a canonical memory address.
 *
 * Layout:
 * | Bits   | Content      | Description                                |
 * |--------|--------------|--------------------------------------------|
 * | 63-33  | Tag          | High bits to make it a non-canonical value.|
 * | 32     | owner (1)    | The owner of the object (1=global, 0=local)|
 * | 31-17  | type (15)    | The type of the object.                    |
 * | 16-1   | objindex (16)| The index of the object.                   |
 * | 0      | flag (1)     | Must be 1 to indicate an objdescriptor.    |
 */

// The minimum value for an object descriptor. This ensures the high bits
// place it in a non-canonical address range.
// Note: this causes these descriptors to fall into the vmemmap section
#define KAGE_OBJDESC_BASE 0xfffffe0000000000ULL

// The flag in the LSB to identify an object descriptor.
#define KAGE_OBJDESC_FLAG 1ULL

#define KAGE_OWNER_GLOBAL 1U

/**
 * is_kage_objdescriptor - Check if a value is a valid kage object descriptor.
 * @val: The 64-bit value to check.
 *
 * A value is a valid object descriptor if it's in the non-canonical address
 * range reserved for them and has the object descriptor flag set. This function
 * does not validate the contents of the data fields (type, owner, objindex).
 *
 * Returns: true if the value is a valid object descriptor, false otherwise.
 */
static inline bool is_kage_objdescriptor(u64 val)
{
  bool is_in_range = (val & KAGE_OBJDESC_BASE) == KAGE_OBJDESC_BASE;

  bool has_flag = ((val & KAGE_OBJDESC_FLAG) != 0);

  return is_in_range && has_flag;
}

/**
 * kage_pack_objdescriptor - Creates an object descriptor from its components.
 * @type: An 15-bit type value.
 * @owner: An 1-bit owner value.
 * @objindex: A 16-bit object index.
 *
 * Returns: A 64-bit object descriptor value.
 */
#define kage_pack_objdescriptor(_type, _owner, _objindex) \
  (KAGE_OBJDESC_BASE | \
   ((u64)(_owner) << 32) | \
   ((u64)(_type) << 17) | \
   ((u64)(_objindex) << 1) | \
   KAGE_OBJDESC_FLAG)
/**
 * kage_unpack_objdescriptor_type - Extracts the 'type' field from an object descriptor.
 * @val: A 64-bit object descriptor.
 *
 * Returns: The 15-bit type value.
 */
static inline u16 kage_unpack_objdescriptor_type(u64 val)
{
  return (val >> 17) & 0x7FFF;
}

/**
 * kage_unpack_objdescriptor_owner - Extracts the 'owner' field from an object descriptor.
 * @val: A 64-bit object descriptor.
 *
 * Returns: The 1-bit owner value.
 */
static inline u8 kage_unpack_objdescriptor_owner(u64 val)
{
  return (val >> 32) & 0x1;
}

/**
 * kage_unpack_objdescriptor_objindex - Extracts the 'objindex' field from an object descriptor.
 * @val: A 64-bit object descriptor.
 *
 * Returns: The 16-bit object index.
 */
static inline u16 kage_unpack_objdescriptor_objindex(u64 val)
{
  return (val >> 1) & 0xFFFF;
}

#endif
