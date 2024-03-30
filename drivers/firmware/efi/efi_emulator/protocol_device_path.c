//SPDX-License-Identifier: GPL-2.0
#include <linux/efi.h>
#include <asm/efi.h>
#include "emulator.h"

static inline bool is_end_node(efi_device_path_protocol_t *node)
{
	return node->type == EFI_DEV_END_PATH &&
		node->sub_type == EFI_DEV_END_ENTIRE;
}

static inline efi_device_path_protocol_t *
	next_device_path_node(efi_device_path_protocol_t *node)
{
    return (efi_device_path_protocol_t *)((u8 *)node + node->length);
}

/*
 * efi_device_path_compare - Compare two EFI device paths
 *
 * Return: 0 if equal, otherwise non-zero
 */
int efi_device_path_compare(efi_device_path_protocol_t *path1,
		efi_device_path_protocol_t *path2)
{
	efi_device_path_protocol_t *node1 = path1;
	efi_device_path_protocol_t *node2 = path2;

	while (!is_end_node(node1) && !is_end_node(node2)) {
		if (node1->type != node2->type ||
		    node1->sub_type != node2->sub_type ||
		    node1->length != node2->length)
			return 1;

		node1 = next_device_path_node(node1);
		node2 = next_device_path_node(node2);
	}

	/* Check if both reached the end */
	if (is_end_node(node1) && is_end_node(node2))
		return 0;

	return 1;
}

/*
 * efi_device_path_size - Calculate the total size of an EFI device path
 * @path: Pointer to the first EFI_DEVICE_PATH structure
 *
 * Return: Total size of the EFI device path
 */
size_t efi_device_path_size(efi_device_path_protocol_t *path)
{
	efi_device_path_protocol_t *node = path;
	size_t total_size = 0;

	while (!is_end_node(node)) {
		total_size += node->length;
		node = next_device_path_node(node);
	}

	/* Include the size of the end node */
	total_size += node->length;

	return total_size;
}

int efi_device_path_clone(efi_device_path_protocol_t *dst,
		efi_device_path_protocol_t *dp)
{
	size_t sz = efi_device_path_size(dp);

	memcpy((void *)dst, (void *)dp, sz);
	return 0;
}
