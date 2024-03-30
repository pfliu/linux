//SPDX-License-Identifier: GPL-2.0

#include <linux/efi.h>
#include <asm/efi.h>

#include "emulator.h"

static efi_status_t __efiapi emulator_get_rng(efi_rng_protocol_t * this,
						 efi_guid_t *uuid, unsigned long size,
						 u8 *out)
{
	/* in fact, disable aslr */
	*out = 0;
	return EFI_SUCCESS;
}

efi_rng_protocol_t emulator_rng = {
	.get_rng = emulator_get_rng,
};

static efi_status_t __efiapi emulator_get_memory_attributes(
	efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64 *)
{
	return EFI_SUCCESS;
}

static efi_status_t __efiapi emulator_set_memory_attributes(
	efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64)
{
	return EFI_SUCCESS;
}

static efi_status_t __efiapi emulator_clear_memory_attributes(
	efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64)
{
	return EFI_SUCCESS;
}

efi_memory_attribute_protocol_t emulator_memory_attribute = {
	.get_memory_attributes = emulator_get_memory_attributes,
	.set_memory_attributes = emulator_set_memory_attributes,
	.clear_memory_attributes = emulator_clear_memory_attributes,
};
