//SPDX-License-Identifier: GPL-2.0

#include "emulator.h"

static efi_status_t conjoin_memreserve_table(void *table, efi_config_table_t *head)
{
	struct linux_efi_memreserve *new, *next;

	new = (struct linux_efi_memreserve *)table;
	new->next = 0;
	next = (struct linux_efi_memreserve *)head->table;
	while (next->next != 0)
		next = (struct linux_efi_memreserve *)next->next;
	next->next = (phys_addr_t)new;

	return EFI_SUCCESS;
}

efi_status_t conjoin_table(efi_guid_t *uuid, void *table, efi_config_table_t *t)
{
	if (!efi_guidcmp(t->guid, LINUX_EFI_MEMRESERVE_TABLE_GUID))
		return conjoin_memreserve_table(table, t);

	return EFI_OUT_OF_RESOURCES;
}
