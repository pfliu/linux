//SPDX-License-Identifier: GPL-2.0
#include <linux/efi.h>
#include <asm/efi.h>

#include "emulator.h"

/*
 * mem_type affects the allocated chunk in efi_memory_desc_t's type. Later,
 * kernel can know whether to reclaim them.
 */
efi_status_t __emulator_allocate_pages(int alloc_type, int mem_type,
			unsigned long nr_pages, efi_physical_addr_t *addr)
{
	efi_physical_addr_t res;
	efi_status_t status;

	if (alloc_type == EFI_ALLOCATE_ANY_PAGES) {
		res = (efi_physical_addr_t)aligned_alloc(PAGE_SIZE, nr_pages << PAGE_SHIFT);
		*addr = res;
		status = EFI_SUCCESS;
	} else if (alloc_type == EFI_ALLOCATE_MAX_ADDRESS) {
		//tmp
		res = (efi_physical_addr_t)aligned_alloc(PAGE_SIZE, nr_pages << PAGE_SHIFT);
		*addr = res;
		status = EFI_SUCCESS;
	/* e.g. aarch64 kimage loaded alignment */
	} else if (alloc_type == EFI_ALLOCATE_ADDRESS) {
		//tmp, just aligned on 2MB as aarch64 boot protocol
		res = (efi_physical_addr_t)aligned_alloc(1<<21, nr_pages << PAGE_SHIFT);
		*addr = res;
		status = EFI_SUCCESS;
	}

	return status;
}

//todo
efi_status_t __emulator_allocate_pool(int mem_type, unsigned long sz,
				       void **pool)
{
	void *res;

	res = aligned_alloc(sizeof(unsigned long), sz);
	*pool = res;
	return EFI_SUCCESS;
}

/* @memmap: only holds efi_memory_desc */
efi_status_t emulator_get_memory_map(unsigned long *map_sz,
	void *memmap, unsigned long *map_key, unsigned long *desc_sz,
	unsigned int *desc_version)
{
	//todo rt_info.memmap will be accessed by kernel, so it should be marked as reserved
	struct efi_boot_memmap *p = &emulator_param->rt_info.memmap;
	//efi_memory_desc_t *desc = p->map;

	if (!map_sz || !desc_sz)
		return EFI_INVALID_PARAMETER;
	if (*map_sz < p->map_size || !memmap) {
		*map_sz = p->map_size;
		*desc_sz = p->desc_size;
		return EFI_BUFFER_TOO_SMALL;
	}

	/* desc range size*/
	*map_sz = p->map_size;
	memcpy(memmap, p->map, p->map_size);
	if (!!desc_sz)
		*desc_sz = p->desc_size;
	if (!!desc_version)
		*desc_version = p->desc_ver;

	return EFI_SUCCESS;
}
