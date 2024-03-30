//SPDX-License-Identifier: GPL-2.0
#include "emulator.h"

char *heap_start, *heap_end, *heap_cur;

void initialize_heap(struct efi_emulator_param *param)
{
	heap_start = (char *)param->mempool_start;
	heap_end = heap_start + param->mempool_sz;
	heap_cur = heap_start;
}

//2do, the memory management is more complicated since we need to distinguish EFI_BOOT_SERVICE, RUNTIME, LOADER memory descr

void *aligned_alloc(size_t alignment, size_t size)
{
	char *p;

	p = (char *)ALIGN((unsigned long)heap_cur, alignment);
	heap_cur = p + size;

	//todo, update the efi_memory_desc to include this page, if it crosses the PAGE boundary
	//as EFI_BOOT_SERVICE,
	return p;
}


