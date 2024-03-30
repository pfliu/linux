/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EFI_EMULATOR_H
#define _LINUX_EFI_EMULATOR_H

#include <linux/types.h>
#include <linux/nls.h>
#include <linux/efi.h>

//todo, arch abstraction, for x86, it is efi_info
struct efi_rt_info {
	const efi_runtime_services_t	*runtime;	/* EFI runtime services table */
	unsigned int runtime_version;	/* Runtime services version */
	u32 runtime_supported_mask;
	/* Build systab tables from the following */
	unsigned int systab_nr_tables;
	efi_config_table_t systab_tables[20];
	struct efi_boot_memmap	memmap;
};

/* 1st kernel passes information through this struct */
struct efi_emulator_param {
	unsigned long sp;
	/* Should be page-aligned */
	unsigned long load_address;
	unsigned int sz_in_byte;
	wchar_t cmdline[512];
	bool noefi_boot;
	bool print_enabled;
	char earlycon_name[16];
	phys_addr_t earlycon_reg_base;
	unsigned long earlycon_reg_sz;

	bool mmu_on;
	/* root of pgtable */
	phys_addr_t pgd_root;
	phys_addr_t kernel_img_start;
	unsigned long kernel_img_sz;
	phys_addr_t dtb;
	phys_addr_t mempool_start;
	unsigned long mempool_sz;
	/* The last struct */
	struct efi_rt_info rt_info;
};

extern unsigned char _efi_emulator_start[], _efi_emulator_end[];
#endif
