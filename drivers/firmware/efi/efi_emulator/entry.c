//SPDX-License-Identifier: GPL-2.0
#include <linux/types.h>
#include <linux/efi_emulator.h>
#include <asm/barrier.h>
#include <asm/sysreg.h>
#include <asm/elf.h>
#include <uapi/linux/elf.h>

#include "emulator.h"
#include "earlycon.h"

extern void enable_sctlr_el1(unsigned long scratch_reg);
static void arch_handle_mmu(struct efi_emulator_param *param)
{
	if (!param->mmu_on && param->pgd_root) {
	}
}

extern const Elf64_Rela _rela_start[], _rela_end[];

static void noinline arch_reloc_fixup(long delta)
{
	unsigned long *apply_addr, res;
	Elf64_Rela *rela;

	/* fix rela */
	for (rela = (Elf64_Rela *)_rela_start; rela < _rela_end; rela++) {
		//todo counterpart of R_AARCH64_RELATIVE on riscv
		if (ELF64_R_TYPE(rela->r_info) != R_AARCH64_RELATIVE)
			continue;
		apply_addr = (unsigned long *)(rela->r_offset + delta);
		res = rela->r_addend + delta;
		*apply_addr = res;
	}
	// todo flush cache

}

/* 
 * Ensure this entry and @param is in the mapping before jump to it.
 * It should be PIC and at the beginning of emulator.
 * It should be memory aligned
 */
void emulator_main(struct efi_emulator_param *param)
{
	long delta = param->load_address - EMULATOR_BASE_ADDR;
	struct efi_pe_instance *inst;

	arch_handle_mmu(param);
	arch_reloc_fixup(delta);
	setup_earlycon(param);
	printf("param:0x%lx, delta=0x%lx\n", (unsigned long)param, delta);
	printf("kernel_img_start:0x%lx, sz:0x%lx\n", (unsigned long)param->kernel_img_start, (unsigned long)param->kernel_img_sz);
	initialize_emulator_service(param);
	initialize_heap(param);
	printf(" load_kernel_pe\n");

	inst = allocate_pe_instance((char *)param->kernel_img_start,
					param->kernel_img_sz);
	load_kernel_pe(inst, &systabs);
}
