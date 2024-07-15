/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/mm/proc.S
 *
 * Copyright (C) 2001 Deep Blue Solutions Ltd.
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/pgtable.h>
#include <linux/cfi_types.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/asm_pointer_auth.h>
#include <asm/hwcap.h>
#include <asm/kernel-pgtable.h>
#include <asm/pgtable-hwdef.h>
#include <asm/cpufeature.h>
#include <asm/alternative.h>
#include <asm/smp.h>
#include <asm/sysreg.h>

#ifdef CONFIG_ARM64_64K_PAGES
#define TCR_TG_FLAGS	TCR_TG0_64K | TCR_TG1_64K
#elif defined(CONFIG_ARM64_16K_PAGES)
#define TCR_TG_FLAGS	TCR_TG0_16K | TCR_TG1_16K
#else /* CONFIG_ARM64_4K_PAGES */
#define TCR_TG_FLAGS	TCR_TG0_4K | TCR_TG1_4K
#endif

#ifdef CONFIG_RANDOMIZE_BASE
#define TCR_KASLR_FLAGS	TCR_NFD1
#else
#define TCR_KASLR_FLAGS	0
#endif

#define TCR_SMP_FLAGS	TCR_SHARED

/* PTWs cacheable, inner/outer WBWA */
#define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA

#ifdef CONFIG_KASAN_SW_TAGS
#define TCR_KASAN_SW_FLAGS TCR_TBI1 | TCR_TBID1
#else
#define TCR_KASAN_SW_FLAGS 0
#endif

#ifdef CONFIG_KASAN_HW_TAGS
#define TCR_MTE_FLAGS TCR_TCMA1 | TCR_TBI1 | TCR_TBID1
#elif defined(CONFIG_ARM64_MTE)
/*
 * The mte_zero_clear_page_tags() implementation uses DC GZVA, which relies on
 * TBI being enabled at EL1.
 */
#define TCR_MTE_FLAGS TCR_TBI1 | TCR_TBID1
#else
#define TCR_MTE_FLAGS 0
#endif

/*
 * Default MAIR_EL1. MT_NORMAL_TAGGED is initially mapped as Normal memory and
 * changed during mte_cpu_setup to Normal Tagged if the system supports MTE.
 */
#define MAIR_EL1_SET							\
	(MAIR_ATTRIDX(MAIR_ATTR_DEVICE_nGnRnE, MT_DEVICE_nGnRnE) |	\
	 MAIR_ATTRIDX(MAIR_ATTR_DEVICE_nGnRE, MT_DEVICE_nGnRE) |	\
	 MAIR_ATTRIDX(MAIR_ATTR_NORMAL_NC, MT_NORMAL_NC) |		\
	 MAIR_ATTRIDX(MAIR_ATTR_NORMAL, MT_NORMAL) |			\
	 MAIR_ATTRIDX(MAIR_ATTR_NORMAL, MT_NORMAL_TAGGED))


SYM_FUNC_START(__cpu_setup)
	tlbi	vmalle1				// Invalidate local TLB
	dsb	nsh

	msr	cpacr_el1, xzr			// Reset cpacr_el1
	mov_q	x1, CPACR_EL1_FPEN_EL1EN | CPACR_EL1_FPEN_EL0EN | CPACR_EL1_ZEN_EL1EN
	msr	cpacr_el1, x1			// avoid the trap of FPSIMD in uefi code
	isb
	mov	x1, #1 << 12			// Reset mdscr_el1 and disable
	msr	mdscr_el1, x1			// access to the DCC from EL0
	reset_pmuserenr_el0 x1			// Disable PMU access from EL0
	reset_amuserenr_el0 x1			// Disable AMU access from EL0

	/*
	 * Default values for VMSA control registers. These will be adjusted
	 * below depending on detected CPU features.
	 */
	mair	.req	x17
	tcr	.req	x16
	mov_q	mair, MAIR_EL1_SET
	mov_q	tcr, TCR_T0SZ(IDMAP_VA_BITS) | TCR_T1SZ(VA_BITS_MIN) | TCR_CACHE_FLAGS | \
		     TCR_SMP_FLAGS | TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
		     TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS | TCR_MTE_FLAGS

	tcr_clear_errata_bits tcr, x9, x5

#ifdef CONFIG_ARM64_VA_BITS_52
	mov		x9, #64 - VA_BITS
alternative_if ARM64_HAS_VA52
	tcr_set_t1sz	tcr, x9
#ifdef CONFIG_ARM64_LPA2
	orr		tcr, tcr, #TCR_DS
#endif
alternative_else_nop_endif
#endif

	/*
	 * Set the IPS bits in TCR_EL1.
	 */
	tcr_compute_pa_size tcr, #TCR_IPS_SHIFT, x5, x6
#ifdef CONFIG_ARM64_HW_AFDBM
	/*
	 * Enable hardware update of the Access Flags bit.
	 * Hardware dirty bit management is enabled later,
	 * via capabilities.
	 */
	mrs	x9, ID_AA64MMFR1_EL1
	and	x9, x9, ID_AA64MMFR1_EL1_HAFDBS_MASK
	cbz	x9, 1f
	orr	tcr, tcr, #TCR_HA		// hardware Access flag update
1:
#endif	/* CONFIG_ARM64_HW_AFDBM */
	msr	mair_el1, mair
	msr	tcr_el1, tcr

	mrs_s	x1, SYS_ID_AA64MMFR3_EL1
	ubfx	x1, x1, #ID_AA64MMFR3_EL1_S1PIE_SHIFT, #4
	cbz	x1, .Lskip_indirection

	/*
	 * The PROT_* macros describing the various memory types may resolve to
	 * C expressions if they include the PTE_MAYBE_* macros, and so they
	 * can only be used from C code. The PIE_E* constants below are also
	 * defined in terms of those macros, but will mask out those
	 * PTE_MAYBE_* constants, whether they are set or not. So #define them
	 * as 0x0 here so we can evaluate the PIE_E* constants in asm context.
	 */

#define PTE_MAYBE_NG		0
#define PTE_MAYBE_SHARED	0

	mov_q	x0, PIE_E0
	msr	REG_PIRE0_EL1, x0
	mov_q	x0, PIE_E1
	msr	REG_PIR_EL1, x0

#undef PTE_MAYBE_NG
#undef PTE_MAYBE_SHARED

	mov	x0, TCR2_EL1x_PIE
	msr	REG_TCR2_EL1, x0

.Lskip_indirection:

	/*
	 * Prepare SCTLR
	 */
	mov_q	x0, INIT_SCTLR_EL1_MMU_ON
	ret					// return to head.S

	.unreq	mair
	.unreq	tcr
SYM_FUNC_END(__cpu_setup)

SYM_FUNC_START(enable_sctlr_el1)
	stp     x29, x30, [sp, #-16]!
	bl      __cpu_setup
	set_sctlr_el1 x0
	ldp     x29, x30, [sp], #16
	ret
SYM_FUNC_END(enable_sctlr_el1)

