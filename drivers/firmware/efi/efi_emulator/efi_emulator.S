/* SPDX-License-Identifier: GPL-2.0 */

	.section .rodata, "a"

	.align	8
_efi_emulator_start:
	.globl	_efi_emulator_start
	.incbin	"drivers/firmware/efi/efi_emulator/emulator.raw"

	.align	8
_efi_emulator_end:
	.globl	_efi_emulator_end
