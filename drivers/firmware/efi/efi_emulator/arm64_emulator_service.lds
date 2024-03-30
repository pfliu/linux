/* SPDX-License-Identifier: GPL-2.0 */

ENTRY(emulator_entry)
EMULATOR_BASE_ADDR = 0x0;

SECTIONS
{
	. = EMULATOR_BASE_ADDR;
	.head : ALIGN(4096) {
		*(.head.text)
	}

	.text : {
		*(.text* .init.text*)
	}

	.rodata : ALIGN(8) {
		*(.rodata* .init.rodata* .srodata*)

		_etext = ALIGN(4096);
		. = _etext;
	}

	.rela.dyn : ALIGN(4096) {
		_rela_start = .;
		*(.rela .rela*)
		_rela_end = .;
	}

	.data : ALIGN(4096) {
		*(.data* .init.data*)
		_edata = ALIGN(512);
		. = _edata;
	}

	.bss : {
		*(.bss* .init.bss*)
		_end = ALIGN(512);
		. = _end;
	}

	/DISCARD/ : {
		*(.modinfo .init.modinfo)
	}
}
