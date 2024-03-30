//SPDX-License-Identifier: GPL-2.0
.section        ".head.text","ax"

/* x0 holds the physical address of emulator_param */
emulator_entry:
	ldr	x1, [x0]
	mov	sp, x1
	adrp	x2, emulator_main
	add	x2, x2, #:lo12:emulator_main
	br	x2
