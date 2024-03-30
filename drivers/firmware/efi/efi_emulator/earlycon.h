/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/efi_emulator.h>
#include <asm/processor.h>
#include <asm/io.h>
#include <asm-generic/io.h>

struct earlycon {
	bool (*match)(struct efi_emulator_param *param, const char *name);
	int (*put_str)(const char *str, void *data);
	void (*reset)(void *data);
	void *data;
	const char *name;
};

extern struct earlycon pl011;

extern int pl011_puts(const char *str);
void setup_earlycon(struct efi_emulator_param *param);
