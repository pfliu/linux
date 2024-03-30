//SPDX-License-Identifier: GPL-2.0

#include <linux/stdarg.h>
#include <linux/amba/serial.h>
#include "earlycon.h"

#define SERIAL_IO_MEM32 3
#define UPIO_MEM32 SERIAL_IO_MEM32

struct uart_port {
	unsigned long		iobase;			/* in/out[bwl] */
	unsigned char __iomem	*membase;		/* read/write[bwl] */
	unsigned char		iotype;			/* io access style */
};

static struct uart_port pl011_port;

static void pl011_putc(struct uart_port *port, unsigned char c)
{
	while (readl(port->membase + UART01x_FR) & UART01x_FR_TXFF)
		cpu_relax();
	if (port->iotype == UPIO_MEM32)
		writel(c, port->membase + UART01x_DR);
	else
		writeb(c, port->membase + UART01x_DR);
	while (readl(port->membase + UART01x_FR) & UART01x_FR_BUSY)
		cpu_relax();
}

static int pl011_put_str(const char *str, void *data)
{
	char *p = (char *)str;
	struct uart_port *port = (struct uart_port *)data;

	for (; *p != '\0'; p++)
		pl011_putc(port, *p);

	return (p - str);
}

static void pl011_write(struct uart_port *port, unsigned int reg, unsigned int val)
{
	void __iomem *addr = port->membase + reg;

	if (port->iotype == UPIO_MEM32)
		writel_relaxed(val, addr);
	else
		writew_relaxed(val, addr);
}

static bool pl011_match(struct efi_emulator_param *param, const char *name)
{
	struct uart_port *port = &pl011_port;

	if (strcmp(param->earlycon_name, name))
		return false;

	port->iotype = UPIO_MEM32;
	port->membase = (unsigned char *)param->earlycon_reg_base;
	return true;
}

static void pl011_reset(void *data)
{
	struct uart_port *port = data;

	/* disable DMA */
	pl011_write(port, UART011_DMACR, 0);
	/* disable interrupt */
	pl011_write(port, UART011_IMSC, 0);
	/* Skip: set clk rate */
	/* Now, pl011 can be used in poll mode */
}

struct earlycon pl011 = {
	.match = pl011_match,
	.reset = pl011_reset,
	.put_str = pl011_put_str,
	.data = &pl011_port,
	.name = "amba-pl011",
};
