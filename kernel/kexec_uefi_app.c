// SPDX-License-Identifier: GPL-2.0
/*
 * UEFI appilication file helpers
 *
 * Copyright (C) 2025, 2026 Red Hat, Inc
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/pe.h>
#include <linux/string.h>
#include "kexec_internal.h"

/*
 * The UEFI Terse Executable (TE) image has MZ header.
 */
static bool is_valid_pe(const char *kernel_buf, unsigned long kernel_len)
{
	struct mz_hdr *mz;
	struct pe_hdr *pe;

	if (!kernel_buf)
		return false;
	mz = (struct mz_hdr *)kernel_buf;
	if (mz->magic != IMAGE_DOS_SIGNATURE)
		return false;
	if (kernel_len < mz->peaddr + sizeof(struct pe_hdr))
		return false;
	pe = (struct pe_hdr *)(kernel_buf + mz->peaddr);
	if (pe->magic != IMAGE_NT_SIGNATURE)
		return false;
	if (pe->opt_hdr_size == 0) {
		pr_err("optional header is missing\n");
		return false;
	}
	return true;
}

bool pe_has_bpf_section(const char *file_buf, unsigned long pe_sz)
{
	char *sect_start = NULL;
	unsigned long sect_sz = 0;
	int ret;

	if (!is_valid_pe(file_buf, pe_sz))
		return false;
	ret = pe_get_section(file_buf, pe_sz, ".bpf", &sect_start, &sect_sz);
	if (ret < 0)
		return false;
	return true;
}

int pe_get_section(const char *file_buf, unsigned long buf_sz,
		   const char *sect_name, char **sect_start,
		   unsigned long *sect_sz)
{
	struct pe_hdr *pe_hdr;
	struct pe32plus_opt_hdr *opt_hdr;
	struct section_header *sect_hdr;
	int section_nr, i;
	struct mz_hdr *mz = (struct mz_hdr *)file_buf;

	*sect_start = NULL;
	*sect_sz = 0;

	/* Check MZ header fits in buffer */
	if (buf_sz < sizeof(struct mz_hdr))
		return -1;

	/* Check PE header offset is within buffer */
	if (mz->peaddr >= buf_sz || mz->peaddr > buf_sz - sizeof(struct pe_hdr))
		return -1;

	pe_hdr = (struct pe_hdr *)(file_buf + mz->peaddr);
	section_nr = pe_hdr->sections;

	/* Check optional header fits in buffer */
	if (mz->peaddr + sizeof(struct pe_hdr) > buf_sz ||
	    mz->peaddr + sizeof(struct pe_hdr) + pe_hdr->opt_hdr_size > buf_sz)
		return -1;

	opt_hdr = (struct pe32plus_opt_hdr *)(file_buf + mz->peaddr +
					      sizeof(struct pe_hdr));

	/* Check section headers fit in buffer */
	unsigned long sect_hdr_offset =
		mz->peaddr + sizeof(struct pe_hdr) + pe_hdr->opt_hdr_size;
	unsigned long sect_hdr_size =
		section_nr * sizeof(struct section_header);

	if (sect_hdr_offset > buf_sz ||
	    sect_hdr_size > buf_sz - sect_hdr_offset)
		return -1;

	sect_hdr = (struct section_header *)((char *)opt_hdr +
					     pe_hdr->opt_hdr_size);

	for (i = 0; i < section_nr; i++) {
		if (strcmp(sect_hdr->name, sect_name) == 0) {
			/* Check section data is within buffer */
			if (sect_hdr->data_addr >= buf_sz ||
			    sect_hdr->raw_data_size >
				    buf_sz - sect_hdr->data_addr)
				return -1;

			*sect_start = (char *)file_buf + sect_hdr->data_addr;
			*sect_sz = sect_hdr->raw_data_size;
			return 0;
		}
		sect_hdr++;
	}
	return -1;
}
