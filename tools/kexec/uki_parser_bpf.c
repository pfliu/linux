// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat, Inc
//
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "image_size.h"

/* ringbuf 2,3,4 are useless */
#define MIN_BUF_SIZE 1
#define MAX_RECORD_SIZE (IMAGE_SIZE + 40960)
#define RINGBUF1_SIZE IMAGE_SIZE_POWER2_ALIGN
#define RINGBUF2_SIZE MIN_BUF_SIZE
#define RINGBUF3_SIZE MIN_BUF_SIZE
#define RINGBUF4_SIZE MIN_BUF_SIZE

#include "template.c"

#define MAX_PARSING_BUFS 16
#define PE_SCAN_MAX      16
#define ELF_SCAN_MAX     16

/* SHN_UNDEF is a uapi macro not exported via BTF/vmlinux.h */
#ifndef SHN_UNDEF
#define SHN_UNDEF 0
#endif

#ifndef EIO
#define EIO 5
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

static const char linux_sect_name[]   = ".linux";
static const char initrd_sect_name[]   = ".initrd";
static const char cmdline_sect_name[]   = ".cmdline";
static const char uki_sect_name[]   = ".uki";
static const char addon_sect_name[] = ".addon";


#define MAKE_CMD(cmd, subcmd)  ((__u32)(cmd) | ((__u32)(subcmd) << 16))

static int fill_cmd(char *buf, __u32 cmd_word, __u32 pipeline_flag,
			const char *src, __u32 data_len)
{
	struct cmd_hdr *hdr;
	char *payload;

	__u16 cmd = (__u16)(cmd_word & 0xffff);
	__u16 subcmd = (__u16)(cmd_word >> 16);

	hdr = (struct cmd_hdr *)buf;
	hdr->cmd = cmd;
	hdr->subcmd = subcmd;
	hdr->pipeline_flag = pipeline_flag;
	hdr->payload_len = data_len;
	hdr->num_chunks = 0;

	payload = (char *)(hdr + 1);
	/* Only cmd, no payload */
	if (!src || !data_len)
		return sizeof(*hdr);
	if (data_len > MAX_RECORD_SIZE - sizeof(struct cmd_hdr))
		return -EINVAL;
	bpf_probe_read_kernel(payload, data_len, src);

	return sizeof(*hdr) + data_len;
}

static int process_uki_pe(const char *pe_buf, __u32 pe_sz, char *scratch,
			  struct bpf_parser_context *bpf_ctx)
{
	__u32 pe_offset, pe_sig, section_table_off;
	__u16 dos_magic, num_sections, opt_hdr_sz;
	__u16 pipeline_flag = 0;
	int i, ret;

	if (pe_sz < 64)
		return -EINVAL;
	if (pe_sz > MAX_RECORD_SIZE)
		return -EINVAL;

	if (bpf_probe_read_kernel(&dos_magic, sizeof(dos_magic), pe_buf) < 0)
		return -EIO;
	if (dos_magic != 0x5A4D)
		return -EINVAL;

	if (bpf_probe_read_kernel(&pe_offset, sizeof(pe_offset),
				  pe_buf + 0x3c) < 0)
		return -EIO;
	if (pe_offset + 24 > pe_sz)
		return -EINVAL;

	if (bpf_probe_read_kernel(&pe_sig, sizeof(pe_sig),
				  pe_buf + pe_offset) < 0)
		return -EIO;
	if (pe_sig != 0x00004550)
		return -EINVAL;

	if (bpf_probe_read_kernel(&num_sections, sizeof(num_sections),
				  pe_buf + pe_offset + 6) < 0)
		return -EIO;
	if (bpf_probe_read_kernel(&opt_hdr_sz, sizeof(opt_hdr_sz),
				  pe_buf + pe_offset + 20) < 0)
		return -EIO;

	section_table_off = pe_offset + 4 + 20 + opt_hdr_sz;
	if (section_table_off >= pe_sz)
		return -EINVAL;

	for (i = 0; i < PE_SCAN_MAX; i++) {
		__u32 raw_size, raw_off, shdr_off;
		char sec_name[8];
		__u16 subcmd;

		if (i >= num_sections)
			break;

		shdr_off = section_table_off + i * 40;
		if (shdr_off + 40 > pe_sz)
			break;

		if (bpf_probe_read_kernel(sec_name, sizeof(sec_name),
					  pe_buf + shdr_off) < 0)
			continue;

		pipeline_flag = 0;
		if (__builtin_memcmp(sec_name, linux_sect_name, sizeof(linux_sect_name)) == 0) {
			subcmd = KEXEC_BPF_SUBCMD_KERNEL;
			/*
			 * .linux section may contain different format kernel, which should be
			 * passed to the next stage to handle
			 */
			pipeline_flag = KEXEC_BPF_PIPELINE_FILL;
		}
		else if (__builtin_memcmp(sec_name, initrd_sect_name, sizeof(initrd_sect_name)) == 0)
			subcmd = KEXEC_BPF_SUBCMD_INITRD;
		else if (__builtin_memcmp(sec_name, cmdline_sect_name, sizeof(cmdline_sect_name)) == 0)
			subcmd = KEXEC_BPF_SUBCMD_CMDLINE;
		else
			continue;

		if (bpf_probe_read_kernel(&raw_size, sizeof(raw_size),
					  pe_buf + shdr_off + 16) < 0)
			continue;
		if (bpf_probe_read_kernel(&raw_off, sizeof(raw_off),
					  pe_buf + shdr_off + 20) < 0)
			continue;

		if (!raw_size || raw_off + raw_size > pe_sz)
			continue;

		ret = fill_cmd(scratch,
				MAKE_CMD(KEXEC_BPF_CMD_COPY, subcmd),
				pipeline_flag,
				pe_buf + raw_off,
				raw_size);
		ret = bpf_buffer_parser(scratch, ret, bpf_ctx);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * do_parse_elf_container - parse an ELF container and dispatch each
 *                          .uki / .addon section via process_uki_pe()
 *
 * @buf:     pointer to ELF data
 * @buf_sz:  size of ELF data
 * @bpf_ctx: parser context
 *
 * Returns 0 on success, negative errno on format error.
 */
static int do_parse_elf_container(const char *buf, unsigned long buf_sz,
				  char *scratch,
				  struct bpf_parser_context *bpf_ctx)
{
	Elf64_Ehdr ehdr;
	Elf64_Shdr shstr_shdr;
	__u64 shstrtab_off, shstrtab_sz;
	int i, ret;

	if (bpf_probe_read_kernel(&ehdr, sizeof(ehdr), buf) < 0)
		return -EIO;
	if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 ||
	    ehdr.e_shstrndx == SHN_UNDEF)
		return -EINVAL;

	if (bpf_probe_read_kernel(&shstr_shdr, sizeof(shstr_shdr),
				  buf + ehdr.e_shoff +
				  ehdr.e_shstrndx * sizeof(Elf64_Shdr)) < 0)
		return -EIO;

	shstrtab_off = shstr_shdr.sh_offset;
	shstrtab_sz  = shstr_shdr.sh_size;

	for (i = 1; i < ELF_SCAN_MAX; i++) {
		Elf64_Shdr shdr;
		char sec_name[8];
		__u64 name_off;

		if (i >= ehdr.e_shnum)
			break;

		if (bpf_probe_read_kernel(&shdr, sizeof(shdr),
					  buf + ehdr.e_shoff +
					  i * sizeof(Elf64_Shdr)) < 0)
			continue;

		name_off = shstrtab_off + shdr.sh_name;
		if (name_off + sizeof(sec_name) > shstrtab_off + shstrtab_sz)
			continue;
		if (bpf_probe_read_kernel(sec_name, sizeof(sec_name),
					  buf + name_off) < 0)
			continue;

		if (__builtin_memcmp(sec_name, uki_sect_name, sizeof(uki_sect_name)) != 0 &&
		    __builtin_memcmp(sec_name, addon_sect_name, sizeof(addon_sect_name)) != 0)
			continue;

		if (!shdr.sh_size || shdr.sh_offset + shdr.sh_size > buf_sz)
			continue;

		ret = process_uki_pe(buf + shdr.sh_offset,
				     (__u32)shdr.sh_size,
				     scratch,
				     bpf_ctx);
		if (ret) {
			bpf_printk("do_parse_elf_container: process_uki_pe failed at section %d: %d\n",
				   i, ret);
			return ret;
		}
	}

	return 0;
}

/*
 * parse_one_buf - detect format and dispatch a single independent
 *                 PE or ELF buffer (multi-buffer path only).
 *
 * Signature verification has already been performed by the kernel;
 * this function only parses content and dispatches KEXEC_BPF_CMD_COPY.
 *
 * Returns 0 on success, negative errno on format error.
 */
static int parse_one_buf(const char *buf, unsigned long sz, char *scratch,
			 struct bpf_parser_context *bpf_ctx)
{
	__u8 magic[4];

	if (!buf || sz < 4)
		return -EINVAL;

	if (bpf_probe_read_kernel(magic, sizeof(magic), buf) < 0)
		return -EIO;

	if (magic[0] == 'M' && magic[1] == 'Z')
		return process_uki_pe(buf, (__u32)sz, scratch, bpf_ctx);

	if (magic[0] == 0x7f && magic[1] == 'E' &&
	    magic[2] == 'L'  && magic[3] == 'F')
		return do_parse_elf_container(buf, sz, scratch, bpf_ctx);

	bpf_printk("parse_one_buf: unrecognized format\n");
	return -EINVAL;
}

SEC("fentry.s/kexec_image_parser_anchor")
int BPF_PROG(parse_uki, struct kexec_context *context, unsigned long parser_id)
{
	struct bpf_parser_context *bpf_ctx;
	char *buf0, *buf1, *scratch;
	__u8 magic[4];
	int ret;

	bpf_printk("parse_uki: start\n");
	buf0 = BPF_CORE_READ(context, parsing_buf[0]);
	if (!buf0)
		return 0;

	bpf_ctx = bpf_get_parser_context(parser_id);
	if (!bpf_ctx) {
		bpf_printk("parse_uki: no parser context for id %lu\n",
			   parser_id);
		return 0;
	}

	buf1 = BPF_CORE_READ(context, parsing_buf[1]);

	/*
	 * Single-buffer path: original parse_uki behaviour.
	 * parsing_buf[0] is either a plain PE UKI or an ELF container
	 * with embedded .uki / .addon sections.
	 */
	if (!buf1) {
		unsigned long sz = BPF_CORE_READ(context, parsing_buf_sz[0]);

		if (sz < 4)
			goto out2;

		if (bpf_probe_read_kernel(magic, sizeof(magic), buf0) < 0)
			goto out2;

		scratch = bpf_ringbuf_reserve(&ringbuf_1, MAX_RECORD_SIZE, 0);
		if (!scratch) {
			bpf_printk("ringbuf reserve failed\n");
			goto out2;
		}

		if (magic[0] == 'M' && magic[1] == 'Z') {
			ret = process_uki_pe(buf0, (__u32)sz, scratch, bpf_ctx);
			if (ret) {
				bpf_printk("parse_uki: PE path failed: %d\n",
					   ret);
			}
			else {
				bpf_printk("fill KEXEC_BPF_CMD_DONE \n");
				ret = fill_cmd(scratch, MAKE_CMD(KEXEC_BPF_CMD_DONE, 0),
						0, NULL, 0);
				ret = bpf_buffer_parser(scratch, ret, bpf_ctx);
				if (ret)
					bpf_printk("parse_uki: inject KEXEC_BPF_CMD_DONE failed: %d\n",
					   ret);
			}
		} else if (magic[0] == 0x7f && magic[1] == 'E' &&
		    magic[2] == 'L'  && magic[3] == 'F') {
			ret = do_parse_elf_container(buf0, sz, scratch, bpf_ctx);
			if (ret) {
				bpf_printk("parse_uki: ELF container failed: %d\n",
					   ret);
			}
			else {
				ret = fill_cmd(scratch, MAKE_CMD(KEXEC_BPF_CMD_DONE, 0),
						0, NULL, 0);
				ret = bpf_buffer_parser(scratch, ret, bpf_ctx);
			}
		} else {
			bpf_printk("parse_uki: unrecognized format\n");
		}

		bpf_ringbuf_discard(scratch, BPF_RB_NO_WAKEUP);
		goto out2;
	}

#if 0
	/*
	 * Multi-buffer path: each parsing_buf[i] is an independent PE
	 * whose signature has already been verified by the kernel.
	 * Process each in order; a format error causes immediate exit.
	 */
	scratch = bpf_ringbuf_reserve(&ringbuf_1, MAX_RECORD_SIZE, 0);
	if (!scratch) {
		bpf_printk("ringbuf reserve failed\n");
		goto out2;
	}
	for (i = 0; i < MAX_PARSING_BUFS; i++) {
		unsigned long sz;
		char *buf;

		buf = BPF_CORE_READ(context, parsing_buf[i]);
		if (!buf)
			break;

		sz = BPF_CORE_READ(context, parsing_buf_sz[i]);

		ret = parse_one_buf(buf, sz, scratch, bpf_ctx);
		if (ret) {
			bpf_printk("parse_uki: buf[%d] failed: %d\n", i, ret);
			break;
		}
	}

out1:
	bpf_ringbuf_discard(scratch, BPF_RB_NO_WAKEUP);
out2:
	bpf_put_parser_context(bpf_ctx);
	return 0;
}
