// SPDX-License-Identifier: GPL-2.0
//
// Copyright (C) 2025, 2026 Red Hat, Inc
//
#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include "image_size.h"
#include <linux/elf.h>

/* ringbuf 2,3,4 are useless */
#define MIN_BUF_SIZE 1
#define MAX_RECORD_SIZE (IMAGE_SIZE + 40960)
#define RINGBUF1_SIZE IMAGE_SIZE_POWER2_ALIGN
#define RINGBUF2_SIZE MIN_BUF_SIZE
#define RINGBUF3_SIZE MIN_BUF_SIZE
#define RINGBUF4_SIZE MIN_BUF_SIZE

#include "template.c"

/*
 * dispatch_cmd - build a ringbuf entry with a single KEXEC_BPF_CHUNK_PE
 *                chunk and call bpf_buffer_parser()
 *
 * @cmd:     KEXEC_BPF_CMD_* value
 * @subcmd:  KEXEC_BPF_SUBCMD_* value (0 if not applicable)
 * @data:    pointer to payload
 * @data_len: length of payload
 * @bpf_ctx: parser context
 *
 * Returns 0 on success, negative errno otherwise.
 */
static int dispatch_cmd(__u16 cmd, __u16 subcmd, const char *data,
			__u32 data_len, struct bpf_parser_context *bpf_ctx)
{
	__u32 total =
		sizeof(struct cmd_hdr) + sizeof(struct cmd_chunk) + data_len;
	struct cmd_chunk *chunk;
	struct cmd_hdr *hdr;
	char *payload;
	void *buf;
	int ret;

	buf = bpf_ringbuf_reserve(&ringbuf_1, total, 0);
	if (!buf) {
		bpf_printk("dispatch_cmd: ringbuf reserve failed\n");
		return -ENOMEM;
	}

	hdr = (struct cmd_hdr *)buf;
	hdr->cmd = cmd;
	hdr->subcmd = subcmd;
	hdr->payload_len = sizeof(struct cmd_chunk) + data_len;
	hdr->num_chunks = 1;

	chunk = (struct cmd_chunk *)((char *)buf + sizeof(*hdr));
	chunk->type = KEXEC_BPF_CHUNK_PE;
	chunk->len = data_len;

	payload = (char *)(chunk + 1);
	bpf_probe_read_kernel(payload, data_len, data);

	ret = bpf_buffer_parser(buf, total, bpf_ctx);
	if (ret) {
		bpf_printk(
			"dispatch_cmd: bpf_buffer_parser cmd=0x%x failed: %d\n",
			cmd, ret);
		bpf_ringbuf_discard(buf, BPF_RB_NO_WAKEUP);
		return ret;
	}

	bpf_ringbuf_submit(buf, 0);
	return 0;
}

/*
 * process_pe_section - verify and dispatch a single PE section
 *
 * Verification behaviour is governed by context->sig_enforced:
 *
 *   SIG_ENFORCE_NONE: skip verification, dispatch COPY directly
 *   SIG_ENFORCE_SIG:  VERIFY_SIG must pass; no IMA fallback
 *   SIG_ENFORCE_IMA:  try VERIFY_SIG first; if absent or invalid,
 *                     require IMA_CHECK with @ima_data/@ima_len
 *
 * @pe_data:  pointer to PE payload
 * @pe_len:   length of PE payload
 * @ima_data: IMA sig blob, or NULL if no .ima section followed
 * @ima_len:  length of IMA sig blob, or 0
 * @sig_enforced: value of context->sig_enforced
 * @bpf_ctx:  parser context
 *
 * Returns 0 on success, negative errno otherwise.
 */
static int process_pe_section(const char *pe_data, __u32 pe_len,
			      const char *ima_data, __u32 ima_len,
			      enum kexec_sig_enforced sig_enforced,
			      struct bpf_parser_context *bpf_ctx)
{
	int ret = 0;

	switch (sig_enforced) {
	case SIG_ENFORCE_NONE:
		break;

	case SIG_ENFORCE_SIG:
		ret = dispatch_cmd(KEXEC_BPF_CMD_VERIFY_SIG, 0, pe_data, pe_len,
				   bpf_ctx);
		if (ret) {
			bpf_printk(
				"process_pe_section: SIG verification failed: %d\n",
				ret);
			return ret;
		}
		break;

	case SIG_ENFORCE_IMA:
		ret = dispatch_cmd(KEXEC_BPF_CMD_VERIFY_SIG, 0, pe_data, pe_len,
				   bpf_ctx);
		if (ret) {
			/*
                         * Signature absent or invalid: fall back to IMA.
                         * Require a .ima section to be present.
                         */
			if (!ima_data || !ima_len) {
				bpf_printk(
					"process_pe_section: SIG failed (%d) and no IMA sig available\n",
					ret);
				return ret;
			}

			ret = dispatch_cmd(KEXEC_BPF_CMD_IMA_CHECK, 0, ima_data,
					   ima_len, bpf_ctx);
			if (ret) {
				bpf_printk(
					"process_pe_section: IMA check failed: %d\n",
					ret);
				return ret;
			}
		}
		break;

	default:
		bpf_printk(
			"process_pe_section: unknown sig_enforced value %d\n",
			sig_enforced);
		return -EINVAL;
	}

	return dispatch_cmd(KEXEC_BPF_CMD_COPY, 0, pe_data, pe_len, bpf_ctx);
}

SEC("fentry.s/kexec_image_parser_anchor")
int BPF_PROG(parse_elf_container, struct kexec_context *context,
	     unsigned long parser_id)
{
	unsigned long buf_sz = BPF_CORE_READ(context, parsing_buf_sz);
	char *buf = BPF_CORE_READ(context, parsing_buf);
	enum kexec_sig_enforced sig_enforced =
		BPF_CORE_READ(context, sig_enforced);
	struct {
		__u64 sh_offset;
		__u32 sh_size;
		bool valid;
	} pending = {};
	struct bpf_parser_context *bpf_ctx;
	Elf64_Ehdr ehdr;
	Elf64_Shdr shstr_shdr;
	__u64 shstrtab_off, shstrtab_sz;
	__u8 magic[4];
	int i, ret;

	if (!buf || buf_sz < 64)
		return 0;

	if (bpf_probe_read_kernel(magic, sizeof(magic), buf) < 0)
		return 0;

	/* Must be an ELF container */
	if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' ||
	    magic[3] != 'F') {
		bpf_printk("parse_elf_container: not an ELF image\n");
		return 0;
	}

	bpf_ctx = bpf_get_parser_context(parser_id);
	if (!bpf_ctx) {
		bpf_printk(
			"parse_elf_container: no parser context for id %lu\n",
			parser_id);
		return 0;
	}

	if (bpf_probe_read_kernel(&ehdr, sizeof(ehdr), buf) < 0)
		return 0;
	if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0 ||
	    ehdr.e_shstrndx == SHN_UNDEF)
		return 0;

	if (bpf_probe_read_kernel(
		    &shstr_shdr, sizeof(shstr_shdr),
		    buf + ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr)) <
	    0)
		return 0;

	shstrtab_off = shstr_shdr.sh_offset;
	shstrtab_sz = shstr_shdr.sh_size;

	/*
         * Single pass over ELF section table in file order.
         *
         * Invariant: @pending holds the most recently seen .pe.xxx section
         * that has not yet been dispatched.  A .ima section immediately
         * following consumes @pending (PE verified + dispatched with IMA).
         * Any other .pe.xxx section causes @pending to be flushed first
         * without an IMA blob.
         */
	for (i = 1; i < ELF_SCAN_MAX; i++) {
		Elf64_Shdr shdr;
		char sec_name[8];
		__u64 name_off;
		bool is_pe, is_ima;

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

		is_pe = __builtin_memcmp(sec_name, ".pe.", 4) == 0;
		is_ima = __builtin_memcmp(sec_name, ".ima\0", 5) == 0;

		if (is_ima) {
			if (!pending.valid)
				continue;

			ret = process_pe_section(buf + pending.sh_offset,
						 pending.sh_size,
						 buf + shdr.sh_offset,
						 (__u32)shdr.sh_size,
						 sig_enforced, bpf_ctx);
			pending.valid = false;
			if (ret) {
				bpf_printk(
					"parse_elf_container: section %d (with IMA) failed: %d\n",
					i, ret);
				return 0;
			}
			continue;
		}

		if (is_pe) {
			/* Flush pending PE that had no .ima */
			if (pending.valid) {
				ret = process_pe_section(
					buf + pending.sh_offset,
					pending.sh_size, NULL, 0, sig_enforced,
					bpf_ctx);
				if (ret) {
					bpf_printk(
						"parse_elf_container: flush pending PE failed: %d\n",
						ret);
					return 0;
				}
			}

			if (!shdr.sh_size ||
			    shdr.sh_offset + shdr.sh_size > buf_sz)
				continue;

			pending.sh_offset = shdr.sh_offset;
			pending.sh_size = (__u32)shdr.sh_size;
			pending.valid = true;
			continue;
		}
	}

	/* Flush last pending PE if no trailing .ima */
	if (pending.valid) {
		ret = process_pe_section(buf + pending.sh_offset,
					 pending.sh_size, NULL, 0, sig_enforced,
					 bpf_ctx);
		if (ret)
			bpf_printk(
				"parse_elf_container: final PE flush failed: %d\n",
				ret);
	}

	return 0;
}
